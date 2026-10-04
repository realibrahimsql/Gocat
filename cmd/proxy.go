package cmd

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/realibrahimsql/Gocat/internal/logger"
	"github.com/spf13/cobra"
)

var (
	proxyListen          string
	proxyTarget          string
	proxyTargets         []string
	proxyLoadBalance     string
	proxyHealthCheck     string
	proxyTimeout         time.Duration
	proxyMaxConns        int
	proxyMaxBody         int64
	proxyModifyHeader    bool
	proxyLogRequests     bool
	proxySSL             bool
	proxySSLCert         string
	proxySSLKey          string
	proxyInsecureBackend bool
)

// ProxyStats holds proxy statistics
type ProxyStats struct {
	TotalRequests  int64
	ActiveRequests int64
	FailedRequests int64
	BytesReceived  int64
	BytesSent      int64
	AverageLatency time.Duration
	totalLatency   int64
	BackendStats   map[string]*BackendStats
}

// BackendStats holds per-backend statistics
type BackendStats struct {
	Requests       int64
	Active         int64
	Failures       int64
	LastHealthy    time.Time
	IsHealthy      bool
	AverageLatency time.Duration
}

var proxyStats = &ProxyStats{
	BackendStats: make(map[string]*BackendStats),
}

var proxyCmd = &cobra.Command{
	Use:     "proxy",
	Aliases: []string{"p", "reverse-proxy"},
	Short:   "HTTP/HTTPS reverse proxy server",
	Long: `Start an HTTP/HTTPS reverse proxy server that forwards requests to backend servers.
Supports load balancing, health checks, and request/response modification.

Examples:
  # Simple reverse proxy
  gocat proxy --listen :8080 --target http://backend:80

  # Load balancing with multiple backends
  gocat proxy --listen :8080 --backends http://backend1:80,http://backend2:80

  # With SSL/TLS
  gocat proxy --listen :443 --target http://backend:80 --ssl --cert cert.pem --key key.pem

  # With health checks
  gocat proxy --listen :8080 --backends http://backend1:80,http://backend2:80 --health-check /health
`,
	Run: runProxy,
}

// It binds command-line options (listen address, target/backends, load-balancing algorithm,
// health check path, timeouts, connection limits, header modification, request logging, and TLS
// certificate/key) to the package-level configuration variables with their default values.
func init() {
	rootCmd.AddCommand(proxyCmd)

	proxyCmd.Flags().StringVarP(&proxyListen, "listen", "l", ":8080", "Listen address")
	proxyCmd.Flags().StringVar(&proxyTarget, "target", "", "Target backend URL")
	proxyCmd.Flags().StringSliceVar(&proxyTargets, "backends", nil, "Multiple backend URLs for load balancing")
	proxyCmd.Flags().StringVar(&proxyLoadBalance, "lb-algorithm", "round-robin", "Load balancing algorithm (round-robin, least-connections, ip-hash)")
	proxyCmd.Flags().StringVar(&proxyHealthCheck, "health-check", "", "Health check path (e.g., /health)")
	proxyCmd.Flags().DurationVar(&proxyTimeout, "timeout", 2*time.Second, "Backend timeout")
	proxyCmd.Flags().IntVar(&proxyMaxConns, "max-connections", 1000, "Maximum concurrent connections")
	proxyCmd.Flags().Int64Var(&proxyMaxBody, "max-body", 10<<20, "Maximum proxied request body in bytes (0 = unlimited)")
	proxyCmd.Flags().BoolVar(&proxyModifyHeader, "modify-headers", false, "Add X-Forwarded-* headers")
	proxyCmd.Flags().BoolVar(&proxyLogRequests, "log-requests", true, "Log all requests")
	proxyCmd.Flags().BoolVar(&proxySSL, "ssl", false, "Enable SSL/TLS")
	proxyCmd.Flags().StringVar(&proxySSLCert, "cert", "", "SSL certificate file")
	proxyCmd.Flags().StringVar(&proxySSLKey, "key", "", "SSL key file")
	proxyCmd.Flags().BoolVar(&proxyInsecureBackend, "insecure-backend", false, "Skip TLS verification for backend/health-check connections (self-signed backends)")
}

// runProxy starts the reverse proxy server according to CLI configuration.
// It builds the backend list from the --target/--backends flags, initializes per-backend stats,
// optionally starts periodic health checks, creates the configured load balancer and HTTP handler,
// launches the stats reporter, and serves HTTP or HTTPS depending on SSL flags.
// The function logs a fatal error and exits on invalid configuration (missing backends or bad URLs),
// missing SSL credentials when SSL is enabled, or on unrecoverable server errors.
func runProxy(cmd *cobra.Command, args []string) {
	// Validate configuration
	if proxyTarget == "" && len(proxyTargets) == 0 {
		logger.Fatal("Either --target or --backends must be specified")
	}

	// Build backend list
	var backends []*url.URL
	if proxyTarget != "" {
		target, err := url.Parse(proxyTarget)
		if err != nil {
			logger.Fatal("Invalid target URL: %v", err)
		}
		backends = append(backends, target)
		proxyStats.BackendStats[target.String()] = &BackendStats{
			IsHealthy:   true,
			LastHealthy: time.Now(),
		}
	}

	for _, backendURL := range proxyTargets {
		target, err := url.Parse(backendURL)
		if err != nil {
			logger.Fatal("Invalid backend URL %s: %v", backendURL, err)
		}
		backends = append(backends, target)
		proxyStats.BackendStats[backendURL] = &BackendStats{
			IsHealthy:   true,
			LastHealthy: time.Now(),
		}
	}

	logger.Info("Starting reverse proxy on %s", proxyListen)
	logger.Info("Backends: %v", backends)

	// Start health checks if enabled
	if proxyHealthCheck != "" {
		startHealthChecks(backends)
	}

	// Create load balancer
	lb := newLoadBalancer(backends, proxyLoadBalance)

	// Create reverse proxy handler
	var sem chan struct{}
	if proxyMaxConns > 0 {
		sem = make(chan struct{}, proxyMaxConns)
	}
	handler := &proxyHandler{
		loadBalancer: lb,
		sem:          sem,
		transport: &http.Transport{
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: proxyTimeout,
			DialContext: (&net.Dialer{
				Timeout:   proxyTimeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
	}
	if proxyInsecureBackend {
		handler.transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		logger.Warn("--insecure-backend: backend TLS certificates are NOT verified")
	}

	// Create HTTP server
	server := &http.Server{
		Addr:           proxyListen,
		Handler:        handler,
		ReadTimeout:    proxyTimeout + 5*time.Second,
		WriteTimeout:   proxyTimeout + 5*time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	// Start stats reporter
	go reportStats()

	// Start server
	var err error
	if proxySSL {
		if proxySSLCert == "" || proxySSLKey == "" {
			logger.Fatal("SSL certificate and key are required for SSL mode")
		}
		logger.Info("Starting HTTPS proxy...")
		err = server.ListenAndServeTLS(proxySSLCert, proxySSLKey)
	} else {
		logger.Info("Starting HTTP proxy...")
		err = server.ListenAndServe()
	}

	if err != nil && err != http.ErrServerClosed {
		logger.Fatal("Proxy server error: %v", err)
	}
}

type proxyHandler struct {
	loadBalancer *loadBalancer
	transport    *http.Transport
	sem          chan struct{}
}

func (h *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Enforce --max-connections instead of silently ignoring the flag.
	if h.sem != nil {
		select {
		case h.sem <- struct{}{}:
			defer func() { <-h.sem }()
		default:
			http.Error(w, "Service Unavailable (connection limit)", http.StatusServiceUnavailable)
			atomic.AddInt64(&proxyStats.FailedRequests, 1)
			return
		}
	}
	startTime := time.Now()
	atomic.AddInt64(&proxyStats.TotalRequests, 1)
	atomic.AddInt64(&proxyStats.ActiveRequests, 1)
	defer atomic.AddInt64(&proxyStats.ActiveRequests, -1)

	// Cap proxied request bodies (default 10MB) so one client cannot tie
	// up a backend connection indefinitely.
	if proxyMaxBody > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, proxyMaxBody)
	}

	// Log request
	if proxyLogRequests {
		logger.Info("%s %s %s", r.Method, r.URL.Path, r.RemoteAddr)
	}

	// Get backend
	backend := h.loadBalancer.NextBackend(r)
	if backend == nil {
		logger.Error("No healthy backend available")
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		atomic.AddInt64(&proxyStats.FailedRequests, 1)
		return
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(backend)
	proxy.Transport = h.transport

	// Modify request
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		if proxyModifyHeader {
			req.Header.Set("X-Forwarded-Host", req.Host)
			req.Header.Set("X-Forwarded-Proto", req.URL.Scheme)
			req.Header.Set("X-Real-IP", r.RemoteAddr)
		}
	}

	// Error handler
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("Proxy error for %s: %v", backend.String(), err)
		atomic.AddInt64(&proxyStats.FailedRequests, 1)

		// Mark backend as unhealthy
		if stats, ok := proxyStats.BackendStats[backend.String()]; ok {
			stats.IsHealthy = false
			atomic.AddInt64(&stats.Failures, 1)
		}

		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	// Serve request with per-backend active tracking for least-connections.
	if stats, ok := proxyStats.BackendStats[backend.String()]; ok {
		atomic.AddInt64(&stats.Active, 1)
		defer atomic.AddInt64(&stats.Active, -1)
	}
	proxy.ServeHTTP(w, r)

	// Update stats
	latency := time.Since(startTime)
	atomic.AddInt64(&proxyStats.totalLatency, int64(latency))

	if stats, ok := proxyStats.BackendStats[backend.String()]; ok {
		atomic.AddInt64(&stats.Requests, 1)
	}
}

// Load balancer
type loadBalancer struct {
	backends  []*url.URL
	algorithm string
	counter   uint64
	mu        sync.RWMutex
}

// selection algorithm.
func newLoadBalancer(backends []*url.URL, algorithm string) *loadBalancer {
	return &loadBalancer{
		backends:  backends,
		algorithm: algorithm,
	}
}

func (lb *loadBalancer) NextBackend(r *http.Request) *url.URL {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	if len(lb.backends) == 0 {
		return nil
	}

	// Filter healthy backends
	var healthy []*url.URL
	for _, backend := range lb.backends {
		if stats, ok := proxyStats.BackendStats[backend.String()]; ok && stats.IsHealthy {
			healthy = append(healthy, backend)
		} else if !ok {
			// No stats yet, assume healthy
			healthy = append(healthy, backend)
		}
	}

	if len(healthy) == 0 {
		// No healthy backends, try any backend
		healthy = lb.backends
	}

	switch lb.algorithm {
	case "round-robin":
		idx := atomic.AddUint64(&lb.counter, 1) % uint64(len(healthy))
		return healthy[idx]

	case "least-connections":
		// Find backend with least *active* connections (not cumulative requests).
		var minBackend *url.URL
		var minConns int64 = -1
		for _, backend := range healthy {
			if stats, ok := proxyStats.BackendStats[backend.String()]; ok {
				active := atomic.LoadInt64(&stats.Active)
				if minConns == -1 || active < minConns {
					minConns = active
					minBackend = backend
				}
			}
		}
		if minBackend != nil {
			return minBackend
		}
		return healthy[0]

	case "ip-hash":
		// Hash client IP to backend
		ip := strings.Split(r.RemoteAddr, ":")[0]
		hash := hashString(ip)
		idx := hash % uint64(len(healthy))
		return healthy[idx]

	default:
		return healthy[0]
	}
}

// hashing and distribution.
func hashString(s string) uint64 {
	var hash uint64
	for _, c := range s {
		hash = hash*31 + uint64(c)
	}
	return hash
}

// startHealthChecks starts a background routine that periodically checks the health
// of each provided backend URL using the configured health-check path.
// It runs checks on a 10-second interval and invokes checkBackendHealth concurrently for each backend.
func startHealthChecks(backends []*url.URL) {
	logger.Info("Starting health checks on %s", proxyHealthCheck)

	ticker := time.NewTicker(10 * time.Second)
	go func() {
		for range ticker.C {
			for _, backend := range backends {
				go checkBackendHealth(backend)
			}
		}
	}()
}

// checkBackendHealth performs an HTTP GET to the backend's health-check endpoint and updates
// proxyStats.BackendStats for that backend: it sets IsHealthy to true and LastHealthy to the
// current time when the response is a 2xx status, and sets IsHealthy to false on request
// errors or non-2xx responses.
func checkBackendHealth(backend *url.URL) {
	healthURL := backend.String() + proxyHealthCheck

	transport := &http.Transport{}
	if proxyInsecureBackend {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}

	resp, err := client.Get(healthURL)
	if err != nil {
		logger.Debug("Health check failed for %s: %v", backend.String(), err)
		if stats, ok := proxyStats.BackendStats[backend.String()]; ok {
			stats.IsHealthy = false
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if stats, ok := proxyStats.BackendStats[backend.String()]; ok {
			stats.IsHealthy = true
			stats.LastHealthy = time.Now()
		}
		logger.Debug("Health check OK for %s", backend.String())
	} else {
		logger.Debug("Health check failed for %s: status %d", backend.String(), resp.StatusCode)
		if stats, ok := proxyStats.BackendStats[backend.String()]; ok {
			stats.IsHealthy = false
		}
	}
}

// reportStats logs aggregated proxy metrics and per-backend status.
//
// It periodically (every 30 seconds) records total requests, active requests,
// failed requests, average latency, and for each backend reports health status,
// request count, and failure count.
func reportStats() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		total := atomic.LoadInt64(&proxyStats.TotalRequests)
		active := atomic.LoadInt64(&proxyStats.ActiveRequests)
		failed := atomic.LoadInt64(&proxyStats.FailedRequests)

		var avgLatency time.Duration
		if total > 0 {
			avgLatency = time.Duration(atomic.LoadInt64(&proxyStats.totalLatency) / total)
		}

		logger.Info("Proxy Stats - Total: %d, Active: %d, Failed: %d, Avg Latency: %v",
			total, active, failed, avgLatency)

		// Backend stats
		for backendURL, stats := range proxyStats.BackendStats {
			status := "healthy"
			if !stats.IsHealthy {
				status = "unhealthy"
			}
			logger.Info("  Backend %s: %s, Requests: %d, Failures: %d",
				backendURL, status, stats.Requests, stats.Failures)
		}
	}
}
