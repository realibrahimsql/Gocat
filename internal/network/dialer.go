package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/realibrahimsql/Gocat/internal/errors"
	"github.com/realibrahimsql/Gocat/internal/security"
)

// Dialer provides advanced dialing capabilities with retry logic and circuit breaker
type Dialer struct {
	config           *DialerConfig
	validator        *security.InputValidator
	circuitBreakers  map[string]*CircuitBreaker
	metricsCollector MetricsCollector
	mu               sync.RWMutex
}

// DialerConfig holds configuration for the  dialer
type DialerConfig struct {
	MaxRetries              int           `yaml:"max_retries"`
	InitialRetryDelay       time.Duration `yaml:"initial_retry_delay"`
	MaxRetryDelay           time.Duration `yaml:"max_retry_delay"`
	RetryMultiplier         float64       `yaml:"retry_multiplier"`
	ConnectionTimeout       time.Duration `yaml:"connection_timeout"`
	KeepAlive               time.Duration `yaml:"keep_alive"`
	EnableCircuitBreaker    bool          `yaml:"enable_circuit_breaker"`
	CircuitBreakerThreshold int           `yaml:"circuit_breaker_threshold"`
	CircuitBreakerTimeout   time.Duration `yaml:"circuit_breaker_timeout"`
	EnableMetrics           bool          `yaml:"enable_metrics"`
	DualStack               bool          `yaml:"dual_stack"`
	FallbackDelay           time.Duration `yaml:"fallback_delay"`
}

// DefaultDialerConfig returns default dialer configuration
func DefaultDialerConfig() *DialerConfig {
	return &DialerConfig{
		MaxRetries:              3,
		InitialRetryDelay:       1 * time.Second,
		MaxRetryDelay:           30 * time.Second,
		RetryMultiplier:         2.0,
		ConnectionTimeout:       30 * time.Second,
		KeepAlive:               30 * time.Second,
		EnableCircuitBreaker:    true,
		CircuitBreakerThreshold: 5,
		CircuitBreakerTimeout:   60 * time.Second,
		EnableMetrics:           true,
		DualStack:               true,
		FallbackDelay:           300 * time.Millisecond,
	}
}

// CircuitBreakerState represents the state of a circuit breaker
type CircuitBreakerState int

const (
	CircuitBreakerClosed CircuitBreakerState = iota
	CircuitBreakerOpen
	CircuitBreakerHalfOpen
)

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	threshold   int
	timeout     time.Duration
	state       CircuitBreakerState
	failures    int64
	successes   int64
	lastFailure time.Time
	nextAttempt time.Time
	mu          sync.RWMutex
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(threshold int, timeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		threshold: threshold,
		timeout:   timeout,
		state:     CircuitBreakerClosed,
	}
}

// Allow checks if the circuit breaker allows the operation
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()

	switch cb.state {
	case CircuitBreakerClosed:
		return true
	case CircuitBreakerOpen:
		if now.After(cb.nextAttempt) {
			cb.state = CircuitBreakerHalfOpen
			return true
		}
		return false
	case CircuitBreakerHalfOpen:
		return true
	}

	return false
}

// RecordSuccess records a successful operation
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	atomic.AddInt64(&cb.successes, 1)

	if cb.state == CircuitBreakerHalfOpen {
		cb.state = CircuitBreakerClosed
		cb.failures = 0
	}
}

// RecordFailure records a failed operation
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	atomic.AddInt64(&cb.failures, 1)
	cb.lastFailure = time.Now()

	if cb.failures >= int64(cb.threshold) {
		cb.state = CircuitBreakerOpen
		cb.nextAttempt = time.Now().Add(cb.timeout)
	}
}

// GetState returns the current state of the circuit breaker
func (cb *CircuitBreaker) GetState() CircuitBreakerState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// GetStats returns circuit breaker statistics
func (cb *CircuitBreaker) GetStats() CircuitBreakerStats {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	return CircuitBreakerStats{
		State:       cb.state,
		Failures:    atomic.LoadInt64(&cb.failures),
		Successes:   atomic.LoadInt64(&cb.successes),
		LastFailure: cb.lastFailure,
		NextAttempt: cb.nextAttempt,
	}
}

// CircuitBreakerStats holds circuit breaker statistics
type CircuitBreakerStats struct {
	State       CircuitBreakerState `json:"state"`
	Failures    int64               `json:"failures"`
	Successes   int64               `json:"successes"`
	LastFailure time.Time           `json:"last_failure"`
	NextAttempt time.Time           `json:"next_attempt"`
}

// NewDialer creates a new  dialer
func NewDialer(config *DialerConfig) *Dialer {
	if config == nil {
		config = DefaultDialerConfig()
	}

	return &Dialer{
		config:          config,
		validator:       security.NewInputValidator(),
		circuitBreakers: make(map[string]*CircuitBreaker),
	}
}

// Dial connects to the specified address with retry logic and circuit breaker
func (d *Dialer) Dial(ctx context.Context, address string) (Connection, error) {
	startTime := time.Now()

	// Validate address format
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.ValidationError("VAL018", fmt.Sprintf("Invalid address format: %s", address)).WithSuggestion("Use format 'host:port'")
	}

	// Validate hostname
	if validationErr := d.validator.ValidateHostname(host); validationErr != nil {
		return nil, errors.WrapError(validationErr, errors.ErrorTypeValidation, errors.SeverityMedium, "VAL019", "Invalid hostname")
	}

	// Validate port
	port, err := d.validator.ValidatePort(portStr)
	if err != nil {
		return nil, errors.WrapError(err, errors.ErrorTypeValidation, errors.SeverityMedium, "VAL020", "Invalid port")
	}

	// Check circuit breaker
	if d.config.EnableCircuitBreaker {
		cb := d.getCircuitBreaker(address)
		if !cb.Allow() {
			if d.metricsCollector != nil {
				d.metricsCollector.IncrementCounter("dial_circuit_breaker_open", map[string]string{
					"address": address,
				})
			}
			return nil, errors.NetworkError("NET035", fmt.Sprintf("Circuit breaker is open for %s", address)).WithUserFriendly("Service is temporarily unavailable")
		}
	}

	// Attempt connection with retry logic
	conn, err := d.dialWithRetry(ctx, host, port)

	// Record metrics
	if d.metricsCollector != nil {
		duration := time.Since(startTime)
		tags := map[string]string{
			"address": address,
			"success": "false",
		}

		if err == nil {
			tags["success"] = "true"
			if d.config.EnableCircuitBreaker {
				d.getCircuitBreaker(address).RecordSuccess()
			}
		} else {
			if d.config.EnableCircuitBreaker {
				d.getCircuitBreaker(address).RecordFailure()
			}
		}

		d.metricsCollector.RecordTimer("dial_duration", duration, tags)
		d.metricsCollector.IncrementCounter("dial_attempts", tags)
	}

	return conn, err
}

// dialWithRetry attempts to dial with exponential backoff retry logic
func (d *Dialer) dialWithRetry(ctx context.Context, host string, port int) (Connection, error) {
	var lastErr error
	delay := d.config.InitialRetryDelay

	for attempt := 0; attempt <= d.config.MaxRetries; attempt++ {
		if attempt > 0 {
			// Wait before retry
			select {
			case <-ctx.Done():
				return nil, errors.TimeoutError("NET036", "Connection cancelled during retry").WithCause(ctx.Err())
			case <-time.After(delay):
			}

			// Calculate next delay with exponential backoff
			delay = time.Duration(float64(delay) * d.config.RetryMultiplier)
			if delay > d.config.MaxRetryDelay {
				delay = d.config.MaxRetryDelay
			}
		}

		// Record retry attempt
		if d.metricsCollector != nil && attempt > 0 {
			d.metricsCollector.IncrementCounter("dial_retries", map[string]string{
				"attempt": strconv.Itoa(attempt),
				"host":    host,
			})
		}

		conn, err := d.dialOnce(ctx, host, port)
		if err == nil {
			return conn, nil
		}

		lastErr = err

		// Check if error is retryable
		if !d.isRetryableError(err) {
			break
		}

		// Check if we should continue retrying
		if attempt == d.config.MaxRetries {
			break
		}
	}

	return nil, lastErr
}

// dialOnce performs a single dial attempt with dual-stack support
func (d *Dialer) dialOnce(ctx context.Context, host string, port int) (Connection, error) {
	address := net.JoinHostPort(host, strconv.Itoa(port))

	// Create context with timeout
	dialCtx, cancel := context.WithTimeout(ctx, d.config.ConnectionTimeout)
	defer cancel()

	// Configure dialer
	dialer := &net.Dialer{
		Timeout:   d.config.ConnectionTimeout,
		KeepAlive: d.config.KeepAlive,
	}

	var conn net.Conn
	var err error

	if d.config.DualStack {
		// Use Happy Eyeballs algorithm for dual-stack
		conn, err = d.dialDualStack(dialCtx, dialer, host, port)
	} else {
		// Standard dial
		conn, err = dialer.DialContext(dialCtx, "tcp", address)
	}

	if err != nil {
		return nil, d.wrapDialError(err, address)
	}

	// Configure TCP-specific options
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(d.config.KeepAlive)
	}

	// Create  connection
	Conn := NewConnection(conn, "tcp")

	// Set metrics collector if available
	if d.metricsCollector != nil {
		Conn.SetMetrics(d.metricsCollector)
	}

	return Conn, nil
}

// dialDualStack implements Happy Eyeballs algorithm for IPv4/IPv6 dual-stack
func (d *Dialer) dialDualStack(ctx context.Context, dialer *net.Dialer, host string, port int) (net.Conn, error) {
	// Resolve addresses for both IPv4 and IPv6
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	if len(addresses) == 0 {
		return nil, &net.DNSError{
			Err:  "no addresses found",
			Name: host,
		}
	}

	// Separate IPv4 and IPv6 addresses
	var ipv4Addrs, ipv6Addrs []net.IPAddr
	for _, addr := range addresses {
		if addr.IP.To4() != nil {
			ipv4Addrs = append(ipv4Addrs, addr)
		} else {
			ipv6Addrs = append(ipv6Addrs, addr)
		}
	}

	// Create channels for results
	type dialResult struct {
		conn net.Conn
		err  error
	}

	resultChan := make(chan dialResult, len(addresses))
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Start with IPv6 if available
	if len(ipv6Addrs) > 0 {
		go func() {
			addr := net.JoinHostPort(ipv6Addrs[0].IP.String(), strconv.Itoa(port))
			conn, err := dialer.DialContext(dialCtx, "tcp6", addr)
			resultChan <- dialResult{conn: conn, err: err}
		}()

		// Wait a bit before trying IPv4 (Happy Eyeballs delay)
		if len(ipv4Addrs) > 0 {
			go func() {
				time.Sleep(d.config.FallbackDelay)
				select {
				case <-dialCtx.Done():
					return
				default:
				}

				addr := net.JoinHostPort(ipv4Addrs[0].IP.String(), strconv.Itoa(port))
				conn, err := dialer.DialContext(dialCtx, "tcp4", addr)
				resultChan <- dialResult{conn: conn, err: err}
			}()
		}
	} else if len(ipv4Addrs) > 0 {
		// Only IPv4 available
		go func() {
			addr := net.JoinHostPort(ipv4Addrs[0].IP.String(), strconv.Itoa(port))
			conn, err := dialer.DialContext(dialCtx, "tcp4", addr)
			resultChan <- dialResult{conn: conn, err: err}
		}()
	}

	// Wait for first successful connection
	var lastErr error
	expectedResults := 1
	if len(ipv4Addrs) > 0 && len(ipv6Addrs) > 0 {
		expectedResults = 2
	}

	for i := 0; i < expectedResults; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-resultChan:
			if result.err == nil {
				// Success! Cancel other attempts and return
				cancel()
				return result.conn, nil
			}
			lastErr = result.err
		}
	}

	return nil, lastErr
}

// isRetryableError determines if an error should trigger a retry
func (d *Dialer) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Check if it's a GoCat error with retry flag
	if gcErr, ok := err.(*errors.GoCatError); ok {
		return gcErr.IsRetryable()
	}

	// Check for specific network errors that are retryable
	errStr := strings.ToLower(err.Error())
	retryablePatterns := []string{
		"connection refused",
		"connection reset",
		"connection timeout",
		"timeout",
		"temporary failure",
		"network is unreachable",
		"no route to host",
	}

	for _, pattern := range retryablePatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	// Check for net.Error timeouts. Temporary() is deprecated and too broad.
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}

	return false
}

// wrapDialError wraps dial errors with appropriate error types and context
func (d *Dialer) wrapDialError(err error, address string) error {
	errStr := strings.ToLower(err.Error())

	switch {
	case strings.Contains(errStr, "connection refused"):
		return errors.WrapError(err, errors.ErrorTypeNetwork, errors.SeverityHigh, "NET037", "Connection refused").
			SetRetryable(true).
			WithUserFriendly(fmt.Sprintf("Could not connect to %s", address)).
			WithSuggestion("Check if the service is running and accessible").
			WithContext("address", address)

	case strings.Contains(errStr, "timeout"):
		return errors.WrapError(err, errors.ErrorTypeTimeout, errors.SeverityHigh, "NET038", "Connection timeout").
			SetRetryable(true).
			WithUserFriendly(fmt.Sprintf("Connection to %s timed out", address)).
			WithSuggestion("Check network connectivity and increase timeout").
			WithContext("address", address)

	case strings.Contains(errStr, "no route to host"):
		return errors.WrapError(err, errors.ErrorTypeNetwork, errors.SeverityHigh, "NET039", "Host unreachable").
			SetRetryable(true).
			WithUserFriendly(fmt.Sprintf("Cannot reach %s", address)).
			WithSuggestion("Check network routing and firewall settings").
			WithContext("address", address)

	case strings.Contains(errStr, "network is unreachable"):
		return errors.WrapError(err, errors.ErrorTypeNetwork, errors.SeverityHigh, "NET040", "Network unreachable").
			SetRetryable(true).
			WithUserFriendly("Network is unreachable").
			WithSuggestion("Check network configuration").
			WithContext("address", address)

	case strings.Contains(errStr, "no such host"):
		return errors.WrapError(err, errors.ErrorTypeNetwork, errors.SeverityMedium, "NET041", "DNS resolution failed").
			SetRetryable(false).
			WithUserFriendly(fmt.Sprintf("Cannot resolve hostname in %s", address)).
			WithSuggestion("Check hostname and DNS configuration").
			WithContext("address", address)

	case strings.Contains(errStr, "permission denied"):
		return errors.WrapError(err, errors.ErrorTypePermission, errors.SeverityHigh, "NET042", "Permission denied").
			SetRetryable(false).
			WithUserFriendly("Permission denied").
			WithSuggestion("Check if you have permission to connect to this address").
			WithContext("address", address)

	default:
		return errors.WrapError(err, errors.ErrorTypeNetwork, errors.SeverityHigh, "NET043", "Connection failed").
			SetRetryable(true).
			WithUserFriendly(fmt.Sprintf("Failed to connect to %s", address)).
			WithContext("address", address)
	}
}

// getCircuitBreaker gets or creates a circuit breaker for the given address
func (d *Dialer) getCircuitBreaker(address string) *CircuitBreaker {
	d.mu.RLock()
	cb, exists := d.circuitBreakers[address]
	d.mu.RUnlock()

	if exists {
		return cb
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Double-check after acquiring write lock
	if cb, exists := d.circuitBreakers[address]; exists {
		return cb
	}

	// Create new circuit breaker
	cb = NewCircuitBreaker(d.config.CircuitBreakerThreshold, d.config.CircuitBreakerTimeout)
	d.circuitBreakers[address] = cb
	return cb
}

// SetMetrics sets the metrics collector for the dialer
func (d *Dialer) SetMetrics(collector MetricsCollector) {
	d.mu.Lock()
	d.metricsCollector = collector
	d.mu.Unlock()
}

// GetCircuitBreakerStats returns statistics for all circuit breakers
func (d *Dialer) GetCircuitBreakerStats() map[string]CircuitBreakerStats {
	d.mu.RLock()
	defer d.mu.RUnlock()

	stats := make(map[string]CircuitBreakerStats)
	for address, cb := range d.circuitBreakers {
		stats[address] = cb.GetStats()
	}
	return stats
}

// ResetCircuitBreaker resets the circuit breaker for a specific address
func (d *Dialer) ResetCircuitBreaker(address string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if cb, exists := d.circuitBreakers[address]; exists {
		cb.mu.Lock()
		cb.state = CircuitBreakerClosed
		cb.failures = 0
		cb.successes = 0
		cb.mu.Unlock()
	}
}

// DialTLS creates a TLS connection with the specified configuration
func (d *Dialer) DialTLS(ctx context.Context, address string, tlsConfig *tls.Config) (Connection, error) {
	conn, err := d.Dial(ctx, address)
	if err != nil {
		return nil, err
	}

	// Upgrade to TLS
	host, _, _ := net.SplitHostPort(address)
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12, // Secure minimum TLS version
		}
	}

	tlsConn := tls.Client(conn, tlsConfig)

	// Perform TLS handshake
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, errors.WrapError(err, errors.ErrorTypeSecurity, errors.SeverityHigh, "SEC006", "TLS handshake failed").
			WithUserFriendly("Failed to establish secure connection").
			WithSuggestion("Check TLS configuration and certificates")
	}

	// Create  TLS connection
	Conn := NewConnection(tlsConn, "tls")

	if d.metricsCollector != nil {
		Conn.SetMetrics(d.metricsCollector)
	}

	return Conn, nil
}
