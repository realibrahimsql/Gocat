package cmd

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/realibrahimsql/Gocat/internal/logger"
	"github.com/spf13/cobra"
)

var (
	dnsTunnelDomain    string
	dnsTunnelListen    string
	dnsTunnelTarget    string
	dnsTunnelServer    bool
	dnsTunnelClient    bool
	dnsTunnelDNSPort   int
	dnsTunnelDNSServer string
	dnsTunnelEncoding  string
)

type dnsSession struct {
	id         string
	conn       net.Conn
	lastActive time.Time
	buffer     []byte
	mu         sync.Mutex
}

var dnsSessions = struct {
	sessions map[string]*dnsSession
	mu       sync.RWMutex
}{
	sessions: make(map[string]*dnsSession),
}

var dnsTunnelCmd = &cobra.Command{
	Use:     "dns-tunnel",
	Aliases: []string{"dnstun", "dns"},
	Short:   "DNS tunneling for data exfiltration and firewall bypass",
	Long: `Create a covert channel using DNS queries and responses.
Useful for bypassing firewalls that only allow DNS traffic.

Examples:
  # Start DNS tunnel server
  gocat dns-tunnel --server --domain tunnel.example.com --listen :53 --target localhost:8080

  # Start DNS tunnel client
  gocat dns-tunnel --client --domain tunnel.example.com --dns-server 8.8.8.8:53 --listen :8080

  # With hex encoding
  gocat dns-tunnel --server --domain tunnel.example.com --encoding hex
`,
	Run: runDNSTunnel,
}

// required "domain" flag.
func init() {
	rootCmd.AddCommand(dnsTunnelCmd)

	dnsTunnelCmd.Flags().StringVar(&dnsTunnelDomain, "domain", "", "Tunnel domain (e.g., tunnel.example.com)")
	dnsTunnelCmd.Flags().StringVar(&dnsTunnelListen, "listen", ":53", "Listen address")
	dnsTunnelCmd.Flags().StringVar(&dnsTunnelTarget, "target", "", "Target address for server mode")
	dnsTunnelCmd.Flags().BoolVar(&dnsTunnelServer, "server", false, "Run as DNS tunnel server")
	dnsTunnelCmd.Flags().BoolVar(&dnsTunnelClient, "client", false, "Run as DNS tunnel client")
	dnsTunnelCmd.Flags().StringVar(&dnsTunnelDNSServer, "dns-server", "8.8.8.8", "Authoritative DNS server host for client mode")
	dnsTunnelCmd.Flags().IntVar(&dnsTunnelDNSPort, "dns-port", 53, "DNS server port")
	dnsTunnelCmd.Flags().StringVar(&dnsTunnelEncoding, "encoding", "base32", "Encoding method (base32, base64, hex)")

	dnsTunnelCmd.MarkFlagRequired("domain")
}

// runDNSTunnel validates CLI mode flags and dispatches execution to the selected DNS tunnel mode.
// It enforces that exactly one of server or client mode is set and that `--target` is provided when server mode is selected.
// On invalid configuration it logs a fatal error and exits the process.
func runDNSTunnel(cmd *cobra.Command, args []string) {
	if !dnsTunnelServer && !dnsTunnelClient {
		logger.Fatal("Specify either --server or --client mode")
	}

	if dnsTunnelServer && dnsTunnelClient {
		logger.Fatal("Cannot run as both server and client")
	}

	if dnsTunnelServer {
		if dnsTunnelTarget == "" {
			logger.Fatal("--target required for server mode")
		}
		runDNSTunnelServer()
	} else {
		runDNSTunnelClient()
	}
}

// runDNSTunnelServer starts the DNS tunnel server by listening for DNS queries on dnsTunnelListen,
// accepting UDP requests, spawning a goroutine to handle each query, and running periodic session cleanup.
func runDNSTunnelServer() {
	logger.Info("Starting DNS tunnel server on %s", dnsTunnelListen)
	logger.Info("Domain: %s", dnsTunnelDomain)
	logger.Info("Target: %s", dnsTunnelTarget)

	// Listen for DNS queries
	addr, err := net.ResolveUDPAddr("udp", dnsTunnelListen)
	if err != nil {
		logger.Fatal("Failed to resolve address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		logger.Fatal("Failed to listen: %v", err)
	}
	defer conn.Close()

	logger.Info("DNS tunnel server started")

	// Session cleanup
	go cleanupDNSSessions()

	buf := make([]byte, 512)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			logger.Error("Read error: %v", err)
			continue
		}

		go handleDNSQuery(conn, clientAddr, buf[:n])
	}
}

// handleDNSQuery parses a DNS query and handles DNS-tunnel requests for the configured tunnel domain.
//
// If the query is not for the tunnel domain it sends a DNS name-error response. For tunnel requests it
// extracts the session ID and encoded payload, decodes and forwards the payload to the session's target
// TCP connection (creating the session and connection if needed), and then returns any buffered response
// bytes to the DNS client in a TXT response. On protocol or I/O failures it sends an appropriate DNS error response.
func handleDNSQuery(conn *net.UDPConn, clientAddr *net.UDPAddr, query []byte) {
	// Parse DNS query
	if len(query) < 12 {
		logger.Debug("Invalid DNS query (too short)")
		return
	}

	// Extract domain name from query
	domain, _ := parseDNSQuery(query)
	if domain == "" {
		logger.Debug("Failed to parse DNS query")
		return
	}

	logger.Debug("DNS query: %s from %s", domain, clientAddr)

	// Check if this is a tunnel query
	if !strings.HasSuffix(domain, dnsTunnelDomain) {
		logger.Debug("Not a tunnel query: %s", domain)
		sendDNSError(conn, clientAddr, query)
		return
	}

	// Extract session ID and data
	sessionID, tunnelData := extractTunnelData(domain, dnsTunnelDomain)

	// Get or create session
	session := getOrCreateSession(sessionID)
	if session == nil {
		logger.Warn("DNS tunnel session table full, dropping %s", sessionID)
		sendDNSError(conn, clientAddr, query)
		return
	}

	// Decode and process data
	if tunnelData != "" {
		decoded := decodeTunnelData(tunnelData)
		if len(decoded) > 0 {
			// Send to target
			session.mu.Lock()
			if session.conn == nil {
				// Create connection to target
				targetConn, err := net.Dial("tcp", dnsTunnelTarget)
				if err != nil {
					logger.Error("Failed to connect to target: %v", err)
					session.mu.Unlock()
					sendDNSError(conn, clientAddr, query)
					return
				}
				session.conn = targetConn

				// Start reading responses
				go readTargetResponses(session, conn, clientAddr)
			}

			// Write data to target
			if _, err := session.conn.Write(decoded); err != nil {
				logger.Error("Failed to write to target: %v", err)
				session.mu.Unlock()
				sendDNSError(conn, clientAddr, query)
				return
			}
			session.mu.Unlock()
		}
	}

	// Send response with buffered data
	session.mu.Lock()
	responseData := session.buffer
	session.buffer = nil
	session.mu.Unlock()

	sendDNSResponse(conn, clientAddr, query, responseData)
}

// parseDNSQuery extracts the queried domain name from a DNS query packet and
// returns the domain and the remaining bytes following the domain label sequence.
// The function expects a standard DNS header (12 bytes) followed by label-encoded
// QNAME; on malformed or too-short input it returns an empty domain and nil
// remainder.
func parseDNSQuery(query []byte) (string, []byte) {
	if len(query) < 12 {
		return "", nil
	}

	// Skip DNS header (12 bytes)
	pos := 12
	var domain strings.Builder

	for pos < len(query) {
		length := int(query[pos])
		if length == 0 {
			break
		}
		pos++

		if pos+length > len(query) {
			return "", nil
		}

		if domain.Len() > 0 {
			domain.WriteByte('.')
		}
		domain.Write(query[pos : pos+length])
		pos += length
	}

	remainder := []byte{}
	if pos < len(query) {
		remainder = query[pos:]
	}

	return domain.String(), remainder
}

// extractTunnelData extracts a session identifier and the encoded payload portion from a full DNS query domain,
// relative to the configured base domain.
//
// The domain is expected in the form: "<encoded>.<sessionID>.<baseDomain>". The function strips the base domain,
// splits the remaining prefix by dots, and returns the last label as the sessionID and the concatenation of the
// preceding labels (with no separators) as data.
// If the prefix does not contain at least two labels, it returns sessionID "default" and an empty data string.
func extractTunnelData(domain, baseDomain string) (sessionID, data string) {
	// Remove base domain
	prefix := strings.TrimSuffix(domain, "."+baseDomain)

	// Extract session ID and data
	// Format: data.sessionid.basedomain
	parts := strings.Split(prefix, ".")
	if len(parts) < 2 {
		return "default", ""
	}

	sessionID = parts[len(parts)-1]
	data = strings.Join(parts[:len(parts)-1], "")

	return sessionID, data
}

// decodeTunnelData decodes an encoded tunnel payload according to the dnsTunnelEncoding setting.
// Supported encodings are "base32" (DNS-safe, case-insensitive), "base64" (URL-safe), and "hex".
// For any other encoding value the raw input bytes are returned. If decoding fails the function returns nil.
func decodeTunnelData(encoded string) []byte {
	switch dnsTunnelEncoding {
	case "base32":
		decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(encoded))
		if err != nil {
			return nil
		}
		return decoded
	case "base64":
		decoded, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return nil
		}
		return decoded
	case "hex":
		decoded, err := hex.DecodeString(encoded)
		if err != nil {
			return nil
		}
		return decoded
	default:
		return []byte(encoded)
	}
}

// encodeTunnelData encodes the provided bytes according to the global dnsTunnelEncoding setting.
// Supported encodings:
// - "base32": lowercase Base32 (raw, no padding, DNS-safe)
// - "base64": URL-safe Base64 (raw, no padding)
// - "hex": hexadecimal
// For any other encoding value, the raw byte slice is returned as a string.
func encodeTunnelData(data []byte) string {
	switch dnsTunnelEncoding {
	case "base32":
		return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data))
	case "base64":
		return base64.RawURLEncoding.EncodeToString(data)
	case "hex":
		return hex.EncodeToString(data)
	default:
		return string(data)
	}
}

// maxDNSSessions caps attacker-created tunnel sessions and maxDNSBuffer
// caps each session buffer so query floods cannot exhaust memory.
const (
	maxDNSSessions = 1000
	maxDNSBuffer   = 64 << 10
)

// getOrCreateSession returns the dnsSession for the given session ID, creating and storing a new session if none exists.
// It also updates the session's lastActive timestamp to the current time.
func getOrCreateSession(sessionID string) *dnsSession {
	dnsSessions.mu.Lock()
	defer dnsSessions.mu.Unlock()

	session, exists := dnsSessions.sessions[sessionID]
	if !exists {
		if len(dnsSessions.sessions) >= maxDNSSessions {
			return nil
		}
		session = &dnsSession{
			id:         sessionID,
			lastActive: time.Now(),
			buffer:     make([]byte, 0),
		}
		dnsSessions.sessions[sessionID] = session
		logger.Debug("Created new DNS tunnel session: %s", sessionID)
	}

	session.lastActive = time.Now()
	return session
}

// readTargetResponses appends bytes from the session's target TCP connection to the session buffer.
func readTargetResponses(session *dnsSession, _ *net.UDPConn, _ *net.UDPAddr) {
	buf := make([]byte, 200) // Small chunks for DNS
	for {
		n, err := session.conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				logger.Error("Target read error: %v", err)
			}
			break
		}

		// Buffer response data (capped; drop overflow and fail the session)
		session.mu.Lock()
		if len(session.buffer) < maxDNSBuffer {
			room := maxDNSBuffer - len(session.buffer)
			if n > room {
				n = room
			}
			session.buffer = append(session.buffer, buf[:n]...)
		}
		session.mu.Unlock()

		logger.Debug("Buffered %d bytes from target for session %s", n, session.id)
	}

	// Close session
	session.mu.Lock()
	if session.conn != nil {
		session.conn.Close()
		session.conn = nil
	}
	session.mu.Unlock()

	logger.Debug("Target connection closed for session %s", session.id)
}

// sendDNSResponse constructs a DNS response containing a single TXT answer and sends it to the client address.
//
// The response reuses the request header, marks the packet as a standard response with recursion available,
// and includes one TXT record whose payload is the tunnel-encoded `data`. The TXT payload is truncated to
// at most 255 bytes if necessary and the record TTL is set to 60 seconds. The finalized DNS packet is written
// to `clientAddr` using `conn`.
func sendDNSResponse(conn *net.UDPConn, clientAddr *net.UDPAddr, query []byte, data []byte) {
	// Build DNS response
	response := make([]byte, 512)

	// Copy query header
	copy(response, query[:12])

	// Set response flags
	response[2] = 0x81 // Response, recursion available
	response[3] = 0x80

	// Answer count
	response[6] = 0x00
	response[7] = 0x01

	// Copy question section
	pos := 12
	for i := 12; i < len(query) && query[i] != 0; i++ {
		response[pos] = query[i]
		pos++
	}
	response[pos] = 0 // End of domain
	pos++

	// Copy QTYPE and QCLASS
	if pos+4 <= len(query) {
		copy(response[pos:pos+4], query[pos:pos+4])
		pos += 4
	}

	// Add answer section
	// Pointer to domain name
	response[pos] = 0xc0
	response[pos+1] = 0x0c
	pos += 2

	// TYPE (TXT record)
	response[pos] = 0x00
	response[pos+1] = 0x10
	pos += 2

	// CLASS (IN)
	response[pos] = 0x00
	response[pos+1] = 0x01
	pos += 2

	// TTL (60 seconds)
	response[pos] = 0x00
	response[pos+1] = 0x00
	response[pos+2] = 0x00
	response[pos+3] = 0x3c
	pos += 4

	// Encode data
	encoded := encodeTunnelData(data)
	if len(encoded) > 255 {
		encoded = encoded[:255]
	}

	// RDLENGTH
	rdlen := len(encoded) + 1
	response[pos] = byte(rdlen >> 8)
	response[pos+1] = byte(rdlen)
	pos += 2

	// TXT data length
	response[pos] = byte(len(encoded))
	pos++

	// TXT data
	copy(response[pos:], encoded)
	pos += len(encoded)

	// Send response
	conn.WriteToUDP(response[:pos], clientAddr)
}

// sendDNSError sends a DNS response with RCODE Name Error (3) for the provided query to the client address.
// It copies the original query, sets the DNS header flags to indicate a name error, and writes the response to the UDP connection.
func sendDNSError(conn *net.UDPConn, clientAddr *net.UDPAddr, query []byte) {
	response := make([]byte, len(query))
	copy(response, query)
	response[2] = 0x81
	response[3] = 0x83 // Name error
	conn.WriteToUDP(response, clientAddr)
}

// cleanupDNSSessions periodically removes idle DNS tunneling sessions.
//
// It runs an internal 60-second ticker and for each session whose lastActive
// timestamp is more than 5 minutes in the past it closes any open target
// connection and deletes the session from the in-memory session store.
func cleanupDNSSessions() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		dnsSessions.mu.Lock()
		for id, session := range dnsSessions.sessions {
			if time.Since(session.lastActive) > 5*time.Minute {
				session.mu.Lock()
				if session.conn != nil {
					session.conn.Close()
				}
				session.mu.Unlock()
				delete(dnsSessions.sessions, id)
				logger.Debug("Cleaned up DNS session: %s", id)
			}
		}
		dnsSessions.mu.Unlock()
	}
}

// runDNSTunnelClient starts a DNS-tunnel client that listens on the local TCP address
// configured by dnsTunnelListen, accepts incoming connections, and spawns a goroutine
// per connection to forward traffic over DNS TXT queries to the configured DNS server
// and relay responses back to the local peer.
func runDNSTunnelClient() {
	logger.Info("Starting DNS tunnel client")
	logger.Info("Domain: %s", dnsTunnelDomain)
	logger.Info("DNS Server: %s", dnsTunnelServerAddr())

	// Listen for local connections
	listener, err := net.Listen("tcp", dnsTunnelListen)
	if err != nil {
		logger.Fatal("Failed to listen: %v", err)
	}
	defer listener.Close()

	logger.Info("DNS tunnel client listening on %s", dnsTunnelListen)

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error("Accept error: %v", err)
			continue
		}

		go handleDNSTunnelClient(conn)
	}
}

// handleDNSTunnelClient manages a local TCP client connection for the DNS tunnel.
// It reads application data from conn, encodes it into DNS TXT queries using a
// per-connection session ID, sends those queries to the configured DNS server,
// and writes any TXT response payloads back to the local connection.
// The function logs read errors, runs until the local connection is closed or EOF,
// and closes conn before returning.
func handleDNSTunnelClient(conn net.Conn) {
	defer conn.Close()

	sessionID := fmt.Sprintf("%d", time.Now().UnixNano()%10000)
	logger.Debug("New DNS tunnel client session: %s", sessionID)

	// Read from local connection and send via DNS
	buf := make([]byte, 100) // Small chunks for DNS
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				logger.Error("Read error: %v", err)
			}
			break
		}

		// Encode and send via DNS query
		encoded := encodeTunnelData(buf[:n])
		domain := fmt.Sprintf("%s.%s.%s", encoded, sessionID, dnsTunnelDomain)

		// Send DNS query and get response
		response := sendDNSQueryAndWait(domain)
		if len(response) > 0 {
			conn.Write(response)
		}
	}
}

// dnsTunnelServerAddr resolves the client-mode upstream DNS server.
// --dns-server accepts bare host or host:port; --dns-port supplies the
// port when absent.
func dnsTunnelServerAddr() string {
	host := strings.TrimSpace(dnsTunnelDNSServer)
	if host == "" {
		host = "8.8.8.8"
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", dnsTunnelDNSPort))
}

// sendDNSQueryAndWait sends a DNS TXT query for the given domain to the configured DNS server
// and returns the decoded TXT record payload from the response or nil on error.
//
// The function contacts dnsTunnelServerAddr(), waits up to 5 seconds
// for a reply, and parses the TXT data using parseDNSResponse. It returns nil if sending,
// receiving, or parsing fails.
func sendDNSQueryAndWait(domain string) []byte {
	query := buildDNSQuery(domain)

	dnsServer := dnsTunnelServerAddr()
	conn, err := net.Dial("udp", dnsServer)
	if err != nil {
		logger.Error("Failed to connect to DNS server: %v", err)
		return nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write(query); err != nil {
		logger.Error("Failed to send DNS query: %v", err)
		return nil
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		logger.Error("Failed to read DNS response: %v", err)
		return nil
	}

	// Parse TXT record data
	return parseDNSResponse(buf[:n])
}

// buildDNSQuery builds a DNS query packet for the given domain that requests a TXT record.
// The packet uses a crypto-random transaction ID, standard query flags, and a single question;
// the domain is encoded in DNS label format and QTYPE is set to TXT (16) with QCLASS IN (1).
// The function returns the raw DNS query bytes ready to be sent over UDP.
func buildDNSQuery(domain string) []byte {
	query := make([]byte, 512)

	// Random transaction ID (crypto/rand, math/rand fallback).
	var txid [2]byte
	if _, err := rand.Read(txid[:]); err != nil {
		n := time.Now().UnixNano()
		txid[0] = byte(n >> 8)
		txid[1] = byte(n)
	}
	query[0] = txid[0]
	query[1] = txid[1]

	// Flags (standard query)
	query[2] = 0x01
	query[3] = 0x00

	// Questions: 1
	query[4] = 0x00
	query[5] = 0x01

	// Encode domain name
	pos := 12
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		query[pos] = byte(len(label))
		pos++
		copy(query[pos:], label)
		pos += len(label)
	}
	query[pos] = 0 // End of domain
	pos++

	// QTYPE (TXT = 16)
	query[pos] = 0x00
	query[pos+1] = 0x10
	pos += 2

	// QCLASS (IN = 1)
	query[pos] = 0x00
	query[pos+1] = 0x01
	pos += 2

	return query[:pos]
}

// parseDNSResponse parses a DNS response and returns the decoded payload from the first TXT answer
// using the tunnel's configured encoding. It returns nil if the response is malformed or contains no TXT data.
func parseDNSResponse(response []byte) []byte {
	// Simple TXT record parser
	// This is a simplified version
	if len(response) < 12 {
		return nil
	}

	// Skip to answer section
	pos := 12

	// Skip question section
	for pos < len(response) && response[pos] != 0 {
		if response[pos] >= 0xc0 {
			pos += 2
			break
		}
		pos += int(response[pos]) + 1
	}
	if pos < len(response) && response[pos] == 0 {
		pos++
	}
	pos += 4 // Skip QTYPE and QCLASS

	// Parse answer
	if pos+12 > len(response) {
		return nil
	}

	// Skip name, type, class, TTL
	if response[pos] >= 0xc0 {
		pos += 2
	}
	pos += 10

	// Read RDLENGTH
	if pos+2 > len(response) {
		return nil
	}
	rdlen := int(response[pos])<<8 | int(response[pos+1])
	pos += 2

	// Read TXT data
	if pos+rdlen > len(response) {
		return nil
	}

	txtLen := int(response[pos])
	pos++

	if pos+txtLen > len(response) {
		return nil
	}

	encoded := string(response[pos : pos+txtLen])
	return decodeTunnelData(encoded)
}
