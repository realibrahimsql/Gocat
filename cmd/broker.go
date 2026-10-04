package cmd

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/realibrahimsql/Gocat/internal/logger"
	"github.com/spf13/cobra"
)

var (
	brokerPort     string
	brokerClients  map[string]net.Conn
	brokerMutex    sync.RWMutex
	brokerMaxConns int
	brokerHost     string
	brokerAuth     string
)

var brokerCmd = &cobra.Command{
	Use:   "broker [port]",
	Short: "Start a broker mode for relaying connections",
	Long: `Start GoCat in broker mode. This mode allows multiple clients to connect
and relay data between them. Useful for creating a central hub for communication.`,
	Args: cobra.ExactArgs(1),
	Run:  runBroker,
}

func init() {
	rootCmd.AddCommand(brokerCmd)
	brokerCmd.Flags().IntVarP(&brokerMaxConns, "max-conns", "m", 10, "Maximum number of concurrent connections")
	brokerCmd.Flags().StringVar(&brokerHost, "host", "127.0.0.1", "Bind address (use 0.0.0.0 with --auth for LAN relays)")
	brokerCmd.Flags().StringVar(&brokerAuth, "auth", "", "Require password as user:pass")
	brokerClients = make(map[string]net.Conn)
}

func runBroker(cmd *cobra.Command, args []string) {
	brokerPort = args[0]

	// Override with global flags if set
	if globalMaxConns, _ := cmd.Root().PersistentFlags().GetInt("max-conns"); globalMaxConns > 0 {
		brokerMaxConns = globalMaxConns
	}

	logger.Info("Starting broker mode on port %s (max connections: %d)", brokerPort, brokerMaxConns)

	if err := startBroker(brokerPort); err != nil {
		logger.Fatal("Broker error: %v", err)
	}
}

func startBroker(port string) error {
	listener, err := net.Listen("tcp", net.JoinHostPort(brokerHost, port))
	if err != nil {
		return fmt.Errorf("failed to start broker listener: %w", err)
	}
	defer listener.Close()

	if !isLoopbackAddr(brokerHost) && brokerAuth == "" {
		logger.Warn("Broker on %s without --auth: anyone on the network can relay traffic", listener.Addr())
	}
	logger.Info("Broker listening on %s", listener.Addr())

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error("Failed to accept connection: %v", err)
			continue
		}

		brokerMutex.RLock()
		full := len(brokerClients) >= brokerMaxConns
		brokerMutex.RUnlock()
		if full {
			logger.Warn("Maximum connections reached, rejecting %s", conn.RemoteAddr())
			if err := conn.Close(); err != nil {
				logger.Error("Failed to close connection: %v", err)
			}
			continue
		}

		clientID := fmt.Sprintf("%s-%d", conn.RemoteAddr().String(), time.Now().Unix())
		logger.Info("Client connected: %s (ID: %s)", conn.RemoteAddr(), clientID)
		go handleBrokerClient(clientID, conn)
	}
}

func handleBrokerClient(clientID string, conn net.Conn) {
	if !checkBrokerAuth(conn) {
		logger.Warn("Broker auth failed from %s", conn.RemoteAddr())
		_ = conn.Close()
		return
	}
	brokerMutex.Lock()
	brokerClients[clientID] = conn
	brokerMutex.Unlock()
	defer func() {
		brokerMutex.Lock()
		delete(brokerClients, clientID)
		brokerMutex.Unlock()
		if err := conn.Close(); err != nil {
			logger.Error("Failed to close connection: %v", err)
		}
		logger.Info("Client disconnected: %s", clientID)
	}()

	buffer := make([]byte, 4096)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			logger.Debug("Client %s read error: %v", clientID, err)
			return
		}

		data := buffer[:n]
		logger.Debug("Received %d bytes from %s", n, clientID)

		// Snapshot under RLock, write outside the lock with deadlines so
		// one slow client cannot stall every broadcast.
		brokerMutex.RLock()
		others := make(map[string]net.Conn, len(brokerClients))
		for otherID, otherConn := range brokerClients {
			if otherID != clientID {
				others[otherID] = otherConn
			}
		}
		brokerMutex.RUnlock()
		for otherID, otherConn := range others {
			_ = otherConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := otherConn.Write(data); err != nil {
				logger.Error("Failed to write to client %s: %v", otherID, err)
				brokerMutex.Lock()
				if c, ok := brokerClients[otherID]; ok && c == otherConn {
					delete(brokerClients, otherID)
					_ = otherConn.Close()
				}
				brokerMutex.Unlock()
			}
		}
	}
}

// checkBrokerAuth gates a fresh relay client when --auth is configured.
func checkBrokerAuth(conn net.Conn) bool {
	if brokerAuth == "" {
		return true
	}
	parts := strings.SplitN(brokerAuth, ":", 2)
	if len(parts) != 2 {
		logger.Error("Invalid --auth format. Use user:pass")
		return false
	}
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1024), 1024)
	if _, err := conn.Write([]byte("Password: ")); err != nil {
		return false
	}
	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	if !scanner.Scan() || !checkChatAuth(scanner.Text(), parts[0], parts[1]) {
		_, _ = conn.Write([]byte("Authentication failed.\n"))
		return false
	}
	return true
}
