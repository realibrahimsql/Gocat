package cmd

import (
	"bufio"
	"crypto/subtle"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/realibrahimsql/Gocat/internal/logger"
	"github.com/spf13/cobra"
)

var (
	chatPort     string
	chatClients  map[string]*ChatClient
	chatMutex    sync.RWMutex
	chatMaxConns int
	chatRoomName string
	chatHost     string
	chatAuth     string
)

type ChatClient struct {
	Conn     net.Conn
	Nickname string
	JoinTime time.Time
}

var chatCmd = &cobra.Command{
	Use:   "chat [port]",
	Short: "Start a chat server mode",
	Long: `Start GoCat in chat server mode. This creates a simple chat room where
multiple clients can connect and exchange messages with nicknames.`,
	Args: cobra.ExactArgs(1),
	Run:  runChat,
}

func init() {
	rootCmd.AddCommand(chatCmd)
	chatCmd.Flags().IntVarP(&chatMaxConns, "max-conns", "m", 20, "Maximum number of concurrent chat connections")
	chatCmd.Flags().StringVarP(&chatRoomName, "room", "r", "GoCat-Room", "Chat room name")
	chatCmd.Flags().StringVar(&chatHost, "host", "127.0.0.1", "Bind address (use 0.0.0.0 with --auth for LAN rooms)")
	chatCmd.Flags().StringVar(&chatAuth, "auth", "", "Require password as user:pass (strongly recommended unless loopback)")
	chatClients = make(map[string]*ChatClient)
}

func runChat(cmd *cobra.Command, args []string) {
	chatPort = args[0]

	// Override with global flags if set
	if globalMaxConns, _ := cmd.Root().PersistentFlags().GetInt("max-conns"); globalMaxConns > 0 {
		chatMaxConns = globalMaxConns
	}

	logger.Info("Starting chat server '%s' on port %s (max connections: %d)", chatRoomName, chatPort, chatMaxConns)

	if err := startChatServer(chatPort); err != nil {
		logger.Fatal("Chat server error: %v", err)
	}
}

func startChatServer(port string) error {
	listener, err := net.Listen("tcp", net.JoinHostPort(chatHost, port))
	if err != nil {
		return fmt.Errorf("failed to start chat server: %w", err)
	}
	defer listener.Close()

	if !isLoopbackAddr(chatHost) && chatAuth == "" {
		logger.Warn("Chat room on %s without --auth: anyone on the network can join and impersonate users", listener.Addr())
	}
	logger.Info("Chat server '%s' listening on %s", chatRoomName, listener.Addr())

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error("Failed to accept chat connection: %v", err)
			continue
		}

		chatMutex.Lock()
		if len(chatClients) >= chatMaxConns {
			logger.Warn("Maximum chat connections reached, rejecting %s", conn.RemoteAddr())
			if _, err := conn.Write([]byte("Chat room is full. Please try again later.\n")); err != nil {
				logger.Error("Failed to write to connection: %v", err)
			}
			if err := conn.Close(); err != nil {
				logger.Error("Failed to close connection: %v", err)
			}
			chatMutex.Unlock()
			continue
		}
		chatMutex.Unlock()

		logger.Info("New chat connection from: %s", conn.RemoteAddr())
		go handleChatClient(conn)
	}
}

func handleChatClient(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Panic in handleChatClient: %v", r)
		}
		if err := conn.Close(); err != nil {
			logger.Error("Error closing chat connection: %v", err)
		}
	}()

	// Welcome message and nickname prompt
	if _, err := conn.Write([]byte(fmt.Sprintf("Welcome to %s!\nPlease enter your nickname: ", chatRoomName))); err != nil {
		logger.Error("Failed to send welcome message: %v", err)
		return
	}

	// Optional password gate before the client can speak.
	if chatAuth != "" {
		parts := strings.SplitN(chatAuth, ":", 2)
		if len(parts) != 2 {
			logger.Error("Invalid --auth format. Use user:pass")
			return
		}
		if _, err := conn.Write([]byte("Password: ")); err != nil {
			return
		}
		if err := conn.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
			return
		}
		scanner := bufio.NewScanner(conn)
		scanner.Buffer(make([]byte, maxChatLine), maxChatLine)
		if !scanner.Scan() || !checkChatAuth(scanner.Text(), parts[0], parts[1]) {
			_, _ = conn.Write([]byte("Authentication failed.\n"))
			logger.Warn("Chat auth failed from %s", conn.RemoteAddr())
			return
		}
		_ = conn.SetReadDeadline(time.Time{})
	}

	// Per-connection scanner: lines capped at maxChatLine, no cross-call loss.
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, maxChatLine), maxChatLine)

	// Read nickname (bounded, sanitized)
	nickname, err := readChatLine(conn, scanner)
	if err != nil {
		logger.Debug("Failed to read nickname from %s: %v", conn.RemoteAddr(), err)
		return
	}
	nickname = sanitizeNickname(nickname)
	if nickname == "" {
		nickname = fmt.Sprintf("Guest-%d", time.Now().Unix()%10000)
	}

	// Check if nickname is already taken and register client atomically
	chatMutex.Lock()
	originalNick := nickname
	counter := 1
	for {
		taken := false
		for _, client := range chatClients {
			if client.Nickname == nickname {
				taken = true
				break
			}
		}
		if !taken {
			break
		}
		counter++
		nickname = fmt.Sprintf("%s%d", originalNick, counter)
	}

	clientID := fmt.Sprintf("%s-%d", conn.RemoteAddr().String(), time.Now().Unix())
	client := &ChatClient{
		Conn:     conn,
		Nickname: nickname,
		JoinTime: time.Now(),
	}
	chatClients[clientID] = client
	chatMutex.Unlock()

	// Notify about successful join
	if _, err := conn.Write([]byte(fmt.Sprintf("You joined as '%s'. Type /help for commands.\n", nickname))); err != nil {
		logger.Error("Failed to send join confirmation: %v", err)
		// Remove client from map since we couldn't confirm join
		chatMutex.Lock()
		delete(chatClients, clientID)
		chatMutex.Unlock()
		return
	}
	broadcastMessage(fmt.Sprintf("*** %s joined the chat ***", nickname), "")

	logger.Info("Chat user '%s' joined from %s", nickname, conn.RemoteAddr())

	defer func() {
		chatMutex.Lock()
		delete(chatClients, clientID)
		chatMutex.Unlock()
		broadcastMessage(fmt.Sprintf("*** %s left the chat ***", nickname), "")
		logger.Info("Chat user '%s' left", nickname)
	}()

	// Handle messages (each line bounded; idle clients time out)
	for {
		message, err := readChatLine(conn, scanner)
		if err != nil {
			logger.Debug("Chat client %s disconnected: %v", nickname, err)
			return
		}

		message = strings.TrimSpace(message)
		if message == "" {
			continue
		}
		if len(message) > 2048 {
			message = message[:2048]
		}

		// Handle commands
		if strings.HasPrefix(message, "/") {
			handleChatCommand(client, message)
			continue
		}

		// Broadcast regular message
		formattedMsg := fmt.Sprintf("[%s] %s: %s", time.Now().Format("15:04"), nickname, message)
		broadcastMessage(formattedMsg, clientID)
		logger.Debug("Chat message from %s: %s", nickname, message)
	}
}

func handleChatCommand(client *ChatClient, command string) {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return
	}

	cmd := strings.ToLower(parts[0])
	switch cmd {
	case "/help":
		help := `Available commands:
/help - Show this help
/list - List online users
/time - Show current time
/quit - Leave the chat
`
		client.Conn.Write([]byte(help))

	case "/list":
		chatMutex.RLock()
		userList := fmt.Sprintf("Online users (%d):\n", len(chatClients))
		for _, c := range chatClients {
			duration := time.Since(c.JoinTime).Truncate(time.Second)
			userList += fmt.Sprintf("  %s (online for %s)\n", c.Nickname, duration)
		}
		chatMutex.RUnlock()
		client.Conn.Write([]byte(userList))

	case "/time":
		timeStr := fmt.Sprintf("Current time: %s\n", time.Now().Format("2006-01-02 15:04:05"))
		client.Conn.Write([]byte(timeStr))

	case "/quit":
		client.Conn.Write([]byte("Goodbye!\n"))
		client.Conn.Close()

	default:
		client.Conn.Write([]byte(fmt.Sprintf("Unknown command: %s. Type /help for available commands.\n", cmd)))
	}
}

func broadcastMessage(message string, excludeClientID string) {
	chatMutex.RLock()
	// Create a copy of clients to avoid holding lock during network operations
	clients := make(map[string]*ChatClient)
	for id, client := range chatClients {
		if id != excludeClientID {
			clients[id] = client
		}
	}
	chatMutex.RUnlock()

	// Send messages without holding the lock
	for clientID, client := range clients {
		_ = client.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := client.Conn.Write([]byte(message + "\n")); err != nil {
			logger.Warn("Failed to send message to client %s: %v", clientID, err)
			// Remove failed client from the map
			chatMutex.Lock()
			if _, exists := chatClients[clientID]; exists {
				delete(chatClients, clientID)
				if closeErr := client.Conn.Close(); closeErr != nil {
					logger.Error("Error closing failed client connection: %v", closeErr)
				}
			}
			chatMutex.Unlock()
		}
	}
}

// maxChatLine caps a single chat line at 4KB so a client that never sends
// a newline cannot grow server memory without bound.
const maxChatLine = 4096

// readChatLine reads one line through the connection scanner with an idle
// deadline. Overlong lines fail the scan and drop the client.
func readChatLine(conn net.Conn, scanner *bufio.Scanner) (string, error) {
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Minute)); err != nil {
		return "", err
	}
	defer conn.SetReadDeadline(time.Time{})
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}
		return "", fmt.Errorf("client disconnected")
	}
	return strings.TrimSpace(scanner.Text()), nil
}

// sanitizeNickname keeps printable runes up to 32 chars so nicknames cannot
// inject terminal escapes or break the user list.
func sanitizeNickname(nick string) string {
	var sb strings.Builder
	for _, r := range nick {
		if sb.Len() >= 32 {
			break
		}
		if r >= 32 && r != 127 {
			sb.WriteRune(r)
		}
	}
	return strings.TrimSpace(sb.String())
}

// checkChatAuth compares "user:pass" password input in constant time.
func checkChatAuth(got, user, pass string) bool {
	u, p, ok := strings.Cut(got, ":")
	if !ok {
		// Bare password also accepted when it matches.
		return subtle.ConstantTimeCompare([]byte(got), []byte(pass)) == 1
	}
	if subtle.ConstantTimeCompare([]byte(u), []byte(user)) != 1 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(p), []byte(pass)) == 1
}

// isLoopbackAddr reports whether a bind address is loopback-only.
func isLoopbackAddr(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
