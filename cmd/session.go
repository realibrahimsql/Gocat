package cmd

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/realibrahimsql/Gocat/internal/logger"
	"github.com/realibrahimsql/Gocat/internal/modules"
	"github.com/realibrahimsql/Gocat/internal/session"
	"github.com/realibrahimsql/Gocat/internal/shell"
	"github.com/spf13/cobra"
)

var (
	sessionAgentHost string
	sessionAgentPort int
	sessionPFBind    string
)

var sessionCmd = &cobra.Command{
	Use:     "session",
	Aliases: []string{"sessions", "sess"},
	Short:   "Manage active shell sessions",
	Long: `View, interact with, and manage active reverse/bind shell sessions.

Provides multi-session tracking, upgrade, file transfer, and module execution.

Subcommands:
  list                     List all active sessions
  info <id>                Show detailed session information
  interact <id>            Attach to a session (foreground)
  detach                   Detach from current session
  kill <id>                Kill a session
  killall                  Kill all sessions
  upgrade <id>             Upgrade shell to PTY
  exec <id> <command>      Execute command on session
  upload <id> <file>       Upload file to session
  download <id> <path>     Download file from session
  modules                  List available modules
  run <module> <id>        Run a module on session
  agent <id>               Deploy/connect the Python reverse agent
  portfwd <id> <lport> <rhost:rport>
  cleanup <id>             Remove uploaded files

Examples:
  gocat session list
  gocat session interact 1
  gocat session exec 1 whoami
  gocat session upgrade 1
  gocat session upload 1 linpeas.sh
  gocat session download 1 /etc/passwd
  gocat session run linpeas 1
  gocat session modules`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println(session.DefaultManager.SessionsTable())
			return
		}
		cmd.Help()
	},
}

var sessionListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all active sessions",
	Run: func(cmd *cobra.Command, args []string) {
		asJSON, _ := cmd.Flags().GetBool("json")
		asCSV, _ := cmd.Flags().GetBool("csv")
		outFile, _ := cmd.Flags().GetString("output")
		var out string
		switch {
		case asJSON:
			out = session.DefaultManager.SessionsJSON()
		case asCSV:
			out = session.DefaultManager.SessionsCSV()
		default:
			out = session.DefaultManager.SessionsTable()
		}
		if outFile != "" {
			if err := os.WriteFile(outFile, []byte(out+"\n"), 0o640); err != nil {
				logger.Error("Write failed: %v", err)
				return
			}
			logger.Info("Wrote %s", outFile)
			return
		}
		fmt.Println(out)
	},
}

var sessionInfoCmd = &cobra.Command{
	Use:   "info <id>",
	Short: "Show detailed session information",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		id, err := strconv.Atoi(args[0])
		if err != nil {
			logger.Error("Invalid session ID: %s", args[0])
			return
		}
		fmt.Println(session.DefaultManager.SessionInfo(id))
	},
}

var sessionInteractCmd = &cobra.Command{
	Use:     "interact <id>",
	Aliases: []string{"attach", "use"},
	Short:   "Attach to a session",
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		id, err := strconv.Atoi(args[0])
		if err != nil {
			logger.Error("Invalid session ID: %s", args[0])
			return
		}
		if err := session.DefaultManager.InteractSession(id); err != nil {
			logger.Error("Interaction failed: %v", err)
		}
	},
}

var sessionDetachCmd = &cobra.Command{
	Use:   "detach",
	Short: "Detach from current session",
	Run: func(cmd *cobra.Command, args []string) {
		session.DefaultManager.DetachSession()
	},
}

var sessionKillCmd = &cobra.Command{
	Use:     "kill <id>",
	Aliases: []string{"rm", "remove"},
	Short:   "Kill a session",
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		id, err := strconv.Atoi(args[0])
		if err != nil {
			logger.Error("Invalid session ID: %s", args[0])
			return
		}
		session.DefaultManager.RemoveSession(id)
		logger.Info("Session %d killed", id)
	},
}

var sessionKillAllCmd = &cobra.Command{
	Use:   "killall",
	Short: "Kill all sessions",
	Run: func(cmd *cobra.Command, args []string) {
		session.DefaultManager.StopAll()
	},
}

var sessionUpgradeCmd = &cobra.Command{
	Use:   "upgrade <id> [method]",
	Short: "Upgrade shell to PTY (methods: auto, python, script, socat)",
	Args:  cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		id, err := strconv.Atoi(args[0])
		if err != nil {
			logger.Error("Invalid session ID: %s", args[0])
			return
		}

		sess := session.DefaultManager.GetSession(id)
		if sess == nil {
			logger.Error("Session %d not found", id)
			return
		}

		method := shell.MethodAuto
		if len(args) > 1 {
			switch args[1] {
			case "python":
				method = shell.MethodPython
			case "script":
				method = shell.MethodScript
			case "socat":
				method = shell.MethodSocat
			}
		}

		result := shell.Upgrade(sess, method)
		if result.Success {
			logger.Info("Session %d upgraded via %s", id, result.Method)
		} else {
			logger.Error("Upgrade failed: %v", result.Error)
		}
	},
}

var sessionExecCmd = &cobra.Command{
	Use:   "exec <id> <command...>",
	Short: "Execute command on session",
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		id, err := strconv.Atoi(args[0])
		if err != nil {
			logger.Error("Invalid session ID: %s", args[0])
			return
		}

		sess := session.DefaultManager.GetSession(id)
		if sess == nil {
			logger.Error("Session %d not found", id)
			return
		}

		command := strings.Join(args[1:], " ")
		resp, err := sess.Exec(command, 0)
		if err != nil {
			logger.Error("Exec failed: %v", err)
			return
		}
		fmt.Println(resp)
	},
}

var sessionUploadCmd = &cobra.Command{
	Use:   "upload <id> <file> [remote_path]",
	Short: "Upload file to session",
	Args:  cobra.RangeArgs(2, 3),
	Run: func(cmd *cobra.Command, args []string) {
		id, err := strconv.Atoi(args[0])
		if err != nil {
			logger.Error("Invalid session ID: %s", args[0])
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
	},
}

var sessionDownloadCmd = &cobra.Command{
	Use:   "download <id> <remote_path> [local_dir]",
	Short: "Download file from session",
	Args:  cobra.RangeArgs(2, 3),
	Run: func(cmd *cobra.Command, args []string) {
		id, err := strconv.Atoi(args[0])
		if err != nil {
			logger.Error("Invalid session ID: %s", args[0])
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
	},
}

var sessionModulesCmd = &cobra.Command{
	Use:     "modules",
	Aliases: []string{"mods", "module"},
	Short:   "List available modules",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(modules.DefaultRegistry.FormatModuleList())
	},
}

var sessionRunModCmd = &cobra.Command{
	Use:   "run <module> <session_id> [args...]",
	Short: "Run a module on a session",
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		modName := args[0]
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

		if err := modules.DefaultRegistry.Run(modName, sess, modArgs); err != nil {
			logger.Error("Module error: %v", err)
		}
	},
}

var sessionAgentCmd = &cobra.Command{
	Use:   "agent <id>",
	Short: "Deploy the Python reverse agent for multiplexed session features",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		id, err := strconv.Atoi(args[0])
		if err != nil {
			logger.Error("Invalid session ID: %s", args[0])
			return
		}
		sess := session.DefaultManager.GetSession(id)
		if sess == nil {
			logger.Error("Session %d not found", id)
			return
		}
		if err := sess.StartAgent(sessionAgentHost, sessionAgentPort, 15*time.Second); err != nil {
			logger.Error("Agent failed: %v", err)
			return
		}
		logger.Info("Agent ready for session %d", id)
	},
}

var sessionPortForwardCmd = &cobra.Command{
	Use:     "portfwd <id> <local_port> <remote_host:remote_port>",
	Aliases: []string{"pf", "forward"},
	Short:   "Forward a local TCP port through a session agent",
	Args:    cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		id, err := strconv.Atoi(args[0])
		if err != nil {
			logger.Error("Invalid session ID: %s", args[0])
			return
		}
		localPort, err := strconv.Atoi(args[1])
		if err != nil || localPort < 1 || localPort > 65535 {
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
			logger.Info("Agent is not active; deploying it first...")
			if err := sess.StartAgent(sessionAgentHost, sessionAgentPort, 15*time.Second); err != nil {
				logger.Error("Agent failed: %v", err)
				return
			}
		}
		if err := runSessionPortForward(sess, localPort, remote); err != nil {
			logger.Error("Port forward failed: %v", err)
		}
	},
}

var sessionCleanupCmd = &cobra.Command{
	Use:   "cleanup <id>",
	Short: "Remove uploaded files from target",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		id, err := strconv.Atoi(args[0])
		if err != nil {
			logger.Error("Invalid session ID: %s", args[0])
			return
		}

		sess := session.DefaultManager.GetSession(id)
		if sess == nil {
			logger.Error("Session %d not found", id)
			return
		}

		removed := sess.Cleanup()
		logger.Info("Removed %d files from target", removed)
	},
}

func init() {
	rootCmd.AddCommand(sessionCmd)

	sessionCmd.AddCommand(sessionListCmd)
	sessionCmd.AddCommand(sessionInfoCmd)
	sessionCmd.AddCommand(sessionInteractCmd)
	sessionCmd.AddCommand(sessionDetachCmd)
	sessionCmd.AddCommand(sessionKillCmd)
	sessionCmd.AddCommand(sessionKillAllCmd)
	sessionCmd.AddCommand(sessionUpgradeCmd)
	sessionCmd.AddCommand(sessionExecCmd)
	sessionCmd.AddCommand(sessionUploadCmd)
	sessionCmd.AddCommand(sessionDownloadCmd)
	sessionCmd.AddCommand(sessionModulesCmd)
	sessionCmd.AddCommand(sessionRunModCmd)
	sessionCmd.AddCommand(sessionAgentCmd)
	sessionCmd.AddCommand(sessionPortForwardCmd)
	sessionCmd.AddCommand(sessionCleanupCmd)

	sessionAgentCmd.Flags().StringVar(&sessionAgentHost, "host", "", "Local host/IP the target should connect back to")
	sessionAgentCmd.Flags().IntVar(&sessionAgentPort, "port", 0, "Local port for the reverse agent callback (0 = random)")
	sessionListCmd.Flags().Bool("json", false, "Output sessions as JSON")
	sessionListCmd.Flags().Bool("csv", false, "Output sessions as CSV")
	sessionListCmd.Flags().String("output", "", "Write output to file instead of stdout")
	sessionPortForwardCmd.Flags().StringVar(&sessionPFBind, "bind", "127.0.0.1", "Local bind address for the forwarded port")
	sessionPortForwardCmd.Flags().StringVar(&sessionAgentHost, "agent-host", "", "Local host/IP the target should connect back to")
	sessionPortForwardCmd.Flags().IntVar(&sessionAgentPort, "agent-port", 0, "Local port for the reverse agent callback (0 = random)")
}

func runSessionPortForward(sess *session.Session, localPort int, remote string) error {
	listener, err := net.Listen("tcp", net.JoinHostPort(sessionPFBind, strconv.Itoa(localPort)))
	if err != nil {
		return err
	}
	defer listener.Close()

	logger.Info("Session port forward active: %s:%d -> %s via session [%d]", sessionPFBind, localPort, remote, sess.ID)

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go handleSessionForwardConn(sess, conn, remote)
	}
}

func handleSessionForwardConn(sess *session.Session, conn net.Conn, remote string) {
	defer conn.Close()

	stream, err := sess.OpenAgentStream(remote)
	if err != nil {
		logger.Error("Failed to open agent stream: %v", err)
		return
	}
	defer sess.CloseAgentStream(stream.ID)

	errCh := make(chan error, 2)
	go func() {
		buf := make([]byte, 32768)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if sendErr := sess.SendAgentStreamData(stream.ID, buf[:n]); sendErr != nil {
					errCh <- sendErr
					return
				}
			}
			if err != nil {
				errCh <- err
				return
			}
		}
	}()
	go func() {
		_, err := io.Copy(conn, stream)
		errCh <- err
	}()

	<-errCh
}
