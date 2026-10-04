//go:build unix

package session

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/realibrahimsql/Gocat/internal/terminal"
	"golang.org/x/term"
)

var detachSequences = [][]byte{
	{0x1d},             // Ctrl+]
	[]byte("\x1b[24~"), // F12 in common terminals
}

// InteractSession attaches local stdin to a session in raw mode. Control bytes
// such as Ctrl+C are sent to the remote shell instead of interrupting GoCat.
func (m *Manager) InteractSession(id int) error {
	sess := m.GetSession(id)
	if sess == nil {
		return fmt.Errorf("session %d not found", id)
	}
	if err := m.AttachSession(id); err != nil {
		return err
	}

	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		restore, err := terminal.Guard()
		if err != nil {
			m.DetachSession()
			return fmt.Errorf("failed to enter raw mode: %w", err)
		}
		defer restore()

		// In raw mode Ctrl+C arrives as a byte and is forwarded below;
		// an externally delivered SIGINT detaches cleanly instead of
		// killing the process with the terminal still raw.
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, syscall.SIGINT)
		defer signal.Stop(sigint)
		intDone := make(chan struct{})
		defer close(intDone)
		go func() {
			select {
			case <-sigint:
				restore()
				m.DetachSession()
				fmt.Fprintln(os.Stderr, "\r\n[GoCat] detached (SIGINT).\r")
				os.Exit(130)
			case <-intDone:
			}
		}()
	}

	fmt.Fprintln(os.Stderr, "\r\n[GoCat] attached. Press F12 or Ctrl+] to detach; Ctrl+C is forwarded to the remote shell.\r")
	sendTerminalSize(sess)

	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)
	done := make(chan struct{})
	defer close(done)

	go func() {
		for {
			select {
			case <-winch:
				sendTerminalSize(sess)
			case <-done:
				return
			}
		}
	}()

	buf := make([]byte, 4096)
	translateCR := sess.Type != ShellPTY
	for {
		n, err := os.Stdin.Read(buf)
		if n > 0 {
			data := translateLineEndings(append([]byte(nil), buf[:n]...), translateCR)
			if containsDetachSequence(data) {
				m.DetachSession()
				fmt.Fprintln(os.Stderr, "\r\n[GoCat] detached.\r")
				return nil
			}
			if translateCR {
				for i, b := range data {
					if b == '\r' {
						data[i] = '\n'
					}
				}
			}
			if _, sendErr := sess.Send(data); sendErr != nil {
				m.DetachSession()
				return sendErr
			}
			sess.Record(data, true)
		}
		if err != nil {
			m.DetachSession()
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}
func containsDetachSequence(data []byte) bool {
	for _, seq := range detachSequences {
		if bytes.Contains(data, seq) {
			return true
		}
	}
	return false
}

// translateLineEndings maps CR to LF for raw (non-PTY) sessions. A PTY
// translates CR to LF itself (ICRNL); a raw shell has no line discipline,
// so an Enter arriving as a lone CR would never terminate the remote
// command line. PTY input passes through untouched.
func translateLineEndings(data []byte, translate bool) []byte {
	if !translate {
		return data
	}
	for i, b := range data {
		if b == '\r' {
			data[i] = '\n'
		}
	}
	return data
}

func sendTerminalSize(sess *Session) {
	if sess.Type != ShellPTY || !term.IsTerminal(int(os.Stdin.Fd())) {
		return
	}
	width, height, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil || width <= 0 || height <= 0 {
		return
	}
	_, _ = sess.Send([]byte(fmt.Sprintf("stty rows %d cols %d\n", height, width)))
}
