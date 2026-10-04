package session

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/realibrahimsql/Gocat/internal/logger"
)

// OSType represents the detected operating system type
type OSType string

const (
	OSUnix    OSType = "Unix"
	OSWindows OSType = "Windows"
	OSUnknown OSType = "Unknown"
)

// ShellType represents the type of shell
type ShellType string

const (
	ShellRaw      ShellType = "Raw"
	ShellPTY      ShellType = "PTY"
	ShellReadline ShellType = "Readline"
)

// ShellSubType represents the shell sub-type (for Windows)
type ShellSubType string

const (
	SubTypeNone ShellSubType = ""
	SubTypeCmd  ShellSubType = "cmd"
	SubTypePSH  ShellSubType = "psh"
	SubTypeBash ShellSubType = "bash"
	SubTypeSH   ShellSubType = "sh"
)

// Source represents how the session was created
type Source string

const (
	SourceReverse Source = "reverse"
	SourceBind    Source = "bind"
)

// Session represents an active shell session
type Session struct {
	ID          int
	Socket      net.Conn
	Target      string
	Port        int
	IP          string
	LocalHost   string
	LocalPort   int
	ListenerID  int
	Source      Source
	OS          OSType
	Type        ShellType
	SubType     ShellSubType
	Interactive bool
	Echoing     bool
	PTYReady    bool

	Hostname string
	System   string
	Arch     string
	User     string
	ShellPID string
	TTY      string

	Name        string
	NameColored string

	Directory string
	LogPath   string
	LogFile   *os.File

	CreatedAt   time.Time
	LastActive  time.Time
	IsAttached  bool
	IsNew       bool
	AgentActive bool
	AgentConn   net.Conn
	AgentMux    *Messenger

	UploadedPaths map[string]int64
	Tasks         map[string][]interface{}
	Streams       map[uint16]*Stream
	StreamLock    sync.Mutex
	NextStreamID  uint16

	OutBuf       []byte
	ShellBuf     []byte
	LastLines    *LineBuffer
	Prompt       []byte
	AlternateBuf bool
	PumpActive   bool
	outputMu     sync.Mutex
	outputSignal chan struct{}

	Binaries map[string]string
	TmpDir   string
	CWD      string

	lock  sync.Mutex
	wlock sync.Mutex
}

// LineBuffer keeps the last N lines for re-display on attach
type LineBuffer struct {
	lines    [][]byte
	maxLines int
	mu       sync.Mutex
}

// NewLineBuffer creates a new line buffer
func NewLineBuffer(maxLines int) *LineBuffer {
	return &LineBuffer{
		lines:    make([][]byte, 0, maxLines),
		maxLines: maxLines,
	}
}

// Write adds data to the line buffer
func (lb *LineBuffer) Write(data []byte) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.lines = append(lb.lines, data)
	if len(lb.lines) > lb.maxLines {
		lb.lines = lb.lines[len(lb.lines)-lb.maxLines:]
	}
}

// Bytes returns all buffered data
func (lb *LineBuffer) Bytes() []byte {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	var result []byte
	for _, line := range lb.lines {
		result = append(result, line...)
	}
	return result
}

// Stream represents a multiplexed data stream within a session
type Stream struct {
	ID      uint16
	Session *Session
	ReadFD  *os.File
	WriteFD *os.File
}

// NewStream creates a new stream with a pipe
func NewStream(id uint16, sess *Session) (*Stream, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stream pipe: %w", err)
	}
	return &Stream{
		ID:      id,
		Session: sess,
		ReadFD:  r,
		WriteFD: w,
	}, nil
}

// Write sends data to the stream
func (s *Stream) Write(data []byte) (int, error) {
	return s.WriteFD.Write(data)
}

// Read reads data from the stream
func (s *Stream) Read(buf []byte) (int, error) {
	return s.ReadFD.Read(buf)
}

// Close closes the stream
func (s *Stream) Close() error {
	s.ReadFD.Close()
	s.WriteFD.Close()
	return nil
}

// addrIPPort extracts IP/port without panicking on non-TCP addresses.
func addrIPPort(addr net.Addr) (string, int) {
	if addr == nil {
		return "unknown", 0
	}
	if tcp, ok := addr.(*net.TCPAddr); ok && tcp != nil {
		if tcp.IP != nil {
			return tcp.IP.String(), tcp.Port
		}
		return "unknown", tcp.Port
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String(), 0
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return host, port
}

// NewSession creates a new session from a connection.
// It never panics on non-TCP addresses: TLS-wrapped, Unix socket or
// in-memory conns fall back to string parsing.
func NewSession(conn net.Conn, target string, port int, listenerID int, source Source) *Session {
	localIP, localPort := addrIPPort(conn.LocalAddr())
	remoteIP, _ := addrIPPort(conn.RemoteAddr())

	sess := &Session{
		Socket:        conn,
		Target:        target,
		Port:          port,
		IP:            remoteIP,
		LocalHost:     localIP,
		LocalPort:     localPort,
		ListenerID:    listenerID,
		Source:        source,
		OS:            OSUnknown,
		Type:          ShellRaw,
		SubType:       SubTypeNone,
		Interactive:   false,
		Echoing:       false,
		IsNew:         true,
		CreatedAt:     time.Now(),
		LastActive:    time.Now(),
		UploadedPaths: make(map[string]int64),
		Tasks:         map[string][]interface{}{"portfwd": {}, "scripts": {}},
		Streams:       make(map[uint16]*Stream),
		LastLines:     NewLineBuffer(20),
		outputSignal:  make(chan struct{}, 1),
		Binaries:      make(map[string]string),
	}

	return sess
}

// Send sends data to the session's socket
func (s *Session) Send(data []byte) (int, error) {
	s.wlock.Lock()
	defer s.wlock.Unlock()
	s.LastActive = time.Now()
	return s.Socket.Write(data)
}

// Recv receives data from the session's socket
func (s *Session) Recv(buf []byte) (int, error) {
	n, err := s.Socket.Read(buf)
	if n > 0 {
		s.LastActive = time.Now()
	}
	return n, err
}

// Exec sends a command and reads the response with delimiters
func (s *Session) Exec(cmd string, timeout time.Duration) (string, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.OS == OSUnknown {
		return "", fmt.Errorf("session OS not determined")
	}

	// Generate random tokens for delimiter-based command execution
	token1 := randomString(10)
	token2 := randomString(10)
	token3 := randomString(10)
	token4 := randomString(10)

	var fullCmd string
	var pattern *regexp.Regexp

	if s.OS == OSUnix {
		fullCmd = fmt.Sprintf(" %s=%s %s=%s;printf ${%s}${%s};%s;printf ${%s}${%s}\n",
			token1, token2, token3, token4,
			token1, token3, cmd, token3, token1)
		pattern = regexp.MustCompile(fmt.Sprintf(`(?s)%s%s(.*)%s%s`, token2, token4, token4, token2))
	} else if s.OS == OSWindows {
		if s.SubType == SubTypeCmd {
			fullCmd = fmt.Sprintf("set %s=%s&set %s=%s\r\necho %%%s%%%%%s%%&%s&echo %%%s%%%%%s%%\r\n",
				token1, token2, token3, token4,
				token1, token3, cmd, token3, token1)
		} else {
			fullCmd = fmt.Sprintf("$env:%s=\"%s\";$env:%s=\"%s\"\r\necho $env:%s$env:%s;%s;echo $env:%s$env:%s\r\n",
				token1, token2, token3, token4,
				token1, token3, cmd, token3, token1)
		}
		pattern = regexp.MustCompile(fmt.Sprintf(`(?s)%s%s(.*)%s%s`, token2, token4, token4, token2))
	}

	if s.PumpActive {
		s.outputMu.Lock()
		s.OutBuf = s.OutBuf[:0]
		s.outputMu.Unlock()
	}

	// Send command
	_, err := s.Send([]byte(fullCmd))
	if err != nil {
		return "", fmt.Errorf("failed to send command: %w", err)
	}

	if s.PumpActive {
		return s.waitForExecOutput(pattern, timeout)
	}

	// Read response with timeout
	if timeout == 0 {
		timeout = 4 * time.Second
	}

	var response []byte
	buf := make([]byte, 16384)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		s.Socket.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := s.Socket.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Check if we have complete response
				if pattern != nil {
					matches := pattern.FindSubmatch(response)
					if matches != nil {
						s.Socket.SetReadDeadline(time.Time{})
						return strings.TrimSpace(string(matches[1])), nil
					}
				}
				continue
			}
			break
		}
		response = append(response, buf[:n]...)

		// Check if response is complete
		if pattern != nil {
			matches := pattern.FindSubmatch(response)
			if matches != nil {
				s.Socket.SetReadDeadline(time.Time{})
				return strings.TrimSpace(string(matches[1])), nil
			}
		}
	}

	s.Socket.SetReadDeadline(time.Time{})
	return "", fmt.Errorf("command timed out")
}

func (s *Session) waitForExecOutput(pattern *regexp.Regexp, timeout time.Duration) (string, error) {
	if timeout == 0 {
		timeout = 4 * time.Second
	}

	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()

	for {
		s.outputMu.Lock()
		response := append([]byte(nil), s.OutBuf...)
		s.outputMu.Unlock()

		if pattern != nil {
			matches := pattern.FindSubmatch(response)
			if matches != nil {
				return strings.TrimSpace(string(matches[1])), nil
			}
		}

		select {
		case <-s.outputSignal:
		case <-ticker.C:
		case <-deadline.C:
			return "", fmt.Errorf("command timed out")
		}
	}
}

// HandleOutput records bytes read by the single session socket reader and
// makes them available to attached terminals and delimiter-based Exec calls.
func (s *Session) HandleOutput(data []byte) {
	if len(data) == 0 {
		return
	}

	s.Record(data, false)

	s.outputMu.Lock()
	s.OutBuf = append(s.OutBuf, data...)
	if len(s.OutBuf) > 1024*1024 {
		s.OutBuf = s.OutBuf[len(s.OutBuf)-1024*1024:]
	}
	s.outputMu.Unlock()

	select {
	case s.outputSignal <- struct{}{}:
	default:
	}
}

// Determine detects the OS and shell type of the session
func matchedShellMarker(respStr, v2, v4 string) bool {
	if strings.Contains(respStr, v2+v4) {
		return true
	}
	if strings.Contains(respStr, "is not recognized as an internal or external command") {
		return true
	}
	return regexp.MustCompile(`PS.*>`).MatchString(respStr)
}

func (s *Session) Determine() bool {
	v1 := randomString(4)
	v2 := randomString(4)
	v3 := randomString(4)
	v4 := randomString(4)

	cmd := fmt.Sprintf(" %s=%s %s=%s; echo ${%s}${%s}\n", v1, v2, v3, v4, v1, v3)

	sendProbe := func() error {
		_, err := s.Send([]byte(cmd))
		return err
	}
	if err := sendProbe(); err != nil {
		return false
	}

	// Read response. Slow shells (heavy rc files, loaded hosts) can take
	// many seconds before answering, so allow 15s and re-send the probe
	// every 5s; input arriving late still gets answered.
	buf := make([]byte, 16384)
	var response []byte
	deadline := time.Now().Add(15 * time.Second)
	nextProbe := time.Now().Add(5 * time.Second)

	for time.Now().Before(deadline) {
		s.Socket.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := s.Socket.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if len(response) > 0 && matchedShellMarker(string(response), v2, v4) {
					break
				}
				if time.Now().After(nextProbe) {
					if err := sendProbe(); err != nil {
						break
					}
					nextProbe = time.Now().Add(5 * time.Second)
				}
				continue
			}
			break
		}
		response = append(response, buf[:n]...)

		respStr := string(response)
		if matchedShellMarker(respStr, v2, v4) {
			break
		}
	}
	s.Socket.SetReadDeadline(time.Time{})

	if len(response) == 0 {
		return false
	}

	respStr := string(response)

	if strings.Contains(respStr, v2+v4) {
		s.OS = OSUnix
		s.Interactive = true
		s.Echoing = strings.Contains(respStr, fmt.Sprintf("echo ${%s}${%s}", v1, v3))
		logger.Debug("Detected Unix shell (interactive=%v, echoing=%v)", s.Interactive, s.Echoing)
	} else if strings.Contains(respStr, "is not recognized as an internal or external command") ||
		regexp.MustCompile(`Microsoft Windows.*>`).MatchString(respStr) {
		s.OS = OSWindows
		s.Type = ShellRaw
		s.SubType = SubTypeCmd
		s.Interactive = true
		s.Echoing = true
		logger.Debug("Detected Windows CMD shell")
	} else if strings.Contains(respStr, "is not recognized as the name of a cmdlet") ||
		regexp.MustCompile(`PS.*>`).MatchString(respStr) {
		s.OS = OSWindows
		s.Type = ShellRaw
		s.SubType = SubTypePSH
		s.Interactive = true
		s.Echoing = false
		logger.Debug("Detected Windows PowerShell")
	} else {
		return false
	}

	return true
}

// GetSystemInfo retrieves system information from the target
func (s *Session) GetSystemInfo() bool {
	if s.OS == OSUnix {
		resp, err := s.Exec(`printf "$(uname -n)\t$(uname -s)\t$(uname -m 2>/dev/null)"`, 5*time.Second)
		if err != nil {
			logger.Debug("Failed to get system info: %v", err)
			return false
		}
		parts := strings.Split(resp, "\t")
		if len(parts) >= 3 {
			s.Hostname = parts[0]
			s.System = parts[1]
			s.Arch = parts[2]
		}
	} else if s.OS == OSWindows {
		resp, err := s.Exec("hostname", 5*time.Second)
		if err == nil {
			s.Hostname = strings.TrimSpace(resp)
		}
	}

	return true
}

// GetUser retrieves the current user
func (s *Session) GetUser() string {
	if s.OS == OSUnix {
		resp, err := s.Exec(`echo "$(id -un)($(id -u))"`, 3*time.Second)
		if err == nil {
			s.User = resp
			return resp
		}
	} else if s.OS == OSWindows {
		resp, err := s.Exec("whoami", 3*time.Second)
		if err == nil {
			s.User = strings.TrimSpace(resp)
			return s.User
		}
	}
	return ""
}

// GetBinaries checks for available binaries on Unix targets
func (s *Session) GetBinaries() {
	if s.OS != OSUnix {
		return
	}

	binaries := []string{
		"sh", "bash", "python", "python3", "uname",
		"script", "socat", "tty", "echo", "base64", "wget",
		"curl", "tar", "rm", "stty", "setsid", "find", "nc",
	}

	cmd := fmt.Sprintf(`for i in %s; do which $i 2>/dev/null || echo;done`, strings.Join(binaries, " "))
	resp, err := s.Exec(cmd, 5*time.Second)
	if err != nil {
		return
	}

	lines := strings.Split(resp, "\n")
	for i, bin := range binaries {
		if i < len(lines) && strings.HasPrefix(lines[i], "/") {
			s.Binaries[bin] = lines[i]
		}
	}

	logger.Debug("Available binaries: %v", s.Binaries)
}

// FindTmpDir locates a writable temp directory on the target
func (s *Session) FindTmpDir() string {
	if s.TmpDir != "" {
		return s.TmpDir
	}

	if s.OS == OSUnix {
		dirs := []string{"/dev/shm", "/tmp", "/var/tmp"}
		testName := randomString(10)
		for _, dir := range dirs {
			resp, err := s.Exec(fmt.Sprintf("echo %s > %s/%s 2>&1; echo $?", testName, dir, testName), 3*time.Second)
			if err == nil && strings.TrimSpace(resp) == "0" {
				s.Exec(fmt.Sprintf("rm %s/%s", dir, testName), 2*time.Second)
				s.TmpDir = dir
				return dir
			}
		}
	} else if s.OS == OSWindows {
		resp, err := s.Exec("echo %TEMP%", 3*time.Second)
		if err == nil {
			s.TmpDir = strings.TrimSpace(resp)
			return s.TmpDir
		}
	}

	return ""
}

// SetupLogging creates session log directory and file
func (s *Session) SetupLogging(baseDir string) error {
	s.Directory = filepath.Join(baseDir, "sessions", s.Name)
	if err := os.MkdirAll(s.Directory, 0o750); err != nil {
		return err
	}

	s.LogPath = filepath.Join(s.Directory,
		time.Now().Format("2006_01_02-15_04_05")+".log")

	f, err := os.OpenFile(s.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	s.LogFile = f
	return nil
}

// Record logs data to the session log
func (s *Session) Record(data []byte, isInput bool) {
	s.LastLines.Write(data)
	if s.LogFile != nil {
		if isInput {
			s.LogFile.Write([]byte("ISSUED ==> "))
		}
		s.LogFile.Write(data)
	}
}

// Kill terminates the session
func (s *Session) Kill() {
	logger.Info("Killing session [%d]...", s.ID)

	// Close all streams
	s.StreamLock.Lock()
	for _, stream := range s.Streams {
		stream.Close()
	}
	s.Streams = make(map[uint16]*Stream)
	s.StreamLock.Unlock()

	// Close socket
	if s.Socket != nil {
		s.Socket.Close()
	}

	// Close log file
	if s.LogFile != nil {
		s.LogFile.Close()
	}
}

// BuildName constructs the session display name
func (s *Session) BuildName() {
	hostname := s.Hostname
	ip := s.IP
	system := s.System
	if system == "" {
		system = string(s.OS)
	}
	if s.Arch != "" {
		system += "-" + s.Arch
	}

	sep := ""
	if hostname != "" {
		sep = "~"
	}
	s.Name = fmt.Sprintf("%s%s%s-%s", sanitizeNamePart(hostname), sep, ip, sanitizeNamePart(system))
	s.NameColored = fmt.Sprintf("%s %s %s", hostname, ip, system)
}

// sanitizeNamePart strips anything outside a safe set from target-supplied
// strings used in local paths, so a hostile hostname cannot escape the
// session directory.
func sanitizeNamePart(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('_')
		}
	}
	out := sb.String()
	if out == "" || out == "." || out == ".." {
		return "unknown"
	}
	return out
}

// NewStreamID allocates a new stream ID
func (s *Session) NewStreamID() (*Stream, error) {
	s.StreamLock.Lock()
	defer s.StreamLock.Unlock()

	if len(s.Streams) >= 65535 {
		return nil, fmt.Errorf("too many open streams")
	}

	s.NextStreamID++
	for {
		if _, exists := s.Streams[s.NextStreamID]; !exists {
			break
		}
		s.NextStreamID++
	}

	stream, err := NewStream(s.NextStreamID, s)
	if err != nil {
		return nil, err
	}
	s.Streams[s.NextStreamID] = stream
	return stream, nil
}

// Messenger handles TLV-based protocol communication
type Messenger struct {
	LenBuffer []byte
	MsgBuffer []byte
	ExpLen    int
}

// Message types
const (
	MsgShell  byte = 1
	MsgResize byte = 2
	MsgExec   byte = 3
	MsgStream byte = 4
	MsgHello  byte = 5
)

// NewMessenger creates a new Messenger
func NewMessenger() *Messenger {
	return &Messenger{
		LenBuffer: make([]byte, 0, 2),
		MsgBuffer: make([]byte, 0),
	}
}

// PackMessage creates a TLV message
func PackMessage(msgType byte, data []byte) []byte {
	length := len(data) + 1
	msg := make([]byte, 3+len(data))
	binary.BigEndian.PutUint16(msg[0:2], uint16(length))
	msg[2] = msgType
	copy(msg[3:], data)
	return msg
}

// Feed processes incoming data and yields messages
func (m *Messenger) Feed(data []byte) []struct {
	Type byte
	Data []byte
} {
	var messages []struct {
		Type byte
		Data []byte
	}

	offset := 0
	for offset < len(data) {
		if m.ExpLen == 0 {
			// Reading length header
			need := 2 - len(m.LenBuffer)
			available := len(data) - offset
			if available < need {
				m.LenBuffer = append(m.LenBuffer, data[offset:]...)
				break
			}
			m.LenBuffer = append(m.LenBuffer, data[offset:offset+need]...)
			offset += need
			m.ExpLen = int(binary.BigEndian.Uint16(m.LenBuffer))
			m.LenBuffer = m.LenBuffer[:0]
		} else {
			// Reading message
			need := m.ExpLen - len(m.MsgBuffer)
			available := len(data) - offset
			if available < need {
				m.MsgBuffer = append(m.MsgBuffer, data[offset:]...)
				break
			}
			m.MsgBuffer = append(m.MsgBuffer, data[offset:offset+need]...)
			offset += need

			msgType := m.MsgBuffer[0]
			msgData := make([]byte, len(m.MsgBuffer)-1)
			copy(msgData, m.MsgBuffer[1:])

			messages = append(messages, struct {
				Type byte
				Data []byte
			}{msgType, msgData})

			m.ExpLen = 0
			m.MsgBuffer = m.MsgBuffer[:0]
		}
	}

	return messages
}

// randomString generates a random alphanumeric string using crypto/rand.
// Falls back to a time-seeded walk only if the OS RNG fails.
func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, n)
	if _, err := rand.Read(b); err == nil {
		for i := range b {
			b[i] = letters[int(b[i])%len(letters)]
		}
		return string(b)
	}
	t := time.Now().UnixNano()
	for i := range b {
		// #nosec G404 -- last-resort fallback when crypto/rand is unavailable.
		b[i] = letters[(t+int64(i)*31)%int64(len(letters))]
		t = t*1103515245 + 12345
	}
	return string(b)
}

// Upload sends a local file to the remote target
func (s *Session) Upload(localPath string, remotePath string) (string, error) {
	if s.OS == OSUnix {
		return s.uploadUnix(localPath, remotePath)
	} else if s.OS == OSWindows {
		return s.uploadWindows(localPath, remotePath)
	}
	return "", fmt.Errorf("unsupported OS for upload")
}

func (s *Session) uploadUnix(localPath string, remotePath string) (string, error) {
	// Check required binaries
	for _, bin := range []string{"base64", "rm"} {
		if s.Binaries[bin] == "" {
			return "", fmt.Errorf("'%s' binary not available on target", bin)
		}
	}

	data, sourceName, err := readSourceData(localPath)
	if err != nil {
		return "", err
	}
	sourceName = sanitizeRemoteName(sourceName)

	// Base64 encode and upload in chunks
	encoded := encodeBase64(data)
	dest := remotePath
	tmpDir := s.FindTmpDir()
	if tmpDir == "" {
		tmpDir = "/tmp"
	}
	if dest == "" {
		dest = tmpDir
	}

	tempFile := fmt.Sprintf("%s/%s", tmpDir, randomString(8))
	chunkSize := 51200
	totalChunks := (len(encoded) + chunkSize - 1) / chunkSize

	for i := 0; i < len(encoded); i += chunkSize {
		end := i + chunkSize
		if end > len(encoded) {
			end = len(encoded)
		}
		chunk := encoded[i:end]
		chunkNum := i/chunkSize + 1
		_, err := s.Exec(fmt.Sprintf("printf %s >> %s", ShellQuote(chunk), ShellQuote(tempFile)), 10*time.Second)
		if err != nil {
			return "", fmt.Errorf("upload chunk %d/%d failed: %w", chunkNum, totalChunks, err)
		}
		if totalChunks > 1 {
			logger.Debug("Upload progress: %d/%d chunks (%.0f%%)", chunkNum, totalChunks, float64(chunkNum)/float64(totalChunks)*100)
		}
	}

	// Decode and extract
	remoteFile := remoteJoin(s.OS, dest, sourceName)
	_, err = s.Exec(fmt.Sprintf("mkdir -p %s 2>/dev/null; base64 -d < %s > %s; rm %s",
		ShellQuote(dest), ShellQuote(tempFile), ShellQuote(remoteFile), ShellQuote(tempFile)), 10*time.Second)
	if err != nil {
		return "", fmt.Errorf("remote decode failed: %w", err)
	}

	s.UploadedPaths[remoteFile] = time.Now().Unix()
	logger.Info("Upload OK: %s", remoteFile)
	return remoteFile, nil
}

func (s *Session) uploadWindows(localPath string, remotePath string) (string, error) {
	data, sourceName, err := readSourceData(localPath)
	if err != nil {
		return "", err
	}
	sourceName = sanitizeRemoteName(sourceName)

	dest := remotePath
	if dest == "" {
		dest = s.FindTmpDir()
		if dest == "" {
			dest = `%TEMP%`
		}
	}
	if !validWindowsPath(dest) {
		return "", fmt.Errorf("remote path contains cmd metacharacters: %q", dest)
	}

	remoteFile := remoteJoin(s.OS, dest, sourceName)
	tempFile := remoteFile + ".b64"
	encoded := encodeBase64(data)

	_, _ = s.Exec(fmt.Sprintf(`cmd /Q /D /C if not exist "%s" mkdir "%s"`, dest, dest), 5*time.Second)
	_, _ = s.Exec(fmt.Sprintf(`cmd /Q /D /C del /f /q "%s" 2>NUL`, tempFile), 5*time.Second)

	chunkSize := 7000
	totalChunks := (len(encoded) + chunkSize - 1) / chunkSize
	for i := 0; i < len(encoded); i += chunkSize {
		end := i + chunkSize
		if end > len(encoded) {
			end = len(encoded)
		}
		chunk := encoded[i:end]
		chunkNum := i/chunkSize + 1
		if _, err := s.Exec(fmt.Sprintf(`cmd /Q /D /C echo %s>>"%s"`, chunk, tempFile), 10*time.Second); err != nil {
			return "", fmt.Errorf("upload chunk %d/%d failed: %w", chunkNum, totalChunks, err)
		}
		if totalChunks > 1 {
			logger.Debug("Upload progress: %d/%d chunks (%.0f%%)", chunkNum, totalChunks, float64(chunkNum)/float64(totalChunks)*100)
		}
	}

	decodeCmd := fmt.Sprintf(`cmd /Q /D /C certutil -f -decode "%s" "%s" >NUL 2>&1 && del /f /q "%s"`, tempFile, remoteFile, tempFile)
	if _, err := s.Exec(decodeCmd, 20*time.Second); err == nil {
		s.UploadedPaths[remoteFile] = time.Now().Unix()
		logger.Info("Upload OK: %s", remoteFile)
		return remoteFile, nil
	}

	psCmd := fmt.Sprintf(`powershell -NoProfile -ExecutionPolicy Bypass -Command "$b=Get-Content -Raw '%s';[IO.File]::WriteAllBytes('%s',[Convert]::FromBase64String($b));Remove-Item -Force '%s'"`,
		escapePowerShellSingleQuoted(tempFile), escapePowerShellSingleQuoted(remoteFile), escapePowerShellSingleQuoted(tempFile))
	if _, err := s.Exec(psCmd, 20*time.Second); err != nil {
		return "", fmt.Errorf("remote decode failed: %w", err)
	}

	s.UploadedPaths[remoteFile] = time.Now().Unix()
	logger.Info("Upload OK: %s", remoteFile)
	return remoteFile, nil
}

// Download retrieves a remote file from the target
func (s *Session) Download(remotePath string, localDir string) (string, error) {
	if localDir == "" {
		localDir = filepath.Join(s.Directory, "downloads")
	}
	os.MkdirAll(localDir, 0o750)

	if s.OS == OSUnix {
		return s.downloadUnix(remotePath, localDir)
	} else if s.OS == OSWindows {
		return s.downloadWindows(remotePath, localDir)
	}
	return "", fmt.Errorf("unsupported OS for download")
}

func (s *Session) downloadUnix(remotePath string, localDir string) (string, error) {
	// Get file via base64
	resp, err := s.Exec(fmt.Sprintf("base64 %s 2>/dev/null | tr -d '\\n'", ShellQuote(remotePath)), 30*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to read remote file: %w", err)
	}

	data, err := decodeBase64(resp)
	if err != nil {
		return "", fmt.Errorf("failed to decode file data: %w", err)
	}

	localPath := filepath.Join(localDir, filepath.Base(remotePath))
	if err := os.WriteFile(localPath, data, 0o640); err != nil {
		return "", fmt.Errorf("failed to write local file: %w", err)
	}

	logger.Info("Download OK: %s", localPath)
	return localPath, nil
}

func (s *Session) downloadWindows(remotePath string, localDir string) (string, error) {
	cmd := fmt.Sprintf(`powershell -NoProfile -ExecutionPolicy Bypass -Command "[Convert]::ToBase64String([IO.File]::ReadAllBytes('%s'))"`,
		escapePowerShellSingleQuoted(remotePath))
	resp, err := s.Exec(cmd, 30*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to read remote file: %w", err)
	}

	data, err := decodeBase64(resp)
	if err != nil {
		return "", fmt.Errorf("failed to decode file data: %w", err)
	}

	localPath := filepath.Join(localDir, filepath.Base(strings.ReplaceAll(remotePath, `\`, `/`)))
	if err := os.WriteFile(localPath, data, 0o640); err != nil {
		return "", fmt.Errorf("failed to write local file: %w", err)
	}

	logger.Info("Download OK: %s", localPath)
	return localPath, nil
}

// Cleanup removes all uploaded files from the target
func (s *Session) Cleanup() int {
	removed := 0
	for path := range s.UploadedPaths {
		var cmd string
		if s.OS == OSUnix {
			cmd = fmt.Sprintf(`[ -e %s ] && rm -rf -- %s && echo "OK" || echo "FAIL"`, ShellQuote(path), ShellQuote(path))
		} else {
			cmd = fmt.Sprintf(`cmd /Q /D /C if exist "%s" (del /f /q "%s" && echo OK) else (echo FAIL)`, path, path)
		}

		resp, err := s.Exec(cmd, 5*time.Second)
		if err == nil && strings.TrimSpace(resp) == "OK" {
			logger.Info("Deleted '%s'", path)
			delete(s.UploadedPaths, path)
			removed++
		} else {
			logger.Error("Failed to delete '%s'", path)
		}
	}
	return removed
}

// WriteAccess checks if the session has write access to a directory
func (s *Session) WriteAccess(directory string) bool {
	if s.OS == OSUnix {
		resp, err := s.Exec(fmt.Sprintf(`[ -w %s ]; echo $?`, ShellQuote(directory)), 3*time.Second)
		if err != nil || strings.TrimSpace(resp) != "0" {
			return false
		}
		return true
	}
	return true
}

// encodeBase64 encodes data to base64 string
func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// decodeBase64 decodes a base64 string
func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimSpace(s))
}

func readSourceData(source string) ([]byte, string, error) {
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		resp, err := http.Get(source)
		if err != nil {
			return nil, "", fmt.Errorf("failed to download %s: %w", source, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return nil, "", fmt.Errorf("failed to download %s: HTTP %s", source, resp.Status)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 200<<20))
		if err != nil {
			return nil, "", fmt.Errorf("failed to read %s: %w", source, err)
		}

		name := randomString(8)
		if parsed, err := url.Parse(source); err == nil {
			if base := path.Base(parsed.Path); base != "." && base != "/" && base != "" {
				name = base
			}
		}
		return data, name, nil
	}

	data, err := os.ReadFile(source)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read local file: %w", err)
	}
	return data, filepath.Base(source), nil
}

func remoteJoin(osType OSType, dir, name string) string {
	if osType == OSWindows {
		sep := `\`
		if strings.HasSuffix(dir, `\`) || strings.HasSuffix(dir, `/`) {
			sep = ""
		}
		return dir + sep + name
	}
	if strings.HasSuffix(dir, "/") {
		return dir + name
	}
	return dir + "/" + name
}

// ShellQuote single-quotes a string for POSIX shells, escaping embedded
// single quotes. Use it whenever interpolating untrusted text into a
// remote shell command line.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func escapePowerShellSingleQuoted(s string) string {
	return strings.ReplaceAll(s, `'`, `''`)
}

// validWindowsPath rejects cmd.exe metacharacters in operator-supplied
// remote paths. Double quotes cannot be escaped reliably for cmd.exe, so
// anything outside a conservative set is refused outright.
func validWindowsPath(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	return !strings.ContainsAny(s, "\"&|<>()^%!`$")
}

// sanitizeRemoteName replaces characters hostile to remote shells with '_'
// so URL basenames and local filenames are safe to interpolate (quoted).
func sanitizeRemoteName(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r < 32 || r == 127 || strings.ContainsRune("\"&|<>()^%!`$';", r) {
			sb.WriteRune('_')
		} else {
			sb.WriteRune(r)
		}
	}
	out := sb.String()
	if out == "" || out == "." || out == ".." {
		return "file"
	}
	return out
}

// Ensure Session implements io.ReadWriteCloser
var _ io.ReadWriteCloser = (*sessionRWC)(nil)

type sessionRWC struct {
	s *Session
}

func (r *sessionRWC) Read(p []byte) (n int, err error)  { return r.s.Recv(p) }
func (r *sessionRWC) Write(p []byte) (n int, err error) { return r.s.Send(p) }
func (r *sessionRWC) Close() error                      { r.s.Kill(); return nil }

// AsReadWriteCloser returns the session as an io.ReadWriteCloser
func (s *Session) AsReadWriteCloser() io.ReadWriteCloser {
	return &sessionRWC{s: s}
}
