package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/realibrahimsql/Gocat/internal/logger"
)

// Manager manages all sessions, listeners, and file servers
type Manager struct {
	Sessions    map[int]*Session
	Listeners   map[int]*Listener
	FileServers map[int]*FileServerInfo
	Hosts       map[string][]*Session

	AttachedSession *Session
	BaseDir         string

	nextSessionID    int
	nextListenerID   int
	nextFileServerID int

	Maintain      int
	SingleSession bool
	// MaxSessions caps active sessions per host.
	// Default 5; 0 rejects all new sessions, negative disables the cap.
	MaxSessions int
	NoLog       bool
	NoUpgrade   bool
	NoAttach    bool

	// RespawnFn is called when a host drops below the Maintain threshold.
	// The callback receives the last known session name (host key) and is
	// responsible for spawning a new reverse shell via one of the existing
	// sessions for that host (if any remain).
	RespawnFn func(hostName string, remaining []*Session)

	mu sync.RWMutex
}

// Listener represents an active TCP listener
type Listener struct {
	ID     int
	Host   string
	Port   int
	Active bool
	Jump   []string
}

// FileServerInfo represents an active file server
type FileServerInfo struct {
	ID   int
	Host string
	Port int
}

// Global manager instance
var DefaultManager *Manager

func init() {
	homeDir, _ := os.UserHomeDir()
	DefaultManager = NewManager(filepath.Join(homeDir, ".gocat"))
}

// NewManager creates a new session manager
func NewManager(baseDir string) *Manager {
	os.MkdirAll(baseDir, 0o750)
	return &Manager{
		Sessions:    make(map[int]*Session),
		Listeners:   make(map[int]*Listener),
		FileServers: make(map[int]*FileServerInfo),
		Hosts:       make(map[string][]*Session),
		BaseDir:     baseDir,
		Maintain:    1,
		MaxSessions: 5,
	}
}

// AddSession registers a new session and assigns an ID.
// Returns -1 when the per-host MaxSessions cap rejects the session.
func (m *Manager) AddSession(sess *Session) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Per-host cap: N caps, 0 rejects all new, negative disables.
	// Name is built before AddSession in the listen/console paths;
	// skip the cap when unknown.
	if sess.Name != "" && m.MaxSessions >= 0 {
		if len(m.Hosts[sess.Name]) >= m.MaxSessions {
			logger.Warn("Max sessions (%d) reached for %s, rejecting new session",
				m.MaxSessions, sess.Name)
			return -1
		}
	}

	m.nextSessionID++
	sess.ID = m.nextSessionID
	m.Sessions[sess.ID] = sess

	// Group by host
	m.Hosts[sess.Name] = append(m.Hosts[sess.Name], sess)

	// Setup logging
	if !m.NoLog {
		if err := sess.SetupLogging(m.BaseDir); err != nil {
			logger.Warn("Failed to setup session logging: %v", err)
		}
	}

	logger.Info("[New %s Shell] => %s | User: %s | Session ID <%d>",
		sess.Source, sess.NameColored, sess.User, sess.ID)

	return sess.ID
}

// RemoveSession removes a session from the manager
func (m *Manager) RemoveSession(id int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sess, ok := m.Sessions[id]
	if !ok {
		return
	}

	hostName := sess.Name

	// Remove from hosts
	if hosts, exists := m.Hosts[hostName]; exists {
		for i, s := range hosts {
			if s.ID == id {
				m.Hosts[hostName] = append(hosts[:i], hosts[i+1:]...)
				break
			}
		}
		if len(m.Hosts[hostName]) == 0 {
			delete(m.Hosts, hostName)
			logger.Error("Session [%d] died... We lost %s", id, sess.NameColored)
		}
	}

	// Detach if attached
	if m.AttachedSession != nil && m.AttachedSession.ID == id {
		m.AttachedSession = nil
	}

	sess.Kill()
	delete(m.Sessions, id)

	// Check maintain threshold and trigger respawn if needed
	remaining := m.Hosts[hostName]
	if m.Maintain > 0 && len(remaining) > 0 && len(remaining) < m.Maintain && m.RespawnFn != nil {
		copied := make([]*Session, len(remaining))
		copy(copied, remaining)
		go m.RespawnFn(hostName, copied)
	}
}

// GetSession returns a session by ID
func (m *Manager) GetSession(id int) *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.Sessions[id]
}

// ListSessions returns all active sessions
func (m *Manager) ListSessions() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sessions := make([]*Session, 0, len(m.Sessions))
	for _, sess := range m.Sessions {
		sessions = append(sessions, sess)
	}
	return sessions
}

// SessionCount returns the number of active sessions
func (m *Manager) SessionCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.Sessions)
}

// AttachSession attaches to a session (foreground)
func (m *Manager) AttachSession(id int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sess, ok := m.Sessions[id]
	if !ok {
		return fmt.Errorf("session %d not found", id)
	}

	if m.AttachedSession != nil {
		m.AttachedSession.IsAttached = false
	}

	sess.IsAttached = true
	m.AttachedSession = sess

	logger.Info("Interacting with session [%d] • %s • Type: %s",
		sess.ID, sess.NameColored, sess.Type)

	if !m.NoLog && sess.LogPath != "" {
		logger.Info("Session log: %s", sess.LogPath)
	}

	return nil
}

// DetachSession detaches from the current session
func (m *Manager) DetachSession() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.AttachedSession != nil {
		m.AttachedSession.IsAttached = false
		logger.Warn("Session detached")
		m.AttachedSession = nil
	}
}

// AddListener registers a new listener
func (m *Manager) AddListener(host string, port int) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nextListenerID++
	m.Listeners[m.nextListenerID] = &Listener{
		ID:     m.nextListenerID,
		Host:   host,
		Port:   port,
		Active: true,
	}
	return m.nextListenerID
}

// RemoveListener removes a listener
func (m *Manager) RemoveListener(id int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.Listeners, id)
}

// ListListeners returns all active listeners
func (m *Manager) ListListeners() []*Listener {
	m.mu.RLock()
	defer m.mu.RUnlock()

	listeners := make([]*Listener, 0, len(m.Listeners))
	for _, l := range m.Listeners {
		listeners = append(listeners, l)
	}
	return listeners
}

// AddFileServer registers a file server advertised by the console/session layer.
func (m *Manager) AddFileServer(host string, port int) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nextFileServerID++
	m.FileServers[m.nextFileServerID] = &FileServerInfo{
		ID:   m.nextFileServerID,
		Host: host,
		Port: port,
	}
	return m.nextFileServerID
}

// RemoveFileServer removes a registered file server.
func (m *Manager) RemoveFileServer(id int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.FileServers, id)
}

// ListFileServers returns all registered file servers.
func (m *Manager) ListFileServers() []*FileServerInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	servers := make([]*FileServerInfo, 0, len(m.FileServers))
	for _, server := range m.FileServers {
		servers = append(servers, server)
	}
	return servers
}

// SessionsForHost returns all sessions for a given host
func (m *Manager) SessionsForHost(name string) []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.Hosts[name]
}

// StopAll terminates all sessions and listeners
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	logger.Warn("Killing all sessions...")
	for id, sess := range m.Sessions {
		sess.Kill()
		delete(m.Sessions, id)
	}
	m.Hosts = make(map[string][]*Session)
	m.AttachedSession = nil
}

// SessionInfo returns a formatted summary of a session
func (m *Manager) SessionInfo(id int) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sess, ok := m.Sessions[id]
	if !ok {
		return fmt.Sprintf("Session %d not found", id)
	}

	attached := ""
	if sess.IsAttached {
		attached = " [ATTACHED]"
	}

	return fmt.Sprintf(
		"Session [%d]%s\n"+
			"  Name:     %s\n"+
			"  Target:   %s:%d\n"+
			"  OS:       %s\n"+
			"  Type:     %s / %s\n"+
			"  User:     %s\n"+
			"  Hostname: %s\n"+
			"  System:   %s %s\n"+
			"  Source:   %s\n"+
			"  Created:  %s\n"+
			"  Active:   %s\n"+
			"  Agent:    %v",
		sess.ID, attached,
		sess.Name,
		sess.IP, sess.Port,
		sess.OS,
		sess.Type, sess.SubType,
		sess.User,
		sess.Hostname,
		sess.System, sess.Arch,
		sess.Source,
		sess.CreatedAt.Format("2006-01-02 15:04:05"),
		sess.LastActive.Format("2006-01-02 15:04:05"),
		sess.AgentActive,
	)
}

// SessionsTable returns a formatted table of all sessions
func (m *Manager) SessionsTable() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.Sessions) == 0 {
		return "No active sessions"
	}

	header := fmt.Sprintf("%-4s %-20s %-15s %-6s %-8s %-6s %-15s %-8s %s",
		"ID", "Name", "IP", "Port", "OS", "Type", "User", "Source", "Active")
	separator := "─────────────────────────────────────────────────────────────────────────────────────────────────────────"

	result := header + "\n" + separator + "\n"

	for _, sess := range m.Sessions {
		attached := ""
		if sess.IsAttached {
			attached = " *"
		}

		result += fmt.Sprintf("%-4d %-20s %-15s %-6d %-8s %-6s %-15s %-8s %s%s\n",
			sess.ID,
			truncate(sess.Name, 20),
			sess.IP,
			sess.Port,
			sess.OS,
			sess.Type,
			truncate(sess.User, 15),
			sess.Source,
			timeSince(sess.LastActive),
			attached,
		)
	}

	return result
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// sessionExport is the JSON/CSV projection of a Session.
type sessionExport struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	IP         string `json:"ip"`
	Port       int    `json:"port"`
	OS         string `json:"os"`
	Type       string `json:"type"`
	User       string `json:"user"`
	Hostname   string `json:"hostname"`
	Source     string `json:"source"`
	Attached   bool   `json:"attached"`
	Agent      bool   `json:"agent"`
	LastActive string `json:"last_active"`
}

func (m *Manager) exportSessions() []sessionExport {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]sessionExport, 0, len(m.Sessions))
	for _, sess := range m.Sessions {
		out = append(out, sessionExport{
			ID:         sess.ID,
			Name:       sess.Name,
			IP:         sess.IP,
			Port:       sess.Port,
			OS:         string(sess.OS),
			Type:       string(sess.Type),
			User:       sess.User,
			Hostname:   sess.Hostname,
			Source:     string(sess.Source),
			Attached:   sess.IsAttached,
			Agent:      sess.AgentActive,
			LastActive: sess.LastActive.Format(time.RFC3339),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// SessionsJSON returns all sessions as indented JSON.
func (m *Manager) SessionsJSON() string {
	data, err := json.MarshalIndent(m.exportSessions(), "", "  ")
	if err != nil {
		return "[]"
	}
	return string(data)
}

// SessionsCSV returns all sessions as CSV with a header row.
func (m *Manager) SessionsCSV() string {
	var sb strings.Builder
	sb.WriteString("id,name,ip,port,os,type,user,hostname,source,attached,agent,last_active\n")
	for _, s := range m.exportSessions() {
		fmt.Fprintf(&sb, "%d,%s,%s,%d,%s,%s,%s,%s,%s,%v,%v,%s\n",
			s.ID, s.Name, s.IP, s.Port, s.OS, s.Type, s.User,
			s.Hostname, s.Source, s.Attached, s.Agent, s.LastActive)
	}
	return strings.TrimRight(sb.String(), "\n")
}

func timeSince(t time.Time) string {
	d := time.Since(t)
	if d < time.Minute {
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh ago", int(d.Hours()))
}
