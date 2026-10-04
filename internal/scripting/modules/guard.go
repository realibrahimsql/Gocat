package modules

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	lua "github.com/yuin/gopher-lua"
)

// ScriptGuard carries per-engine sandbox policy into module functions.
// Engines created via scripting.NewEngine always install one; direct
// Register* users get a zero (unrestricted) guard for backward compatibility.
type ScriptGuard struct {
	Restricted   bool
	SandboxRoot  string
	AllowedHosts []string
	DeniedHosts  []string
}

var (
	guardMu sync.RWMutex
	guards  = map[*lua.LState]*ScriptGuard{}
)

// SetGuard installs the sandbox policy for one Lua state.
func SetGuard(L *lua.LState, g *ScriptGuard) {
	if L == nil || g == nil {
		return
	}
	if g.SandboxRoot == "" {
		if cwd, err := os.Getwd(); err == nil {
			g.SandboxRoot = cwd
		}
	}
	guardMu.Lock()
	guards[L] = g
	guardMu.Unlock()
}

// ClearGuard drops the policy (called on engine Close).
func ClearGuard(L *lua.LState) {
	guardMu.Lock()
	delete(guards, L)
	guardMu.Unlock()
}

// GetGuard returns the installed policy or nil when absent.
func GetGuard(L *lua.LState) *ScriptGuard {
	guardMu.RLock()
	defer guardMu.RUnlock()
	return guards[L]
}

func sysRestricted(L *lua.LState) bool {
	g := GetGuard(L)
	return g != nil && g.Restricted
}

// resolveSandboxPath confines p inside the sandbox root in restricted mode.
// Absolute paths must already be inside; relative paths resolve against the
// root. Existing symlinks are evaluated and re-checked.
func resolveSandboxPath(g *ScriptGuard, p string) (string, error) {
	if g == nil || !g.Restricted {
		return p, nil
	}
	root := g.SandboxRoot
	if root == "" {
		return "", fmt.Errorf("sandbox root not configured")
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(absRoot, p)
	}
	clean := filepath.Clean(p)
	rel, err := filepath.Rel(absRoot, clean)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes sandbox: %q", p)
	}
	if _, statErr := os.Lstat(clean); statErr == nil {
		if real, evalErr := filepath.EvalSymlinks(clean); evalErr == nil {
			rel, err = filepath.Rel(absRoot, real)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return "", fmt.Errorf("path escapes sandbox via symlink: %q", p)
			}
			return real, nil
		}
	}
	return clean, nil
}

// maxScriptBody caps a single scripted HTTP response at 8MB.
const maxScriptBody = 8 << 20

// guardedPath resolves a Lua string argument through the sandbox.
func guardedPath(L *lua.LState, n int) (string, bool) {
	p, err := resolveSandboxPath(GetGuard(L), L.ToString(n))
	if err != nil {
		return "", false
	}
	return p, true
}

// validateScriptURL enforces scheme and host policy before any request.
func validateScriptURL(g *ScriptGuard, rawurl string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(rawurl))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("only http/https URLs allowed: %q", rawurl)
	}
	if u.User != nil {
		return nil, fmt.Errorf("credentials in URL not allowed")
	}
	if g == nil || !g.Restricted {
		return u, nil
	}
	host := u.Hostname()
	for _, denied := range g.DeniedHosts {
		if strings.EqualFold(strings.TrimSpace(denied), host) {
			return nil, fmt.Errorf("host denied by policy: %q", host)
		}
	}
	for _, allowed := range g.AllowedHosts {
		if strings.EqualFold(strings.TrimSpace(allowed), host) {
			return u, nil
		}
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("cannot resolve host: %q", host)
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() || ip.Equal(net.ParseIP("169.254.169.254")) {
			return nil, fmt.Errorf("host %q resolves to restricted address %s", host, ip)
		}
	}
	return u, nil
}
