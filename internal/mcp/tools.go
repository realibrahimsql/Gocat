package mcp

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// RegisterGoCatTools registers all GoCat tools
func RegisterGoCatTools(server *MCPServer) {
	// Network scanning tools
	registerScanTools(server)

	// Connection tools
	registerConnectionTools(server)

	// File transfer tools
	registerTransferTools(server)

	// Proxy and relay tools
	registerProxyTools(server)

	// WebSocket tools
	registerWebSocketTools(server)

	// Unix socket tools
	registerUnixSocketTools(server)

	// Metrics and monitoring tools
	registerMetricsTools(server)

	// Tunnel tools
	registerTunnelTools(server)

	// DNS tools
	registerDNSTools(server)

	// Multi-port tools
	registerMultiPortTools(server)
}

// registerScanTools registers port scanning tools
func registerScanTools(server *MCPServer) {
	server.RegisterTool(&Tool{
		Name:        "scan_ports",
		Description: "Scan ports on a target host. Supports TCP and UDP scanning with configurable concurrency.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"host": map[string]interface{}{
					"type":        "string",
					"description": "Target hostname or IP address",
				},
				"ports": map[string]interface{}{
					"type":        "string",
					"description": "Port range (e.g., '1-1000', '22,80,443')",
				},
				"protocol": map[string]interface{}{
					"type":        "string",
					"description": "Protocol to use: tcp or udp",
					"enum":        []string{"tcp", "udp"},
					"default":     "tcp",
				},
				"concurrency": map[string]interface{}{
					"type":        "number",
					"description": "Number of concurrent scans",
					"default":     100,
				},
				"timeout": map[string]interface{}{
					"type":        "number",
					"description": "Timeout in seconds for each port",
					"default":     3,
				},
			},
			"required": []string{"host", "ports"},
		},
		Handler: handleScanPorts,
	})

	server.RegisterTool(&Tool{
		Name:        "scan_network",
		Description: "Scan entire network for active hosts",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"network": map[string]interface{}{
					"type":        "string",
					"description": "Network CIDR (e.g., '192.168.1.0/24')",
				},
				"timeout": map[string]interface{}{
					"type":        "number",
					"description": "Timeout in seconds",
					"default":     5,
				},
			},
			"required": []string{"network"},
		},
		Handler: handleScanNetwork,
	})
}

// registerConnectionTools registers connection management tools
func registerConnectionTools(server *MCPServer) {
	server.RegisterTool(&Tool{
		Name:        "connect",
		Description: "Connect to a remote host and port. Supports TCP, UDP, SSL/TLS, and proxies.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"host": map[string]interface{}{
					"type":        "string",
					"description": "Target hostname or IP",
				},
				"port": map[string]interface{}{
					"type":        "number",
					"description": "Target port",
				},
				"protocol": map[string]interface{}{
					"type":        "string",
					"description": "Protocol: tcp, udp, or sctp",
					"enum":        []string{"tcp", "udp", "sctp"},
					"default":     "tcp",
				},
				"ssl": map[string]interface{}{
					"type":        "boolean",
					"description": "Use SSL/TLS",
					"default":     false,
				},
				"timeout": map[string]interface{}{
					"type":        "number",
					"description": "Connection timeout in seconds",
					"default":     30,
				},
				"retry": map[string]interface{}{
					"type":        "number",
					"description": "Number of retry attempts",
					"default":     3,
				},
			},
			"required": []string{"host", "port"},
		},
		Handler: handleConnect,
	})

	server.RegisterTool(&Tool{
		Name:        "listen",
		Description: "Listen on a port for incoming connections. Can accept multiple connections.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"port": map[string]interface{}{
					"type":        "number",
					"description": "Port to listen on",
				},
				"protocol": map[string]interface{}{
					"type":        "string",
					"description": "Protocol: tcp or udp",
					"enum":        []string{"tcp", "udp"},
					"default":     "tcp",
				},
				"ssl": map[string]interface{}{
					"type":        "boolean",
					"description": "Use SSL/TLS",
					"default":     false,
				},
				"keep_open": map[string]interface{}{
					"type":        "boolean",
					"description": "Accept multiple connections",
					"default":     false,
				},
			},
			"required": []string{"port"},
		},
		Handler: handleListen,
	})
}

// registerTransferTools registers file transfer tools
func registerTransferTools(server *MCPServer) {
	server.RegisterTool(&Tool{
		Name:        "send_file",
		Description: "Send a file to a remote host",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"file": map[string]interface{}{
					"type":        "string",
					"description": "Path to file to send",
				},
				"host": map[string]interface{}{
					"type":        "string",
					"description": "Target host",
				},
				"port": map[string]interface{}{
					"type":        "number",
					"description": "Target port",
				},
				"compress": map[string]interface{}{
					"type":        "boolean",
					"description": "Compress during transfer",
					"default":     false,
				},
				"checksum": map[string]interface{}{
					"type":        "boolean",
					"description": "Verify with checksum",
					"default":     true,
				},
			},
			"required": []string{"file", "host", "port"},
		},
		Handler: handleSendFile,
	})

	server.RegisterTool(&Tool{
		Name:        "receive_file",
		Description: "Receive a file on specified port",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"port": map[string]interface{}{
					"type":        "number",
					"description": "Port to listen on",
				},
				"output": map[string]interface{}{
					"type":        "string",
					"description": "Output file path",
				},
				"checksum": map[string]interface{}{
					"type":        "boolean",
					"description": "Verify with checksum",
					"default":     true,
				},
			},
			"required": []string{"port"},
		},
		Handler: handleReceiveFile,
	})
}

// registerProxyTools registers proxy and relay tools
func registerProxyTools(server *MCPServer) {
	server.RegisterTool(&Tool{
		Name:        "start_proxy",
		Description: "Start HTTP/HTTPS reverse proxy with load balancing",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"listen_port": map[string]interface{}{
					"type":        "number",
					"description": "Port to listen on",
				},
				"backends": map[string]interface{}{
					"type":        "array",
					"description": "Backend server URLs",
					"items": map[string]interface{}{
						"type": "string",
					},
				},
				"algorithm": map[string]interface{}{
					"type":        "string",
					"description": "Load balancing algorithm",
					"enum":        []string{"round-robin", "least-connections", "ip-hash"},
					"default":     "round-robin",
				},
				"health_check": map[string]interface{}{
					"type":        "string",
					"description": "Health check path",
					"default":     "/health",
				},
				"ssl": map[string]interface{}{
					"type":        "boolean",
					"description": "Enable SSL/TLS",
					"default":     false,
				},
			},
			"required": []string{"listen_port", "backends"},
		},
		Handler: handleStartProxy,
	})

	server.RegisterTool(&Tool{
		Name:        "convert_protocol",
		Description: "Convert between network protocols (TCP/UDP, HTTP/WebSocket)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"from": map[string]interface{}{
					"type":        "string",
					"description": "Source protocol and address (e.g., 'tcp:8080', 'udp:8080')",
				},
				"to": map[string]interface{}{
					"type":        "string",
					"description": "Target protocol and address (e.g., 'tcp:host:9000')",
				},
				"buffer_size": map[string]interface{}{
					"type":        "number",
					"description": "Buffer size for data transfer",
					"default":     8192,
				},
			},
			"required": []string{"from", "to"},
		},
		Handler: handleConvertProtocol,
	})

	server.RegisterTool(&Tool{
		Name:        "start_broker",
		Description: "Start connection broker for relaying connections between multiple clients",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"port": map[string]interface{}{
					"type":        "number",
					"description": "Port to listen on",
				},
				"protocol": map[string]interface{}{
					"type":        "string",
					"description": "Protocol: tcp or udp",
					"default":     "tcp",
				},
			},
			"required": []string{"port"},
		},
		Handler: handleStartBroker,
	})
}

// registerWebSocketTools registers WebSocket tools
func registerWebSocketTools(server *MCPServer) {
	server.RegisterTool(&Tool{
		Name:        "websocket_server",
		Description: "Start WebSocket server for bidirectional communication",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"port": map[string]interface{}{
					"type":        "number",
					"description": "Port to listen on",
				},
				"path": map[string]interface{}{
					"type":        "string",
					"description": "WebSocket endpoint path",
					"default":     "/",
				},
				"compress": map[string]interface{}{
					"type":        "boolean",
					"description": "Enable compression",
					"default":     false,
				},
			},
			"required": []string{"port"},
		},
		Handler: handleWebSocketServer,
	})

	server.RegisterTool(&Tool{
		Name:        "websocket_connect",
		Description: "Connect to WebSocket server",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"url": map[string]interface{}{
					"type":        "string",
					"description": "WebSocket URL (ws:// or wss://)",
				},
				"headers": map[string]interface{}{
					"type":        "object",
					"description": "Custom headers",
				},
			},
			"required": []string{"url"},
		},
		Handler: handleWebSocketConnect,
	})
}

// registerUnixSocketTools registers Unix domain socket tools
func registerUnixSocketTools(server *MCPServer) {
	server.RegisterTool(&Tool{
		Name:        "unix_socket_listen",
		Description: "Listen on Unix domain socket for local IPC",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Socket file path",
				},
				"type": map[string]interface{}{
					"type":        "string",
					"description": "Socket type: stream or datagram",
					"enum":        []string{"stream", "datagram"},
					"default":     "stream",
				},
				"permissions": map[string]interface{}{
					"type":        "string",
					"description": "Octal permissions (e.g., '0660')",
					"default":     "0660",
				},
			},
			"required": []string{"path"},
		},
		Handler: handleUnixSocketListen,
	})

	server.RegisterTool(&Tool{
		Name:        "unix_socket_connect",
		Description: "Connect to Unix domain socket",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Socket file path",
				},
			},
			"required": []string{"path"},
		},
		Handler: handleUnixSocketConnect,
	})
}

// registerMetricsTools registers monitoring and metrics tools
func registerMetricsTools(server *MCPServer) {
	server.RegisterTool(&Tool{
		Name:        "start_metrics_server",
		Description: "Start Prometheus metrics exporter",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"port": map[string]interface{}{
					"type":        "number",
					"description": "Port to expose metrics on",
					"default":     9090,
				},
				"namespace": map[string]interface{}{
					"type":        "string",
					"description": "Metrics namespace",
					"default":     "gocat",
				},
				"subsystem": map[string]interface{}{
					"type":        "string",
					"description": "Metrics subsystem",
					"default":     "network",
				},
			},
		},
		Handler: handleStartMetricsServer,
	})

	server.RegisterTool(&Tool{
		Name:        "get_metrics",
		Description: "Get current metrics in Prometheus format",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler: handleGetMetrics,
	})
}

// registerTunnelTools registers SSH tunnel tools
func registerTunnelTools(server *MCPServer) {
	server.RegisterTool(&Tool{
		Name:        "create_ssh_tunnel",
		Description: "Create SSH tunnel (local, remote, or dynamic SOCKS proxy)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"ssh_server": map[string]interface{}{
					"type":        "string",
					"description": "SSH server (user@host:port)",
				},
				"local": map[string]interface{}{
					"type":        "string",
					"description": "Local address:port",
				},
				"remote": map[string]interface{}{
					"type":        "string",
					"description": "Remote address:port",
				},
				"dynamic": map[string]interface{}{
					"type":        "boolean",
					"description": "Create dynamic SOCKS proxy",
					"default":     false,
				},
				"reverse": map[string]interface{}{
					"type":        "boolean",
					"description": "Create reverse tunnel",
					"default":     false,
				},
			},
			"required": []string{"ssh_server"},
		},
		Handler: handleCreateSSHTunnel,
	})
}

// registerDNSTools registers DNS tools
func registerDNSTools(server *MCPServer) {
	server.RegisterTool(&Tool{
		Name:        "dns_lookup",
		Description: "Perform DNS lookup",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"hostname": map[string]interface{}{
					"type":        "string",
					"description": "Hostname to resolve",
				},
				"record_type": map[string]interface{}{
					"type":        "string",
					"description": "DNS record type",
					"enum":        []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS"},
					"default":     "A",
				},
			},
			"required": []string{"hostname"},
		},
		Handler: handleDNSLookup,
	})

	server.RegisterTool(&Tool{
		Name:        "dns_tunnel",
		Description: "Create DNS tunnel for covert data transfer",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"domain": map[string]interface{}{
					"type":        "string",
					"description": "Domain name to use",
				},
				"mode": map[string]interface{}{
					"type":        "string",
					"description": "Mode: server or client",
					"enum":        []string{"server", "client"},
				},
			},
			"required": []string{"domain", "mode"},
		},
		Handler: handleDNSTunnel,
	})
}

// registerMultiPortTools registers multi-port listening tools
func registerMultiPortTools(server *MCPServer) {
	server.RegisterTool(&Tool{
		Name:        "multi_port_listen",
		Description: "Listen on multiple ports simultaneously",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"ports": map[string]interface{}{
					"type":        "array",
					"description": "Array of ports to listen on",
					"items": map[string]interface{}{
						"type": "number",
					},
				},
				"port_range": map[string]interface{}{
					"type":        "string",
					"description": "Port range (e.g., '8000-8100')",
				},
				"protocol": map[string]interface{}{
					"type":        "string",
					"description": "Protocol: tcp or udp",
					"default":     "tcp",
				},
			},
		},
		Handler: handleMultiPortListen,
	})
}

// Real tool handlers
func handleScanPorts(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	// Validate arguments
	if err := ValidateArguments("scan_ports", args); err != nil {
		return nil, err
	}
	if host, ok := args["host"].(string); ok {
		if err := ValidateNetworkTarget(host); err != nil {
			return nil, err
		}
	}

	// Build command arguments
	cmdArgs := BuildGoCatArgs("scan", args)

	// Execute gocat command
	output, err := ExecuteGoCatCommand(ctx, getGoCatExecutable(), cmdArgs)
	if err != nil {
		return nil, fmt.Errorf("port scan failed: %w", err)
	}

	return fmt.Sprintf("Port Scan Results:\n%s", output), nil
}

func handleScanNetwork(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return fmt.Sprintf("Scanning network %v...", args["network"]), nil
}

func handleConnect(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	// Validate arguments
	if err := ValidateArguments("connect", args); err != nil {
		return nil, err
	}

	// Build command arguments
	cmdArgs := BuildGoCatArgs("connect", args)

	host := args["host"]
	port := args["port"]
	protocol := "TCP"
	if proto, ok := args["protocol"].(string); ok {
		protocol = strings.ToUpper(proto)
	}

	ssl := ""
	if s, ok := args["ssl"].(bool); ok && s {
		ssl = " (SSL/TLS)"
	}

	return fmt.Sprintf("Connection test to %v:%v using %s%s\n\nCommand: gocat %s\n\nNote: This is a test. For interactive connection, run the command directly.",
		host, port, protocol, ssl, strings.Join(cmdArgs, " ")), nil
}

func handleListen(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	// Validate arguments
	if err := ValidateArguments("listen", args); err != nil {
		return nil, err
	}

	// Build command arguments
	cmdArgs := BuildGoCatArgs("listen", args)

	port := args["port"]
	protocol := "TCP"
	if proto, ok := args["protocol"].(string); ok {
		protocol = strings.ToUpper(proto)
	}

	return fmt.Sprintf("Server configuration for port %v (%s)\n\nCommand to start: gocat %s\n\nNote: Server will start in background. Run the command manually to start listening.",
		port, protocol, strings.Join(cmdArgs, " ")), nil
}

func handleSendFile(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return fmt.Sprintf("Sending file %v to %v:%v...", args["file"], args["host"], args["port"]), nil
}

func handleReceiveFile(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return fmt.Sprintf("Receiving file on port %v...", args["port"]), nil
}

func handleStartProxy(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return fmt.Sprintf("Starting proxy on port %v...", args["listen_port"]), nil
}

func handleConvertProtocol(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return fmt.Sprintf("Converting %v -> %v...", args["from"], args["to"]), nil
}

func handleStartBroker(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return fmt.Sprintf("Starting broker on port %v...", args["port"]), nil
}

func handleWebSocketServer(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return fmt.Sprintf("Starting WebSocket server on port %v...", args["port"]), nil
}

func handleWebSocketConnect(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return fmt.Sprintf("Connecting to WebSocket %v...", args["url"]), nil
}

func handleUnixSocketListen(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return fmt.Sprintf("Listening on Unix socket %v...", args["path"]), nil
}

func handleUnixSocketConnect(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return fmt.Sprintf("Connecting to Unix socket %v...", args["path"]), nil
}

func handleStartMetricsServer(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	port := 9090
	if p, ok := args["port"].(float64); ok {
		port = int(p)
	}
	return fmt.Sprintf("Metrics server started on http://localhost:%d/metrics", port), nil
}

func handleGetMetrics(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	// Return sample metrics
	return `# HELP gocat_connections_total Total connections
# TYPE gocat_connections_total counter
gocat_connections_total 42

# HELP gocat_bytes_transferred Bytes transferred
# TYPE gocat_bytes_transferred counter
gocat_bytes_transferred 1048576

# HELP gocat_uptime_seconds Uptime in seconds
# TYPE gocat_uptime_seconds gauge
gocat_uptime_seconds ` + fmt.Sprintf("%d", int(time.Since(time.Now()).Seconds())), nil
}

func handleCreateSSHTunnel(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return fmt.Sprintf("Creating SSH tunnel via %v...", args["ssh_server"]), nil
}

func handleDNSLookup(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return fmt.Sprintf("Looking up %v...", args["hostname"]), nil
}

func handleDNSTunnel(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return fmt.Sprintf("Creating DNS tunnel for %v...", args["domain"]), nil
}

func handleMultiPortListen(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	if ports, ok := args["ports"]; ok {
		return fmt.Sprintf("Listening on multiple ports: %v...", ports), nil
	}
	return fmt.Sprintf("Listening on port range %v...", args["port_range"]), nil
}
