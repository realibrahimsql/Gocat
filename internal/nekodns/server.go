package nekodns

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/fatih/color"
)

// Server represents the NekoDNS server
type Server struct {
	IP       string
	Port     int
	Protocol string
	Silent   bool
	Handler  *Handler
}

// NewServer creates a new NekoDNS server
func NewServer(ip string, port int, protocol string, silent bool) *Server {
	return &Server{
		IP:       ip,
		Port:     port,
		Protocol: protocol,
		Silent:   silent,
		Handler:  NewHandler(),
	}
}

// Start starts the DNS server
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.IP, s.Port)

	if !s.Silent {
		PrintBanner()
		color.Yellow("[>] Waiting for connection on %s over %s..\n", addr, s.Protocol)
	}

	if s.Protocol == "udp" {
		return s.startUDPServer(addr)
	}
	return s.startTCPServer(addr)
}

// startUDPServer starts a UDP DNS server
func (s *Server) startUDPServer(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to start UDP server: %v", err)
	}
	defer conn.Close()

	// Start prompt in background
	prompt := NewPrompt(s.Handler, s.Silent)
	go prompt.Loop()

	buffer := make([]byte, 4096)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			color.Red("[!] UDP read error: %v", err)
			continue
		}

		go s.handleDNSQuery(buffer[:n], func(response []byte) {
			conn.WriteToUDP(response, clientAddr)
		})
	}
}

// startTCPServer starts a TCP DNS server
func (s *Server) startTCPServer(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to start TCP server: %v", err)
	}
	defer listener.Close()

	// Start prompt in background
	prompt := NewPrompt(s.Handler, s.Silent)
	go prompt.Loop()

	for {
		conn, err := listener.Accept()
		if err != nil {
			color.Red("[!] TCP accept error: %v", err)
			continue
		}

		go s.handleTCPConnection(conn)
	}
}

// handleTCPConnection handles a TCP DNS connection
func (s *Server) handleTCPConnection(conn net.Conn) {
	defer conn.Close()

	// Read DNS message length (2 bytes)
	lengthBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, lengthBytes); err != nil {
		return
	}

	msgLength := binary.BigEndian.Uint16(lengthBytes)
	if msgLength < 12 {
		return
	}

	// Read DNS message
	buffer := make([]byte, msgLength)
	if _, err := io.ReadFull(conn, buffer); err != nil {
		return
	}

	s.handleDNSQuery(buffer, func(response []byte) {
		// Prepend length for TCP
		fullResponse := make([]byte, 2+len(response))
		binary.BigEndian.PutUint16(fullResponse[:2], uint16(len(response)))
		copy(fullResponse[2:], response)
		conn.Write(fullResponse)
	})
}

// handleDNSQuery processes a DNS query
func (s *Server) handleDNSQuery(query []byte, sendResponse func([]byte)) {
	defer func() {
		_ = recover()
	}()
	if len(query) < 12 {
		return
	}
	domain := ExtractQuery(query)
	response := s.Handler.BuildResponse(query, domain)
	sendResponse(response)
}

// PrintBanner prints the NekoDNS banner
func PrintBanner() {
	banner := `
  _   _      _         ____  _   _ ____  
 | \ | | __ | | __ __ |  _ \| \ | / ___| 
 |  \| |/ _ \ |/ / _ \| | | |  \| \___ \ 
 | |\  |  __/   < (_) | |_| | |\  |___) |
 |_| \_|\___|_|\_\___/|____/|_| \_|____/ 
`
	color.Blue(banner)
	color.Green("\n  ----------- by @JoelGMSec -----------")
	color.Green("  ----- Go Implementation by @ibrahmsql -----\n")
}
