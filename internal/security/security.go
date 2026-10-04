package security

import (
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/realibrahimsql/Gocat/internal/errors"
)

var (
	hostnameLabelRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)
	spaceRunRegex      = regexp.MustCompile(` +`)
)

// SecurityValidator validates user input
type SecurityValidator interface {
	ValidateHostname(hostname string) error
	ValidatePort(port string) (int, error)
	ValidateCommand(command string) (string, error)
	ValidateFilePath(path string) error
	SanitizeInput(input string) string
}

// InputValidator provides input validation functions
type InputValidator struct {
	MaxHostnameLength int
	MaxPortNumber     int
	AllowedProtocols  []string
	MaxCommandLength  int
	MaxPathLength     int
	AllowedCommands   []string
}

// NewInputValidator creates a new input validator with default settings
func NewInputValidator() *InputValidator {
	return &InputValidator{
		MaxHostnameLength: 253, // RFC 1035
		MaxPortNumber:     65535,
		AllowedProtocols:  []string{"tcp", "udp", "tcp4", "tcp6", "udp4", "udp6", "unix", "unixgram"},
		MaxCommandLength:  1000,
		MaxPathLength:     4096, // Most filesystems limit
		AllowedCommands:   []string{"echo", "cat", "ls", "pwd", "whoami", "date", "uname"},
	}
}

// ValidateHostname validates a hostname or IP address with  security checks
func (v *InputValidator) ValidateHostname(hostname string) error {
	if len(hostname) == 0 {
		return errors.ValidationError("VAL001", "Hostname cannot be empty").
			WithUserFriendly("Please provide a valid hostname or IP address").
			WithSuggestion("Use a valid hostname (e.g., example.com) or IP address (e.g., 192.168.1.1)")
	}

	if len(hostname) > v.MaxHostnameLength {
		return errors.ValidationError("VAL002", fmt.Sprintf("Hostname too long: %d characters (max %d)", len(hostname), v.MaxHostnameLength)).
			WithContext("hostname_length", len(hostname)).
			WithContext("max_length", v.MaxHostnameLength).
			WithUserFriendly("The hostname is too long").
			WithSuggestion("Use a shorter hostname or IP address")
	}

	// Check for suspicious patterns that might indicate injection attempts
	suspiciousPatterns := []string{
		"../", "./", "\\", "|", "&", ";", "$", "`", "(", ")", "{", "}", "[", "]",
		"<", ">", "?", "*", "~", "!", "@", "#", "%", "^", "+", "=",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(hostname, pattern) {
			return errors.SecurityError("SEC006", fmt.Sprintf("Hostname contains suspicious pattern: %s", pattern)).
				WithContext("hostname", hostname).
				WithContext("suspicious_pattern", pattern).
				WithUserFriendly("The hostname contains invalid characters").
				WithSuggestion("Use only alphanumeric characters, dots, and hyphens in hostnames")
		}
	}

	// Check if it's a valid IP address (IPv4 or IPv6)
	if ip := net.ParseIP(hostname); ip != nil {
		// Additional validation for IP addresses
		if ip.IsLoopback() {
			// Allow localhost but log it
		} else if ip.IsPrivate() {
			// Allow private IPs but validate they're not suspicious
		} else if ip.IsMulticast() || ip.IsUnspecified() {
			return errors.ValidationError("VAL003", "Invalid IP address type").
				WithContext("ip", hostname).
				WithUserFriendly("The IP address type is not supported").
				WithSuggestion("Use a valid unicast IP address")
		}
		return nil
	}

	//  hostname validation with stricter regex
	// RFC 1123 compliant hostname validation
	if len(hostname) > 0 && (hostname[0] == '-' || hostname[len(hostname)-1] == '-') {
		return errors.ValidationError("VAL004", "Hostname cannot start or end with hyphen").
			WithContext("hostname", hostname).
			WithUserFriendly("Invalid hostname format").
			WithSuggestion("Hostnames cannot start or end with a hyphen")
	}

	// Check for consecutive dots. Consecutive hyphens are legal per
	// RFC 1123 (notably the "xn--" IDN/punycode prefix), so only reject
	// "--" in labels that are not IDN punycode.
	if strings.Contains(hostname, "..") {
		return errors.ValidationError("VAL005", "Hostname contains consecutive dots").
			WithContext("hostname", hostname).
			WithUserFriendly("Invalid hostname format").
			WithSuggestion("Hostnames cannot contain consecutive dots")
	}
	for _, label := range strings.Split(hostname, ".") {
		if strings.Contains(label, "--") && !strings.HasPrefix(strings.ToLower(label), "xn--") {
			return errors.ValidationError("VAL005", "Hostname contains consecutive hyphens").
				WithContext("hostname", hostname).
				WithUserFriendly("Invalid hostname format").
				WithSuggestion("Hostnames cannot contain consecutive hyphens (except xn-- IDN prefix)")
		}
	}

	// Validate each label in the hostname
	labels := strings.Split(hostname, ".")
	for i, label := range labels {
		if len(label) == 0 {
			return errors.ValidationError("VAL006", "Hostname contains empty label").
				WithContext("hostname", hostname).
				WithContext("label_index", i).
				WithUserFriendly("Invalid hostname format").
				WithSuggestion("Each part of the hostname must contain at least one character")
		}

		if len(label) > 63 {
			return errors.ValidationError("VAL007", fmt.Sprintf("Hostname label too long: %d characters (max 63)", len(label))).
				WithContext("hostname", hostname).
				WithContext("label", label).
				WithContext("label_length", len(label)).
				WithUserFriendly("Hostname part is too long").
				WithSuggestion("Each part of the hostname must be 63 characters or less")
		}

		// Validate label format (alphanumeric and hyphens only, cannot start/end with hyphen)
		if !hostnameLabelRegex.MatchString(label) {
			return errors.ValidationError("VAL008", fmt.Sprintf("Invalid hostname label format: %s", label)).
				WithContext("hostname", hostname).
				WithContext("invalid_label", label).
				WithUserFriendly("Invalid hostname format").
				WithSuggestion("Hostname parts can only contain letters, numbers, and hyphens")
		}
	}

	return nil
}

// ValidatePort validates a port number with  security checks
func (v *InputValidator) ValidatePort(portStr string) (int, error) {
	if len(portStr) == 0 {
		return 0, errors.ValidationError("VAL009", "Port cannot be empty").
			WithUserFriendly("Please provide a valid port number").
			WithSuggestion("Use a port number between 1 and 65535")
	}

	// Check for suspicious characters that might indicate injection
	if strings.ContainsAny(portStr, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*(){}[]|\\:;\"'<>?/~`") {
		return 0, errors.SecurityError("SEC007", "Port contains non-numeric characters").
			WithContext("port_string", portStr).
			WithUserFriendly("Port number must contain only digits").
			WithSuggestion("Use only numeric characters for port numbers")
	}

	// Check for leading zeros (potential octal interpretation)
	if len(portStr) > 1 && portStr[0] == '0' {
		return 0, errors.ValidationError("VAL010", "Port number cannot have leading zeros").
			WithContext("port_string", portStr).
			WithUserFriendly("Invalid port format").
			WithSuggestion("Remove leading zeros from the port number")
	}

	// Check length to prevent extremely long numbers
	if len(portStr) > 5 {
		return 0, errors.ValidationError("VAL011", "Port number too long").
			WithContext("port_string", portStr).
			WithContext("length", len(portStr)).
			WithUserFriendly("Port number is too long").
			WithSuggestion("Port numbers must be between 1 and 65535")
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		// Check if it's a negative number (which would be caught by non-numeric check above)
		if strings.HasPrefix(portStr, "-") {
			return 0, errors.SecurityError("SEC007", "Port contains non-numeric characters").
				WithContext("port_string", portStr).
				WithUserFriendly("Port number must contain only digits").
				WithSuggestion("Use only numeric characters for port numbers")
		}
		return 0, errors.ValidationError("VAL012", "Invalid port number format").
			WithCause(err).
			WithContext("port_string", portStr).
			WithUserFriendly("Invalid port number").
			WithSuggestion("Use a valid numeric port number")
	}

	if port < 1 || port > v.MaxPortNumber {
		return 0, errors.ValidationError("VAL013", fmt.Sprintf("Port number out of range: %d (must be 1-%d)", port, v.MaxPortNumber)).
			WithContext("port", port).
			WithContext("min_port", 1).
			WithContext("max_port", v.MaxPortNumber).
			WithUserFriendly("Port number is out of valid range").
			WithSuggestion(fmt.Sprintf("Use a port number between 1 and %d", v.MaxPortNumber))
	}

	return port, nil
}

// ValidatePortRange validates a port range (e.g., "80-443" or "80")
func (v *InputValidator) ValidatePortRange(portRange string) ([]int, error) {
	if len(portRange) == 0 {
		return nil, fmt.Errorf("port range cannot be empty")
	}

	// Handle single port
	if !strings.Contains(portRange, "-") {
		port, err := v.ValidatePort(portRange)
		if err != nil {
			return nil, err
		}
		return []int{port}, nil
	}

	// Handle port range
	parts := strings.Split(portRange, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid port range format: %s (expected start-end)", portRange)
	}

	startPort, err := v.ValidatePort(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil, fmt.Errorf("invalid start port: %w", err)
	}

	endPort, err := v.ValidatePort(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("invalid end port: %w", err)
	}

	if startPort > endPort {
		return nil, fmt.Errorf("start port (%d) cannot be greater than end port (%d)", startPort, endPort)
	}

	if endPort-startPort > 10000 {
		return nil, fmt.Errorf("port range too large: %d ports (max 10000)", endPort-startPort+1)
	}

	var ports []int
	for port := startPort; port <= endPort; port++ {
		ports = append(ports, port)
	}

	return ports, nil
}

// ValidateProtocol validates a network protocol
func (v *InputValidator) ValidateProtocol(protocol string) error {
	protocol = strings.ToLower(protocol)
	for _, allowed := range v.AllowedProtocols {
		if protocol == allowed {
			return nil
		}
	}
	return fmt.Errorf("unsupported protocol: %s (allowed: %v)", protocol, v.AllowedProtocols)
}

// ValidateCommand validates a command with injection prevention and sanitization
func (v *InputValidator) ValidateCommand(command string) (string, error) {
	if len(command) == 0 {
		return "", errors.ValidationError("VAL014", "Command cannot be empty").
			WithUserFriendly("Please provide a valid command").
			WithSuggestion("Enter a command to execute")
	}

	if len(command) > v.MaxCommandLength {
		return "", errors.ValidationError("VAL015", fmt.Sprintf("Command too long: %d characters (max %d)", len(command), v.MaxCommandLength)).
			WithContext("command_length", len(command)).
			WithContext("max_length", v.MaxCommandLength).
			WithUserFriendly("Command is too long").
			WithSuggestion(fmt.Sprintf("Keep commands under %d characters", v.MaxCommandLength))
	}

	// Trim whitespace
	command = strings.TrimSpace(command)

	// Check for shell metacharacters that could enable injection
	shellMetaChars := []string{
		";", "&", "|", "||", "&&", "`", "$(", "${", "<(", ">(",
		">>", ">", "<", "<<", "*", "?", "[", "]", "{", "}", "~",
		"$", "\\", "\"", "'", "\n", "\r", "\t",
	}

	for _, meta := range shellMetaChars {
		if strings.Contains(command, meta) {
			return "", errors.SecurityError("SEC008", fmt.Sprintf("Command contains shell metacharacter: %s", meta)).
				WithContext("command", command).
				WithContext("metacharacter", meta).
				WithUserFriendly("Command contains unsafe characters").
				WithSuggestion("Remove shell metacharacters from the command")
		}
	}

	// Extract the base command (first word)
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return "", errors.ValidationError("VAL016", "Command is empty after parsing").
			WithContext("original_command", command).
			WithUserFriendly("Invalid command format").
			WithSuggestion("Provide a valid command")
	}

	baseCommand := parts[0]

	// Check if the base command is in the allowed list first
	allowed := false
	for _, allowedCmd := range v.AllowedCommands {
		if baseCommand == allowedCmd {
			allowed = true
			break
		}
	}

	if !allowed {
		return "", errors.SecurityError("SEC010", fmt.Sprintf("Command not in whitelist: %s", baseCommand)).
			WithContext("command", baseCommand).
			WithContext("allowed_commands", v.AllowedCommands).
			WithUserFriendly("Command is not allowed").
			WithSuggestion(fmt.Sprintf("Use one of the allowed commands: %s", strings.Join(v.AllowedCommands, ", ")))
	}

	// Check for dangerous command patterns
	dangerousPatterns := []string{
		"rm ", "del ", "format ", "mkfs", "dd if=", "fdisk",
		"sudo ", "su ", "chmod ", "chown ", "passwd ", "useradd", "userdel",
		"../", "./", "/etc/", "/bin/", "/usr/", "/var/", "/tmp/",
		"wget ", "curl ", "nc ", "netcat ", "telnet ", "ssh ", "ftp ",
		"python ", "perl ", "ruby ", "node ", "php ", "bash ", "sh ",
		"exec ", "eval ", "system ", "popen ", "fork ", "kill ",
	}

	commandLower := strings.ToLower(command)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(commandLower, pattern) {
			return "", errors.SecurityError("SEC009", fmt.Sprintf("Command contains dangerous pattern: %s", pattern)).
				WithContext("command", command).
				WithContext("dangerous_pattern", pattern).
				WithUserFriendly("Command contains potentially dangerous operations").
				WithSuggestion("Use only safe, whitelisted commands")
		}
	}

	// Additional validation for command arguments
	for i, arg := range parts[1:] {
		if len(arg) > 100 {
			return "", errors.ValidationError("VAL017", fmt.Sprintf("Command argument %d too long: %d characters", i+1, len(arg))).
				WithContext("argument_index", i+1).
				WithContext("argument_length", len(arg)).
				WithUserFriendly("Command argument is too long").
				WithSuggestion("Keep command arguments under 100 characters")
		}

		// Check for path traversal in arguments
		if strings.Contains(arg, "..") {
			return "", errors.SecurityError("SEC011", "Command argument contains path traversal").
				WithContext("argument", arg).
				WithContext("argument_index", i+1).
				WithUserFriendly("Command argument contains invalid path").
				WithSuggestion("Remove '..' from command arguments")
		}
	}

	return command, nil
}

// ValidateFilePath validates a file path with path traversal protection
func (v *InputValidator) ValidateFilePath(path string) error {
	if len(path) == 0 {
		return errors.ValidationError("VAL018", "File path cannot be empty").
			WithUserFriendly("Please provide a valid file path").
			WithSuggestion("Enter a valid file or directory path")
	}

	if len(path) > v.MaxPathLength {
		return errors.ValidationError("VAL019", fmt.Sprintf("File path too long: %d characters (max %d)", len(path), v.MaxPathLength)).
			WithContext("path_length", len(path)).
			WithContext("max_length", v.MaxPathLength).
			WithUserFriendly("File path is too long").
			WithSuggestion(fmt.Sprintf("Keep file paths under %d characters", v.MaxPathLength))
	}

	// Check for path traversal attempts
	if strings.Contains(path, "..") {
		return errors.SecurityError("SEC012", "File path contains path traversal").
			WithContext("path", path).
			WithUserFriendly("File path contains invalid directory traversal").
			WithSuggestion("Remove '..' from the file path")
	}

	// Check for null bytes (can be used to bypass filters)
	if strings.Contains(path, "\x00") {
		return errors.SecurityError("SEC013", "File path contains null bytes").
			WithContext("path", path).
			WithUserFriendly("File path contains invalid characters").
			WithSuggestion("Remove null bytes from the file path")
	}

	// Check for dangerous system paths
	dangerousPaths := []string{
		"/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/sudoers",
		"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/",
		"/proc/", "/sys/", "/dev/",
		"C:\\Windows\\", "C:\\Program Files\\", "C:\\Users\\",
		"/var/log/", "/var/run/", "/var/lib/",
	}

	pathLower := strings.ToLower(path)
	for _, dangerousPath := range dangerousPaths {
		if strings.HasPrefix(pathLower, strings.ToLower(dangerousPath)) {
			return errors.SecurityError("SEC014", fmt.Sprintf("File path accesses restricted directory: %s", dangerousPath)).
				WithContext("path", path).
				WithContext("restricted_path", dangerousPath).
				WithUserFriendly("File path accesses a restricted system directory").
				WithSuggestion("Use paths within allowed directories only")
		}
	}

	// Validate path format using filepath.Clean to normalize
	cleanPath := filepath.Clean(path)
	if cleanPath != path && !strings.HasSuffix(path, "/") {
		// Path was modified by Clean, might indicate suspicious input
		return errors.ValidationError("VAL020", "File path contains suspicious elements").
			WithContext("original_path", path).
			WithContext("cleaned_path", cleanPath).
			WithUserFriendly("File path format is invalid").
			WithSuggestion("Use a properly formatted file path")
	}

	// Check for invalid characters in path
	invalidChars := []string{"|", "&", ";", "$", "`", "<", ">", "?", "*"}
	for _, char := range invalidChars {
		if strings.Contains(path, char) {
			return errors.SecurityError("SEC015", fmt.Sprintf("File path contains invalid character: %s", char)).
				WithContext("path", path).
				WithContext("invalid_character", char).
				WithUserFriendly("File path contains invalid characters").
				WithSuggestion("Remove special characters from the file path")
		}
	}

	return nil
}

// SanitizeInput provides general input cleaning and sanitization
func (v *InputValidator) SanitizeInput(input string) string {
	if len(input) == 0 {
		return input
	}

	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")

	// Remove control characters except common whitespace
	var sanitized strings.Builder
	for _, r := range input {
		// Allow printable characters and common whitespace
		if r >= 32 && r <= 126 || r == '\t' || r == '\n' || r == '\r' {
			sanitized.WriteRune(r)
		}
	}

	result := sanitized.String()

	// Trim excessive whitespace
	result = strings.TrimSpace(result)

	// Replace multiple consecutive spaces (but not tabs/newlines) with single space
	result = spaceRunRegex.ReplaceAllString(result, " ")

	// Limit length to prevent DoS
	maxSanitizedLength := 1000
	if len(result) > maxSanitizedLength {
		result = result[:maxSanitizedLength]
	}

	return result
}

// RateLimiterInterface defines the contract for rate limiting
type RateLimiterInterface interface {
	Allow(identifier string) bool
	Reset(identifier string)
	GetStats(identifier string) RateLimitStats
}

// RateLimitStats provides statistics about rate limiting
type RateLimitStats struct {
	Identifier     string        `json:"identifier"`
	RequestCount   int           `json:"request_count"`
	WindowStart    time.Time     `json:"window_start"`
	WindowDuration time.Duration `json:"window_duration"`
	MaxRequests    int           `json:"max_requests"`
	IsBlocked      bool          `json:"is_blocked"`
	NextResetTime  time.Time     `json:"next_reset_time"`
	RemainingQuota int           `json:"remaining_quota"`
}

// Note: RateLimiter implementation moved to ratelimit.go for better organization

// GenerateSecureToken generates a cryptographically secure random token
func GenerateSecureToken(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("token length must be positive")
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return hex.EncodeToString(bytes), nil
}

// SecureCompare performs a constant-time comparison of two strings
func SecureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// IsPrivateIP checks if an IP address is in a private range
func IsPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}

	for _, rangeStr := range privateRanges {
		_, network, err := net.ParseCIDR(rangeStr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// TLS Security Configuration

// GetSecureTLSConfig returns a secure TLS configuration with proper defaults
func GetSecureTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:               tls.VersionTLS12, // Minimum TLS 1.2
		MaxVersion:               tls.VersionTLS13, // Allow TLS 1.3
		InsecureSkipVerify:       false,                      // Always verify certificates by default
		NextProtos:               []string{"h2", "http/1.1"}, // Support HTTP/2
		CipherSuites: []uint16{
			// TLS 1.2 secure cipher suites
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}
}

// ValidateTLSConfig validates a TLS configuration for security
func ValidateTLSConfig(config *tls.Config) error {
	if config.MinVersion < tls.VersionTLS12 {
		return errors.SecurityError("TLS001", "TLS version below 1.2 is not secure").
			WithContext("min_version", config.MinVersion).
			WithUserFriendly("TLS version is too old and insecure").
			WithSuggestion("Use TLS 1.2 or higher for security")
	}

	if config.InsecureSkipVerify {
		return errors.SecurityError("TLS002", "Certificate verification is disabled").
			WithUserFriendly("Certificate verification is disabled, which is insecure").
			WithSuggestion("Enable certificate verification for secure connections")
	}

	return nil
}
