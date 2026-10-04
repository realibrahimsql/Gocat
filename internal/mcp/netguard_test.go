package mcp

import (
	"testing"
)

func TestValidateNetworkTargetBlocksSensitive(t *testing.T) {
	t.Setenv("GOCAT_MCP_ALLOW_HOSTS", "")
	t.Setenv("GOCAT_MCP_ALLOW_PRIVATE", "")
	for _, host := range []string{"127.0.0.1", "localhost", "169.254.169.254", "10.0.0.5", "192.168.1.1", "172.16.0.1", "::1"} {
		if err := ValidateNetworkTarget(host); err == nil {
			t.Errorf("ValidateNetworkTarget(%q) = nil, want rejection", host)
		}
	}
}

func TestValidateNetworkTargetAllowlist(t *testing.T) {
	t.Setenv("GOCAT_MCP_ALLOW_HOSTS", "db.internal, 10.0.0.5")
	t.Setenv("GOCAT_MCP_ALLOW_PRIVATE", "")
	if err := ValidateNetworkTarget("10.0.0.5"); err != nil {
		t.Errorf("allowlisted host rejected: %v", err)
	}
}

func TestValidateNetworkTargetEmpty(t *testing.T) {
	if err := ValidateNetworkTarget(""); err == nil {
		t.Error("empty host accepted, want rejection")
	}
}
