package nekodns

import "testing"

func TestBuildResponseShortPacket(t *testing.T) {
	h := NewHandler()
	for _, q := range [][]byte{nil, {}, {0x12}, make([]byte, 11)} {
		func() {
			defer func() {
				if recover() != nil {
					t.Fatalf("BuildResponse(%d bytes) panicked", len(q))
				}
			}()
			if out := h.BuildResponse(q, ""); out != nil {
				t.Fatalf("BuildResponse(%d bytes) = %x, want nil", len(q), out)
			}
		}()
	}
}

func TestSanitizeDNSDownloadPath(t *testing.T) {
	for _, bad := range []string{"", "/etc/passwd", "../../evil", "../evil", "/tmp/x"} {
		if got := sanitizeDNSDownloadPath(bad); got != "" {
			t.Errorf("sanitizeDNSDownloadPath(%q) = %q, want empty", bad, got)
		}
	}
	if got := sanitizeDNSDownloadPath("loot/out.txt"); got != "loot/out.txt" {
		t.Errorf("sanitizeDNSDownloadPath(loot/out.txt) = %q", got)
	}
}
