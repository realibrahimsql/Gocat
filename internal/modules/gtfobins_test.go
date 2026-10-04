package modules

import "testing"

func TestGtfobinsCoverage(t *testing.T) {
	for _, bin := range []string{"vim", "find", "awk", "python3", "docker", "sudo", "tar", "git", "perl", "ruby", "bash-suid", "systemctl", "kubectl", "mysql"} {
		if _, ok := gtfobins[bin]; !ok {
			t.Errorf("gtfobins missing %q", bin)
		}
	}
	if len(gtfobins) < 60 {
		t.Errorf("gtfobins has %d entries, want >= 60", len(gtfobins))
	}
}
