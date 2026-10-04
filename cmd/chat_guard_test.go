package cmd

import "testing"

func TestSanitizeNickname(t *testing.T) {
	if got := sanitizeNickname("alice\x1b[2Jbob\x07"); got != "alice[2Jbob" {
		t.Errorf("got %q", got)
	}
	if got := sanitizeNickname("   "); got != "" {
		t.Errorf("blank nick = %q, want empty", got)
	}
	long := make([]byte, 100)
	for i := range long {
		long[i] = 'a'
	}
	if got := sanitizeNickname(string(long)); len(got) != 32 {
		t.Errorf("long nick len = %d, want 32", len(got))
	}
}

func TestCheckChatAuth(t *testing.T) {
	if !checkChatAuth("op:s3cret", "op", "s3cret") {
		t.Error("valid user:pass rejected")
	}
	if !checkChatAuth("s3cret", "op", "s3cret") {
		t.Error("bare password rejected")
	}
	if checkChatAuth("op:wrong", "op", "s3cret") {
		t.Error("wrong password accepted")
	}
	if checkChatAuth("intruder:s3cret", "op", "s3cret") {
		t.Error("wrong user accepted")
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "localhost", "::1"} {
		if !isLoopbackAddr(h) {
			t.Errorf("%s should be loopback", h)
		}
	}
	if isLoopbackAddr("0.0.0.0") {
		t.Error("0.0.0.0 should not count as loopback")
	}
}
