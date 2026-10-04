//go:build unix

package session

import (
	"bytes"
	"testing"
)

func TestTranslateLineEndingsRaw(t *testing.T) {
	in := []byte("clera\r")
	got := translateLineEndings(append([]byte(nil), in...), true)
	if !bytes.Equal(got, []byte("clera\n")) {
		t.Fatalf("got %q, want %q", got, "clera\n")
	}
}

func TestTranslateLineEndingsPTYUntouched(t *testing.T) {
	in := []byte("echo hi\r")
	got := translateLineEndings(append([]byte(nil), in...), false)
	if !bytes.Equal(got, in) {
		t.Fatalf("PTY input modified: got %q", got)
	}
}

func TestTranslateLineEndingsKeepsLF(t *testing.T) {
	in := []byte("a\nb\r\nc\r")
	got := translateLineEndings(append([]byte(nil), in...), true)
	if !bytes.Equal(got, []byte("a\nb\n\nc\n")) {
		t.Fatalf("got %q", got)
	}
}
