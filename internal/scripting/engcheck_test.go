package scripting

import (
	"testing"
	"time"
)

func TestDoStringTimeoutAbortsLoop(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxExecutionTime = 2 * time.Second
	eng := NewEngine(cfg)
	defer eng.Close()
	start := time.Now()
	err := eng.LoadString(`while true do end`)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("infinite loop not aborted")
	}
	if elapsed > 10*time.Second {
		t.Fatalf("abort took too long: %v", elapsed)
	}
	t.Logf("aborted after %v: %v", elapsed.Round(time.Millisecond), err)
}
