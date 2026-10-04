package scripting

import "testing"

func TestLuaEngineExecuteScriptPropagatesMainError(t *testing.T) {
	eng := NewLuaEngine(nil)
	defer eng.Close()

	if err := eng.LoadString(`function main() error("boom") end`); err != nil {
		t.Fatalf("LoadString: %v", err)
	}
	if err := eng.ExecuteScript("failing"); err == nil {
		t.Fatal("ExecuteScript(failing main) = nil, want error")
	}
}

func TestLuaEngineExecuteScriptNoMainSucceeds(t *testing.T) {
	eng := NewLuaEngine(nil)
	defer eng.Close()

	if err := eng.LoadString(`x = 1 + 1`); err != nil {
		t.Fatalf("LoadString: %v", err)
	}
	if err := eng.ExecuteScript("no-main"); err != nil {
		t.Fatalf("ExecuteScript(no main) = %v, want nil", err)
	}
}

func TestRestrictedBlocksOsExecute(t *testing.T) {
	eng := NewEngine(nil)
	defer eng.Close()
	if err := eng.LoadString(`os.execute("id")`); err == nil {
		t.Fatal("os.execute succeeded in restricted mode, want error")
	}
}

func TestRestrictedBlocksFileEscape(t *testing.T) {
	eng := NewEngine(nil)
	defer eng.Close()
	if err := eng.LoadString(`f, e = file.read("/etc/passwd"); assert(f == nil, "escaped")`); err != nil {
		t.Fatalf("LoadString: %v", err)
	}
}

func TestRestrictedOsTimeAvailable(t *testing.T) {
	eng := NewEngine(nil)
	defer eng.Close()
	if err := eng.LoadString(`assert(type(os.time()) == "number", "os.time missing")`); err != nil {
		t.Fatalf("LoadString: %v", err)
	}
}

func TestUnrestrictedAllowsOsExecute(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RestrictedMode = false
	eng := NewEngine(cfg)
	defer eng.Close()
	if err := eng.LoadString(`assert(os.execute("true"), "os.execute failed")`); err != nil {
		t.Fatalf("LoadString: %v", err)
	}
}

func TestRestrictedHTTPBlocksMetadata(t *testing.T) {
	eng := NewEngine(nil)
	defer eng.Close()
	code := `r, e = http.get("http://169.254.169.254/latest/"); assert(r == nil, "metadata reachable")`
	if err := eng.LoadString(code); err != nil {
		t.Fatalf("LoadString: %v", err)
	}
}
