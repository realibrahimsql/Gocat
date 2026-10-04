package scripting

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/realibrahimsql/Gocat/internal/logger"
	"github.com/realibrahimsql/Gocat/internal/scripting/modules"
	lua "github.com/yuin/gopher-lua"
)

// Engine represents a Lua scripting engine for GoCat
type Engine struct {
	L             *lua.LState
	config        *Config
	ctx           context.Context
	cancel        context.CancelFunc
	loadedScripts map[string]bool
}

// Config holds configuration for the Lua engine
type Config struct {
	MaxExecutionTime time.Duration
	MaxMemory        int64
	RestrictedMode   bool
	AllowedHosts     []string
	DeniedHosts      []string
	ModulesPath      string
	Debug            bool
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		MaxExecutionTime: 30 * time.Second,
		MaxMemory:        64 * 1024 * 1024, // 64MB
		RestrictedMode:   true,
		Debug:            false,
	}
}

// NewEngine creates a new Lua engine with configuration
func NewEngine(config *Config) *Engine {
	if config == nil {
		config = DefaultConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())
	var L *lua.LState
	if config.RestrictedMode {
		L = lua.NewState(lua.Options{SkipOpenLibs: true})
		openRestrictedLibs(L)
	} else {
		L = lua.NewState()
	}

	// Configure Lua state limits
	L.SetMx(int(config.MaxMemory))

	engine := &Engine{
		L:             L,
		config:        config,
		ctx:           ctx,
		cancel:        cancel,
		loadedScripts: make(map[string]bool),
	}

	// Register all modules
	engine.registerModules()

	return engine
}

// openRestrictedLibs opens only the Lua standard libraries that cannot
// escape the sandbox: no os/io/package/debug. Dangerous base functions
// (dofile, loadfile, load, loadstring, require) are removed after opening.
func openRestrictedLibs(L *lua.LState) {
	for _, lib := range []struct {
		name string
		fn   lua.LGFunction
	}{
		{lua.TabLibName, lua.OpenTable},
		{lua.StringLibName, lua.OpenString},
		{lua.MathLibName, lua.OpenMath},
		{lua.CoroutineLibName, lua.OpenCoroutine},
		{lua.ChannelLibName, lua.OpenChannel},
	} {
		L.Push(L.NewFunction(lib.fn))
		L.Push(lua.LString(lib.name))
		L.Call(1, 0)
	}
	// Base last so its globals exist for stripping.
	L.Push(L.NewFunction(lua.OpenBase))
	L.Push(lua.LString(lua.BaseLibName))
	L.Call(1, 0)
	for _, dangerous := range []string{
		"dofile", "loadfile", "load", "loadstring", "require",
		"collectgarbage", "newproxy",
	} {
		L.SetGlobal(dangerous, lua.LNil)
	}
	// Safe read-only os subset: scripts legitimately use os.time/date/clock.
	// Everything else (execute, getenv, remove, rename, exit, setlocale)
	// stays unavailable in restricted mode.
	L.SetGlobal("os", restrictedOSTable(L))
}

// restrictedOSTable builds a minimal os table with time functions only.
func restrictedOSTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	L.SetField(t, "time", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LNumber(time.Now().Unix()))
		return 1
	}))
	L.SetField(t, "clock", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LNumber(float64(time.Now().UnixNano()) / 1e9))
		return 1
	}))
	L.SetField(t, "date", L.NewFunction(func(L *lua.LState) int {
		format := L.OptString(1, "%c")
		L.Push(lua.LString(time.Now().Format(luaDateFormat(format))))
		return 1
	}))
	L.SetField(t, "difftime", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LNumber(float64(L.ToInt64(1) - L.ToInt64(2))))
		return 1
	}))
	return t
}

// luaDateFormat converts a few common strftime verbs to Go layouts.
func luaDateFormat(format string) string {
	r := strings.NewReplacer(
		"%Y", "2006", "%m", "01", "%d", "02",
		"%H", "15", "%M", "04", "%S", "05",
		"%c", time.ANSIC,
	)
	return r.Replace(format)
}

// registerModules registers all Lua modules
func (e *Engine) registerModules() {
	// Core modules
	modules.SetGuard(e.L, &modules.ScriptGuard{
		Restricted:   e.config.RestrictedMode,
		SandboxRoot:  e.sandboxRoot(),
		AllowedHosts: e.config.AllowedHosts,
		DeniedHosts:  e.config.DeniedHosts,
	})
	modules.RegisterNetworkModule(e.L, e.config.RestrictedMode)
	modules.RegisterHTTPModule(e.L)
	modules.RegisterCryptoModule(e.L)
	modules.RegisterSystemModule(e.L, e.config.RestrictedMode)
	modules.RegisterFileModule(e.L)
	modules.RegisterTimeModule(e.L)
	modules.RegisterUIModule(e.L)
	modules.RegisterJSONModule(e.L)

	// Utility functions (backward compatibility)
	e.registerUtilityFunctions()

	// GoCat environment info
	e.registerGoCatInfo()

	if e.config.Debug {
		logger.Debug("Registered all Lua modules")
	}
}

// registerUtilityFunctions registers utility functions for backward compatibility
func (e *Engine) registerUtilityFunctions() {
	// Legacy functions that are directly in global scope
	e.L.SetGlobal("log", e.L.NewFunction(modules.LuaLog))
	e.L.SetGlobal("sleep", e.L.NewFunction(modules.LuaSleep))
	e.L.SetGlobal("print", e.L.NewFunction(modules.LuaPrint))
	// Legacy flat crypto helpers (hex_encode, base64_encode, ...)
	for name, fn := range modules.GlobalAliases() {
		e.L.SetGlobal(name, e.L.NewFunction(fn))
	}
	// Legacy flat network helpers (connect, send, receive, close, listen)
	for name, fn := range modules.NetworkAliases(e.config.RestrictedMode) {
		e.L.SetGlobal(name, e.L.NewFunction(fn))
	}
}

// registerGoCatInfo registers GoCat environment information
func (e *Engine) registerGoCatInfo() {
	gocatTable := e.L.NewTable()
	gocatTable.RawSetString("version", lua.LString("1.0.0"))
	gocatTable.RawSetString("platform", lua.LString("cross-platform"))

	// Add configuration info
	configTable := e.L.NewTable()
	configTable.RawSetString("restricted", lua.LBool(e.config.RestrictedMode))
	configTable.RawSetString("maxMemory", lua.LNumber(e.config.MaxMemory))
	configTable.RawSetString("maxExecutionTime", lua.LNumber(e.config.MaxExecutionTime.Seconds()))
	gocatTable.RawSetString("config", configTable)

	e.L.SetGlobal("gocat", gocatTable)
}

// sandboxRoot resolves the file sandbox: ModulesPath when configured,
// otherwise the process working directory at engine creation.
func (e *Engine) sandboxRoot() string {
	if e.config.ModulesPath != "" {
		if abs, err := filepath.Abs(e.config.ModulesPath); err == nil {
			return abs
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		return cwd
	}
	return ""
}

// SetArgs sets command line arguments for the script
func (e *Engine) SetArgs(args []string) {
	if e.L == nil {
		return
	}

	// Create arg table (Lua style, 0-indexed for script name, 1+ for args)
	argTable := e.L.NewTable()
	for i, arg := range args {
		argTable.RawSetInt(i+1, lua.LString(arg))
	}
	e.L.SetGlobal("arg", argTable)

	// Also set ARGV for compatibility
	e.L.SetGlobal("ARGV", argTable)
}

// LoadScript loads a Lua script from file
func (e *Engine) LoadScript(scriptPath string) error {
	if e.L == nil {
		return fmt.Errorf("lua engine is closed")
	}

	// Check if script already loaded
	if e.loadedScripts[scriptPath] {
		if e.config.Debug {
			logger.Debug("Script already loaded: %s", scriptPath)
		}
		return nil
	}

	// Check file size
	info, err := os.Stat(scriptPath)
	if err != nil {
		return fmt.Errorf("failed to stat script: %w", err)
	}

	if info.Size() > 10*1024*1024 { // 10MB limit
		return fmt.Errorf("script too large: %d bytes", info.Size())
	}

	// Read script file
	content, err := os.ReadFile(scriptPath)
	if err != nil {
		return fmt.Errorf("failed to read script file: %w", err)
	}

	// Compile and load script with an execution deadline so a hostile
	// top-level loop cannot hang the loader forever.
	if err := e.doStringTimeout(string(content)); err != nil {
		return fmt.Errorf("failed to load script: %w", err)
	}

	e.loadedScripts[scriptPath] = true

	if e.config.Debug {
		logger.Debug("Successfully loaded script: %s", scriptPath)
	}

	return nil
}

// LoadString loads and executes Lua code from a string
func (e *Engine) LoadString(code string) error {
	if e.L == nil {
		return fmt.Errorf("lua engine is closed")
	}

	if len(code) > 10*1024*1024 {
		return fmt.Errorf("script exceeds 10MB size cap")
	}

	if err := e.doStringTimeout(code); err != nil {
		return fmt.Errorf("failed to execute code: %w", err)
	}

	return nil
}

// doStringTimeout runs Lua code with the configured execution deadline.
// gopher-lua aborts the VM when the context expires, so infinite loops in
// untrusted scripts terminate instead of hanging the process.
func (e *Engine) doStringTimeout(code string) error {
	timeout := e.config.MaxExecutionTime
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(e.ctx, timeout)
	defer cancel()
	e.L.SetContext(ctx)
	defer e.L.RemoveContext()
	return e.L.DoString(code)
}

// ExecuteFunction executes a specific function in the loaded script
func (e *Engine) ExecuteFunction(functionName string, args ...lua.LValue) ([]lua.LValue, error) {
	if e.L == nil {
		return nil, fmt.Errorf("lua engine is closed")
	}

	// Get the function
	fn := e.L.GetGlobal(functionName)
	if fn.Type() != lua.LTFunction {
		return nil, fmt.Errorf("function '%s' not found or not a function", functionName)
	}

	// Set execution timeout
	done := make(chan bool)
	var execErr error
	var results []lua.LValue

	go func() {
		// Call function with arguments
		err := e.L.CallByParam(lua.P{
			Fn:      fn,
			NRet:    lua.MultRet,
			Protect: true,
		}, args...)

		if err != nil {
			execErr = fmt.Errorf("error executing function '%s': %w", functionName, err)
			done <- true
			return
		}

		// Collect return values
		top := e.L.GetTop()
		for i := 1; i <= top; i++ {
			results = append(results, e.L.Get(i))
		}
		e.L.SetTop(0) // Clear stack

		done <- true
	}()

	// Wait for completion or timeout
	select {
	case <-done:
		return results, execErr
	case <-time.After(e.config.MaxExecutionTime):
		return nil, fmt.Errorf("function execution timeout after %v", e.config.MaxExecutionTime)
	case <-e.ctx.Done():
		return nil, fmt.Errorf("engine context cancelled")
	}
}

// GetGlobal gets a global variable from Lua state
func (e *Engine) GetGlobal(name string) lua.LValue {
	if e.L == nil {
		return lua.LNil
	}
	return e.L.GetGlobal(name)
}

// SetGlobal sets a global variable in Lua state
func (e *Engine) SetGlobal(name string, value lua.LValue) {
	if e.L != nil {
		e.L.SetGlobal(name, value)
	}
}

// ExecuteScript executes a loaded script's main function
func (e *Engine) ExecuteScript(scriptName string) error {
	// Try to execute main function if it exists
	mainFn := e.L.GetGlobal("main")
	if mainFn == lua.LNil {
		// If no main function, the script has already been executed during LoadScript
		return nil
	}

	// Execute the main function
	if err := e.L.CallByParam(lua.P{
		Fn:      mainFn,
		NRet:    0,
		Protect: true,
	}); err != nil {
		return fmt.Errorf("error executing script '%s': %w", scriptName, err)
	}

	return nil
}

// Close closes the Lua engine and releases resources
func (e *Engine) Close() {
	if e.cancel != nil {
		e.cancel()
	}

	if e.L != nil {
		modules.ClearGuard(e.L)
		e.L.Close()
		e.L = nil
	}

	e.loadedScripts = nil
}

// IsRestricted returns whether the engine is in restricted mode
func (e *Engine) IsRestricted() bool {
	return e.config.RestrictedMode
}

// SetDebug enables or disables debug mode
func (e *Engine) SetDebug(debug bool) {
	e.config.Debug = debug
}
