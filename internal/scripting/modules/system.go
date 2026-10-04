package modules

import (
	"os"
	"os/exec"
	"runtime"
	"strings"

	lua "github.com/yuin/gopher-lua"
)

// RegisterSystemModule registers system-related Lua functions
func RegisterSystemModule(L *lua.LState, restrictedMode bool) {
	sysModule := L.NewTable()

	// OS information
	L.SetField(sysModule, "hostname", L.NewFunction(luaHostname))
	L.SetField(sysModule, "platform", L.NewFunction(luaPlatform))
	L.SetField(sysModule, "env", L.NewFunction(luaEnv))
	L.SetField(sysModule, "pid", L.NewFunction(luaPID))
	L.SetField(sysModule, "pwd", L.NewFunction(luaPWD))

	// File system operations
	L.SetField(sysModule, "ls", L.NewFunction(luaLS))
	L.SetField(sysModule, "mkdir", L.NewFunction(luaMkdir))
	if !restrictedMode {
		L.SetField(sysModule, "cd", L.NewFunction(luaCD))
	}

	// Command execution (restricted)
	if !restrictedMode {
		L.SetField(sysModule, "exec", L.NewFunction(luaExec))
		L.SetField(sysModule, "shell", L.NewFunction(luaShell))
	}

	L.SetGlobal("sys", sysModule)
}

// luaHostname implements sys.hostname()
func luaHostname(L *lua.LState) int {
	hostname, err := os.Hostname()
	if err != nil {
		L.Push(lua.LString(""))
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(lua.LString(hostname))
	L.Push(lua.LNil)
	return 2
}

// luaPlatform implements sys.platform()
func luaPlatform(L *lua.LState) int {
	platform := runtime.GOOS + "/" + runtime.GOARCH
	L.Push(lua.LString(platform))
	return 1
}

// luaEnv implements sys.env(name). Unrestricted in full mode; restricted
// mode only exposes GOCAT_* variables so scripts cannot harvest host secrets.
func luaEnv(L *lua.LState) int {
	name := L.ToString(1)
	if sysRestricted(L) && !strings.HasPrefix(name, "GOCAT_") {
		L.Push(lua.LString(""))
		return 1
	}
	value := os.Getenv(name)
	L.Push(lua.LString(value))
	return 1
}

// luaPID implements sys.pid()
func luaPID(L *lua.LState) int {
	L.Push(lua.LNumber(os.Getpid()))
	return 1
}

// luaPWD implements sys.pwd()
func luaPWD(L *lua.LState) int {
	pwd, err := os.Getwd()
	if err != nil {
		L.Push(lua.LString(""))
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(lua.LString(pwd))
	L.Push(lua.LNil)
	return 2
}

// luaLS implements sys.ls(path)
func luaLS(L *lua.LState) int {
	path := L.ToString(1)
	if path == "" {
		path = "."
	}

	files, err := os.ReadDir(path)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}

	table := L.NewTable()
	for _, file := range files {
		fileInfo := L.NewTable()
		fileInfo.RawSetString("name", lua.LString(file.Name()))
		fileInfo.RawSetString("isDir", lua.LBool(file.IsDir()))

		info, err := file.Info()
		if err == nil {
			fileInfo.RawSetString("size", lua.LNumber(info.Size()))
			fileInfo.RawSetString("mode", lua.LString(info.Mode().String()))
			fileInfo.RawSetString("modTime", lua.LNumber(info.ModTime().Unix()))
		}

		table.Append(fileInfo)
	}

	L.Push(table)
	L.Push(lua.LNil)
	return 2
}

// luaMkdir implements sys.mkdir(path)
func luaMkdir(L *lua.LState) int {
	path := L.ToString(1)
	mode := L.ToInt(2)
	if mode == 0 {
		mode = 0755
	}

	err := os.MkdirAll(path, os.FileMode(mode))
	if err != nil {
		L.Push(lua.LBool(false))
		L.Push(lua.LString(err.Error()))
		return 2
	}

	L.Push(lua.LBool(true))
	L.Push(lua.LNil)
	return 2
}

// luaCD implements sys.cd(path)
func luaCD(L *lua.LState) int {
	path := L.ToString(1)
	err := os.Chdir(path)
	if err != nil {
		L.Push(lua.LBool(false))
		L.Push(lua.LString(err.Error()))
		return 2
	}

	L.Push(lua.LBool(true))
	L.Push(lua.LNil)
	return 2
}

// luaExec implements sys.exec(command, args...)
func luaExec(L *lua.LState) int {
	command := L.ToString(1)

	// Collect arguments
	args := []string{}
	for i := 2; i <= L.GetTop(); i++ {
		args = append(args, L.ToString(i))
	}

	cmd := exec.Command(command, args...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		L.Push(lua.LString(string(output)))
		L.Push(lua.LString(err.Error()))
		return 2
	}

	L.Push(lua.LString(string(output)))
	L.Push(lua.LNil)
	return 2
}

// luaShell implements sys.shell(command)
func luaShell(L *lua.LState) int {
	command := L.ToString(1)

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}

	output, err := cmd.CombinedOutput()

	if err != nil {
		L.Push(lua.LString(string(output)))
		L.Push(lua.LString(err.Error()))
		return 2
	}

	L.Push(lua.LString(string(output)))
	L.Push(lua.LNil)
	return 2
}
