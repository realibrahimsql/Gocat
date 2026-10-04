package modules

import (
	"io"
	"os"
	"path/filepath"

	lua "github.com/yuin/gopher-lua"
)

// RegisterFileModule registers file-related Lua functions
func RegisterFileModule(L *lua.LState) {
	fileModule := L.NewTable()

	L.SetField(fileModule, "read", L.NewFunction(luaFileRead))
	L.SetField(fileModule, "write", L.NewFunction(luaFileWrite))
	L.SetField(fileModule, "append", L.NewFunction(luaFileAppend))
	L.SetField(fileModule, "exists", L.NewFunction(luaFileExists))
	L.SetField(fileModule, "delete", L.NewFunction(luaFileDelete))
	L.SetField(fileModule, "copy", L.NewFunction(luaFileCopy))
	L.SetField(fileModule, "move", L.NewFunction(luaFileMove))
	L.SetField(fileModule, "stat", L.NewFunction(luaFileStat))
	L.SetField(fileModule, "basename", L.NewFunction(luaBasename))
	L.SetField(fileModule, "dirname", L.NewFunction(luaDirname))
	L.SetField(fileModule, "join", L.NewFunction(luaJoinPath))

	L.SetGlobal("file", fileModule)
}

// luaFileRead implements file.read(path)
func luaFileRead(L *lua.LState) int {
	path, ok := guardedPath(L, 1)
	if !ok {
		L.Push(lua.LNil)
		L.Push(lua.LString("path escapes sandbox"))
		return 2
	}

	content, err := os.ReadFile(path)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}

	L.Push(lua.LString(string(content)))
	L.Push(lua.LNil)
	return 2
}

// luaFileWrite implements file.write(path, content)
func luaFileWrite(L *lua.LState) int {
	path, ok := guardedPath(L, 1)
	if !ok {
		L.Push(lua.LBool(false))
		L.Push(lua.LString("path escapes sandbox"))
		return 2
	}
	content := L.ToString(2)

	err := os.WriteFile(path, []byte(content), 0600)
	if err != nil {
		L.Push(lua.LBool(false))
		L.Push(lua.LString(err.Error()))
		return 2
	}

	L.Push(lua.LBool(true))
	L.Push(lua.LNil)
	return 2
}

// luaFileAppend implements file.append(path, content)
func luaFileAppend(L *lua.LState) int {
	path, ok := guardedPath(L, 1)
	if !ok {
		L.Push(lua.LBool(false))
		L.Push(lua.LString("path escapes sandbox"))
		return 2
	}
	content := L.ToString(2)

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		L.Push(lua.LBool(false))
		L.Push(lua.LString(err.Error()))
		return 2
	}
	defer file.Close()

	_, err = file.WriteString(content)
	if err != nil {
		L.Push(lua.LBool(false))
		L.Push(lua.LString(err.Error()))
		return 2
	}

	L.Push(lua.LBool(true))
	L.Push(lua.LNil)
	return 2
}

// luaFileExists implements file.exists(path)
func luaFileExists(L *lua.LState) int {
	path, ok := guardedPath(L, 1)
	if !ok {
		L.Push(lua.LBool(false))
		return 1
	}

	_, err := os.Stat(path)
	exists := err == nil

	L.Push(lua.LBool(exists))
	return 1
}

// luaFileDelete implements file.delete(path)
func luaFileDelete(L *lua.LState) int {
	path, ok := guardedPath(L, 1)
	if !ok {
		L.Push(lua.LBool(false))
		L.Push(lua.LString("path escapes sandbox"))
		return 2
	}

	err := os.Remove(path)
	if err != nil {
		L.Push(lua.LBool(false))
		L.Push(lua.LString(err.Error()))
		return 2
	}

	L.Push(lua.LBool(true))
	L.Push(lua.LNil)
	return 2
}

// luaFileCopy implements file.copy(src, dst)
func luaFileCopy(L *lua.LState) int {
	src, ok := guardedPath(L, 1)
	if !ok {
		L.Push(lua.LBool(false))
		L.Push(lua.LString("source escapes sandbox"))
		return 2
	}
	dst, ok := guardedPath(L, 2)
	if !ok {
		L.Push(lua.LBool(false))
		L.Push(lua.LString("destination escapes sandbox"))
		return 2
	}

	sourceFile, err := os.Open(src)
	if err != nil {
		L.Push(lua.LBool(false))
		L.Push(lua.LString(err.Error()))
		return 2
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		L.Push(lua.LBool(false))
		L.Push(lua.LString(err.Error()))
		return 2
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		L.Push(lua.LBool(false))
		L.Push(lua.LString(err.Error()))
		return 2
	}

	L.Push(lua.LBool(true))
	L.Push(lua.LNil)
	return 2
}

// luaFileMove implements file.move(src, dst)
func luaFileMove(L *lua.LState) int {
	src, ok := guardedPath(L, 1)
	if !ok {
		L.Push(lua.LBool(false))
		L.Push(lua.LString("source escapes sandbox"))
		return 2
	}
	dst, ok := guardedPath(L, 2)
	if !ok {
		L.Push(lua.LBool(false))
		L.Push(lua.LString("destination escapes sandbox"))
		return 2
	}

	err := os.Rename(src, dst)
	if err != nil {
		L.Push(lua.LBool(false))
		L.Push(lua.LString(err.Error()))
		return 2
	}

	L.Push(lua.LBool(true))
	L.Push(lua.LNil)
	return 2
}

// luaFileStat implements file.stat(path)
func luaFileStat(L *lua.LState) int {
	path, ok := guardedPath(L, 1)
	if !ok {
		L.Push(lua.LNil)
		L.Push(lua.LString("path escapes sandbox"))
		return 2
	}

	info, err := os.Stat(path)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}

	stat := L.NewTable()
	stat.RawSetString("name", lua.LString(info.Name()))
	stat.RawSetString("size", lua.LNumber(info.Size()))
	stat.RawSetString("mode", lua.LString(info.Mode().String()))
	stat.RawSetString("modTime", lua.LNumber(info.ModTime().Unix()))
	stat.RawSetString("isDir", lua.LBool(info.IsDir()))

	L.Push(stat)
	L.Push(lua.LNil)
	return 2
}

// luaBasename implements file.basename(path)
func luaBasename(L *lua.LState) int {
	path := L.ToString(1)
	base := filepath.Base(path)
	L.Push(lua.LString(base))
	return 1
}

// luaDirname implements file.dirname(path)
func luaDirname(L *lua.LState) int {
	path := L.ToString(1)
	dir := filepath.Dir(path)
	L.Push(lua.LString(dir))
	return 1
}

// luaJoinPath implements file.join(path1, path2, ...)
func luaJoinPath(L *lua.LState) int {
	paths := []string{}
	for i := 1; i <= L.GetTop(); i++ {
		paths = append(paths, L.ToString(i))
	}

	joined := filepath.Join(paths...)
	L.Push(lua.LString(joined))
	return 1
}
