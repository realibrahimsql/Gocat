package modules

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// RegisterNetworkModule registers network-related Lua functions.
// In restricted mode, connect/listen/scan/banner_grab are disabled and
// return an explanatory error instead of opening arbitrary sockets.
func RegisterNetworkModule(L *lua.LState, restrictedMode bool) {
	netModule := L.NewTable()

	L.SetField(netModule, "connect", L.NewFunction(func(L *lua.LState) int {
		return luaConnect(L, restrictedMode)
	}))
	L.SetField(netModule, "listen", L.NewFunction(func(L *lua.LState) int {
		if restrictedMode {
			L.Push(lua.LNil)
			L.Push(lua.LString("net.listen disabled in restricted mode"))
			return 2
		}
		return luaListen(L)
	}))
	L.SetField(netModule, "send", L.NewFunction(luaSend))
	L.SetField(netModule, "receive", L.NewFunction(luaReceive))
	L.SetField(netModule, "close", L.NewFunction(luaClose))
	L.SetField(netModule, "scan", L.NewFunction(func(L *lua.LState) int {
		if restrictedMode {
			L.Push(L.NewTable())
			L.Push(lua.LString("net.scan disabled in restricted mode"))
			return 2
		}
		return luaScan(L)
	}))
	L.SetField(netModule, "banner_grab", L.NewFunction(func(L *lua.LState) int {
		if restrictedMode {
			L.Push(lua.LNil)
			L.Push(lua.LString("net.banner_grab disabled in restricted mode"))
			return 2
		}
		return luaBannerGrab(L)
	}))

	L.SetGlobal("net", netModule)
}

// NetworkAliases returns bare-global network helpers for backward
// compatibility with scripts written against the legacy flat API
// (connect, send, receive, close, listen). Same restrictions apply.
func NetworkAliases(restricted bool) map[string]lua.LGFunction {
	disabled := func(what string) lua.LGFunction {
		return func(L *lua.LState) int {
			L.Push(lua.LNil)
			L.Push(lua.LString(what + " disabled in restricted mode"))
			return 2
		}
	}
	m := map[string]lua.LGFunction{
		"send":    luaSend,
		"receive": luaReceive,
		"close":   luaClose,
	}
	if restricted {
		m["connect"] = disabled("connect")
		m["listen"] = disabled("listen")
	} else {
		m["connect"] = func(L *lua.LState) int { return luaConnect(L, false) }
		m["listen"] = luaListen
	}
	return m
}

// luaConnect implements net.connect(host, port, protocol)
func luaConnect(L *lua.LState, restrictedMode bool) int {
	if restrictedMode {
		L.Push(lua.LNil)
		L.Push(lua.LString("net.connect disabled in restricted mode"))
		return 2
	}
	host := L.ToString(1)
	port := L.ToInt(2)
	protocol := L.ToString(3)

	if host == "" || port <= 0 {
		L.Push(lua.LNil)
		L.Push(lua.LString("invalid host or port"))
		return 2
	}

	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	var conn net.Conn
	var err error

	timeout := 10 * time.Second

	switch protocol {
	case "tcp", "":
		conn, err = net.DialTimeout("tcp", address, timeout)
	case "udp":
		conn, err = net.DialTimeout("udp", address, timeout)
	default:
		L.Push(lua.LNil)
		L.Push(lua.LString("unsupported protocol: " + protocol))
		return 2
	}

	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}

	userData := L.NewUserData()
	userData.Value = conn
	L.Push(userData)
	L.Push(lua.LNil)
	return 2
}

// luaListen implements net.listen(port, protocol)
func luaListen(L *lua.LState) int {
	port := L.ToInt(1)
	protocol := L.ToString(2)

	if port <= 0 || port > 65535 {
		L.Push(lua.LNil)
		L.Push(lua.LString("invalid port number"))
		return 2
	}

	address := fmt.Sprintf(":%d", port)

	switch protocol {
	case "tcp", "":
		listener, err := net.Listen("tcp", address)
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))
			return 2
		}
		userData := L.NewUserData()
		userData.Value = listener
		L.Push(userData)
		L.Push(lua.LNil)
		return 2

	case "udp":
		udpAddr, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))
			return 2
		}
		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))
			return 2
		}
		userData := L.NewUserData()
		userData.Value = conn
		L.Push(userData)
		L.Push(lua.LNil)
		return 2

	default:
		L.Push(lua.LNil)
		L.Push(lua.LString("unsupported protocol: " + protocol))
		return 2
	}
}

// luaSend implements net.send(conn, data)
func luaSend(L *lua.LState) int {
	userData := L.ToUserData(1)
	data := L.ToString(2)

	if userData == nil || userData.Value == nil {
		L.Push(lua.LNumber(0))
		L.Push(lua.LString("invalid connection"))
		return 2
	}

	conn, ok := userData.Value.(net.Conn)
	if !ok {
		L.Push(lua.LNumber(0))
		L.Push(lua.LString("invalid connection type"))
		return 2
	}

	n, err := conn.Write([]byte(data))
	if err != nil {
		L.Push(lua.LNumber(0))
		L.Push(lua.LString(err.Error()))
		return 2
	}

	L.Push(lua.LNumber(n))
	L.Push(lua.LNil)
	return 2
}

// luaReceive implements net.receive(conn, size)
func luaReceive(L *lua.LState) int {
	userData := L.ToUserData(1)
	size := L.ToInt(2)

	if userData == nil || userData.Value == nil {
		L.Push(lua.LString(""))
		L.Push(lua.LString("invalid connection"))
		return 2
	}

	conn, ok := userData.Value.(net.Conn)
	if !ok {
		L.Push(lua.LString(""))
		L.Push(lua.LString("invalid connection type"))
		return 2
	}

	if size <= 0 {
		size = 2048
	}
	if size > 1<<20 {
		L.Push(lua.LString(""))
		L.Push(lua.LString("receive size capped at 1MB"))
		return 2
	}

	buffer := make([]byte, size)
	n, err := conn.Read(buffer)
	if err != nil {
		L.Push(lua.LString(""))
		L.Push(lua.LString(err.Error()))
		return 2
	}

	L.Push(lua.LString(string(buffer[:n])))
	L.Push(lua.LNil)
	return 2
}

// luaClose implements net.close(conn)
func luaClose(L *lua.LState) int {
	userData := L.ToUserData(1)

	if userData == nil || userData.Value == nil {
		L.Push(lua.LBool(false))
		L.Push(lua.LString("invalid connection"))
		return 2
	}

	switch v := userData.Value.(type) {
	case net.Conn:
		err := v.Close()
		if err != nil {
			L.Push(lua.LBool(false))
			L.Push(lua.LString(err.Error()))
			return 2
		}
	case net.Listener:
		err := v.Close()
		if err != nil {
			L.Push(lua.LBool(false))
			L.Push(lua.LString(err.Error()))
			return 2
		}
	default:
		L.Push(lua.LBool(false))
		L.Push(lua.LString("invalid connection type"))
		return 2
	}

	L.Push(lua.LBool(true))
	L.Push(lua.LNil)
	return 2
}

// luaScan implements net.scan(host, ports)
func luaScan(L *lua.LState) int {
	host := L.ToString(1)
	portsStr := L.ToString(2)

	if host == "" {
		L.Push(L.NewTable())
		return 1
	}

	// Parse ports (e.g., "80,443,8080" or "1-100")
	var portsToScan []int
	if strings.Contains(portsStr, "-") {
		// Range format: "1-100"
		parts := strings.Split(portsStr, "-")
		if len(parts) == 2 {
			start, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
			end, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
			for i := start; i <= end && i <= 65535; i++ {
				portsToScan = append(portsToScan, i)
			}
		}
	} else if strings.Contains(portsStr, ",") {
		// Comma-separated: "80,443,8080"
		parts := strings.Split(portsStr, ",")
		for _, p := range parts {
			port, _ := strconv.Atoi(strings.TrimSpace(p))
			if port > 0 && port <= 65535 {
				portsToScan = append(portsToScan, port)
			}
		}
	} else {
		// Single port
		port, _ := strconv.Atoi(strings.TrimSpace(portsStr))
		if port > 0 && port <= 65535 {
			portsToScan = append(portsToScan, port)
		}
	}

	// Scan ports
	openPorts := []int{}
	timeout := 2 * time.Second

	for _, port := range portsToScan {
		address := net.JoinHostPort(host, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err == nil {
			openPorts = append(openPorts, port)
			conn.Close()
		}
	}

	// Return results as Lua table
	table := L.NewTable()
	for i, port := range openPorts {
		L.RawSet(table, lua.LNumber(i+1), lua.LNumber(port))
	}
	L.Push(table)
	return 1
}

// luaBannerGrab implements net.banner_grab(host, port)
func luaBannerGrab(L *lua.LState) int {
	host := L.ToString(1)
	port := L.ToInt(2)

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 1024)
	n, _ := conn.Read(buffer)

	L.Push(lua.LString(string(buffer[:n])))
	L.Push(lua.LNil)
	return 2
}
