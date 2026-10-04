package modules

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// RegisterHTTPModule registers HTTP-related Lua functions
func RegisterHTTPModule(L *lua.LState) {
	httpModule := L.NewTable()

	L.SetField(httpModule, "get", L.NewFunction(luaHTTPGet))
	L.SetField(httpModule, "post", L.NewFunction(luaHTTPPost))
	L.SetField(httpModule, "put", L.NewFunction(luaHTTPPut))
	L.SetField(httpModule, "delete", L.NewFunction(luaHTTPDelete))
	L.SetField(httpModule, "request", L.NewFunction(luaHTTPRequest))
	L.SetField(httpModule, "download", L.NewFunction(luaHTTPDownload))

	L.SetGlobal("http", httpModule)
}

// scriptHTTPDo validates the URL, performs the request with redirect
// re-validation, and returns a capped body.
func scriptHTTPDo(g *ScriptGuard, method, rawurl string, body io.Reader, headers map[string]string) (*http.Response, []byte, error) {
	u, err := validateScriptURL(g, rawurl)
	if err != nil {
		return nil, nil, err
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			if _, err := validateScriptURL(g, req.URL.String()); err != nil {
				return err
			}
			return nil
		},
	}
	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return nil, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxScriptBody+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > maxScriptBody {
		return nil, nil, fmt.Errorf("response exceeds %d bytes", maxScriptBody)
	}
	return resp, data, nil
}

func pushScriptResponse(L *lua.LState, resp *http.Response, body []byte) {
	result := L.NewTable()
	result.RawSetString("status", lua.LNumber(resp.StatusCode))
	result.RawSetString("body", lua.LString(string(body)))

	headers := L.NewTable()
	for key, values := range resp.Header {
		headers.RawSetString(key, lua.LString(strings.Join(values, ", ")))
	}
	result.RawSetString("headers", headers)

	L.Push(result)
	L.Push(lua.LNil)
}

// luaHTTPGet implements http.get(url)
func luaHTTPGet(L *lua.LState) int {
	g := GetGuard(L)
	url := L.ToString(1)

	resp, body, err := scriptHTTPDo(g, http.MethodGet, url, nil, nil)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString("request failed"))
		return 2
	}
	pushScriptResponse(L, resp, body)
	return 2
}

// luaHTTPPost implements http.post(url, data)
func luaHTTPPost(L *lua.LState) int {
	g := GetGuard(L)
	url := L.ToString(1)
	data := L.ToString(2)
	if len(data) > maxScriptBody {
		L.Push(lua.LNil)
		L.Push(lua.LString("request body too large"))
		return 2
	}

	resp, body, err := scriptHTTPDo(g, http.MethodPost, url, strings.NewReader(data),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString("request failed"))
		return 2
	}
	pushScriptResponse(L, resp, body)
	return 2
}

// luaHTTPPut implements http.put(url, data)
func luaHTTPPut(L *lua.LState) int {
	g := GetGuard(L)
	url := L.ToString(1)
	data := L.ToString(2)
	if len(data) > maxScriptBody {
		L.Push(lua.LNil)
		L.Push(lua.LString("request body too large"))
		return 2
	}

	resp, body, err := scriptHTTPDo(g, http.MethodPut, url, strings.NewReader(data), nil)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString("request failed"))
		return 2
	}
	pushScriptResponse(L, resp, body)
	return 2
}

// luaHTTPDelete implements http.delete(url)
func luaHTTPDelete(L *lua.LState) int {
	g := GetGuard(L)
	url := L.ToString(1)

	resp, body, err := scriptHTTPDo(g, http.MethodDelete, url, nil, nil)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString("request failed"))
		return 2
	}
	pushScriptResponse(L, resp, body)
	return 2
}

// luaHTTPRequest implements http.request(method, url, headers, body)
func luaHTTPRequest(L *lua.LState) int {
	g := GetGuard(L)
	method := L.ToString(1)
	url := L.ToString(2)
	headersTable := L.ToTable(3)
	body := L.ToString(4)
	if len(body) > maxScriptBody {
		L.Push(lua.LNil)
		L.Push(lua.LString("request body too large"))
		return 2
	}

	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead:
	default:
		L.Push(lua.LNil)
		L.Push(lua.LString("method not allowed"))
		return 2
	}

	headers := map[string]string{}
	if headersTable != nil {
		headersTable.ForEach(func(key, value lua.LValue) {
			k := http.CanonicalHeaderKey(key.String())
			switch k {
			case "Host", "Content-Length", "Authorization", "Proxy-Authorization", "Cookie":
				return
			}
			headers[k] = value.String()
		})
	}

	resp, respBody, err := scriptHTTPDo(g, method, url, strings.NewReader(body), headers)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString("request failed"))
		return 2
	}
	pushScriptResponse(L, resp, respBody)
	return 2
}

// luaHTTPDownload implements http.download(url, filepath)
func luaHTTPDownload(L *lua.LState) int {
	g := GetGuard(L)
	url := L.ToString(1)
	filepath := L.ToString(2)

	if filepath == "" {
		L.Push(lua.LBool(false))
		L.Push(lua.LString("filepath is required"))
		return 2
	}
	if g != nil && g.Restricted {
		var err error
		filepath, err = resolveSandboxPath(g, filepath)
		if err != nil {
			L.Push(lua.LBool(false))
			L.Push(lua.LString("path escapes sandbox"))
			return 2
		}
	}

	resp, body, err := scriptHTTPDo(g, http.MethodGet, url, nil, nil)
	if err != nil {
		L.Push(lua.LBool(false))
		L.Push(lua.LString("request failed"))
		return 2
	}

	// Check response status
	if resp.StatusCode != http.StatusOK {
		L.Push(lua.LBool(false))
		L.Push(lua.LString(fmt.Sprintf("HTTP %d", resp.StatusCode)))
		return 2
	}

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		L.Push(lua.LBool(false))
		L.Push(lua.LString("failed to create file"))
		return 2
	}
	defer out.Close()

	// Write the response body to file
	written, err := out.Write(body)
	if err != nil {
		L.Push(lua.LBool(false))
		L.Push(lua.LString("failed to write file"))
		return 2
	}

	L.Push(lua.LBool(true))
	L.Push(lua.LString(fmt.Sprintf("downloaded %d bytes to %s", written, filepath)))
	return 2
}
