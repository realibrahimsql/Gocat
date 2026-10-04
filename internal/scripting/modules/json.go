package modules

import (
	"encoding/json"

	lua "github.com/yuin/gopher-lua"
)

// RegisterJSONModule registers JSON-related Lua functions
func RegisterJSONModule(L *lua.LState) {
	jsonModule := L.NewTable()

	L.SetField(jsonModule, "encode", L.NewFunction(luaJSONEncode))
	L.SetField(jsonModule, "decode", L.NewFunction(luaJSONDecode))
	L.SetField(jsonModule, "pretty", L.NewFunction(luaJSONPretty))

	L.SetGlobal("json", jsonModule)
}

// luaJSONEncode implements json.encode(table)
func luaJSONEncode(L *lua.LState) int {
	value := L.Get(1)

	goValue := luaToGo(value)

	jsonBytes, err := json.Marshal(goValue)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}

	L.Push(lua.LString(string(jsonBytes)))
	L.Push(lua.LNil)
	return 2
}

// luaJSONDecode implements json.decode(jsonString)
func luaJSONDecode(L *lua.LState) int {
	jsonStr := L.ToString(1)
	if len(jsonStr) > 1<<20 {
		L.Push(lua.LNil)
		L.Push(lua.LString("input capped at 1MB"))
		return 2
	}
	var data interface{}
	err := json.Unmarshal([]byte(jsonStr), &data)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}

	luaValue := goToLua(L, data)
	L.Push(luaValue)
	L.Push(lua.LNil)
	return 2
}

// luaJSONPretty implements json.pretty(jsonString)
func luaJSONPretty(L *lua.LState) int {
	jsonStr := L.ToString(1)

	var data interface{}
	err := json.Unmarshal([]byte(jsonStr), &data)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}

	prettyBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}

	L.Push(lua.LString(string(prettyBytes)))
	L.Push(lua.LNil)
	return 2
}

// luaToGo converts Lua values to Go values
func luaToGo(lv lua.LValue) interface{} {
	switch v := lv.(type) {
	case *lua.LNilType:
		return nil
	case lua.LBool:
		return bool(v)
	case lua.LNumber:
		return float64(v)
	case lua.LString:
		return string(v)
	case *lua.LTable:
		// Check if it's an array or object
		maxIndex := 0
		isArray := true

		v.ForEach(func(key, value lua.LValue) {
			if num, ok := key.(lua.LNumber); ok {
				if int(num) > maxIndex {
					maxIndex = int(num)
				}
			} else {
				isArray = false
			}
		})

		if isArray && maxIndex > 0 {
			// Convert to array
			arr := make([]interface{}, maxIndex)
			v.ForEach(func(key, value lua.LValue) {
				if num, ok := key.(lua.LNumber); ok {
					idx := int(num) - 1 // Lua arrays are 1-indexed
					if idx >= 0 && idx < len(arr) {
						arr[idx] = luaToGo(value)
					}
				}
			})
			return arr
		} else {
			// Convert to map
			m := make(map[string]interface{})
			v.ForEach(func(key, value lua.LValue) {
				keyStr := key.String()
				m[keyStr] = luaToGo(value)
			})
			return m
		}
	default:
		return v.String()
	}
}

// goToLua converts Go values to Lua values
func goToLua(L *lua.LState, value interface{}) lua.LValue {
	if value == nil {
		return lua.LNil
	}

	switch v := value.(type) {
	case bool:
		return lua.LBool(v)
	case int:
		return lua.LNumber(v)
	case int64:
		return lua.LNumber(v)
	case float64:
		return lua.LNumber(v)
	case string:
		return lua.LString(v)
	case []interface{}:
		table := L.NewTable()
		for i, item := range v {
			table.RawSetInt(i+1, goToLua(L, item)) // Lua arrays are 1-indexed
		}
		return table
	case map[string]interface{}:
		table := L.NewTable()
		for key, val := range v {
			table.RawSetString(key, goToLua(L, val))
		}
		return table
	default:
		// Try to convert to string
		data, _ := json.Marshal(v)
		return lua.LString(string(data))
	}
}
