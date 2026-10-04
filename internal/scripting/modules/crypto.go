package modules

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	lua "github.com/yuin/gopher-lua"
)

// RegisterCryptoModule registers cryptographic Lua functions
func RegisterCryptoModule(L *lua.LState) {
	cryptoModule := L.NewTable()

	// Hash functions
	L.SetField(cryptoModule, "md5", L.NewFunction(luaMD5))
	L.SetField(cryptoModule, "sha1", L.NewFunction(luaSHA1))
	L.SetField(cryptoModule, "sha256", L.NewFunction(luaSHA256))

	// Encoding functions
	L.SetField(cryptoModule, "base64_encode", L.NewFunction(luaBase64Encode))
	L.SetField(cryptoModule, "base64_decode", L.NewFunction(luaBase64Decode))
	L.SetField(cryptoModule, "hex_encode", L.NewFunction(luaHexEncode))
	L.SetField(cryptoModule, "hex_decode", L.NewFunction(luaHexDecode))

	// Key generation
	L.SetField(cryptoModule, "generate_key", L.NewFunction(luaGenerateKey))

	L.SetGlobal("crypto", cryptoModule)
}

// GlobalAliases returns bare-global encoding helpers for backward
// compatibility with scripts written against the legacy flat API
// (hex_encode, base64_encode, ...). Pure functions, sandbox-safe.
func GlobalAliases() map[string]lua.LGFunction {
	return map[string]lua.LGFunction{
		"md5":           luaMD5,
		"sha1":          luaSHA1,
		"sha256":        luaSHA256,
		"base64_encode": luaBase64Encode,
		"base64_decode": luaBase64Decode,
		"hex_encode":    luaHexEncode,
		"hex_decode":    luaHexDecode,
	}
}

// luaMD5 implements crypto.md5(data)
func luaMD5(L *lua.LState) int {
	data := L.ToString(1)
	hash := md5.Sum([]byte(data))
	L.Push(lua.LString(hex.EncodeToString(hash[:])))
	return 1
}

// luaSHA1 implements crypto.sha1(data)
func luaSHA1(L *lua.LState) int {
	data := L.ToString(1)
	hash := sha1.Sum([]byte(data))
	L.Push(lua.LString(hex.EncodeToString(hash[:])))
	return 1
}

// luaSHA256 implements crypto.sha256(data)
func luaSHA256(L *lua.LState) int {
	data := L.ToString(1)
	hash := sha256.Sum256([]byte(data))
	L.Push(lua.LString(hex.EncodeToString(hash[:])))
	return 1
}

// luaBase64Encode implements crypto.base64_encode(data)
func luaBase64Encode(L *lua.LState) int {
	data := L.ToString(1)
	encoded := base64.StdEncoding.EncodeToString([]byte(data))
	L.Push(lua.LString(encoded))
	return 1
}

// luaBase64Decode implements crypto.base64_decode(data)
func luaBase64Decode(L *lua.LState) int {
	data := L.ToString(1)
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		L.Push(lua.LString(""))
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(lua.LString(string(decoded)))
	L.Push(lua.LNil)
	return 2
}

// luaHexEncode implements crypto.hex_encode(data)
func luaHexEncode(L *lua.LState) int {
	data := L.ToString(1)
	encoded := hex.EncodeToString([]byte(data))
	L.Push(lua.LString(encoded))
	return 1
}

// luaHexDecode implements crypto.hex_decode(data)
func luaHexDecode(L *lua.LState) int {
	data := L.ToString(1)
	decoded, err := hex.DecodeString(data)
	if err != nil {
		L.Push(lua.LString(""))
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(lua.LString(string(decoded)))
	L.Push(lua.LNil)
	return 2
}

// luaGenerateKey implements crypto.generate_key(length)
func luaGenerateKey(L *lua.LState) int {
	length := L.ToInt(1)
	if length <= 0 {
		length = 32
	}
	if length > 256 {
		L.Push(lua.LString(""))
		L.Push(lua.LString("key length capped at 256 bytes"))
		return 2
	}

	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		L.Push(lua.LString(""))
		L.Push(lua.LString(err.Error()))
		return 2
	}

	L.Push(lua.LString(hex.EncodeToString(key)))
	L.Push(lua.LNil)
	return 2
}
