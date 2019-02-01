--require openssl
--@see https://www.openssl.org/docs/man1.1.0/crypto/RC4.html
local ffi = require "ffi"
local ffi_new = ffi.new
local C = ffi.C
local ffi_str = ffi.string
local type = type

local _M = {
    _VERSION = '0.0.1'
}

-- @see https://docs.huihoo.com/doxygen/openssl/1.0.1c/rc4__skey_8c_source.html
-- void private_RC4_set_key(RC4_KEY *key, int len, const unsigned char *data);

-- @see openssl/include/openssl/rc5.h
ffi.cdef [[
    typedef struct rc4_key_st
    {
        unsigned int x,y;
        unsigned int data[256];
    } RC4_KEY;

    void RC4_set_key(RC4_KEY *key,int len,const unsigned char *data);

    void RC4(RC4_KEY *key,size_t len,const unsigned char *indata,unsigned char *outdata);
]]

local rc4_key_ptr_type = ffi.typeof("RC4_KEY[1]")
local RC4_set_key = C.RC4_set_key
local RC4 = C.RC4

local function crypt(data, key)
    if type(data) ~= "string" then
        return nil, "require string type only"
    end
    local text_len = #data
    if text_len == 0 then
        return data
    end
    local cipher_text = ffi_new("unsigned char[?]", text_len)
    local rc4_key = ffi_new(rc4_key_ptr_type)
    RC4_set_key(rc4_key, #key, key)
    RC4(rc4_key, text_len, data, cipher_text)
    return ffi_str(cipher_text, text_len)
end

_M.compile = crypt

_M.encrypt = crypt

_M.decrypt = crypt

return _M