local require = require
local tools = require("wtf.core.tools")
local Plugin = require("wtf.core.classes.plugin")
local route = require "resty.route".new()

local _M = Plugin:extend()
_M.name = "honeybot.fake.asa"
config = {}

function set_headers(hdrs)
  local ngx = ngx
  local pairs = pairs
  ngx.header["Server"] = nil
  
  if hdrs then
    for key,val in pairs(hdrs) do
      ngx.header[key] = val
    end
  end
end

function get_file_extension(url)
  return url:match("^.+%.(.+)$")
end

function set_static_headers()
  local headers = {}
  headers["Pragma"] = "no-cache"
  headers["Date"] = ngx.http_time(ngx.time())
  headers["Cache-Control"] = "no-store"
  headers["X-Frame-Options"] = "SAMEORIGIN"
  headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
  
  local ext = get_file_extension(ngx.var.uri)
  local ct = ""
  if ext == "txt" then
    ct = "text/plain"
  elseif ext == "html" then
    ct = "text/html"
  elseif ext == "css" then
    ct = "text/css; charset=utf-8"
  elseif ext == "js" then
    ct = "application/javascript"
  elseif ext == "gif" then
    ct = "image/gif"
  elseif ext == "jpg" or ext == "jpeg" then
    ct = "image/jpg"
  else
    ct = "text/html"
  end
  headers["Content-Type"] = ct
  set_headers(headers)
end

function set_empty_headers(webvpn)
  local headers = {}
  headers["Content-Type"] = "text/plain"  
  headers["Pragma"] = "no-cache"
  headers["Date"] = ngx.http_time(ngx.time())
  headers["Cache-Control"] = "no-store"
  headers["X-Frame-Options"] = "SAMEORIGIN"
  headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
  if webvpn ~= nil then
    headers["webvpn"] = webvpn
  end
  set_headers(headers)
end

function set_redirect_headers(location)
  local headers = {}
  ngx.header["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
  ngx.header["Content-Length"] = "0"
  ngx.header["Content-Type"] = nil
  ngx.header["Date"] = nil
  ngx.header["Connection"] = nil
  ngx.header["Server"] = nil
  ngx.header["Location"] = location
  -- set_headers(headers)
end

function set_dynamic_headers()
  local headers = {}
  local cookie_webvpn = "webvpn=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure"
  local cookie_webvpn_as = "webvpn_as=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure"
  local cookie_webvpnc = "webvpnc=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure"
  local cookie_webvpn_portal = "webvpn_portal=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure"
  local coookie_webvpnSharePoint = "webvpnSharePoint=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure"
  local cookie_samlPreauthSessionHash = "samlPreauthSessionHash=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure"
  local cookie_webvpnlogin = "webvpnlogin=1; path=/; secure"
  local cookie_acSamlv2Token = "acSamlv2Token=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure"
  local cookie_acSamlv2Error = "acSamlv2Error=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure"
  local cookie_webvpnLang = "webvpnLang=en; path=/; secure"
  
  headers["Content-Type"] = "text/html; charset=utf-8"  
  headers["Set-Cookie"] = {cookie_webvpn, cookie_webvpn_as, cookie_webvpnc, cookie_webvpn_portal, coookie_webvpnSharePoint, cookie_samlPreauthSessionHash, cookie_webvpnlogin, cookie_acSamlv2Token,cookie_acSamlv2Error, cookie_webvpnLang}
  headers["Cache-Control"] = "no-store"
  headers["Pragma"] = "no-cache"
  headers["Date"] = ngx.http_time(ngx.time())
  headers["X-Frame-Options"] = "SAMEORIGIN"
  headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

  set_headers(headers)
end

function send_response(state, content)
  ngx.ctx.response_from_lua = 1
  ngx.status = state
  ngx.print(content)
  ngx.exit(state)
end

function not_found_302(self)
  set_redirect_headers("/+CSCOE+/message.html?mc=2")
  send_response(302, "")
end

function not_found(self)
  local headers = {}
  ngx.header["Content-Type"] = nil
  ngx.header["Server"] = nil
  ngx.header["Pragma"] = "no-cache"
  ngx.header["Date"] = ngx.http_time(ngx.time())
  ngx.header["Cache-Control"] = "no-store"
  ngx.header["X-Frame-Options"] = "SAMEORIGIN"
  ngx.header["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
  send_response(404, "File not found")
end

function not_found_404(self)
  set_headers({["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"})
  send_response(404, "404 Not Found\n")
end

function static(self, path)
  if path == "" or path == "/" then path = "index.html" end
  local filename = config["asa_datapath"] .. config["asa_version"] .. "/" .. path
  local template = io.open(filename, "rb")
  if template ~= nil then
    local page = template:read "*a"
    set_static_headers()
    send_response(200, page)
  else
    not_found_302()
  end
end

function static_cscou(self, path)
  if path == "" or path == nil or path == "/" then path = "/index.html" end
  local filename = config["asa_datapath"] .. config["asa_version"] .. "/+CSCOU+/".. path
  local template = io.open(filename, "rb")
  if template ~= nil then
    local page = template:read "*a"
    set_static_headers()
    send_response(200, page)
  else
    not_found()
  end
end

function static_cscoe(self, path)
  if path == "" or path == nil or path == "/" then 
    path = "/index.html"
  end
  local filename = config["asa_datapath"] .. config["asa_version"] .. "/+CSCOE+/".. path
  local template = io.open(filename, "rb")
  if template ~= nil then
    local page = template:read "*a"
    set_static_headers()
    send_response(200, page)
  else
    not_found()
  end
end

function static_webvpn(self, path)
  if path == "" or path == nil or path == "/" then path = "/index.html" end
  local filename = config["asa_datapath"] .. config["asa_version"] .. "/+webvpn+/".. path
  local template = io.open(filename, "rb")
  if template ~= nil then
    local page = template:read "*a"
    set_static_headers()
    send_response(200, page)
  else
    not_found_404()
  end
end

function index(self)
  local filename = config["asa_datapath"] .. config["asa_version"] .. "/index.html"
  local template = io.open(filename, "rb")
  if template ~= nil then
    local page = template:read "*a"
    set_dynamic_headers()
    send_response(200, page)
  else
    not_found()
  end
end

function logon(self)
  local referer = ngx.var.http_referer
  if referer == nil then referer = "" end
  local filename = config["asa_datapath"] .. config["asa_version"] .. "/+CSCOE+/"
  if referer:find("/%+webvpn%+/index%.html") then
    filename = filename .. "failed_logon.html"
  else
    filename = filename .. "logon.html"
  end
  local template = io.open(filename, "rb")
  if template ~= nil then
    local page = template:read "*a"
    set_dynamic_headers()
    send_response(200, page)
  else
    not_found()
  end
end

function webvpn(self)
  local filename = config["asa_datapath"] .. config["asa_version"] .. "/+webvpn+/index.html"
  local template = io.open(filename, "rb")
  if template ~= nil then
    local page = template:read "*a"
    set_dynamic_headers()
    send_response(200, page)
  else
    not_found()
  end
end

function empty(self)
  set_empty_headers(nil)
  send_response(200, "")
end

function session_password(self)
  set_empty_headers("")
  send_response(200, "")
end

function _M:init(...)
  local select = select
  local instance = select(1, ...)
  config["asa_version"] = self:get_optional_parameter('version')
  config["asa_datapath"] = self:get_optional_parameter('path')

  route "=/" (index)
  route "=/index.html" (index)
  route "=/+webvpn+/index.html" (webvpn)
  route "=/+CSCOE+/logon.html" (logon)
  route "=/+CSCOU+/session_password.html" {
    get = (empty),
    post = (session_password)
  }
  route "#/%+CSCOU%+/(.*)" (static_cscou)
  route "#/%+CSCOE%+/(.*)" (static_cscoe)
  route "#/%+webvpn%+/(.*)" (static_webvpn)
  route "#/(.+)" (static)
  
	return self
end

function _M:content(...)
  route:dispatch(ngx.var.uri, ngx.var.request_method)
end

return _M
