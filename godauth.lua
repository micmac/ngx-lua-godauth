local json = require("cjson")
local configobject = require("configobject")

if not ngx.var.godauthconfigfile then
  error("Set $godauthconfigfile in your nginx config!")
end

local config = configobject.new("config")
local permmap = configobject.new("permmap")

-- utility functions, let's try to keep nginx dependencies here

function tohex(str)
    return (str:gsub('.', function (c)
        return string.format('%02x', string.byte(c))
    end))
end

function xlog(logline)
  ngx.log(0, logline)
end

function sha1_hex(data)
  return tohex(ngx.sha1_bin(data))
end

function now()
  if ngx.time then
    return ngx.time()
  else
    return os.time()
  end
end

function urlencode(str)
  return ngx.escape_uri(str)
end

function base64_decode(str)
  return ngx.decode_base64(str)
end

function create_ipranges(iplist)
  local ranges = {}
  for _, ip in pairs(iplist) do
    local m = string.gmatch(ip, '[0-9]+')
    local ipint = 0
    for i = 1,4 do
      ipint = ipint * 2^8 + m()
    end
    local mask = m() or 32
    mask = 2^(32-mask)
    local ipmin = ipint - ipint % mask
    local ipmax = ipmin + mask - 1
    table.insert(ranges, {[0]=ipmin, [1]=ipmax})
  end
  return ranges
end

function match_ipranges(ip, ranges)
  local m = string.gmatch(ip, '[0-9]+')
  local ipint = 0
  for i = 1,4 do
    ipint = ipint * 2^8 + m()
  end
  for i, range in pairs(ranges) do
    if ipint >= range[0] and ipint <= range[1] then
      return true
    end
  end
  return false
end


-- godauth part

-- validate_cookie
-- returns status, user, roles, timestamp
function validate_cookie(cookie, ua, cookie_secret)

  if not cookie then
    return 'COOKIE_MISSING'
  end

  -- sanitize user agent (separate function candidate)
  if ua then
    if string.match(ua, "AppleWebKit") then
      ua = "StupidAppleWebkitHacksGRRR"
    end
    string.gsub(ua, " FirePHP/%d+%.%d+", "")
  else
    ua = "missing_useragent"
  end

  local cookie_array = {}
  for i in string.gmatch(cookie, "[^-]+") do
    table.insert(cookie_array,i)
  end
  local cookie_hmac = table.remove(cookie_array)
  local ts = table.remove(cookie_array)
  local roles = table.remove(cookie_array)
  local user = table.concat(cookie_array, "-")

  local raw = table.concat({user, roles, ts, ua}, "-")
  local check_hmac = sha1_hex(cookie_secret .. raw)

  local status = 'COOKIE_INVALID'
  if cookie_hmac == check_hmac then
    local cookie_age = now() - ts
    if cookie_age > config:get("cookie_age_max") then
      status = 'COOKIE_OLD'
    elseif cookie_age < -config:get("cookie_future_max") then
      status = 'COOKIE_FUTURE'
    else
      status = 'COOKIE_OK'
    end
  else
    status = 'COOKIE_INVALID'
  end
  return status, user, roles, 0 + ts
end

function redirect_url(where, referer, args)
  local sep
  ref = urlencode("https://" .. referer)
  if string.find(where, "?", 0, true) then
    sep = "&"
  else
    sep = "?"
  end
  url = where .. sep .. "ref=" .. ref
  return url
end

function redir(url)
  return ngx.HTTP_INTERNAL_SERVER_ERROR
--  return ngx.redirect(url, ngx.HTTP_MOVED_TEMPORARILY)
end


-- permissions

function parse_rules(rules, url)
  if rules then
    for _, rule in pairs(rules) do
      if string.match(url, rule.url) then
        return rule.who
      end
    end
  end
  return "none"
end

function whitelist(remote_ip, url)
  local urls = config:get("whitelist_urls")
  local ipranges = config:get("whitelist_ipranges")
  local whitelist_regexp = create_ipranges(ipranges);

  if (match_ipranges(remote_ip, whitelist_regexp)) then
    for _, pattern in ipairs(urls) do
      if string.sub(pattern,1,1) == "^" then
        if string.match(url, string.sub(pattern,2)) then
          return true
        end
      else
        if url == pattern then
          return true
        end
      end
    end
  end
  return false;

end

function user_wants_basicauth(uri_params)
  return uri_params["god"] == "me"
end

function validate_basicauth(auth_header)
  if not auth_header then
    return nil
  end
  if auth_header == config:get("AuthHeader") then
    auth_creds_start = string.find(auth_header, " ") + 1
    auth_creds = string.sub(auth_header, auth_creds_start)
    local basic_userpw = base64_decode(auth_creds)
    local split = string.find(basic_userpw, ":")
    local basic_user = string.sub(basic_userpw,0,split-1)
    return basic_user
  else
    return nil
  end
end

-------
-- reload config if old

local tsnow = now()

if (not config:get("reload_interval")) or (config:get("timestamp") < tsnow - config:get("reload_interval")) then
  ngx.log(0, "Reloading config")
  ngx.log(0, config:load(ngx.var.godauthconfigfile))
  ngx.log(0, permmap:load(config:get("permmap_file")))
end


--  gather request data
local cookie_name = "cookie_" .. config:get("CookieName")
local cookie = ngx.var[cookie_name]
local ua = ngx.var.http_user_agent
local remote_ip = ngx.var.remote_addr
local myurl = ngx.var.host .. ngx.var.uri .. (ngx.var.args and ("?" .. ngx.var.args) or "")
xlog(string.format("Handling auth from %s to %s with cookie %s", remote_ip, myurl, cookie or "nil"))

---------
-- 0) handle whitelist

local wl = whitelist(remote_ip, myurl)
xlog("Whitelist: " .. (wl and "yes" or "no"))
if wl then
  ngx.exit(ngx.OK)
end


---------
-- check if we have a cookie secret

cookie_secret = config:get("CookieSecret") or "nottherightsecret"

---------
-- determine if we need to perform access control

local allow = parse_rules(permmap:get("rules"), myurl)

xlog("Allowed: " .. allow)

----------
-- 1) if we got 'all' or 'none' we're done

if allow == 'none' then
  return ngx.exit(ngx.HTTP_FORBIDDEN)
end

if allow == 'all' then
  return ngx.exit(ngx.OK)
end


----------
-- 2) check for basic auth

local wants_basic = user_wants_basicauth(ngx.req.get_uri_args())
xlog("Wants basic auth: " .. (wants_basic and "yes" or "no"))

local valid_basic = validate_basicauth(ngx.var.http_authorization)
xlog("Has valid basic auth: " .. (valid_basic or "no"))

if valid_basic then
  return ngx.exit(ngx.OK)
elseif wants_basic then
  return ngx.exit(ngx.HTTP_FORBIDDEN)
end

----------
-- 3) we might need auth, see if we have a valid cookie

local cookie_is_valid = validate_cookie(cookie, ua, cookie_secret)
xlog("Cookie: " .. cookie_is_valid)


local redir = nil

local cookie_errors = {
  COOKIE_MISSING = "FailNeedsAuth",
  COOKIE_OLD = "FailCookieOld",
  COOKIE_FUTURE = "FailCookieInvalid",
  COOKIE_INVALID = "FailCookieInvalid"
}

if cookie_is_valid == 'COOKIE_OK' then
  cookie_redirect = nil
else
  cookie_redirect = cookie_errors[cookie_is_valid]
  if not cookie_redirect then
    xlog("invalid return value '" .. cookie_is_valid .. "' from validate_cookie")
    cookie_redirect = cookie_errors["COOKIE_INVALID"]
  end
  redir = config:get(cookie_redirect)
end

redir_url = redirect_url(redir, myurl)
xlog("Redirect to: " .. redir_url)
if redir then
  return ngx.redirect(redir_url, ngx.HTTP_MOVED_TEMPORARILY)
end

ngx.headers['GodAuth-User'] = cookie_user
ngx.headers['GodAuth-Roles'] = cookie_roles
-- we won't add notes and environment, nginx doesn't support CGI

 ----------
 -- 5) exit now for authed

 if allow == 'authed' then
   return ngx.exit(ngx.OK)
 end

 ----------
 -- 6) check usernames/roles

local matches = {}
matches[cookie_user] = true
for r in string.gmatch(cookie_roles, "[^,]+") do
  matches[r] = true
end

local all_allowed = {}
local found_allow = false
for a in string.gmatch(allow, "[^,]+") do
  if matches[a] then
    found_allow = true
    break
  end
end

xlog("Allowed: " .. (found_allow and "yes" or "no"))

if not found_allow then
  redir = config:get("FailNotOnList")
  redir_url = redirect_url(redir, myurl)
  xlog("Redirect to: " .. redir_url)
  if redir then
    return ngx.redirect(redir_url, ngx.HTTP_MOVED_TEMPORARILY)
  end
else
  return ngx.exit(ngx.OK)
end
