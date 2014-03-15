local _P = {}

local _myname = "unnamed configobject"
local _data = {}

local P_mt = { __index = _P }
local objects = {}

json = require("cjson")

function _P.new(name)
  if not objects[name] then
    local newP = {
      _myname = name,
      _data = {}
    }
    objects[name] = setmetatable(newP, P_mt)
  end
  return objects[name]
end


function _P:set_name(name)
  self._myname = name
end

function _P:store(configtable)
  configtable.timestamp = self._data.timestamp
  self._data = configtable
end

function _P:get(key)
  return self._data[key]
end

function _P:set(key, value)
  self._data[key] = value
end

function _P:get_keys()
  local keys = {}
  for ck, _ in pairs(self._data) do
    table.insert(keys,ck)
  end
  return keys
end

function _P:load(json_file)
  local cf = io.open(json_file)
  self._data.timestamp = now()
  if not cf then
    return "Config file open failed for " .. json_file
  end
  
  local cj = cf:read("*a")
  local ctmp = json.decode(cj)
  if ctmp then
    self:store(ctmp)
  end
  return "Config `" .. self._myname .. "' reloaded, timestamp " .. self._data.timestamp
end

ngx.log(0, "Configobject loaded")

return _P
