-- minimal_config.lua
stream = { }

stream_tcp = {
    policy = 'first',
    overlap_limit = 0,
    session_timeout = 180
}

-- Simple rule to ensure traffic processing
local_rules = [[
alert tcp any any -> any any (msg:"TEST"; sid:1000001; rev:1;)
]]

ips = {
    rules = local_rules
}
