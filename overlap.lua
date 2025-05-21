-- minimal_overlap_test.lua
stream_tcp = {
    overlap_limit = 5  -- Set a low limit to trigger the alert quickly
}

local_rules = [[
alert tcp any any -> any any (msg:"TCP TEST"; sid:1000001; rev:1;)
]]
