-- queue_limit_test.lua
stream_tcp = {
    max_queued_bytes = 8192,  -- Set a low byte limit
    max_queued_segs = 10      -- Set a low segment limit
}

local_rules = [[
alert tcp any any -> any any (msg:"TCP TEST"; sid:1000001; rev:1;)
]]
