-- crash_config.lua
-- Configure stream settings to maximize vulnerability potential
stream = { }

stream_tcp = {
    policy = 'first',           -- Use the most permissive TCP reassembly policy
    overlap_limit = 0,          -- Don't limit overlapping segments
    max_window = 65535,         -- Large window size
    session_timeout = 180,
    queue_limit = {
        max_bytes = 4194304,    -- Large queue size (4MB)
        max_segments = 3072     -- Large segment queue
    },
    reassemble_async = true,    -- This is a valid parameter
    small_segments = {
        count = 0,              -- Disable small segment protection
        maximum_size = 0
    }
}

-- Basic rule to ensure traffic gets inspected
local_rules = [[
alert tcp any any -> any any (msg:"TEST"; sid:1000001; rev:1;)
]]
ips = {
    rules = local_rules
}
