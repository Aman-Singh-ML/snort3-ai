-- crash_config.lua

-- Basic configuration
stream = { 
    tcp_cache = { max_sessions = 262144 } -- Large session cache
}

stream_tcp = {
    policy = 'first',  -- Use most permissive reassembly policy
    overlap_limit = 0, -- No limit on overlapping segments
    max_window = 0,    -- No window limit
    flush_factor = 0,  -- Disable flush factor
    session_timeout = 180,
    queue_limit = {
        max_bytes = 4194304, -- Very large queue (4MB)
        max_segments = 3072  -- Large number of segments
    },
    small_segments = {
        count = 0,      -- Disable small segment protection
        maximum_size = 0
    }
}

-- Enable all active responses (for testing normalization)
active = {
    attempts = 2, 
    enabled = true,
}

-- Create a simple rule to ensure the traffic is processed
local_rules = [[
alert tcp any any -> any any (msg:"TEST"; sid:1000001; rev:1;)
]]

ips = {
    rules = local_rules,
    enable_builtin_rules = true
}

-- Enable detailed logging
logging = {
    show_year = true,
    include_vlan = true
}

-- Run in detailed debug mode
process = { 
    daemon = false,
    dirty_pig = true,  -- Continue processing after corruption detected
    show_pass_packets = true
}
