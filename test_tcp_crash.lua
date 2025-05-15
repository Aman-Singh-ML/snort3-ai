-- TCP reassembler crash test configuration - simplified version
-- Define network setup
HOME_NET = "any"
EXTERNAL_NET = "any"

-- Include default variables
include 'snort_defaults.lua'

-- Basic stream configuration
stream = { }

stream_tcp = { 
    policy = 'windows',
    
    -- Small segments to trigger edge cases
    small_segments = {
        count = 1,
        maximum_size = 1
    },
    
    -- Set a small queue limit to force flush conditions
    queue_limit = { 
        max_bytes = 8192,
        max_segments = 20
    },
    
    -- Enable overlap processing
    overlap_limit = 10
}

-- Enable stream inspection for all tcp traffic
binder = {
    { when = { proto = 'tcp' }, use = { type = 'stream' } }
}

-- Create a simple rule to trigger the reassembly
ips = {
    enable_builtin_rules = false,
    rules = [[
        alert tcp any any -> any any (msg:"TCP Reassembly Test"; flow:established,to_server; content:"TRIGGER"; sid:1000001;)
    ]]
}

-- Configure logging
logging = {
    show_year = true,
    console = true
}

-- Configure alert output
alert_fast = {
    file = true,
    packet = false
}

-- Turn on all packet dumps for debugging
packet_tracer = {
    enable = true
}

-- Performance monitoring
profiler = {
    memory = { show = true },
    rules = { show = true }
}
