-- TCP reassembler crash test configuration

-- Define network setup
HOME_NET = "any"
EXTERNAL_NET = "any"

-- Include default variables
include 'snort_defaults.lua'

-- Stream configuration with aggressive reassembly settings
stream = { }

stream_tcp = {
    -- Enable reassembly
    policy = 'windows',
    
    -- Flush on content
    flush_factor = 0,
    
    -- Small segments more likely to trigger edge cases
    small_segments = {
        count = 1,
        maximum_size = 1
    },
    
    -- Enable midstream pickups to test more edge cases
    midstream = true,
    
    -- Set a small queue limit to force flush conditions
    queue_limit = { 
        max_bytes = 8192,
        max_segments = 20
    },
    
    -- Enable overlap processing
    overlap_limit = 10,
    
    -- Enable reassembly for all ports
    reassembly_ports = { all = true }
}

-- Create a simple rule to trigger the reassembly
ips = {
    enable_builtin_rules = false,
    rules = [[
        alert tcp any any -> any any (msg:"TCP Reassembly Test"; flow:established,to_server; content:"TRIGGER"; sid:1000001;)
    ]]
}

-- Enable verbose logging and stats
logging = {
    show_year = true,
    console = true
}

-- Enable alerts to see when the rule matches
alerts = {
    alert_with_interface_name = true,
    output = 'full'
}

-- Turn on all packet dumps for debugging
packet_tracer = {
    enable = true
}

profiler = {
    memory = { show = true },
    rules = { show = true }
}
