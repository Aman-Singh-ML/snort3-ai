-- TCP configuration that could lead to restart() being called
-- with improper packet structure

-- Basic configuration
ips = 
{
    -- Enable rules that can trigger fast_pattern matching for TCP traffic
    enable_builtin_rules = true,
    rules = [[
        alert tcp any any -> any any (msg:"TCP TEST"; sid:1000001; rev:1;)
    ]]
}

-- Stream TCP module configuration
stream_tcp = 
{
    -- Configure a very small segment limit to force reassembly conditions
    small_segments = 
    {
        count = 3,
        maximum_size = 16,
    },
    -- Set a very small flush point to force frequent flush operations
    flush_factor = 10,
    -- Set session timeout values low to force session state changes
    session_timeout = 10,
    max_window = 2048,
    -- Enable all TCP reassembly options
    policy = 'windows',
    -- Enable TCP session restart on out-of-order data
    session_on_syn = true,
    reassemble_async = true,
    -- Specifically enable midstream session pickup which can trigger restart()
    midstream = true,
    -- Generate events that might trigger the restart case
    max_consec_small_segs = 3,
    max_consec_small_seg_size = 16,
    -- These options increase packet processing complexity
    require_3whs = false,
    overlap_limit = 5,
}

-- Configure output for debugging
output = 
{
    -- Enable packet trace for debugging
    packet_trace = { file = true }
}

-- Configure a decoder rule that might help trigger the condition
local_rules =
[[
alert tcp any any -> any any (msg:"BACKDOOR netcat attempt"; flow:to_server; content:"nc "; depth:3; metadata:ruleset community; classtype:misc-activity; sid:107; rev:8;)
]]
