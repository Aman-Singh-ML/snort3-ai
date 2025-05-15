-- Absolute minimal config targeting TCP reassembler
HOME_NET = "any"
EXTERNAL_NET = "any"
include 'snort_defaults.lua'

stream = { }
stream_tcp = {
    policy = 'first',
    flush_factor = 0,
    segment_timeout = 1,
    queue_limit = { max_bytes = 1024 },
    small_segments = { count = 1, maximum_size = 1 }
}

ips = {
    rules = [[
        alert tcp any any -> any any (msg:"Trigger Flush"; content:"TRIGGER_FLUSH"; sid:1;)
    ]]
}
