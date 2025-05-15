-- Minimal configuration for testing
HOME_NET = "any"
EXTERNAL_NET = "any"

include 'snort_defaults.lua'

-- Enable stream and TCP inspection
stream = { }
stream_tcp = { }

-- Simple rule to trigger reassembly
ips = {
    rules = [[
        alert tcp any any -> any any (msg:"TCP Reassembly Test"; flow:established,to_server; content:"TRIGGER"; sid:1000001;)
    ]]
}

-- Output configuration
alert_fast = { }
