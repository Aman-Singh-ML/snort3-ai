-- Extremely minimal configuration

-- Basic network configuration
HOME_NET = 'any'
EXTERNAL_NET = 'any'

-- Default port variables
HTTP_PORTS = '80'

-- Stream and TCP inspector setup (basic default config)
stream = { }
stream_tcp = { }

-- Include a basic rule to ensure something happens
local_rules = [[
alert tcp any any -> any any (msg:"TCP TEST"; sid:1000001; rev:1;)
]]
