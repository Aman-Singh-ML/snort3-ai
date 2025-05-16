-- Minimal TCP configuration to reproduce TcpSession::restart() issue

-- Basic stream configuration
stream = 
{
    -- Enable TCP processing
    tcp = { }
}

-- Stream TCP module configuration - only essential parameters
stream_tcp = 
{
    -- Enable midstream session pickup which can trigger restart()
    midstream = true,
    -- We don't need a 3-way handshake
    require_3whs = false,
    -- Windows policy is typically most permissive
    policy = 'windows'
}
