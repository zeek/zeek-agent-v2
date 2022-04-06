# @TEST-IGNORE

module TestSetup;

@if ( getenv("ZEEK_PORT") != "" )

@if ( Version::number >= 50000 )
redef Broker::default_port_websocket = to_port(getenv("ZEEK_PORT"));
@else
redef ZeekAgent::listen_port = to_port(getenv("ZEEK_PORT"));
@endif

@endif
