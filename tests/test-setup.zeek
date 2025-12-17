# @TEST-IGNORE

module TestSetup;

# This follows testing/btest/cluster/websocket/server/default.zeek.

# Redef snippet for running XPUB/XSUB on ephemeral ports.
@load base/utils/numbers
module Cluster::Backend::ZeroMQ;

global xpub_port = extract_count(getenv("XPUB_PORT"));
global xsub_port = extract_count(getenv("XSUB_PORT"));
redef listen_xsub_endpoint = fmt("tcp://127.0.0.1:%s", xsub_port);
redef connect_xpub_endpoint = listen_xsub_endpoint;
redef listen_xpub_endpoint = fmt("tcp://127.0.0.1:%s", xpub_port);
redef connect_xsub_endpoint = listen_xpub_endpoint;
# Redef snippet ===
