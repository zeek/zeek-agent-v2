# @TEST-DOC: Test the `processes` table script end-to-end with mock data.
#
# @TEST-PORT: ZEEK_PORT
#
# @TEST-EXEC: btest-bg-run zeek  zeek ${FRAMEWORK} ${PACKAGE}/table/processes.zeek %INPUT
# @TEST-EXEC: btest-bg-run agent zeek-agent -M -N -L info -z localhost:${ZEEK_PORT}
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff zeek/zeek-agent-processes.log

@if ( getenv("ZEEK_PORT") != "" )
redef Broker::default_port = to_port(getenv("ZEEK_PORT"));
@endif

global seen: set[Log::ID];

hook Log::log_stream_policy(rec: any, id: Log::ID)
        {
	# We only accept the 1st write per log writer so that our output
	# doesn't depend on runtime duration.
	if ( id in seen )
		break;
	else
		add seen[id];
        }

event do_terminate() { terminate(); }

event ZeekAgentAPI::agent_hello_v1(ctx: ZeekAgent::Context, columns: ZeekAgentAPI::HelloV1)
	{
	schedule 2secs { do_terminate() };
	}
