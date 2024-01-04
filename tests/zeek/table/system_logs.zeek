# @TEST-DOC: Test the `system-logs` table script end-to-end with mock data.
#
# @TEST-PORT: ZEEK_PORT
#
# @TEST-EXEC: btest-bg-run zeek  zeek ${FRAMEWORK} ${PACKAGE}/table/system-logs.zeek %INPUT
# @TEST-EXEC: btest-bg-run agent zeek-agent -c ${CONFIG} -M -N -L info -z localhost:${ZEEK_PORT}
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: cat zeek/zeek-agent-system-logs.log | zeek-cut -cn host >tmp && mv tmp zeek/zeek-agent-system-logs.log
# @TEST-EXEC: btest-diff zeek/zeek-agent-system-logs.log

@load test-setup

redef ZeekAgent_SystemLogs::query_interval = 1sec;

# We only accept the 2nd write writer so that our output doesn't depend on
# runtime duration (1st write is empty).
global already_logged = 0;

hook ZeekAgent_SystemLogs::log_policy(rec: any, id: Log::ID,
    filter: Log::Filter)
	{
	if ( ++already_logged != 2 )
		break;
	}

event do_terminate()
	{
	terminate();
	}

event ZeekAgentAPI::agent_hello_v1(ctx: ZeekAgent::Context,
    columns: ZeekAgentAPI::AgentHelloV1)
	{
	schedule 4secs { do_terminate() };
	}
