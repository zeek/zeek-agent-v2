# @TEST-DOC: Test the `ssh` table script end-to-end with mock data.
#
# @TEST-PORT: ZEEK_PORT
#
# @TEST-EXEC: btest-bg-run zeek  zeek ${FRAMEWORK} ${PACKAGE}/table/ssh.zeek %INPUT
# @TEST-EXEC: btest-bg-run agent zeek-agent -c ${CONFIG} -M -N -L info -z localhost:${ZEEK_PORT}
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: cat zeek/zeek-agent-ssh-authorized-keys.log | zeek-cut -cn host >tmp && mv tmp zeek/zeek-agent-ssh-authorized-keys.log
# @TEST-EXEC: btest-diff zeek/zeek-agent-ssh-authorized-keys.log
#
# Note: We can't test the configuration log because the agent can't mock the
# dynamic record content. Don't see a good way right now how we could do
# that.

@if ( getenv("ZEEK_PORT") != "" )
redef ZeekAgent::listen_port = to_port(getenv("ZEEK_PORT"));
@endif

redef ZeekAgent_SSH::subscription = ZeekAgent::SnapshotPlusDifferences;

# We only accept the 1st write writer so that our output doesn't depend on
# runtime duration.
global already_logged_keys = F;

hook ZeekAgent_SSH::log_policy_keys(rec: any, id: Log::ID, filter: Log::Filter)
{
	if ( already_logged_keys )
		break;
	else
		already_logged_keys = T;
}

event do_terminate()
{
	terminate();
}

event ZeekAgentAPI::agent_hello_v1(ctx: ZeekAgent::Context,
    columns: ZeekAgentAPI::AgentHelloV1)
{
	schedule 5 secs { do_terminate() };
}
