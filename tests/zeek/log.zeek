# @TEST-DOC: Check that agent connectivity gets recorded in log file.
#
# @TEST-PORT: ZEEK_PORT
#
# @TEST-EXEC: btest-bg-run zeek  zeek ${FRAMEWORK} %INPUT
# @TEST-EXEC: btest-bg-run agent zeek-agent -c ${CONFIG} -L info -N -z localhost:${ZEEK_PORT}
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: cat zeek/zeek-agent.log | zeek-cut type_ >changes
# @TEST-EXEC: btest-diff changes

@load test-setup

hook ZeekAgent::log_policy(rec: ZeekAgent::Info, id: Log::ID,
    filter: Log::Filter)
	{
	if ( rec$type_ == "join" )
		terminate();
	}
