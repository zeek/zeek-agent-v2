# @TEST-DOC: Test a query to the agent that requires a table to not exist. Should not generate any result.
#
# @TEST-PORT: ZEEK_PORT
#
# @TEST-EXEC: btest-bg-run zeek  zeek ${FRAMEWORK} %INPUT
# @TEST-EXEC: btest-bg-run agent zeek-agent -c ${CONFIG} -L debug -N -z localhost:${ZEEK_PORT}
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: test '!' -f reporter.log
# @TEST-EXEC: btest-diff zeek/.stdout

@if ( getenv("ZEEK_PORT") != "" )
redef ZeekAgent::listen_port = to_port(getenv("ZEEK_PORT"));
@endif

type Columns: record {
	version: int;
};

event got_result(ctx: ZeekAgent::Context, data: Columns) {
	print "SHOULD NOT HAPPEN 1";
	terminate();
}

event do_terminate() {
	terminate();
}

event zeek_init() {
	ZeekAgent::query([$sql_stmt = "SELECT agent_version FROM zeek_agent", $event_ = got_result, $cookie = "Hurz", $if_missing_tables = set("zeek_agent")]);
	schedule 5 secs { do_terminate() };
}

event ZeekAgentAPI::agent_error_v1(ctx: ZeekAgent::Context, msg: string) {
	print "SHOULD NOT HAPPEN 2", msg;
}
