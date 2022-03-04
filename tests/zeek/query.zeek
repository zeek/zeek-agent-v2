# @TEST-DOC: Test a basic query to the agent.
#
# @TEST-PORT: ZEEK_PORT
#
# @TEST-EXEC: btest-bg-run zeek  zeek ${FRAMEWORK} %INPUT
# @TEST-EXEC: btest-bg-run agent zeek-agent -c ${CONFIG} -L info -N -z localhost:${ZEEK_PORT}
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: cat zeek/.stdout | sed 's/version=[0-9]\{1,\}/version=<version>/g' >zeek/output
# @TEST-EXEC: btest-diff zeek/output

@if ( getenv("ZEEK_PORT") != "" )
redef ZeekAgent::listen_port = to_port(getenv("ZEEK_PORT"));
@endif

type Columns: record {
	version: count;
};

event got_result(ctx: ZeekAgent::Context, data: Columns) {
	print ctx$cookie, data;
	terminate();
}

event zeek_init() {
	ZeekAgent::query([$sql_stmt = "SELECT agent_version FROM zeek_agent", $event_ = got_result, $cookie = "Hurz", $schedule_ = 20 secs]);
}
