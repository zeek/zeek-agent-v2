# @TEST-DOC: Test a query to the agent that requires a non-existent table. Should not generate an error.
#
# @TEST-PORT: ZEEK_PORT
#
# @TEST-EXEC: btest-bg-run zeek  zeek ${FRAMEWORK} %INPUT
# @TEST-EXEC: btest-bg-run agent zeek-agent -c ${CONFIG} -L debug -N -z localhost:${ZEEK_PORT}
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: test '!' -f reporter.log
# @TEST-EXEC: btest-diff zeek/.stdout

@if ( getenv("ZEEK_PORT") != "" )
redef Broker::default_port = to_port(getenv("ZEEK_PORT"));
@endif

event do_terminate() {
	terminate();
}

event got_result() { # can't get here
    }

event zeek_init() {
	ZeekAgent::query([$sql_stmt = "SELECT foo FROM bar", $event_ = got_result, $requires_tables = set("bar")]);
	schedule 5 secs { do_terminate() };
}

event ZeekAgentAPI::agent_error_v1(ctx: ZeekAgent::Context, msg: string) {
	print "SHOULD NOT HAPPEN", msg;
}
