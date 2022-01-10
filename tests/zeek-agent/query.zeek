# @TEST-DOC: Test a basic query to the agent.
#
# @TEST-PORT: ZEEK_PORT
#
# @TEST-EXEC: btest-bg-run zeek  zeek ${PACKAGE} %INPUT
# @TEST-EXEC: btest-bg-run agent zeek-agent -L info -N -z localhost:${ZEEK_PORT}
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff zeek/.stdout

@if ( getenv("ZEEK_PORT") != "" )
redef Broker::default_port = to_port(getenv("ZEEK_PORT"));
@endif

type Columns: record {
	version: int;
};

event got_result(ctx: ZeekAgent::Context, data: Columns)
	{
	print ctx$cookie, data;
	terminate();
	}

event zeek_init()
	{
	ZeekAgent::query([$sql_stmt="SELECT agent_version FROM zeek_agent", $event_=got_result, $cookie="Hurz", $schedule_=10secs]);
	}
