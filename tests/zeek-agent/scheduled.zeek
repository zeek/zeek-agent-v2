# @TEST-DOC: Test a repeatedly scheduled query with cancel.
#
# @TEST-PORT: ZEEK_PORT
#
# @TEST-EXEC: btest-bg-run zeek  zeek ${PACKAGE} %INPUT
# @TEST-EXEC: btest-bg-run agent zeek-agent -L info -N -z localhost:${ZEEK_PORT} >output
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff zeek/.stdout

@if ( getenv("ZEEK_PORT") != "" ) redef Broker::default_port = to_port(getenv("ZEEK_PORT"));
@endif

type Columns : record {
	id: string;
	version: int;
};

event do_terminate() { terminate(); }

global query_id : string;
global n = 0;

event got_result(ctx : ZeekAgent::Context, data : Columns)
	{
	print "got result:", data;

	if ( ++n == 2 ) {
		ZeekAgent::cancel(query_id);
		print "terminating soon - there should not be another 'got result' after this";
		schedule 5secs {do_terminate()};
	}
}

event zeek_init()
	{
	query_id = ZeekAgent::query([
		$sql_stmt = "SELECT id, agent_version FROM zeek_agent", $event_ = got_result, $cookie = "Hurz",
		$schedule_ = 3secs
	]);
	}
