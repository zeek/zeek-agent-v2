##! Internal API between Zeek and Zeek Agent.
##!
##! Note that some of the public types inside the ZeekAgent namespace are part
##! of the API as well.

@load ./types

module ZeekAgentAPI;

export {
	## Agent-side ``hello`` record broadcasted regularly by all agents.
	##
	## The record's field correspond directly to the agents' `zeek_agent`
	## table.
	type HelloV1: record {
		agent_id: string;
		instance_id: string;
		hostname: string &optional;
		address: string &optional;
		platform: string &optional;
		os_name: string &optional;
		kernel_name: string &optional;
		kernel_version: string &optional;
		kernel_arch: string &optional;
		agent_version: int &optional;
		broker: string &optional;
		uptime: int &optional;
	};

	## Regularly broadcasted by all connected agents.
	global agent_hello_v1: event(ctx: ZeekAgent::Context, columns: HelloV1);

	## Broadcasted by agents on regular shutdown.
	global agent_shutdown_v1: event(ctx: ZeekAgent::Context);

	## Send to Zeek by an agent if it encountered an error with a query.
	global agent_error_v1: event(ctx: ZeekAgent::Context, msg: string);

	## Regularly broadcasted by Zeek.
	global zeek_hello_v1: event(zeek_instance: string);

	## Broadcasted by Zeek on regular shutdown.
	global zeek_shutdown_v1: event(zeek_instance: string);

	## Sends query to agents.
	global install_query_v1: event(zeek_instance: string, query_id: string, query: ZeekAgent::Query);

	## Cancels a previously sent query with agents.
	global cancel_query_v1: event(zeek_instance: string, query_id: string);
}
