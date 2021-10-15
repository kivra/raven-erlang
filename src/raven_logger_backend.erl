-module(raven_logger_backend).
-export([
	log/2
]).


log(LogEvent, _Config) ->
	case is_raven_log(LogEvent) of
		true  -> ok; % Dropping raven log, prevents log loop
		false ->
		raven:capture(get_msg(LogEvent), parse_message(LogEvent))
	end.

is_raven_log(#{meta := Meta} = _LogEvent) ->
	case maps:is_key(report_cb, Meta) of
		false -> false;
		true  -> #{report_cb := Report} = Meta,
				 Report =:= fun ssl_logger:format/1
	end.

get_msg(#{msg := MsgList} = _LogEvent) ->
	case MsgList of
		{string, Msg}  -> Msg;
		{report, _Msg} -> "rapport";
		{_, _Msg}      -> "not expected"
	end.

parse_message(LogEvent) ->
	Meta = maps:get(meta, LogEvent),
	Msg  = get_msg(LogEvent),
	Level = maps:get(level, LogEvent),
	[
		{level, Level},
%		{exception, {Class, Reason}},
%		{stacktrace, Stacktrace},
		{extra, [
			{name, "Name"},
			{pid, maps:get(pid, Meta)},
			{last_event, "LastEvent"},
			{state_name, "StateName"},
			{state_data, "StateData"},
			{callback_mode, "CallbackMode"},
			{reason, LogEvent}
		]}
	].

