-module(raven_logger_backend).
-export([ log/2
]).


log(LogEvent, _Config) ->
	case is_raven_log(LogEvent) of
		true  -> ok; % Dropping raven log, prevents log loop
		false ->
		raven_send_sentry_safe:capture(get_msg(LogEvent), parse_message(LogEvent))
	end.

is_raven_log(#{meta := Meta} = _LogEvent) ->
	case maps:is_key(report_cb, Meta) of
		false -> false;
		true  -> #{report_cb := Report} = Meta,
				 Report =:= fun ssl_logger:format/1
	end.

get_msg(#{msg := MsgList} = _LogEvent) ->
	case MsgList of
		{string, Msg}   -> Msg;
		{report, Msg}   -> parse_report_msg(Msg);
		{Format, Args} when is_list(Format) ->
						   make_readable(Format, Args);
		{_, _}	        -> "unexpected log format"
	end.

parse_report_msg(#{format := Format, args := Args} = Report) when is_map(Report)->
	make_readable(Format, Args);
parse_report_msg(_) ->
	"Not a map".

make_readable(Format, Args) ->
	iolist_to_binary(io_lib:format(Format, Args)).

parse_message(LogEvent) ->
	Meta = maps:get(meta, LogEvent),
	Msg  = get_msg(LogEvent),
	Level = sentry_level(maps:get(level, LogEvent)),
	[
		{level, Level},
%		{exception, {Class, Reason}},
%		{stacktrace, Stacktrace},
		{extra, lists:append(maps:to_list(Meta),
			[ {logEvent, LogEvent}
			, {reason, Msg}
			])}
	].

sentry_level(notice) -> info;
sentry_level(Level) -> Level.
