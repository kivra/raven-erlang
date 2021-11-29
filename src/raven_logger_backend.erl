-module(raven_logger_backend).
-export([ log/2
]).

-define(META_FILTER, [gl,pid,time,file,line,mfa,span_ctx]).

log(LogEvent, _Config) ->
	case is_httpc_log(LogEvent) of
		true  -> ok; %Dropping httpc log, prevents log loop
		false ->
			Message = get_msg(LogEvent),
			Args = get_args(Message, LogEvent),
			raven_send_sentry_safe:capture(Message, Args)
	end.

is_httpc_log(#{meta := Meta} = _LogEvent) ->
	case maps:is_key(report_cb, Meta) of
		false -> false;
		true  -> #{report_cb := Report} = Meta,
				 Report =:= fun ssl_logger:format/1
	end.

get_msg(#{msg := MsgList, meta := Meta} = _LogEvent) ->
	case MsgList of
		{string, Msg}                        -> Msg;
		{report, Report}                     -> get_msg_from_report(Report, Meta);
		{Format, _Args} when is_list(Format) -> Format;
		_                                    -> "Not an expected log format"
	end.

%% Specific choice of msg
get_msg_from_report(#{format := Format, args := Args} = _Report, _Meta) ->
	make_readable(Format, Args);
get_msg_from_report(#{description := Description} = _Report, _Meta) ->
	Description;
get_msg_from_report(#{reason := Reason} = _Report, _Meta) ->
	Reason;
get_msg_from_report(#{error := Error} = _Report, _Meta) ->
	Error;
%% If no specific choice, then use provided report_cb
get_msg_from_report(Report, #{error_logger := #{report_cb := Report_cb}} = _Meta) when is_function(Report_cb) ->
	{Format, Args} = Report_cb(Report),
	make_readable(Format, Args);
get_msg_from_report(Report, #{report_cb := Report_cb} = _Meta) when is_function(Report_cb) ->
	{Format, Args} = Report_cb(Report),
	make_readable(Format, Args);
%% If nothing provided, then give up
get_msg_from_report(_Report, _Meta) ->
	"Not an expected report log format".

make_readable(Format, Args) ->
	try
		iolist_to_binary(io_lib:format(Format, Args))
	catch
		Exception:Reason -> iolist_to_binary(io_lib:format("Error in log format string: ~p:~p", [Exception, Reason]))
	end.

get_args(Message, LogEvent) ->
	Level      = sentry_level(maps:get(level, LogEvent)),
	Meta       = maps:get(meta, LogEvent),
	MetaBasic  = maps:without(?META_FILTER, Meta),
	MetaExtra  = maps:with(?META_FILTER, Meta),
	Msg        = maps:get(msg, LogEvent),
	Reason     = Message,
	Basic      = MetaBasic#{level => Level},
	Extra      = get_extra(Reason, MetaExtra, Msg),

	BasicList  = proplists:from_map(Basic),
	ExtraList  = proplists:from_map(Extra),

	BasicList ++ [{extra, ExtraList}].

sentry_level(notice) -> info;
sentry_level(Level) -> Level.

get_extra(Reason, ExtraMeta, {report, Report}) ->
	Extra = maps:merge(ExtraMeta, Report),
	Extra#{reason => Reason};
get_extra(Reason, ExtraMeta, {string, _String}) ->
	ExtraMeta#{reason => Reason};
get_extra(Reason, ExtraMeta, {Format, Args}) when is_list(Format) ->
	Msg = make_readable(Format, Args),
	ExtraMeta#{ reason => Reason
	          , msg => Msg};
get_extra(Reason, ExtraMeta, Msg) ->
	ExtraMeta#{ reason => Reason
                  , msg => Msg}.
