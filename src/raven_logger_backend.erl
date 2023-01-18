-module(raven_logger_backend).
-export([log/2]).
-ignore_xref([log/2]).

-include_lib("kernel/include/logger.hrl").
-include("raven.hrl").

%% see here: https://develop.sentry.dev/sdk/event-payloads/
-define(ATTRIBUTE_FILTER, [ event_id, timestamp, platform, level, logger,
                            transaction, server_name, release, dist, tags,
                            environment, modules, extra, fingerprint, errors,
                            user, http_request, stacktrace, exception]).

%% API

log(LogEvent, _Config) ->
	try log(LogEvent)
	catch _:Reason:StackTrace ->
		LE = list_to_binary(lists:flatten(io_lib:format("~0p", [LogEvent]))),
		ST = list_to_binary(lists:flatten(io_lib:format("~0p", [StackTrace]))),
		?LOG_WARNING(#{ message => <<"Raven logger backend crashed">>,
				crash_message => LE,
				reason => Reason,
				stacktrace => ST})
	end.

%% Private

log(LogEvent) ->
	case is_loop(LogEvent) of
		true  -> ok; %% Dropping prevents log loop
		false ->
			Message = get_msg(LogEvent),
			Args = get_args(Message, LogEvent),
			raven_send_sentry_safe:capture(Message, Args)
	end.

is_loop(LogEvent) ->
	is_log_crash_log(LogEvent) or is_httpc_log(LogEvent).

is_log_crash_log(#{msg := Msg} = _LogEvent) ->
	case Msg of
		{report, #{ message := <<"Raven logger backend crashed">>,
			    crash_message := _,
			    reason := _,
			    stacktrace := _}} ->
			true;
		_ ->
			false
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
		_                                    -> unexpected_log_format(Meta)
	end.

%% Specific choice of msg
get_msg_from_report(#{format := Format, args := Args} = _Report, _Meta) ->
	make_readable(Format, Args);
get_msg_from_report(#{description := Description} = _Report, _Meta) ->
	Description;
get_msg_from_report(#{message := Message} = _Report, _Meta) ->
        Message;
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
get_msg_from_report(_Report, Meta) ->
	unexpected_log_format(Meta).

unexpected_log_format(Meta) ->
  	Module = maps:get(module, Meta),
	"Unexpected log format in module: " ++ atom_to_list(Module).


make_readable(Format, Args) ->
	try
		iolist_to_binary(io_lib:format(Format, Args))
	catch
		Exception:Reason -> iolist_to_binary(io_lib:format("Error in log format string: ~p:~p", [Exception, Reason]))
	end.

get_args(Message, LogEvent) ->
	Level      = sentry_level(maps:get(level, LogEvent)),
	Meta       = maps:get(meta, LogEvent),
	MetaBasic  = maps:with(?ATTRIBUTE_FILTER, Meta),
	MetaExtra  = maps:without(?ATTRIBUTE_FILTER, Meta),
	Msg        = maps:get(msg, LogEvent),
	Reason     = get_reason_maybe(LogEvent, Message),
	Basic      = MetaBasic#{level => Level},
	Extra      = get_extra(Reason, MetaExtra, Msg),

	BasicList  = maps:to_list(Basic),
	ExtraList  = maps:to_list(Extra),

	case maps:get(correlation_id, Meta, undefined) of
		undefined ->
			BasicList ++ [{extra, ExtraList}];
		CorrelationID ->
			BasicList ++ [{extra, ExtraList},
                                      {tags, [{correlation_id, CorrelationID}]}]
	end.

%% Map otp logger severity to sentry severity
%% Sentry levels are: fatal, error, warning, info, debug
%% Otp levels are:
%%   emergency:	system is unusable
%%   alert:      action must be taken immediately
%%   critical:  critical conditions
%%   error:	    error conditions
%%   warning:	  warning conditions
%%   notice:    normal but significant conditions
%%   info:      informational messages
%%   debug:     debug-level messages
sentry_level(emergency) -> fatal;
sentry_level(alert)     -> fatal;
sentry_level(critical)  -> error;
sentry_level(error)     -> error;
sentry_level(warning)   -> warning;
sentry_level(notice)    -> info;
sentry_level(info)      -> info;
sentry_level(debug)     -> debug;
sentry_level(_)         -> debug. %% ?

get_reason_maybe(#{msg := {report, #{reason := Reason}}} = _LogEvent, _Default) ->
        Reason;
get_reason_maybe(_LogEvent, Default) ->
        Default.

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

%%%_* Tests ============================================================
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

logger_backend_test_() ->
  { setup,
    fun test_setup/0,
    fun test_teardown/1,
    [ fun test_log_unknown/0,
      fun test_log_string/0,
      fun test_log_format/0,
      fun test_log_report/0,
      fun test_log_report_with_compound_description/0,
      fun test_log_unknown_report/0
    ]
  }.

test_setup() ->
  persistent_term:put(?RAVEN_SSL_PERSIST_KEY, {ssl, []}),
  meck:new(raven_send_sentry_safe),
  meck:new(httpc),
  meck:expect(raven_send_sentry_safe, capture, 2, fun mock_capture/2),
  meck:expect(httpc, set_options, 1, fun(_) -> ok end),
  meck:expect(httpc, request, 5, fun mock_request/5),
  application:start(raven), %% To se key vsn
  application:set_env(raven, ipfamily, dummy),
  application:set_env(raven, uri, "http://foo"),
  application:set_env(raven, public_key, <<"hello">>),
  application:set_env(raven, private_key, <<"there">>),
  application:set_env(raven, project, "terraform mars").

test_teardown(_) ->
  meck:unload([raven_send_sentry_safe]),
  meck:unload([httpc]),
  application:unset_env(raven, ipfamily),
  application:unset_env(raven, uri),
  application:unset_env(raven, public_key),
  application:unset_env(raven, private_key),
  application:unset_env(raven, project),
  application:stop(raven),
  persistent_term:erase(?RAVEN_SSL_PERSIST_KEY),
  ok.

test_log_unknown() ->
  Msg = "whatisthis",
  Message = "Unexpected log format in module: ievan_polka",
  Args = [{correlation_id,"123456789"},
          {level,info},
          {module, ievan_polka},
          {tags, [{correlation_id, "123456789"}]},
          {extra,[{line, 214},
                  {msg, "whatisthis"},
                  {reason,"Unexpected log format in module: ievan_polka"}]}],
  run(Msg, Message, Args).

test_log_string() ->
  Msg = {string, "foo"},
  Message = "foo",
  Args = [{correlation_id,"123456789"},
          {level,info},
          {module, ievan_polka},
          {tags, [{correlation_id, "123456789"}]},
          {extra,[{line, 214},
                  {reason,"foo"}]}],
  run(Msg, Message, Args).

test_log_format() ->
  Msg = {"Foo ~p", [14]},
  Message = "Foo ~p",
  Args = [{correlation_id,"123456789"},
          {level,info},
          {module, ievan_polka},
          {tags, [{correlation_id, "123456789"}]},
          {extra,[{line, 214},
                  {msg,<<"Foo 14">>},
                  {reason,"Foo ~p"}]}],
  run(Msg, Message, Args).

test_log_report() ->
  Msg = {report, #{description => "gunnar",
                   a => "foo",
                   b => "bar"}},
  Message = "gunnar",
  Args = [{correlation_id,"123456789"},
          {level,info},
          {module, ievan_polka},
          {tags, [{correlation_id, "123456789"}]},
          {extra,[{a,"foo"},
                  {b,"bar"},
                  {description,"gunnar"},
                  {line, 214},
                  {reason,"gunnar"}]}],
  run(Msg, Message, Args).

test_log_report_with_compound_description() ->
  Msg = {report, #{description => {namn, "gunnar"},
                   a => "foo",
                   b => "bar"}},
  Message = {namn, "gunnar"},
  Args = [{correlation_id,"123456789"},
          {level,info},
          {module, ievan_polka},
          {tags, [{correlation_id, "123456789"}]},
          {extra,[{a,"foo"},
                  {b,"bar"},
                  {description,{namn, "gunnar"}},
                  {line, 214},
                  {reason,{namn, "gunnar"}}]}],
  run(Msg, Message, Args).

test_log_unknown_report() ->
  Msg = {report, #{a => "foo",
                   b => "bar"}},
  Message = "Unexpected log format in module: ievan_polka",
  Args = [{correlation_id,"123456789"},
          {level,info},
          {module, ievan_polka},
          {tags, [{correlation_id, "123456789"}]},
          {extra,[{a,"foo"},
                  {b,"bar"},
                  {line, 214},
                  {reason,"Unexpected log format in module: ievan_polka"}]}],
  run(Msg, Message, Args).

run(Msg, ExpectedMessage, ExpectedArgs) ->
  meck:reset([raven_send_sentry_safe, httpc]),
  Event = event(Msg),
  log(Event, []),
  [{_Pid, MFA, _}] = meck:history(raven_send_sentry_safe),
  {raven_send_sentry_safe, capture, [Message, Args]} = MFA,
  ?assertEqual(ExpectedMessage, Message),
  ?assertEqual(sort_args(ExpectedArgs), sort_args(Args)).

event(Msg) ->
  Level = info,
  Meta = meta(),
  #{level => Level, meta => Meta, msg => Msg}.

meta() ->
  #{correlation_id => "123456789",
    module => ievan_polka,
    line => 214}.

sort_args(Args) ->
  SortedExtras = lists:sort(proplists:get_value(extra, Args)),
  lists:sort([{extra, SortedExtras} | proplists:delete(extra, Args)]).

mock_capture(Message, Args) ->
  raven:capture(Message, Args).

mock_request(_Op, {_Path, _Headers, _Type, Body}, _, _, ?RAVEN_HTTPC_PROFILE) ->
  Decoded = jsx:decode(zlib:uncompress(base64:decode(Body))),
  io:format(user, "~n~p~n", [Decoded]),
  {ok, {{foo,200,bar},[],<<"body">>}}.

-endif.
