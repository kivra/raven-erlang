-module(raven_logger_backend).
-export([ log/2
]).

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

get_msg(#{msg := Msg, meta := Meta} = _LogEvent) ->
	case Msg of
		{string, String}                     -> String;
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
	{M, F, A} = maps:get(mfa, Meta, {undefined, undefined, undefined}),
	Line = maps:get(line, Meta, undefined),
	lists:flatten(io_lib:format("Unexpected log format in function: ~p:~p/~p line: ~p", [M, F, A, Line])).

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

sentry_level(notice) -> info;
sentry_level(Level) -> Level.

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
  error_logger:tty(false),
  meck:new(raven_send_sentry_safe, [passthrough]),
  meck:new(httpc, [passthrough]),
  meck:expect(raven_send_sentry_safe, capture, 2, fun mock_capture/2),
  meck:expect(httpc, set_options, 1, fun(_) -> ok end),
  meck:expect(httpc, request, 5, fun mock_request/5),
  ok = application:start(raven),
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
  ok = application:stop(raven),
  error_logger:tty(true),
  ok.

test_log_unknown() ->
  Msg = "whatisthis",
  Message = "Unexpected log format in function: m:f/0 line: 214",
  Args = [{level,info},
          {tags, [{correlation_id, "123456789"}]},
          {extra,[{line, 214},
                  {msg, "whatisthis"},
                  {reason, Message},
                  {mfa, {m, f, 0}},
                  {correlation_id,"123456789"}]}],
  run(Msg, Message, Args).

test_log_string() ->
  Msg = {string, "foo"},
  Message = "foo",
  Args = [{level,info},
          {tags, [{correlation_id, "123456789"}]},
          {extra,[{line, 214},
                  {reason,"foo"},
                  {mfa, {m, f, 0}},
                  {correlation_id,"123456789"}]}],
  run(Msg, Message, Args).

test_log_format() ->
  Msg = {"Foo ~p", [14]},
  Message = "Foo ~p",
  Args = [{level,info},
          {tags, [{correlation_id, "123456789"}]},
          {extra,[{line, 214},
                  {msg,<<"Foo 14">>},
                  {reason,"Foo ~p"},
                  {mfa, {m, f, 0}},
                  {correlation_id,"123456789"}]}],
  run(Msg, Message, Args).

test_log_report() ->
  Msg = {report, #{description => "gunnar",
                   a => "foo",
                   b => "bar"}},
  Message = "gunnar",
  Args = [{level,info},
          {tags, [{correlation_id, "123456789"}]},
          {extra,[{a,"foo"},
                  {b,"bar"},
                  {description,"gunnar"},
                  {line, 214},
                  {reason,"gunnar"},
                  {mfa, {m, f, 0}},
                  {correlation_id,"123456789"}]}],
  run(Msg, Message, Args).

test_log_report_with_compound_description() ->
  Msg = {report, #{description => {namn, "gunnar"},
                   a => "foo",
                   b => "bar"}},
  Message = {namn, "gunnar"},
  Args = [{level,info},
          {tags, [{correlation_id, "123456789"}]},
          {extra,[{a,"foo"},
                  {b,"bar"},
                  {description,{namn, "gunnar"}},
                  {line, 214},
                  {reason,{namn, "gunnar"}},
                  {mfa, {m, f, 0}},
                  {correlation_id,"123456789"}]}],
  run(Msg, Message, Args).

test_log_unknown_report() ->
  Msg = {report, #{a => "foo",
                   b => "bar"}},
  Message = "Unexpected log format in function: m:f/0 line: 214",
  Args = [{level,info},
          {tags, [{correlation_id, "123456789"}]},
          {extra,[{a,"foo"},
                  {b,"bar"},
                  {line, 214},
                  {reason, Message},
                  {mfa, {m, f, 0}},
                  {correlation_id,"123456789"}]}],
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
    mfa => {m, f, 0},
    line => 214}.

sort_args(Args) ->
  SortedExtras = lists:sort(proplists:get_value(extra, Args)),
  lists:sort([{extra, SortedExtras} | proplists:delete(extra, Args)]).

mock_capture(Message, Args) ->
  raven:capture(Message, Args).

mock_request(_Op, {_Path, _Headers, _Type, Body}, _, _, ?RAVEN_HTTPC_PROFILE) ->
  _ = jsx:decode(zlib:uncompress(base64:decode(Body))),
  {ok, {{foo,200,bar},[],<<"body">>}}.

-endif.
