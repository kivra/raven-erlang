-module(raven_error_logger).

-behaviour(gen_event).
-export([
	init/1,
	code_change/3,
	terminate/2,
	handle_call/2,
	handle_event/2,
	handle_info/2
]).


init(_) ->
	{ok, []}.

handle_call(_, State) ->
	{ok, ok, State}.

handle_event({error, _, {Pid, Format, Data}}, State) ->
    capture(parse_message(error, Pid, Format, Data)),
	{ok, State};
handle_event({error_report, _, {Pid, Type, Report}}, State) ->
    capture(parse_report(error, Pid, Type, Report)),
	{ok, State};

handle_event({warning_msg, _, {Pid, Format, Data}}, State) ->
    capture(parse_message(warning, Pid, Format, Data)),
	{ok, State};
handle_event({warning_report, _, {Pid, Type, Report}}, State) ->
    capture(parse_report(warning, Pid, Type, lists:sort(Report))),
	{ok, State};

handle_event(_, State) ->
	{ok, State}.

handle_info(_, State) ->
	{ok, State}.

code_change(_, State, _) ->
	{ok, State}.

terminate(_, _) ->
	ok.

%% @private
capture(mask) ->
    ok;
capture({Message, Details}) ->
    raven:capture(Message, Details).

%% @private
parse_message(error = Level, Pid, "** Generic server " ++ _, [Name, LastMessage, State, Reason]) ->
	%% gen_server terminate
	{Exception, Stacktrace} = parse_reason(Reason),
	{format_exit(gen_server, Name, Reason), [
		{level, Level},
		{exception, Exception},
		{stacktrace, Stacktrace},
		{extra, [
			{name, Name},
			{pid, Pid},
			{last_message, LastMessage},
			{state, State},
			{reason, Reason}
		]}
	]};
parse_message(error = Level, Pid, "** State machine " ++ _, [Name, LastMessage, StateName, State, Reason]) ->
	%% gen_fsm terminate
	{Exception, Stacktrace} = parse_reason(Reason),
	{format_exit(gen_fsm, Name, Reason), [
		{level, Level},
		{exception, Exception},
		{stacktrace, Stacktrace},
		{extra, [
			{name, Name},
			{pid, Pid},
			{last_message, LastMessage},
			{state, State},
			{state_name, StateName},
			{reason, Reason}
		]}
	]};
parse_message(error = Level, Pid, "** gen_event handler " ++ _, [ID, Name, LastMessage, State, Reason]) ->
	%% gen_event terminate
	{Exception, Stacktrace} = parse_reason(Reason),
	{format_exit(gen_event, Name, Reason), [
		{level, Level},
		{exception, Exception},
		{stacktrace, Stacktrace},
		{extra, [
			{id, ID},
			{name, Name},
			{pid, Pid},
			{last_message, LastMessage},
			{state, State},
			{reason, Reason}
		]}
	]};
parse_message(error = Level, Pid, "** Generic process " ++ _, [Name, LastMessage, State, Reason]) ->
	%% gen_process terminate
	{Exception, Stacktrace} = parse_reason(Reason),
	{format_exit(gen_process, Name, Reason), [
		{level, Level},
		{exception, Exception},
		{stacktrace, Stacktrace},
		{extra, [
			{name, Name},
			{pid, Pid},
			{last_message, LastMessage},
			{state, State},
			{reason, Reason}
		]}
	]};
parse_message(error = Level, Pid, "Error in process " ++ _,
              [Name, Node, [ {reason, Reason}
                           , {mfa, {Handler, _, _}}
                           , {stacktrace, Stacktrace}
                           | Extras ]]) ->
	%% cowboy_handler terminate
	{format_exit(process, Name, {Reason, Stacktrace}), [
		{level, Level},
		{exception, {exit, Reason}},
		{stacktrace, Stacktrace},
		{extra, [
			{name, Name},
			{pid, Pid},
			{node, Node},
			{handler, Handler} | Extras
		]}
	]};
parse_message(error = Level, Pid, "Error in process " ++ _, [Name, Node, Reason]) ->
	%% process terminate
	{Exception, Stacktrace} = parse_reason(Reason),
	{format_exit(process, Name, Reason), [
		{level, Level},
		{exception, Exception},
		{stacktrace, Stacktrace},
		{extra, [
			{name, Name},
			{pid, Pid},
			{node, Node},
			{reason, Reason}
		]}
	]};
parse_message(_Level, _Pid, "Ranch listener " ++ _, _Data) ->
    mask;
%% Start of Kivra specific
parse_message(error = Level, Pid, "Unhandled error: ~p~n~p",
			  [[{method, Method}, {url, Url}, {headers, Headers}],
			   {unknown_error, Error}] = Data) ->
	{format("Unhandled error: ~p", [Error]), [
		{level, Level},
		{http_request, {Method, Url, Headers}},
		{extra, [
			{pid, Pid},
			{data, Data}
		]} |
		case Error of
			{lifted_exn, Exception, Stacktrace} ->
				[{exception,  Exception},
				 {stacktrace, Stacktrace}];
			_ ->
				[]
		end
	]};
parse_message(Level, Pid, "Error: ~p" ++ _ = Format, [{failed, _Reason} = Exception | _] = Data) ->
	{format(Format, Data), [
		{level, Level},
		{exception, Exception},
		{extra, [
			{pid, Pid}
		]}
	]};
parse_message(Level, Pid, "Error: ~p" ++ _ = Format, [{failed, Reason, Extras} | Rest])
		when is_list(Extras) ->
	{format(Format, [{failed, Reason} | Rest]), [
		{level, Level},
		{exception, {failed, Reason}},
		{extra, [
			{pid, Pid} |
			[ {Key, Value} || {Key, Value} <- Extras, is_atom(Key) ]
		]}
	]};
parse_message(Level, Pid, "[~p] " ++ _ = Format, [Operation | _] = Data) when is_atom(Operation) ->
	{format(Format, Data), [
		{level, Level},
		{exception, {failed, Operation}},
		{extra, [
			{pid, Pid}
		]}
	]};
parse_message(Level, Pid, "~p: ~p no transition for ~p" = Format, [ID, Name, Event] = Data) ->
	{format(Format, Data), [
		{level, Level},
		{exception, {failed,
		             {mechanus_modron, transition, [{state, Name}, {event, Event}]}}},
		{extra, [
			{pid, Pid},
			{state, Name},
			{event, Event},
			{modron_id, ID}
		]}
	]};
parse_message(Level, Pid, "~p: action ~p failed: ~p",
	          [ID, Action, {lifted_exn, Exception, Stacktrace}]) ->
	{format("~p: action ~p failed", [ID, Action]), [
		{level, Level},
		{exception, Exception},
		{stacktrace, Stacktrace},
		{extra, [
			{pid, Pid},
			{action, Action},
			{modron_id, ID}
		]}
	]};
parse_message(Level, Pid, "~p: action ~p failed: ~p" = Format, [ID, Action, Rsn] = Data) ->
	{format(Format, Data), [
		{level, Level},
		{exception, {failed, {mechanus_modron, action, Action, Rsn}}},
		{extra, [
			{pid, Pid},
			{action, Action},
			{modron_id, ID}
		]}
	]};
parse_message(_Level, Pid, "{~p, ~p} error: ~p, attempt ~p of ~p" = Format,
		[B, _K, Rsn, Attempt, MaxAttempts] = Data) when Attempt < MaxAttempts ->
	{format(Format, Data), [
		{level, warning},
		{exception, {krc_error, {B, Rsn}}},
		{extra, [
			{pid, Pid},
			{data, Data}
		]}
	]};
parse_message(Level, Pid, "** Exception: ~p~n"
						  "** Reason: ~p~n"
						  "** Stacktrace: ~p~n" ++ _ = Format,
						  [ {badmatch, {rollback, function_clause, [{M, F, Args, _} | _]}}
						  , _Rsn
						  , Stacktrace
						  | _
						  ] = Data) ->
	ExceptionValue =
		case Args of
			[Arg1|_] when is_atom(Arg1) -> {M, F, [Arg1|'_']};
			_                           -> {M, F, length(Args)}
		end,
	{format(Format, Data), [
		{level, Level},
		{exception, {{badmatch, {rollback, function_clause, '...'}}, ExceptionValue}},
		{stacktrace, Stacktrace},
		{extra, [
			{pid, Pid}
		]}
	]};
parse_message(Level, Pid, "** Exception: ~p~n"
						  "** Reason: ~p~n"
						  "** Stacktrace: ~p~n" ++ _ = Format,
						  [ {badmatch, {rollback, Exception, [{M, F, Arity, _} | _]}}
						  , _Rsn
						  , Stacktrace
						  | _
						  ] = Data) ->
	{format(Format, Data), [
		{level, Level},
		{exception, {{badmatch, {rollback, Exception, '...'}}, {M, F, Arity}}},
		{stacktrace, Stacktrace},
		{extra, [
			{pid, Pid}
		]}
	]};
% Mask warnings for failed tasks in KKng
parse_message(warning = _Level, _Pid, "failed task: ~w", [_Tid]) ->
	mask;
%% End of Kivra specific
parse_message(Level, Pid, Format, Data) ->
	{format(Format, Data), [
		{level, Level},
		{extra, [
			{pid, Pid},
			{data, Data}
		]}
	]}.


%% @private
parse_report(Level, Pid, crash_report, [Report, Neighbors]) ->
	Name = case proplists:get_value(registered_name, Report, []) of
		[] -> proplists:get_value(pid, Report);
		N -> N
	end,
	case Name of
		undefined ->
			{<<"Process crashed">>, [
				{level, Level},
				{extra, [
					{pid, Pid},
					{neighbors, Neighbors} |
					Report
				]}
			]};
		_ ->
			{Class, R, Trace} = proplists:get_value(error_info, Report, {error, unknown, []}),
			Reason = {{Class, R}, Trace},
			{Exception, Stacktrace} = parse_reason(Reason),
			{format_exit("Process", Name, Reason), [
				{level, Level},
				{exception, Exception},
				{stacktrace, Stacktrace},
				{extra, [
					{name, Name},
					{pid, Pid},
					{reason, Reason} |
					Report
				]}
			]}
	end;
parse_report(Level, Pid, supervisor_report, [{errorContext, Context}, {offender, Offender}, {reason, Reason}, {supervisor, Supervisor}]) ->
	{Exception, Stacktrace} = parse_reason(Reason),
	{format("Supervisor ~s had child exit with reason ~s", [format_name(Supervisor), format_reason(Reason)]), [
		{level, Level},
		{logger, supervisors},
		{exception, Exception},
		{stacktrace, Stacktrace},
		{extra, [
			{supervisor, Supervisor},
			{context, Context},
			{pid, Pid},
			{child_pid, proplists:get_value(pid, Offender)},
			{mfa, format_mfa(proplists:get_value(mfargs, Offender))},
			{restart_type, proplists:get_value(restart_type, Offender)},
			{child_type, proplists:get_value(child_type, Offender)},
			{shutdown, proplists:get_value(shutdown, Offender)}
		]}
	]};
parse_report(info, Pid, progress, [{started, Started}, {supervisor, Supervisor}]) ->
	Message = case proplists:get_value(name, Started, []) of
		[] -> format("Supervisor ~s started child", [format_name(Supervisor)]);
		Name -> format("Supervisor ~s started ~s", [format_name(Supervisor), format_name(Name)])
	end,
	{Message, [
		{level, info},
		{logger, supervisors},
		{extra, [
			{supervisor, Supervisor},
			{pid, Pid},
			{child_pid, proplists:get_value(pid, Started)},
			{mfa, format_mfa(proplists:get_value(mfargs, Started))},
			{restart_type, proplists:get_value(restart_type, Started)},
			{child_type, proplists:get_value(child_type, Started)},
			{shutdown, proplists:get_value(shutdown, Started)}
		]}
	]};
parse_report(Level, Pid, Type, Report) ->
	Message = case proplists:get_value(message, Report, []) of
		[] -> <<"Report from process">>;
		M -> format_string(M)
	end,
	{Toplevel, Extra} = lists:partition(fun
		({exception, _}) -> true;
		({stacktrace, _}) -> true;
		(_) -> false
	end, Report),
	{Message, [
		{level, Level},
		{extra, [
			{type, Type},
			{pid, Pid} |
			lists:keydelete(message, 1, Extra)
		]} |
		Toplevel
	]}.


%% @private
parse_reason({'function not exported', Stacktrace}) ->
	{{exit, undef}, parse_stacktrace(Stacktrace)};
parse_reason({bad_return, {_MFA, {'EXIT', Reason}}}) ->
	parse_reason(Reason);
parse_reason({bad_return, {MFA, Value}}) ->
	{{exit, {bad_return, Value}}, parse_stacktrace(MFA)};
parse_reason({bad_return_value, Value}) ->
	{{exit, {bad_return, Value}}, []};
parse_reason({{bad_return_value, Value}, MFA}) ->
	{{exit, {bad_return, Value}}, parse_stacktrace(MFA)};
parse_reason({badarg, Stacktrace}) ->
	{{error, badarg}, parse_stacktrace(Stacktrace)};
parse_reason({'EXIT', Reason}) ->
	parse_reason(Reason);
parse_reason({Reason, Child}) when is_tuple(Child) andalso element(1, Child) =:= child ->
	parse_reason(Reason);
parse_reason({{Class, Reason}, Stacktrace}) when Class =:= exit; Class =:= error; Class =:= throw ->
	{{Class, Reason}, parse_stacktrace(Stacktrace)};
parse_reason({Reason, Stacktrace}) ->
	{{exit, Reason}, parse_stacktrace(Stacktrace)};
parse_reason(Reason) ->
	{{exit, Reason}, []}.

%% @private
parse_stacktrace({_, _, _} = MFA) -> [MFA];
parse_stacktrace({_, _, _, _} = MFA) -> [MFA];
parse_stacktrace([{_, _, _} | _] = Trace) -> Trace;
parse_stacktrace([{_, _, _, _} | _] = Trace) -> Trace;
parse_stacktrace(_) -> [].


%% @private
format_exit(Tag, Name, Reason) when is_pid(Name) ->
	format("~s terminated with reason: ~s", [Tag, format_reason(Reason)]);
format_exit(Tag, Name, Reason) ->
	format("~s ~s terminated with reason: ~s", [Tag, format_name(Name), format_reason(Reason)]).

%% @private
format_name({local, Name}) -> Name;
format_name({global, Name}) -> format_string(Name);
format_name({via, _, Name}) -> format_string(Name);
format_name(Name) -> format_string(Name).

%% @private
format_reason({'function not exported', Trace}) ->
	["call to undefined function ", format_mfa(Trace)];
format_reason({undef, Trace}) ->
	["call to undefined function ", format_mfa(Trace)];
format_reason({bad_return, {_MFA, {'EXIT', Reason}}}) ->
	format_reason(Reason);
format_reason({bad_return, {Trace, Val}}) ->
	["bad return value ", format_term(Val), " from ", format_mfa(Trace)];
format_reason({bad_return_value, Val}) ->
	["bad return value ", format_term(Val)];
format_reason({{bad_return_value, Val}, Trace}) ->
	["bad return value ", format_term(Val), " in ", format_mfa(Trace)];
format_reason({{badrecord, Record}, Trace}) ->
	["bad record ", format_term(Record), " in ", format_mfa(Trace)];
format_reason({{case_clause, Value}, Trace}) ->
	["no case clause matching ", format_term(Value), " in ", format_mfa(Trace)];
format_reason({function_clause, Trace}) ->
	["no function clause matching ", format_mfa(Trace)];
format_reason({if_clause, Trace}) ->
	["no true branch found while evaluating if expression in ", format_mfa(Trace)];
format_reason({{try_clause, Value}, Trace}) ->
	["no try clause matching ", format_term(Value), " in ", format_mfa(Trace)];
format_reason({badarith, Trace}) ->
	["bad arithmetic expression in ", format_mfa(Trace)];
format_reason({{badmatch, Value}, Trace}) ->
	["no match of right hand value ", format_term(Value), " in ", format_mfa(Trace)];
format_reason({emfile, _Trace}) ->
	"maximum number of file descriptors exhausted, check ulimit -n";
format_reason({system_limit, [{M, F, _}|_] = Trace}) ->
	Limit = case {M, F} of
		{erlang, open_port} ->
			"maximum number of ports exceeded";
		{erlang, spawn} ->
			"maximum number of processes exceeded";
		{erlang, spawn_opt} ->
			"maximum number of processes exceeded";
		{erlang, list_to_atom} ->
			"tried to create an atom larger than 255, or maximum atom count exceeded";
		{ets, new} ->
			"maximum number of ETS tables exceeded";
		_ ->
			format_mfa(Trace)
	end,
	["system limit: ", Limit];
format_reason({badarg, Trace}) ->
	["bad argument in ", format_mfa(Trace)];
format_reason({{badarity, {Fun, Args}}, Trace}) ->
	{arity, Arity} = lists:keyfind(arity, 1, erlang:fun_info(Fun)),
	[io_lib:format("fun called with wrong arity of ~w instead of ~w in ", [length(Args), Arity]), format_mfa(Trace)];
format_reason({noproc, Trace}) ->
	["no such process or port in call to ", format_mfa(Trace)];
format_reason({{badfun, Term}, Trace}) ->
	["bad function ", format_term(Term), " in ", format_mfa(Trace)];
format_reason({Reason, [{M, F, A}|_] = Trace}) when is_atom(M), is_atom(F), is_integer(A) ->
	[format_reason(Reason), " in ", format_mfa(Trace)];
format_reason({Reason, [{M, F, A, Props}|_] = Trace}) when is_atom(M), is_atom(F), is_integer(A), is_list(Props) ->
	[format_reason(Reason), " in ", format_mfa(Trace)];
format_reason(Reason) ->
	format_term(Reason).

%% @private
format_mfa([{_, _, _} = MFA | _]) ->
	format_mfa(MFA);
format_mfa([{_, _, _, _} = MFA | _]) ->
	format_mfa(MFA);
format_mfa({M, F, A, _}) ->
	format_mfa({M, F, A});
format_mfa({M, F, A}) when is_list(A) ->
	{Format, Args} = format_args(A, [], []),
	format("~w:~w(" ++ Format ++ ")", [M, F | Args]);
format_mfa({M, F, A}) when is_integer(A) ->
	format("~w:~w/~w", [M, F, A]);
format_mfa(Term) ->
	format_term(Term).

%% @private
format_args([], FormatAcc, ArgsAcc) ->
	{string:join(lists:reverse(FormatAcc), ", "), lists:reverse(ArgsAcc)};
format_args([Arg | Rest], FormatAcc, ArgsAcc) ->
	format_args(Rest, ["~s" | FormatAcc], [format_term(Arg) | ArgsAcc]).

%% @private
format_string(Term) when is_atom(Term); is_binary(Term) ->
	format("~s", [Term]);
format_string(Term) ->
	try format("~s", [Term]) of
		Result -> Result
	catch
		error:badarg -> format_term(Term)
	end.

%% @private
format_term(Term) ->
	format("~120p", [Term]).

%% @private
format(Format, Data) ->
	iolist_to_binary(kivra_io:format(Format, Data)).
