-module(raven).
-export([
	capture/2,
	capture_prepare/2,
	capture_with_backoff_send/2,
	user_agent/0
]).

-define(SENTRY_VERSION, "2.0").

-record(cfg, {
	uri :: string(),
	public_key :: string(),
	private_key :: string(),
	project :: string(),
	ipfamily :: atom(),
	release :: binary() | undefined
}).

-type cfg_rec() :: #cfg{}.

-spec capture(string() | binary(), [parameter()]) -> ok.
-type parameter() ::
	{stacktrace, [stackframe()]} |
	{exception, {exit | error | throw, term()}} |
	{atom(), binary() | integer()}.
-type stackframe() ::
	{module(), atom(), non_neg_integer() | [term()]} |
	{module(), atom(), non_neg_integer() | [term()], [{atom(), term()}]}.
capture(Message, Params) when is_list(Message) ->
	capture(unicode:characters_to_binary(Message), Params);
capture(Message, Params) ->
	{ok, Body} = capture_prepare(Message, Params),
	capture_with_backoff_send(Body, false).

capture_prepare(Message, Params) ->
	Cfg = get_config(),
	Document = [
		{event_id, event_id_i()},
		{project, unicode:characters_to_binary(Cfg#cfg.project)},
		{platform, erlang},
		{server_name, node()},
		{timestamp, timestamp_i()},
		{release, Cfg#cfg.release},
		{message, term_to_json_i(Message)} |
		lists:map(fun
			({stacktrace, Value}) ->
				{'sentry.interfaces.Stacktrace', [
					{frames,lists:reverse([frame_to_json_i(Frame) || Frame <- Value])}
				]};
			({exception, {Type, Value}}) ->
				{'sentry.interfaces.Exception', [
					{type, term_to_json_i(Type)},
					{value, term_to_json_i(Value)}
				]};
			({exception, Value}) ->
				{'sentry.interfaces.Exception', [
					{type, error},
					{value, term_to_json_i(Value)}
				]};
			({http_request, {Method, Url, Headers}}) ->
				{'sentry.interfaces.Http', [
					{method,  Method},
					{url,     Url},
					{headers, Headers}
				]};
			% Reserved keys are 'id', 'username', 'email' and 'ip_address' out
			% of which ONE needs to be supplied. Additional arbitrary keys may
			% also be sent.
			({user, KVs}) when is_list(KVs) ->
				{'sentry.interfaces.User', KVs};
			({tags, Tags}) ->
				{tags, [{Key, term_to_json_i(Value)} || {Key, Value} <- Tags]};
			({extra, Tags}) ->
				{extra, [{Key, term_to_json_i(Value)} || {Key, Value} <- Tags]};
			({Key, Value}) ->
				{Key, term_to_json_i(Value)}
		end, Params)
	],
	Body = base64:encode(zlib:compress(jsx:encode(Document))),
	{ok, Body}.

%Synchronized set to true returns backoff
%otherwise, it is not returned
capture_with_backoff_send(Body, Synchronized) ->
	Cfg = get_config(),
	Timestamp = integer_to_list(unix_timestamp_i()),
	UA = user_agent(),
	Headers = [
		{"X-Sentry-Auth",
		["Sentry sentry_version=", ?SENTRY_VERSION,
		 ",sentry_client=", UA,
		 ",sentry_timestamp=", Timestamp,
		 ",sentry_key=", Cfg#cfg.public_key]},
		{"User-Agent", UA}
	],
	ok = httpc:set_options([{ipfamily, Cfg#cfg.ipfamily}]),
	{ok, Result} = httpc:request(post,
		{Cfg#cfg.uri ++ "/api/store/", Headers, "application/octet-stream", Body},
		[],
		[{body_format, binary}, {sync, Synchronized}]
	),
	case Synchronized of
		false -> ok;
		true  -> {ok, extract_backoff(Result)}
	end.

extract_backoff(Result)  when is_reference(Result) ->
	io:format("~nHTTP return was reference ~p~n", [Result]),
	0;
extract_backoff({StatusLine, Headers, _Body}) ->
	{_,ResponseCode, _} = StatusLine,
	case ResponseCode of
		429 ->
			Backoff = list_to_integer(proplists:get_value("retry-after", Headers)),
			io:format("       retry:  ~p~n", [Backoff]),
			Backoff;
		_   ->
			0
	end.

-spec user_agent() -> iolist().
user_agent() ->
	{ok, Vsn} = application:get_key(raven, vsn),
	["raven-erlang/", Vsn].

%% @private
-spec get_config() -> cfg_rec().
get_config() ->
	get_config(raven).

-spec get_config(App :: atom()) -> cfg_rec().
get_config(App) ->
	{ok, IpFamily} = application:get_env(App, ipfamily),
	Release = application:get_env(App, release, undefined),
	case application:get_env(App, dsn) of
		{ok, Dsn} ->
			{match, [_, Protocol, PublicKey, SecretKey, Uri, Project]} =
				re:run(Dsn, "^(https?://)(.+):(.+)@(.+)/(.+)$", [{capture, all, list}]),
			#cfg{uri = Protocol ++ Uri,
			     public_key = PublicKey,
			     private_key = SecretKey,
			     project = Project,
			     ipfamily = IpFamily,
			     release = Release};
		undefined ->
			{ok, Uri} = application:get_env(App, uri),
			{ok, PublicKey} = application:get_env(App, public_key),
			{ok, PrivateKey} = application:get_env(App, private_key),
			{ok, Project} = application:get_env(App, project),
			#cfg{uri = Uri,
			     public_key = PublicKey,
			     private_key = PrivateKey,
			     project = Project,
			     ipfamily = IpFamily,
			     release = Release}
	end.


event_id_i() ->
	U0 = rand:uniform((2 bsl 32) - 1) - 1,
	U1 = rand:uniform((2 bsl 16) - 1) - 1,
	U2 = rand:uniform((2 bsl 12) - 1) - 1,
	U3 = rand:uniform((2 bsl 32) - 1) - 1,
	U4 = rand:uniform((2 bsl 30) - 1) - 1,
	<<UUID:128>> = <<U0:32, U1:16, 4:4, U2:12, 2#10:2, U3:32, U4:30>>,
	iolist_to_binary(io_lib:format("~32.16.0b", [UUID])).

timestamp_i() ->
	{{Y,Mo,D}, {H,Mn,S}} = calendar:now_to_datetime(os:timestamp()),
	FmtStr = "~4.10.0B-~2.10.0B-~2.10.0BT~2.10.0B:~2.10.0B:~2.10.0B",
	iolist_to_binary(io_lib:format(FmtStr, [Y, Mo, D, H, Mn, S])).

unix_timestamp_i() ->
	{Mega, Sec, Micro} = os:timestamp(),
	Mega * 1000000 * 1000000 + Sec * 1000000 + Micro.

frame_to_json_i({Module, Function, Arguments}) ->
	frame_to_json_i({Module, Function, Arguments, []});
frame_to_json_i({Module, Function, Arguments, Location}) ->
	Arity = case is_list(Arguments) of
		true -> length(Arguments);
		false -> Arguments
	end,
	Line = case lists:keyfind(line, 1, Location) of
		false -> -1;
		{line, L} -> L
	end,
		case is_list(Arguments) of
			true -> [{vars, [iolist_to_binary(io_lib:format("~w", [Argument])) || Argument <- Arguments]}];
			false -> []
		end ++ [
			{module, Module},
			{function, <<(atom_to_binary(Function, utf8))/binary, "/", (list_to_binary(integer_to_list(Arity)))/binary>>},
			{lineno, Line},
			{filename, case lists:keyfind(file, 1, Location) of
				false -> <<(atom_to_binary(Module, utf8))/binary, ".erl">>;
				{file, File} -> list_to_binary(File)
			end}
		].

term_to_json_i(Term) when is_binary(Term); is_atom(Term) ->
	Term;
term_to_json_i(Term) ->
	iolist_to_binary(s2_io:format("~120p", [Term])).
