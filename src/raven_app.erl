-module(raven_app).
-export([
	start/0,
	stop/0
]).

-behaviour(application).
-export([
	start/2,
	stop/1
]).

-include("raven.hrl").

-spec start() -> ok | {error, term()}.
start() ->
	ensure_started(raven).

-spec stop() -> ok | {error, term()}.
stop() ->
	application:stop(raven).


%% @hidden
start(_StartType, _StartArgs) ->
    persistent_term:put(
    	?RAVEN_SSL_PERSIST_KEY,
    	{ssl, httpc:ssl_verify_host_options(true)}
    ),
    {ok, _ProfilePid} = inets:start(httpc, [{profile, ?RAVEN_HTTPC_PROFILE}]),
	case {application:get_env(uri), application:get_env(dsn)} of
		{undefined, undefined} ->
			{error, missing_configuration};
		_ ->
			case application:get_env(error_logger) of
				{ok, true} ->
					error_logger:add_report_handler(raven_error_logger);
				_ -> ok
			end,
			case application:get_env(otp_logger) of
				{ok, true} ->
					logger:add_handler(raven_otp_logger, raven_logger_backend, #{level => warning
						, filter_default => log
						, filters => [{ssl,      {fun logger_filters:domain/2, {stop, sub, [ssl]}}}
									 ,{progress, {fun logger_filters:domain/2, {stop, equal, [progress]}}}
									 ,{raven,    {fun logger_filters:domain/2, {stop, sub, [raven]}}}
						             ,{sasl,     {fun logger_filters:domain/2, {stop, sub, [otp, sasl]}}}
									 ]});
				_ ->
					ok
			end,
			case raven_sup:start_link() of
				{ok, Pid} ->
					raven_rate_limit:setup(),
					{ok, Pid};
				Error ->
					Error
			end
	end.

%% @hidden
stop(_State) ->
	case application:get_env(error_logger) of
		{ok, true} ->
			error_logger:delete_report_handler(raven_error_logger),
			ok;
		_ ->
			ok
	end,
    ok = inets:stop(httpc, ?RAVEN_HTTPC_PROFILE),
    true = persistent_term:erase(?RAVEN_SSL_PERSIST_KEY),
    raven_rate_limit:teardown().

%% @private
ensure_started(App) ->
	case application:start(App) of
		ok ->
			ok;
		{error, {already_started, App}} ->
			ok;
		{error, {not_started, Other}} ->
			ensure_started(Other),
			ensure_started(App)
	end.
