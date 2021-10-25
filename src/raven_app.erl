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

-spec start() -> ok | {error, term()}.
start() ->
	ensure_started(raven).

-spec stop() -> ok | {error, term()}.
stop() ->
	application:stop(raven).


%% @hidden
start(_StartType, _StartArgs) ->
	case application:get_env(uri) of
		{ok, _} ->
			case application:get_env(error_logger) of
				{ok, true} ->  error_logger:add_report_handler(raven_error_logger);
				{ok, false} -> logger:add_handler(logger_backend, raven_logger_backend, #{level => warning
						, filter_default => log
						, filters => [{ssl,      {fun logger_filters:domain/2, {stop, sub, [ssl]}}}
									 ,{progress, {fun logger_filters:domain/2, {stop, equal, [progress]}}}
									 ,{raven,    {fun logger_filters:domain/2, {stop, sub, [raven]}}}
						             ,{sasl,     {fun logger_filters:domain/2, {stop, sub, [otp, sasl]}}}
									 ]});
				_ -> ok
			end,
			raven_sup:start_link();
		_ ->
			{error, missing_configuration}
	end.

%% @hidden
stop(_State) ->
	case application:get_env(error_logger) of
		{ok, true} ->
			error_logger:delete_report_handler(raven_error_logger),
			ok;
		_ ->
			ok
	end.

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
