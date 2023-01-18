-module(raven_app).

-behavior(application).

-export([start/2, stop/1]).

-include("raven.hrl").

start(_StartType, _StartArgs) ->
    case application:get_env(ssl) of
        {ok, Options} ->
            persistent_term:put(?RAVEN_SSL_PERSIST_KEY, {ssl, Options});
        _ ->
            logger:notice("Raven not configured with httpc ssl options"),
            persistent_term:put(?RAVEN_SSL_PERSIST_KEY, {ssl, []})
    end,
    {ok, _ProfilePid} = inets:start(httpc, [{profile, ?RAVEN_HTTPC_PROFILE}]),
    case application:get_env(uri) of
        {ok, _} ->
            logger:add_handler(raven_otp_logger, raven_logger_backend, #{
                level => warning,
                filter_default => log,
                filters => [
                    {ssl, {fun logger_filters:domain/2, {stop, sub, [ssl]}}},
                    {progress, {fun logger_filters:domain/2, {stop, equal, [progress]}}},
                    {raven, {fun logger_filters:domain/2, {stop, sub, [raven]}}},
                    {sasl, {fun logger_filters:domain/2, {stop, sub, [otp, sasl]}}}
                ]
            }),
            case raven_sup:start_link() of
                {ok, Pid} ->
                    {ok, Pid};
                Error ->
                    Error
            end;
        _ ->
            {error, missing_configuration}
    end.

stop(_State) ->
    inets:stop(httpc, ?RAVEN_HTTPC_PROFILE),
    ok.
