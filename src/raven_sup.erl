-module(raven_sup).
-export([start_link/0]).

-behaviour(supervisor).
-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    {ok, MaxIntensity} = application:get_env(max_restart_intensity),
    Config = #{
        strategy => one_for_one,
        intensity => MaxIntensity,
        period => 10
    },
    SentryWorker = #{
        id => raven_send,
        start => {raven_send_sentry_safe, start_link, []},
        restart => permanent
    },
    {ok,
        {Config, [
            SentryWorker
        ]}}.
