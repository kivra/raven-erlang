-module(raven_sup).
-behavior(supervisor).

-export([start_link/0]).
-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% @hidden
init([]) ->
    SupFlags = #{strategy => one_for_one, intensity => 5, period => 10},
    Workers = [
        #{
            id => raven_send_sentry_safe,
            start => {raven_send_sentry_safe, start_link, []},
            restart => permanent
        }
    ],
    {ok, {SupFlags, Workers}}.
