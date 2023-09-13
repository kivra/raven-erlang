-module(raven_rate_limit).

% API
-export([setup/0]).
-export([teardown/0]).
-export([run/1]).
-export([delay/1]).

%--- API -----------------------------------------------------------------------

setup() ->
    Result = case application:get_env(raven, rate_limit, false) of
        {Intensity, Period} ->
            FuseConfig = {{standard, Intensity, Period}, {reset, Period}},
            ok = fuse:install(?MODULE, FuseConfig),
            {enabled, atomics:new(1, [{signed, false}])};
        false ->
            disabled
    end,
    persistent_term:put(?MODULE, Result).

teardown() ->
    case persistent_term:get(?MODULE) of
        {enabled, _} -> fuse:remove(?MODULE);
        disabled -> ok
    end,
    persistent_term:erase(?MODULE).

run(Fun) ->
    case persistent_term:get(?MODULE) of
        disabled ->
            Fun();
        {enabled, Atomics} ->
            RetryAfter = atomics:get(Atomics, 1),
            case erlang:system_time(second) > RetryAfter of
                true ->
                    case fuse:ask(?MODULE, async_dirty) of
                        blown ->
                            {error, {rate_limit, local}};
                        _ ->
                            ok = fuse:melt(?MODULE),
                            Fun()
                    end;
                false ->
                    {error, {rate_limit, remote}}
            end
    end.

delay(Seconds) when Seconds > 0 ->
    case persistent_term:get(?MODULE) of
        disabled -> ok;
        {enabled, Atomics} ->
            RetryAfter = erlang:system_time(second) + Seconds + 1,
            atomics:put(Atomics, 1, RetryAfter)
    end.
