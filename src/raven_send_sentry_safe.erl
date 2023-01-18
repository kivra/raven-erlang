-module(raven_send_sentry_safe).

-behavior(gen_server).

-export([start_link/0]).
% unresolved reference from raven_sup childspec
-ignore_xref([start_link/0]).

-export([capture/2]).

-export([init/1, terminate/2, handle_call/3, handle_cast/2, handle_info/2]).

%% API

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, undefined, []).

capture(Message, Args) ->
    gen_server:cast(?MODULE, {capture, Message, Args}).

%% gen_server callbacks

init(_Arg) ->
    logger:update_process_metadata(#{domain => [raven]}),
    {ok, #{backoff_until => current_time()}}.

terminate(_Arg, _State) ->
    ok.

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(_Request = {capture, Message, Args}, State) ->
    Qlen = qlen(),
    if
        Qlen > 10 ->
            io:format("    skip, to long queue (~p)~n", [Qlen]),
            {noreply, State};
        true ->
            #{backoff_until := Bou} = State,
            Now = current_time(),
            if
                Bou > Now ->
                    logger:warning(<<"Sentry dropped log event">>),
                    {noreply, State};
                true ->
                    {ok, BackoffUntil} = raven_capture(Message, Args),
                    {noreply, State#{backoff_until => BackoffUntil}}
            end
    end;
handle_cast(_Request, State) ->
    {ok, State}.

handle_info(_Info, State) ->
    {noreply, State}.

%% Local

qlen() ->
    {message_queue_len, Qlen} =
        erlang:process_info(self(), message_queue_len),
    Qlen.

raven_capture(Message, Args) ->
    {ok, Body} = raven:capture_prepare(Message, Args),
    case raven:capture_with_backoff_send(Body, true) of
        ok ->
            {ok, current_time()};
        {ok, Seconds} ->
            {ok, current_time() + Seconds * 1_000_000}
    end.

current_time() ->
    erlang:system_time(microsecond).
