-module(raven_send_sentry_safe).

-behaviour(gen_server).

-export([start/0, start_link/0, stop/0, capture/2]).

-export([init/1, terminate/2, handle_call/3, handle_cast/2, handle_info/2]).

%% API

start() ->
  gen_server:start({local, ?MODULE}, ?MODULE, undefined, []).

start_link() ->
  gen_server:start_link({local, ?MODULE}, ?MODULE, undefined, []).

stop() ->
  gen_server:stop(?MODULE).

capture(Message, Args) ->
  gen_server:cast(?MODULE, {capture, Message, Args}).


%% gen_server callbacks

init(Arg) ->
  io:format("init(~p)~n", [Arg]),
  logger:update_process_metadata(#{domain => [raven]}),
  {ok, #{backoff_until => current_time()}}.

terminate(Arg, State) ->
  io:format("terminate(~p,~p)~n", [Arg, State]),
  ok.

handle_call(Request, From, State) ->
  io:format("handle_call(~p,~p,~p)~n", [Request, From, State]),
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
          io:format("    skip, until backoff~n", []),
          io:format("    now:     ~p~n", [calendar:system_time_to_universal_time(Now, microsecond)]),
          io:format("    backoff: ~p~n", [calendar:system_time_to_universal_time(Bou, microsecond)]),
          {noreply, State};
        true ->
          io:format("    sending~n", []),
          {ok, BackoffUntil} = raven_capture(Message, Args),
          io:format("    sent~n", []),
          {noreply, State#{backoff_until => BackoffUntil}}
      end
  end;
handle_cast(Request, State) ->
  io:format("handle_cast(~p,~p)~n", [Request, State]),
  {ok, State}.

handle_info(Info, State) ->
  io:format("handle_info(~p,~p)~n", [Info, State]),
  {noreply, State}.

%% Local

qlen() ->
  {message_queue_len, Qlen} =
    erlang:process_info(self(), message_queue_len),
  Qlen.

raven_capture(Message, Args) ->
  case raven:captureBackoff(Message, Args, true) of
    ok ->
      {ok, current_time()};
    {ok, Seconds} ->
      {ok, current_time() + Seconds*1_000_000}
  end.

current_time() ->
  erlang:system_time(microsecond).
