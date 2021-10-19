-module(raven_send_sentry_safe).

-behaviour(gen_event).

-export([start/0, stop/0, notify/1, notify/2, request/1]).

-export([init/1, terminate/2, handle_call/2, handle_event/2]).

-define(MGR, send_safe_mgr).

%% API

start() ->
  Mgr = start_mgr(),
  start_handler(Mgr).

stop() ->
  gen_event:stop(?MGR).

notify(Event) ->
  gen_event:notify(?MGR, Event).

notify(_Event, N) when N =< 0 ->
  ok;
notify(Event, N) ->
  gen_event:notify(?MGR, Event),
  notify(Event, N-1).

request(Request) ->
  ID = gen_event:send_request(?MGR, ?MODULE, Request),
  gen_event:receive_response(ID, 1000).

%% gen_event callbacks

init(Arg) ->
  io:format("init(~p)~n", [Arg]),
  {ok, #{backoff_until => current_time()}}.

terminate(Arg, State) ->
  io:format("terminate(~p,~p)~n", [Arg, State]),
  ok.

handle_call(Request, State) ->
  io:format("handle_call(~p,~p)~n", [Request, State]),
  {ok, {self(),whereis(?MGR)}, State}.

handle_event(Event, State) ->
  io:format("handle_event(~p,~p)~n", [Event, State]),
  Qlen = qlen(),
  if
    Qlen > 10 ->
      io:format("    skip, to long queue (~p)~n", [Qlen]),
      {ok, State};
    true ->
      #{backoff_until := Bou} = State,
      Now = current_time(),
      if
        Bou > Now ->
          io:format("    skip, to backoff~n", []),
          {ok, State};
        true ->
          {ok, BackoffUntil} = send_to_sentry(),
          io:format("    sent to sentry~n", []),
          {ok, State#{backoff_until => BackoffUntil}}
      end
  end.

%% Local

start_mgr() ->
  case gen_event:start({local,?MGR}) of
    {ok, Mgr} ->
      Mgr;
    {error, {already_started, Mgr}} ->
      Mgr
  end.

start_handler(Mgr) ->
  Handlers = gen_event:which_handlers(Mgr),
  case lists:member(?MODULE, Handlers) of
    true ->
      already_started;
    false ->
      ok = gen_event:add_handler(Mgr, ?MODULE, foo)
  end.

qlen() ->
  {message_queue_len, Qlen} =
    erlang:process_info(whereis(?MGR), message_queue_len),
  Qlen.

send_to_sentry() ->
  timer:sleep(1000),
  {ok, current_time()}.

current_time() ->
  erlang:system_time(microsecond).
