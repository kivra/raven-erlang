-module(raven_send_sentry_safe).

-behaviour(gen_server).

-export([start/0, start_link/0, stop/0, notify/1, notify/2]).

-export([init/1, terminate/2, handle_call/3, handle_cast/2, handle_info/2]).

%% API

start() ->
  gen_server:start({local, ?MODULE}, ?MODULE, undefined, []).

start_link() ->
  gen_server:start_link({local, ?MODULE}, ?MODULE, undefined, []).

stop() ->
  gen_server:stop(?MODULE).

notify(Event) ->
  gen_server:cast(?MODULE, {notify, Event}).

%% Test
notify(_Event, N) when N =< 0 ->
  ok;
notify(Event, N) ->
  notify({N, Event}),
  notify(Event, N-1).

%% gen_server callbacks

init(Arg) ->
  io:format("init(~p)~n", [Arg]),
  {ok, #{backoff_until => current_time()}}.

terminate(Arg, State) ->
  io:format("terminate(~p,~p)~n", [Arg, State]),
  ok.

handle_call(Request, From, State) ->
  io:format("handle_call(~p,~p,~p)~n", [Request, From, State]),
  {reply, ok, State}.

handle_cast(Request = {notify, Event}, State) ->
  io:format("handle_cast(~p,~p)~n", [Request, State]),
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
          io:format("    skip, to backoff~n", []),
          {noreply, State};
        true ->
          io:format("    sending~n", []),
          {ok, BackoffUntil} = send_to_sentry(Event),
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

send_to_sentry(_Event) ->
  timer:sleep(1000),
  {ok, current_time()}.

current_time() ->
  erlang:system_time(microsecond).
