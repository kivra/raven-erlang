%% @doc raven backend for lager

-module(raven_lager_backend).
-behaviour(gen_event).


-export([
         init/1,
         code_change/3,
         terminate/2,
         handle_call/2,
         handle_event/2,
         handle_info/2
]).


-record(state, {level}).

init([{level, Level}]) ->
    {ok, #state{level=lager_util:level_to_num(Level)}}.


%% @private
handle_call(get_loglevel, #state{level=Level} = State) ->
    {ok, Level, State};
handle_call({set_loglevel, Level}, State) ->
   try lager_util:level_to_num(Level) of
        Levels ->
           {ok, ok, State#state{level=Levels}}
   catch
       _:_ ->
           {ok, {error, bad_log_level}, State}
   end;
handle_call(_, State) ->
    {ok, ok, State}.

%% @private
handle_event({log, Data},
    #state{level=L} = State) ->
    case lager_util:is_loggable(Data, L, ?MODULE) of
        true ->
            capture(parse_message(Data)),
            {ok, State};
        false ->
            {ok, State}
    end;
handle_event(_Event, State) ->
    {ok, State}.


handle_info(_, State) ->
    {ok, State}.

code_change(_, State, _) ->
    {ok, State}.

terminate(_, _) ->
    ok.

capture({Message, Params}) ->
    raven:capture(Message, Params).

parse_message(Log) ->
    {lager_msg:message(Log), [ {level, lager_msg:severity(Log)}
                             | extra(Log)
                             ]}.

extra(Log) ->
    case lager_msg:metadata(Log) of
        []    -> [];
        Extra -> [{extra, Extra}]
    end.
