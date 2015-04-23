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

init(Level) ->
    {ok, #state{level=lager_util:config_to_mask(Level)}}.


%% @private
handle_call(get_loglevel, #state{level=Level} = State) ->
    {ok, Level, State};
handle_call({set_loglevel, Level}, State) ->
   try lager_util:config_to_mask(Level) of
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

capture(mask) ->
    ok;
capture({Message, Params}) ->
    raven:capture(Message, Params).

%% TODO - check what other metadata can be sent to sentry
parse_message({lager_msg, [], MetaData, Level, _, _Time, Message}) ->
    case parse_meta(MetaData) of
        mask ->
            mask;
        Extra ->
            {Message, [{level, Level},
                       {extra, Extra}]}
    end.


%% @doc Extracts pid from lager message metadata. Lager messages that came
%% from error_logger are flagged as such in the metadata, in which case we
%% immediately return 'mask', indicating that the message should be skipped.
%% This assumes that raven's error_logger handler is installed, to avoid
%% double-capturing error_logger events.
%% TODO: respect default_error_logger config, instead of assuming it is set
%% to true.
parse_meta(MetaData) ->
    parse_meta(MetaData, []).

parse_meta([], Acc) ->
    Acc;
parse_meta([{pid, Pid} = PidProp | Rest], Acc) when is_pid(Pid) ->
    parse_meta(Rest, [PidProp | Acc]);
parse_meta([{error_logger, _} | _Rest], _Acc) ->
    mask;
parse_meta([{_, _} | Rest], Acc) ->
    parse_meta(Rest, Acc).

