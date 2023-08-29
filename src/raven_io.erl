-module(raven_io).

-export([format/2]).

format(Format, Args) ->
    Chars =
        try lists:flatten(
                io_lib:build_text(
                    lists:map( fun(Elem) -> update(Elem, 50, 50) end
                             , io_lib:scan_format(Format, Args))))
        catch
            _:_ ->
                lists:flatten(
                    io_lib:format("FORMAT ERROR: ~p ~p", [Format, Args]))
        end,
    
    MaxLenth = 8192,
    if
        length(Chars) =< MaxLenth -> Chars;
        true                     -> lists:sublist(Chars, MaxLenth - 3) ++ "..."
    end.

update(M = #{control_char := $p, args := [Arg]}, PDepth, _) ->
    M#{control_char := $P, args := [Arg, PDepth]};
update(M = #{control_char := $w, args := [Arg]}, _, WDepth) ->
    M#{control_char := $W, args := [Arg, WDepth]};
update(X, _, _) -> X.


-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

format_test() ->
    %% Format error
    ?assertEqual( "FORMAT ERROR: \"Data: ~p\" wat"
                , format("Data: ~p", wat)),

    ok.
-endif.