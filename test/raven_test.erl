-module(raven_test).

-include_lib("eunit/include/eunit.hrl").

% Callbacks
-export([do/1]).

%--- Tests ---------------------------------------------------------------------

all_test_() ->
    {setup, fun setup/0, fun cleanup/1, {inparallel, [
        fun simple_capture_/0
    ]}}.

simple_capture_() ->
    ?assertEqual(ok, raven:capture(foo, [])).

%--- Harness -------------------------------------------------------------------

setup() ->
    error_logger:tty(false),
    {ok, InetApps} = application:ensure_all_started(inets),
    {ok, HTTPD} = inets:start(httpd, [
        {port, 0},
        {server_name, "httpd_test"},
        {server_root, "."},
        {document_root, "."},
        {bind_address, "localhost"},
        {modules, [?MODULE]}
    ]),
    Info = httpd:info(HTTPD),
    Port = proplists:get_value(port, Info),
    URI = #{
        scheme => "http",
        path => "/1",
        userinfo => "PUBLIC_KEY:PRIVATE_KEY",
        host => "localhost",
        port => Port
    },
    application:set_env([{raven, [
        {dsn, uri_string:recompose(URI)}
    ]}]),
    {ok, RavenApps} = application:ensure_all_started(raven),
    {HTTPD, InetApps ++ RavenApps}.

cleanup({HTTPD, Apps}) ->
    [ok = application:stop(A) || A <- lists:reverse(Apps)],
    ok = inets:stop(httpd, HTTPD),
    error_logger:tty(true).

%--- Callbacks -----------------------------------------------------------------

do(_Data) -> {break, [{response, {200, ""}}]}.
