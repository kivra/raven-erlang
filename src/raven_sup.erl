-module(raven_sup).
-export([
	start_link/0
]).

-behaviour(supervisor).
-export([
	init/1
]).

-define(SUPERVISOR(I),      {I, {supervisor, start_link, [?MODULE, I]}, permanent, infinity, supervisor, [?MODULE]}).
-define(SUPERVISOR(I, N),   {I, {supervisor, start_link, [{local, N}, ?MODULE, I]}, permanent, infinity, supervisor, [?MODULE]}).
-define(WORKER(M, F, A, R), {M,  {M, F, A}, R, 5000, worker, [M]}).


start_link() ->
	supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% @hidden
init([]) ->
  Config = {one_for_one, 5, 10},
  SendSentrySafe = ?WORKER(raven_send_sentry_safe, start_link, [], permanent),
  Workers = [SendSentrySafe],
  {ok, {Config, Workers}}.
