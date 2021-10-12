-module(raven_logger_backend).
-export([
	log/2
]).


log(LogEvent, _Config) ->
	timer:sleep(5000),
	raven:capture(LogEvent, []).

