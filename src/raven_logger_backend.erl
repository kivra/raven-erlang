-module(raven_logger_backend).
-export([
	log/2
]).


log(LogEvent, _Config) ->
	case is_raven_log(LogEvent) of
		true  -> ok; % Dropping raven log, prevents log loop
		false -> raven:capture(LogEvent, [])
	end.

is_raven_log(#{meta := Meta} = _LogEvent) ->
	case maps:is_key(report_cb, Meta) of
		false -> false;
		true  -> #{report_cb := Report} = Meta,
				 Report =:= fun ssl_logger:format/1
	end.

