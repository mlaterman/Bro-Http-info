module HTTPINFO;
@load base/protocols/http

#TODO: Get Http::Info records when an http event fires
#TODO: Get HTTP::Info record when conn_stats event for an http connection rises

#Used for testing when generating traffic from localhost, diable otherwise
redef ignore_checksums = T;

export {
    #redef enum Log::ID += { LOG };

    redef  HTTP::Info += {
        req_start:      time    &log &default=double_to_time(0.0);
        req_end:        time    &log &default=double_to_time(0.0);
        res_start:      time    &log &default=double_to_time(0.0);
        res_end:        time    &log &default=double_to_time(0.0);
       server_retrans: count   &log &default=0;
        content_type:   string  &log &default="NONE";
        no_cache:       bool    &log &default=F;
        no_store:       bool    &log &default=F;
        public:         bool    &log &default=T;
        location:       string  &log &default="ND";
    };

    #global log_HTTPINFO: event(rec: http_info);
    #global info: table[string] of http_info;
}

event bro_init() {
    Analyzer::enable_analyzer(Analyzer::ANALYZER_TCPSTATS);
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
		local entry: HTTP::Info = #somehow get http::Info for connection
        entry$req_start = c$start_time;
        entry$req_end = c$start_time+c$duration;
    }
}

event http_header(c: connection, is_orig: bool, name: string, value: string) {
		local entry: HTTP::Info = #somehow get http::Info for connection
        if(name == "CONTENT-TYPE") {
            local c_type = split1(value, /;/);
            if(|c_type| >= 1) {
                entry$content_type = to_upper(subst_string(c_type[1], " ", ""));
            } else {
                entry$content_type = "BAD/BAD";
            }
        } else if(name == "LOCATION") {
            entry$location = value;
        } else if(name == "CACHE-CONTROL") {
            local cache_info = to_lower(value);
            if(/no-cache/ in cache_info) {
                entry$no_cache = T;
            }
            if(/no-store/ in cache_info) {
                entry$no_store = T;
            }
            if(/private/ in cache_info) {
                entry$public = F;
            }
        }
}

event http_reply(c: connection, version: string, code: count, reason: string) {
		local entry: HTTP::Info = #somehow get http::Info for connection
        entry$res_start = c$start_time;
        entry$res_end = c$start_time+c$duration;
}

#This event does not seem to trigger
event conn_stats(c: connection, os: endpoint_stats, rs:endpoint_stats) {
	local entry: HTTP::Info = #somehow get http::Info for connection
    if() { # Ensure that this connection was for an HTTP connection somehow
        entry$server_retrans = rs$num_rxmit;
    }
}

