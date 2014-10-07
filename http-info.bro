@load base/protocols/http

#Used for testing when generating traffic from localhost
#redef ignore_checksums = T;

export {
    redef record HTTP::Info += {
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
}

event bro_init() {
    Analyzer::enable_analyzer(Analyzer::ANALYZER_TCPSTATS);
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
   c$http$req_start = c$start_time;
   c$http$req_end = c$start_time + c$duration;
}

event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if(name == "CONTENT-TYPE") {
        local c_type = split1(value, /;/);
        if(|c_type| >= 1) {
            c$http$content_type = to_upper(subst_string(c_type[1], " ", ""));
        } else {
            c$http$content_type = "BAD/BAD";
        }
    } else if(name == "LOCATION") {
        c$http$location = value;
    } else if(name == "CACHE-CONTROL") {
        local cache_info = to_lower(value);
        if(/no-cache/ in cache_info) {
            c$http$no_cache = T;
        }
        if(/no-store/ in cache_info) {
            c$http$no_store = T;
        }
        if(/private/ in cache_info) {
            c$http$public = F;
        }
    }
}

event http_reply(c: connection, version: string, code: count, reason: string) {
    c$http$res_start = c$start_time;
    c$http$res_end = c$start_time+c$duration;
}

event conn_stats(c: connection, os: endpoint_stats, rs:endpoint_stats) {
    if(c?$http) {
        c$http$server_retrans = rs$num_rxmit;
    }
}

