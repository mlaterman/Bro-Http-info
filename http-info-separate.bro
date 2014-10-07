module HTTPINFO;
@load base/protocols/http

#Used for testing when generating traffic from localhost
#redef ignore_checksums = T;

export {
    redef enum Log::ID += { LOG };

    type http_info: record {
        uid:            string  &log &default="ERROR";
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

    global log_HTTPINFO: event(rec: http_info);
    global info: table[string] of http_info;
}

event bro_init() {
    Log::create_stream(HTTPINFO::LOG, [$columns=http_info, $ev=log_HTTPINFO]);
    Analyzer::enable_analyzer(Analyzer::ANALYZER_TCPSTATS);
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    if(c$uid in info) {
       info[c$uid]$req_start = network_time();
    } else {
        local h_info: HTTPINFO::http_info;
        h_info$uid = c$uid;
        h_info$req_start = network_time();
        info[c$uid] = h_info;
    }
}

event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if(c$uid in info) {
        if(name == "CONTENT-TYPE") {
            local c_type = split1(value, /;/);
            if(|c_type| >= 1) {
                info[c$uid]$content_type = to_upper(subst_string(c_type[1], " ", ""));
            } else {
                info[c$uid]$content_type = "BAD/BAD";
            }
        } else if(name == "LOCATION") {
            info[c$uid]$location = value;
        } else if(name == "CACHE-CONTROL") {
            local cache_info = to_lower(value);
            if(/no-cache/ in cache_info) {
                info[c$uid]$no_cache = T;
            }
            if(/no-store/ in cache_info) {
                info[c$uid]$no_store = T;
            }
            if(/private/ in cache_info) {
                info[c$uid]$public = F;
            }
        }
   }
}

event http_reply(c: connection, version: string, code: count, reason: string) {
    if(c$uid in info) {
        info[c$uid]$res_start = network_time();
    } else {
        local h_info: HTTPINFO::http_info;
        h_info$uid = c$uid;
        h_info$res_start = network_time();
        info[c$uid] = h_info;
    }
}

event http_end_entity(c: connection, is_orig: bool) {
    if(is_orig) {
        info[c$uid]$req_end = network_time();
	} else {
        info[c$uid]$res_end = network_time();
	}
}

#Al multiple request/responses can use the same connection an entry in the httpinfo log is
#not made for each entry in the http log
event conn_stats(c: connection, os: endpoint_stats, rs:endpoint_stats) {
    if(c$uid in info) {
        info[c$uid]$server_retrans = rs$num_rxmit;
        Log::write(HTTPINFO::LOG, info[c$uid]);
        delete info[c$uid];
    }
}

