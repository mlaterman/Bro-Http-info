module HTTPINFO;
@load base/protocols/http

#Used for testing when generating traffic from localhost, disable otherwise
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
    Analyzer::enable_analyzer(Analyzer::ANALYZER_TCPSTATS);
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    if(c$uid in info) {
       info[c$uid]$req_start = c$start_time;
	   info[c$uid]$req_end = c$start_time + c$duration;
    } else {
        local h_info: HTTPINFO::http_info;
        h_info$uid = c$uid;
        h_info$req_start = c$start_time;
        h_info$req_end = c$start_time+c$duration;
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
    if(c$uid in info) { # record response start and end time
        local con = info[c$uid];
        con$res_start = c$start_time;
        con$res_end = c$start_time+c$duration;
    } else {
        local h_info: HTTPINFO::http_info;
        h_info$uid = c$uid;
	    h_info$res_start = c$start_time;
		h_info$res_end = c$start_time + c$duration;
		info[c$uid] = h_info;
    }
}

#This event does not seem to trigger all the time
event conn_stats(c: connection, os: endpoint_stats, rs:endpoint_stats) {
    if(c$uid in info) {
        info[c$uid]$server_retrans = rs$num_rxmit;
    }
}

event HTTP::log_http(rec: HTTP::Info) {
	if(rec$uid in info) {
		local hInfo = info[rec$uid];
		rec$req_start = hInfo$req_start;
		rec$req_end = hInfo$req_end;
		rec$res_start = hInfo$res_start;
		rec$res_end = hInfo$res_end;
		rec$server_retrans = hInfo$server_retrans;
		rec$content_type = hInfo$content_type;
		rec$no_cache = hInfo$no_cache;
		rec$no_store = hInfo$no_store;
		rec$public = hInfo$public;
		rec$location = hInfo$location;
        delete info[c$uid];
	}
}
