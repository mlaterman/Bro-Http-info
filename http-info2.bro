#TODO end timstamps, measured in req/reply->c$start+duration or message-end?
#TODO log output & record deletion where?
@load base/frameworks/notice/weird
@load base/protocols/http

#Capture http packets on standard ports (80 & 443)
redef capture_filters += {["tcp"] = "tcp"};
redef restrict_filters += {["HTTP"] = "port 80 or port 443"};
#define a new log for output
redef enum Log::ID += {HTTPINFO};

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

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    if(c$uid in info) {
        #request with the connection uid was made previously
    } else {
        local h_info: http_info; 
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
        #Something went wrong
    }
}

#event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) {
#    if() {
#        if(c$id$resp_h) { #HTTP Request
#            #info[c$uid]$req_start = stat$start;
#        } else { #HTTP reply
#            #info[c$uid]$res_end = stat$start;
#        }
#    }
#}

event conn_stats(c: connection, os: endpoint_stats, rs:endpoint_stats) {
    if(c$uid in info) {
        info[c$uid]$server_retrans = rs$num_rxmit;
        Log::write(HTTPINFO, info[c$uid]); # write record to log
        delete info[c$uid]; # Done with HTTP response for now, delete here or in conn_stats?
    }
}

