
################################################################
##
##                    data_collection.bro
##
## v13 - does not consider connections originating from probe (136.159.15.39);
##     - includes full user agent string
## v12 - fixed small bug in prior version
## v11 - checks sequence numbers before calculating bytes transferred
## v10 - now tracks original_URI field instead of etags (since etags not used very often)
## v9 - - now tracks etags
## v8 - does not consider connections originating from my desktop (136.159.17.51)
## v7 - - (decends v6, not v6 a)
##	- getting rid of division operation on each packet
##	- changed time outputs to be timestamps instead of durations
## v6 - - reducing CPU resources
##	- got rid of client/server packet counts (were not being outputted anyways)
##	- tweaked user agent processing
## v5 - - reducing amount of stored info by summarizing cache headers
##	- reduced amount of user agent field kept 
## v4 - - does not consider connections where the responder is within
##	  the UofC network
##      - added some checking to http_headers to not consider 
##        header values that are the empty string 
## v3 -	- considers user agent header
##	- handles pipelining correctly
##	- prints out anonymized user identifier
##	- prints out server IP (interesting to not filter out U of C because of CDN nodes)
## v2 - P: linked together HTTP transactions and TCP connections, output stats
##	on the fly removing state as required. Some logic borrowed from youtube_v5.bro
##	P: disabled syslog
## v1 - gathers basic statistics on http connections. Much of the script
##      borrowed from connections.bro and content_encoding.bro
##
###############################################################

@load weird
@load http

redef enable_syslog=F;
redef capture_filters += {["tcp"] = "tcp" };
redef restrict_filters += {["HTTP"] = "port 80" };


type tcp_state: enum{
	not_established,  		
	waiting_ACK,		# seen a SYNACK waiting for ACK of it
	established,		# seen SYN, SYNACK and ACK
	complete, 			# closed "gracefully"
	error_occurred,		# something went wrong along the way

};

type http_state: enum{

	waiting_for_reply,
	waiting_for_reply_end,
	waiting_for_ack_of_reply,
	transaction_complete,
	transaction_interrupted,
	transaction_gapped

};

type http_info: record{
	state: http_state;	
	request_t: time;			# time of request
	reply_start_t: time;    	# start of reply
	reply_end_t: time;		# end of reply
	reply_start_seq: count;		#sequence number of beginning of reply
	reply_end_seq: count;		#sequence number of end of reply
	code: count;            	# status code
	content_type: string;   	# content type
	method: string;         	# method
	user_agent: string;		# user agent
	content_length_up: string; 	# length of the content c->s
	content_length_down: string; 	# length of content s->c
	server_retrans: count;		# number of retransmissions from the server
	uri: string;			# requested uri
	host: string;			# host
	location: string;			# if the request is referred to another location
	referer: string;			# where the request was referred from
	version: string;			# HTTP version used by this connection
	no_cache: bool;		# variables to represent cache control headers
	no_store: bool;
	public: bool;

	uri: string;
	
	

};


## store some basic connection statistics
type tcp_info: record{
	connID: int;
	connstate: tcp_state;		# state of the connection
	#server_pkts: count;		# number of packets s->c
	#client_pkts: count;		#number of packets c->s
	server_seq: count;		#highest received byte from server
	client_seq: count;		#highest received byte from client
	server_ack: count;		#highest ack num from server
	client_ack: count;		#highest ack num from client
	num_requests: count;		# number of http requests
	num_replies: count;		# number of http replies
	num_replies_acked: count; 	# number of replies acked on this conn
	server_retrans: count;		# keeps count of retrans s->c
	client_retrans: count; 		 #keeps count of retrans c->s
	transactions: table[count] of http_info; # info on the http connections	
	pipelined: bool;		# if this connection uses pipelining or not 
};

global UofC: net 136.159.;

global info: table[conn_id] of tcp_info; # keep track of info on connections
global NextConnID: int = 0; 

global ClientID: table[addr] of int; #map IP addresses to unique integers
global NextClientID: int = 0;

# IP/TCP header of last packet seen.  Used to communicate between
# new_packet() event handler and other events.  We rely on the fact
# that new_packet() is generated prior to other events for the same packet.
global last_hdr: pkt_hdr;

##
## outputs stats on a specific HTTP transaction
## within the connection specified by id
##
function http_tostring(id:conn_id,transaction: http_info):string
{
	if(id !in info)
		return "CONNECTION NOT IN INFO";

	local conn = info[id];
	
	
	#if both sequence numbers have been assigned (will not be correct if the sequence number actually is 0...
	if(transaction$reply_end_seq > 0 && transaction$reply_start_seq > 0)
	{	local db = transaction$reply_end_seq - transaction$reply_start_seq;


		return fmt("%s|%s|%s|%s|%s|%s|%s|%d|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|ND|%s",
		conn$connID,  
		ClientID[id$orig_h], 
		id$resp_h,
		conn$pipelined,
		transaction$request_t,
		transaction$reply_start_t,
		transaction$reply_end_t,
		db,  # bytes transferred,
		transaction$user_agent,
		transaction$method,
		transaction$version,
		transaction$host,
		transaction$content_length_up,
		transaction$content_length_down,
		transaction$content_type,
		transaction$code,
		transaction$server_retrans,
		transaction$no_cache,
		transaction$no_store,
		transaction$public,
		transaction$location,
		transaction$referer,
		transaction$uri
		);
	}
	else
	{ # no valid byte count
		return fmt("%s|%s|%s|%s|%s|%s|%s|ND|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|ND|%s",
		conn$connID,  
		ClientID[id$orig_h], 
		id$resp_h,
		conn$pipelined,
		transaction$request_t,
		transaction$reply_start_t,
		transaction$reply_end_t,
		
		transaction$user_agent,
		transaction$method,
		transaction$version,
		transaction$host,
		transaction$content_length_up,
		transaction$content_length_down,
		transaction$content_type,
		transaction$code,
		transaction$server_retrans,
		transaction$no_cache,
		transaction$no_store,
		transaction$public,
		transaction$location,
		transaction$referer,
		transaction$uri
		);
	}
	
}




##
## delete information on a connection closed
## with the partial close event
##
event connection_partial_close(c: connection)
{
	local id = c$id;
	if(id in info )
	{	
		delete info[id];
	}
}

##
## delete information on a connection closed 
## with the half finished event
##
event connection_half_finished(c:connection)
{
	local id = c$id;

	if(id in info)
	{
		delete info[id];
	}
}

##
## delete information on a connection closed
## with a RST
##
event connection_reset(c:connection)
{
	local id = c$id;

	if(id in info)
	{
		delete info[id];
	}
}

##
## delete information on a connection closed
## with the finished event
##
event connection_finished(c:connection)
{
	local id = c$id;

	if(id in info)
	{
		delete info[id];
	}
}

##
## Watch out for connection IDs being recycled
## from connections.bro
##
event new_connection(c: connection)
{

	local id = c$id;

	if(id in info)
	{
	# ignore connections that appear to be in FIN_WAIT2
	# i.e., orig == TCP_INACTIVE, resp == TCP_CLOSED
	if(c$orig$state==0 && c$resp$state==5)
		return;

  	delete info[id];
  }

}


## keep count of packets, track connections
event new_packet(c: connection, p: pkt_hdr)
{
	local id = c$id;
	local resp_net = to_net(id$resp_h);
	if(resp_net == UofC)
		return;
	if(id$orig_h==136.159.15.39)
		return;

	local is_client = p$ip$src == c$id$orig_h; #client or server?	

	##local is_RST = ((p$tcp$flags/4)%2 > 0);

	if( p$tcp$flags == TH_RST || p$tcp$flags == TH_RST + TH_ACK )
	{
		if(id !in info) 
		{
			#ignore
		}
		else if(info[id]$connstate == not_established ||
		   info[id]$connstate == waiting_ACK) 
		{
			info[id]$connstate = error_occurred;
		}
		else if(info[id]$connstate == error_occurred)
			return;
		else if(info[id]$num_replies_acked == 0)
		{
			local thisidx = 0;
			if(thisidx in info[id]$transactions)
			{
				info[id]$transactions[thisidx]$reply_end_t = network_time();
				info[id]$transactions[thisidx]$state = transaction_interrupted;
				print fmt("I|%s",
					http_tostring(id,info[id]$transactions[thisidx]));
				delete info[id]$transactions[thisidx];
			}
	
		}
		else {
			info[id]$connstate = error_occurred;
		}
                return;
	}

	# First packet for this connection, check that its a SYN
	if(id !in info)
	{
		local tcp_conn: tcp_info;
		local transactions: table[count] of http_info;
		tcp_conn$connID = NextConnID;
		
		tcp_conn$connstate = not_established;
		tcp_conn$num_requests=0;
		tcp_conn$num_replies=0;
		tcp_conn$num_replies_acked = 0;
		#tcp_conn$server_pkts = 0;
		#tcp_conn$client_pkts = 0;
		tcp_conn$client_seq = 0;
		tcp_conn$server_seq = 0;
		tcp_conn$client_ack = 0;
		tcp_conn$server_ack = 0;
		tcp_conn$server_retrans = 0;
		tcp_conn$client_retrans = 0;
		tcp_conn$transactions = transactions;
		tcp_conn$pipelined = F;	
	
		if(id$orig_h !in ClientID)
		{
			ClientID[id$orig_h] = NextClientID;
			++NextClientID;
		}
		info[id] = tcp_conn;

		++NextConnID;

	}
	if(id !in info)
		return;

	if(info[id]$connstate == error_occurred)
		return;

	local pkt_size = p$ip$len - p$ip$hl - p$tcp$hl;
	
	local state = info[id]$connstate;

	if(is_client && state == waiting_ACK)
	{
	
	#first packet from client since SYNACK, call the connection open
		info[id]$connstate = established;
	}

	state = info[id]$connstate;

	if(is_client && state == established ) #c->s
	{
		
		#++info[id]$client_pkts;
		
		local index = info[id]$num_replies_acked;
	
		if(index in info[id]$transactions && 
		info[id]$transactions[index]$state == waiting_for_ack_of_reply)
		{
			local ack_seq = p$tcp$ack;
			local dack = ack_seq - info[id]$transactions[index]$reply_end_seq;

			if(dack>=0)
			{
				++info[id]$num_replies_acked;
				info[id]$transactions[index]$reply_end_t = network_time();
				info[id]$transactions[index]$state = transaction_complete;
				print fmt("C|%s",http_tostring(id,info[id]$transactions[index]));
				delete info[id]$transactions[index];
			}

		}

	}
	else if(!is_client && state == not_established )
	{
		# this should be a SYNACK from the server
		if( p$tcp$flags != TH_SYN + TH_ACK)
			return;

		info[id]$connstate = waiting_ACK;

		info[id]$server_seq = p$tcp$seq + 1;
	}
	else if(!is_client && state == established)#s->c
	{
		
		# missed initial request
		if(info[id]$num_requests == 0)
		{
		
		info[id]$connstate = error_occurred;
		}
		else
		{
			#++info[id]$server_pkts;
			
			#check for new data and update sequence number
			if(p$tcp$seq == info[id]$server_seq)
			{
				info[id]$server_seq = p$tcp$seq+pkt_size;
			}
			else if(p$tcp$seq < info[id]$server_seq)
			{
				#some retransmitted data 
				++info[id]$server_retrans;
				
				if(p$tcp$seq+pkt_size > info[id]$server_seq) #some new data update seq num
					info[id]$server_seq = p$tcp$seq+pkt_size;

				local idx: count;
				if(info[id]$num_requests ==0)
				{
					info[id]$connstate = error_occurred;
				}
				else if(info[id]$num_requests > info[id]$num_replies)
				{
					idx = info[id]$num_replies;
					if(idx in info[id]$transactions)
						++info[id]$transactions[idx]$server_retrans;
				}
				else
				{	#more replies than reqs
					idx =0;
					local myi: count;
					for(myi in info[id]$transactions)
					{
						if(myi+1 < info[id]$num_replies)
							++idx;

						if(idx in info[id]$transactions)
							++info[id]$transactions[idx]$server_retrans;
					}
				}	
			}
			else
			{
				#gap in data
				info[id]$server_seq = p$tcp$seq + pkt_size;
			}
		}		
	}

	last_hdr = p;

}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
	local id = c$id; #id of this connection

	if(id !in info)
		return;
	else if(info[id]$connstate == error_occurred)
		return; 

	else if(info[id]$connstate == established)
	{
		local request_index = info[id]$num_requests;
	
		if(request_index !in info[id]$transactions)
		{
			## build up a new transaction state for this request
			local transaction: http_info;
			transaction$method = method;
			transaction$user_agent = "ND";
			transaction$state = waiting_for_reply;
			transaction$content_type = "NONE/NONE";
			transaction$reply_start_seq = 0;
			transaction$reply_end_seq = 0;
			transaction$reply_start_t = 0.0;
			transaction$reply_end_t = 0.0;
			transaction$request_t = network_time();
			transaction$code = 999;
			transaction$server_retrans = 0;
			transaction$content_length_up = "ND";
			transaction$content_length_down = "ND";
			transaction$uri = original_URI;
			transaction$host = "ND";
			transaction$location = "ND";
			transaction$referer = "ND";
			transaction$version = version;
			transaction$no_cache = F;
			transaction$no_store = F;
			transaction$public = T;
			transaction$uri = original_URI;

			info[id]$transactions[request_index]=transaction;

			++info[id]$num_requests; #increase the index into the transactions array

			if(info[id]$num_requests >(info[id]$num_replies + 1))
			{
				# pipelined requests
				info[id]$pipelined = T;
			}
		}
		else
		{
			info[id]$connstate = error_occurred;
		}
	}
	else
	{
		info[id]$connstate = error_occurred;
	}
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
	local id = c$id; #id of this connection

	if(id !in info)
		return;
	else if(info[id]$connstate == error_occurred)
		return;
	
	else if(info[id]$connstate == established)
	{
		if(info[id]$num_requests == 0)
		{
			info[id]$connstate = error_occurred;
			return;
		}
		local reply_index = info[id]$num_replies;

		if(reply_index in info[id]$transactions &&
			info[id]$transactions[reply_index]$state == waiting_for_reply)
		{
			## update the status and record the start time of the reply
			info[id]$transactions[reply_index]$reply_start_seq = last_hdr$tcp$seq;
			info[id]$transactions[reply_index]$state = waiting_for_reply_end;
			info[id]$transactions[reply_index]$reply_start_t = network_time();
			info[id]$transactions[reply_index]$code = code;
			info[id]$transactions[reply_index]$version = version;
		}
		else
		{
			info[id]$connstate = error_occurred;
		}
	}
	else 
	{	
		info[id]$connstate = error_occurred;
	}	
}


event http_header(c: connection, is_orig: bool, name:string, value: string)
{

	local id = c$id;
	local index:count;

	if(id !in info)
		return;	
	
	if(is_orig) ## data from client
	{
		index = info[id]$num_requests-1;
			
		if(index !in info[id]$transactions)
			return;

		if(value == "") #don't insert arguments with length 0
			return;
		## track content length c->s
		
		if(name=="CONTENT-LENGTH")
			info[id]$transactions[index]$content_length_up = value;
		else if(name=="HOST")
			info[id]$transactions[index]$host = value;
		else if(name == "REFERER")
			info[id]$transactions[index]$referer = value;
		else if(name == "USER-AGENT")
		{
			if(value == "contype" || value == " contype")
			{
				return;
			}
			info[id]$transactions[index]$user_agent = value;
#			local pieces = split(value,/;/);
#			local len = length(pieces);
#			if(len>1)
#				info[id]$transactions[index]$user_agent = fmt("%s;%s",pieces[1], pieces[2]);
#			else if(len ==1)
#				info[id]$transactions[index]$user_agent = pieces[1];
			
			

		}
	}
	else
	{
		## server headers
		index = info[id]$num_replies;
		if(index !in info[id]$transactions)
			return;
		
		if(value == "") #don't insert arguments with length 0
			return;

		
		if(name=="CONTENT-TYPE")
		{
			
			local pieces2 = split1(value,/;/);
			if(length(pieces2) >=1)
			{
				info[id]$transactions[index]$content_type = to_upper(subst_string(pieces2[1]," ",""));
			}
			else
				info[id]$transactions[index]$content_type = "BAD/BAD";			

			
		}
		else if(name=="CONTENT-LENGTH") # track content length s->c
			info[id]$transactions[index]$content_length_down = value;
		else if(name=="LOCATION")
			info[id]$transactions[index]$location = value;
		else if(name =="CACHE-CONTROL")
		{
			local lower = to_lower(value);
			if(/no-cache/ in lower )
				info[id]$transactions[index]$no_cache=T;
			if(/no-store/ in lower)
				info[id]$transactions[index]$no_store = T;
			if(/private/ in lower)
				info[id]$transactions[index]$public = F;
		
		}	
	}	
	
}


event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
{
	if ( is_orig )
		# It's for the client rather than the server - ignore.
		return;

	local id = c$id;
	
	if(id !in info)
		return;
	if(info[id]$connstate == error_occurred)
	{
		return;
	}
	else if(info[id]$connstate == established)
	{
		local index = info[id]$num_replies;

		if(index in info[id]$transactions && info[id]$transactions[index]$state==waiting_for_reply_end)
		{
			local pkt_size = last_hdr$ip$len - last_hdr$ip$hl - last_hdr$tcp$hl;

			info[id]$transactions[index]$reply_end_seq = last_hdr$tcp$seq + pkt_size;

			info[id]$transactions[index]$reply_end_t = network_time();
			info[id]$transactions[index]$state = waiting_for_ack_of_reply;
			++info[id]$num_replies; #increase index for replies	
		}
		else
		{
			## got end of reply but most recent received reply is not 
			## waiting for the end of the reply
			info[id]$connstate=error_occurred;
		}
	}
	else
	{	
		info[id]$connstate =error_occurred;
	}
	
}


event content_gap(c: connection, is_orig: bool, seq: count, length: count)
{
	local id = c$id;

	if(id !in info)
	{
	  return;
	}
        else if (info[id]$connstate == error_occurred)
        {
          return;
        }
	else if (info[id]$num_replies_acked == 0)
	{
		local idx = 0;
		if(idx in info[id]$transactions)
		{
			info[id]$transactions[idx]$reply_end_t = network_time();

			info[id]$transactions[idx]$state = transaction_gapped;
			print fmt("G|%s",http_tostring(id,info[id]$transactions[idx]));
			delete info[id]$transactions[idx];
		}
	}	
	info[id]$connstate = error_occurred;
}


event bro_done()
{

}
