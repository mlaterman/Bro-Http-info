#http-info

Bro script to gather extra data about http connections.

Original version written by Phillipa Gill (2008)

Updated version by Michel Laterman (2014)

##http-info.bro

http-info.bro adds information to http.log by extending the HTTP::Info records. Additional information is logged directly to the http.log file. Extra fields that are generated are listed below.

##http-info-separate.bro

http-info-separate.bro collects data not present in bro's default http.log and puts it into a new output log. A table based on conn$uid is used to track connections - as multiple req+res pairs can use the same conn it is possible for the httpinfo.log file to have less entries than the http.log file; in the implemenation this is because a connection-level event is used to write to the log and earse terminated connections.

##Additional fields
attribute name   |  type   |  default  | description
-----------------|---------|-----------|-----------------
req_start        |  time   |  0        | request start time
req_end          |  time   |  0        | request end time
res_start        |  time   |  0        | response start time
res_end          |  time   |  0        | response end time
server_restrans  |  count  |  0        | number of server retransmissions (in packets)
content_type     |  string |  NONE     | value of the content-type header or NONE if header does not exist
no_cache         |  bool   |  F        | if the cache control header disallows caching
no_store         |  bool   |  F        | if the cache control header disallows storage
public           |  bool   |  T        | if the cache control header specifies private data
location         |  string |  ND       | value of the location header

