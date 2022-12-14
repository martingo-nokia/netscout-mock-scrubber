# Netscout mock scrubber

Based on the work that the A-team put together, this respository will explain how to bring up a fake scrubber with a Netscout API that can be used by Nokia Deepfield to test out the Netscout connector from a control plane perspective

## Configuration

1. Create the API key that will be used from Deepfield to configure the Netscout connector

```
curl -k -X POST http://127.0.0.1:8888/api/key -H 'Content-Type: application/json' -d '{"api_token": "PQgBvre6N94RwaSmbSE_Ui_sBFQeOXz22HYW6EoV"}'
```

This will create a file in the local folder called "netscout_data.pkl"

2. Test out that it works:

```
curl -H "X-Arbux-APIToken: PQgBvre6N94RwaSmbSE_Ui_sBFQeOXz22HYW6EoV" -H "Content-Type: application/vnd.api+json" -L http://localhost:8888/api/sp/mitigation_templates/?include=tms_group | json_pp
```
The output should look like this:

```
{
   "data" : [
      {
         "attributes" : {
            "description" : "Default mitigation values inherited by all new IPv4 mitigations (unless otherwise scoped)",
            "ip_version" : 4,
            "name" : "Default IPv4",
            "subobject" : {
               "aif_http_url_regexp" : {
                  "aif_http_level" : "low",
                  "blacklist_on_blocked" : true
               },
               "bgp_announce" : true,
               "black_white_lists" : {
                  "blacklist_sources" : false,
                  "blacklist_sources_locked" : true
               },
               "diversion_prefix_enabled" : false,
               "diversion_prefix_locked" : true,
               "dns_auth" : {
                  "enabled" : true,
                  "locked" : true,
                  "timeout" : 60
               },
               "dns_malformed" : {
                  "enabled" : true,
                  "locked" : true
               },
               "dns_object_ratelimiting" : {
                  "blacklist_enabled" : false,
                  "enabled" : false,
                  "limit" : 100,
                  "locked" : true
               },
               "dns_regex" : {
                  "match_direction" : "query",
                  "match_direction_locked" : true
               },
               "http_malformed" : {
                  "enabled" : true,
                  "level" : "low",
                  "locked" : true
               },
               "http_object" : {
                  "enabled" : true,
                  "limit" : 10,
                  "locked" : true
               },
               "http_request" : {
                  "enabled" : true,
                  "limit" : 100,
                  "locked" : true
               },
               "ip_address_filterlist" : {
                  "blacklist_sources" : true,
                  "blacklist_sources_locked" : true
               },
               "ip_location_filterlist" : {
                  "drop_matched_or_unmatched" : "matched"
               },
               "packet_header_filtering" : {
                  "locked" : true
               },
               "payload" : {
                  "blacklist_hosts" : false,
                  "match_src_port" : false,
                  "match_src_port_locked" : false
               },
               "per_connection_flood_protection" : {
                  "enabled" : false,
                  "enforcement" : "block",
                  "locked" : true,
                  "maximum_bps" : 0,
                  "maximum_pps" : 0
               },
[Output truncated]
```

2. Ensure the Netscout connector license is installed in your Deepfield deployment

TBC
