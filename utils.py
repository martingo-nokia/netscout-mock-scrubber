import arrow


def response_start_tms_mitigation(data, current_mitigation_id):
    tms_mitigation_data = {
        "data": {
            "attributes": {
                "description": data["data"]["attributes"]["description"],
                "ip_version": data["data"]["attributes"]["ip_version"],
                "is_automitigation": False,
                "name": data["data"]["attributes"]["name"],
                "ongoing": True,
                "start": str(arrow.utcnow()),
                "subobject": {
                    "aif_http_url_regexp": {
                        "active": False,
                        "aif_http_level": "low",
                        "blacklist_on_blocked": True,
                    },
                    "bgp_announce": True,
                    "black_white_lists": {"active": False},
                    "diversion_prefix_enabled": False,
                    "diversion_prefixes": data["data"]["attributes"]["subobject"][
                        "protection_prefixes"
                    ],
                    "dns_auth": {
                        "active": True,
                        "enabled": True,
                        "mode": "passive",
                        "timeout": 60,
                    },
                    "dns_malformed": {"active": True, "enabled": True},
                    "dns_nx_ratelimiting": {"active": False},
                    "dns_object_ratelimiting": {"active": False, "limit": 100},
                    "dns_ratelimiting": {"active": False, "limit": 100},
                    "dns_regex": {"active": False, "match_direction": "query"},
                    "dns_scoping": {"active": False, "apply_on_match": True},
                    "http_malformed": {"active": True, "enabled": True, "level": "low"},
                    "http_object": {"active": True, "enabled": True, "limit": 10},
                    "http_request": {"active": True, "enabled": True, "limit": 100},
                    "http_scoping": {"active": False, "apply_on_match": True},
                    "ip_address_filterlist": {
                        "active": False,
                        "blacklist_sources": True,
                    },
                    "ip_location_filterlist": {
                        "active": False,
                        "drop_matched_or_unmatched": "matched",
                    },
                    "ip_location_policing": {"active": False},
                    "packet_header_filtering": {"active": False},
                    "payload": {"active": False},
                    "per_connection_flood_protection": {
                        "active": True,
                        "enabled": False,
                        "enforcement": "block",
                        "maximum_bps": 0,
                        "maximum_pps": 0,
                    },
                    "protection_prefixes": data["data"]["attributes"]["subobject"][
                        "protection_prefixes"
                    ],
                    "protocol_baselines": {"active": False},
                    "proxy_list_threshold_exceptions": {"scaling_factor": 1.0},
                    "shaping": {"active": False},
                    "sip_malformed": {"active": True, "enabled": True},
                    "sip_request_limiting": {
                        "active": True,
                        "enabled": True,
                        "limit": 100,
                    },
                    "ssl_negotiation": {
                        "active": False,
                        "clients_can_alert": True,
                        "max_cipher_suites": 100,
                        "max_early_close": 25,
                        "max_extensions": 10,
                        "max_pend_secs": 30,
                        "min_pend_secs": 15,
                    },
                    "tcp_connection_limiting": {
                        "active": False,
                        "blacklist": True,
                        "idle_timeout": 60,
                        "ignore_idle": True,
                        "max_connections": 25,
                    },
                    "tcp_connection_reset": {
                        "active": True,
                        "enabled": True,
                        "slow_application_bitrate_interval": 60,
                        "slow_application_header_time": 60,
                        "slow_application_request_bitrate": 200,
                        "timeout": 90,
                        "track_long_lived": True,
                    },
                    "tcp_syn_auth": {
                        "active": True,
                        "auto": False,
                        "enabled": True,
                        "idle_timeout": 60,
                    },
                    "udp_reflection_amp": {
                        "active": False,
                        "auto_transfer_misuse": False,
                        "auto_transfer_misuse_dns": False,
                        "blacklist_enabled": True,
                        "dns": {"match_fcap": "bytes " "2049..65535"},
                    },
                    "zombie_detection": {
                        "active": True,
                        "all_hosts": {"thresholds": {"bps": 2000000, "pps": 500}},
                        "enabled": True,
                    },
                },
                "subtype": "tms",
                "user": "deepfield",
            },
            "links": {"self": "https://localhost:11443/api/sp/v4/mitigations/tms-8"},
            "relationships": {
                "mitigation_template": {
                    "data": {
                        "id": data["data"]["relationships"]["mitigation_template"][
                            "data"
                        ]["id"],
                        "type": data["data"]["relationships"]["mitigation_template"][
                            "data"
                        ]["type"],
                    },
                    "links": {
                        "related": "https://localhost:11443/api/sp/v4/mitigation_templates/1"
                    },
                },
                "rates": {
                    "links": {
                        "related": "https://localhost:11443/api/sp/v4/mitigations/tms-8/rates/"
                    }
                },
                "rates_all_devices": {
                    "links": {
                        "related": "https://localhost:11443/api/sp/v4/mitigations/tms-8/rates_all_devices"
                    }
                },
                "tms_group": {
                    "data": {"id": "3", "type": "tms_group"},
                    "links": {
                        "related": "https://localhost:11443/api/sp/v4/tms_groups/3"
                    },
                },
            },
            "type": "mitigation",
        }
    }

    tms_mitigation_data["data"]["id"] = f"tms-{current_mitigation_id}"

    return tms_mitigation_data


def response_patch_tms_mitigation(patch_data, stored):
    protection_prefixes = (
        patch_data.get("data", {})
        .get("attributes", {})
        .get("subobject", {})
        .get("protection_prefixes", {})
    )
    if type(protection_prefixes) == list:
        stored["data"]["attributes"]["subobject"][
            "protection_prefixes"
        ] = protection_prefixes
        stored["data"]["attributes"]["subobject"][
            "diversion_prefixes"
        ] = protection_prefixes

    ongoing = patch_data.get("data", {}).get("attributes", {}).get("ongoing", {})
    if type(ongoing) == bool:
        stored["data"]["attributes"]["ongoing"] = ongoing

    if type(ongoing) == bool and ongoing is False:
        stored["data"]["attributes"]["stop"] = str(arrow.utcnow())

    return stored


DEFAULT_MITIGATION_ID_TEMPLATES = {
    "1": {
        "data": {
            "attributes": {
                "description": "Default mitigation values inherited by all "
                "new IPv4 mitigations (unless otherwise "
                "scoped)",
                "ip_version": 4,
                "name": "Default IPv4",
                "subobject": {
                    "aif_http_url_regexp": {
                        "aif_http_level": "low",
                        "blacklist_on_blocked": True,
                    },
                    "bgp_announce": True,
                    "black_white_lists": {
                        "blacklist_sources": False,
                        "blacklist_sources_locked": True,
                    },
                    "diversion_prefix_enabled": False,
                    "diversion_prefix_locked": True,
                    "dns_auth": {"enabled": True, "locked": True, "timeout": 60},
                    "dns_malformed": {"enabled": True, "locked": True},
                    "dns_object_ratelimiting": {
                        "blacklist_enabled": False,
                        "enabled": False,
                        "limit": 100,
                        "locked": True,
                    },
                    "dns_regex": {
                        "match_direction": "query",
                        "match_direction_locked": True,
                    },
                    "http_malformed": {"enabled": True, "level": "low", "locked": True},
                    "http_object": {"enabled": True, "limit": 10, "locked": True},
                    "http_request": {"enabled": True, "limit": 100, "locked": True},
                    "ip_address_filterlist": {
                        "blacklist_sources": True,
                        "blacklist_sources_locked": True,
                    },
                    "ip_location_filterlist": {"drop_matched_or_unmatched": "matched"},
                    "packet_header_filtering": {"locked": True},
                    "payload": {
                        "blacklist_hosts": False,
                        "match_src_port": False,
                        "match_src_port_locked": False,
                    },
                    "per_connection_flood_protection": {
                        "enabled": False,
                        "enforcement": "block",
                        "locked": True,
                        "maximum_bps": 0,
                        "maximum_pps": 0,
                    },
                    "protection_prefixes": [""],
                    "protocol_baselines": {"locked": True},
                    "sip_malformed": {"enabled": True, "locked": True},
                    "sip_request_limiting": {
                        "enabled": True,
                        "limit": 100,
                        "locked": True,
                    },
                    "ssl_negotiation": {
                        "clients_can_alert": True,
                        "max_cipher_suites": 100,
                        "max_early_close": 25,
                        "max_extensions": 10,
                        "max_pend_secs": 30,
                        "min_pend_secs": 15,
                    },
                    "tcp_connection_limiting": {
                        "blacklist": True,
                        "enabled": False,
                        "ignore_idle": True,
                        "locked": True,
                    },
                    "tcp_connection_reset": {
                        "enabled": True,
                        "locked": True,
                        "slow_application_bitrate_interval": 60,
                        "slow_application_header_time": 60,
                        "slow_application_request_bitrate": 200,
                        "timeout": 90,
                        "track_long_lived": True,
                    },
                    "tcp_syn_auth": {
                        "enabled": True,
                        "idle_timeout": 60,
                        "locked": True,
                    },
                    "udp_reflection_amp": {
                        "auto_transfer_misuse": False,
                        "auto_transfer_misuse_dns": False,
                        "blacklist_enabled": True,
                        "dns": {"match_fcap": "bytes " "2049..65535"},
                        "enabled": False,
                        "locked": True,
                    },
                    "zombie_detection": {
                        "all_hosts": {"thresholds": {"bps": 2000000, "pps": 500}},
                        "enabled": True,
                        "locked": True,
                    },
                },
                "subtype": "tms",
                "system": True,
            },
            "id": "1",
            "links": {
                "self": "https://localhost:11443/api/sp/v4/mitigation_templates/1?include=tms_group"
            },
            "relationships": {
                "tms_group": {
                    "data": {"id": "3", "type": "tms_group"},
                    "links": {
                        "related": "https://localhost:11443/api/sp/v4/tms_groups/3"
                    },
                }
            },
            "type": "mitigation_template",
        }
    },
    "8": {
        "data": {
            "relationships": {
                "tms_group": {
                    "data": {"type": "tms_group", "id": "3"},
                    "links": {
                        "related": "https://localhost:11443/api/sp/v4/tms_groups/3"
                    },
                }
            },
            "attributes": {
                "description": "Default mitigation values inherited by all new IPv6 mitigations (unless otherwise scoped)",
                "system": True,
                "subtype": "tms",
                "ip_version": 6,
                "subobject": {
                    "dns_auth": {
                        "enabled": True,
                        "locked": True,
                        "mode": "passive",
                        "timeout": 60,
                    },
                    "black_white_lists": {
                        "blacklist_sources": False,
                        "blacklist_sources_locked": True,
                    },
                    "bgp_announce": True,
                    "ip_address_filterlist": {
                        "blacklist_sources": True,
                        "blacklist_sources_locked": True,
                    },
                    "tcp_syn_auth": {
                        "locked": True,
                        "idle_timeout": 60,
                        "enabled": True,
                    },
                    "dns_regex": {
                        "match_direction": "query",
                        "match_direction_locked": True,
                    },
                    "zombie_detection": {
                        "all_hosts": {"thresholds": {"pps": 500, "bps": 2000000}},
                        "enabled": True,
                        "locked": True,
                    },
                    "udp_reflection_amp": {
                        "locked": True,
                        "enabled": False,
                        "blacklist_enabled": True,
                        "dns": {"match_fcap": "bytes 2049..65535"},
                        "auto_transfer_misuse_dns": False,
                        "auto_transfer_misuse": False,
                    },
                    "diversion_prefix_enabled": False,
                    "dns_malformed": {"enabled": True, "locked": True},
                    "protection_prefixes": [""],
                    "diversion_prefix_locked": True,
                    "dns_object_ratelimiting": {
                        "locked": True,
                        "enabled": False,
                        "limit": 100,
                        "blacklist_enabled": False,
                    },
                    "payload": {
                        "match_src_port_locked": False,
                        "match_src_port": False,
                        "blacklist_hosts": False,
                    },
                },
                "name": "Default IPv6",
            },
            "type": "mitigation_template",
            "id": "8",
            "links": {
                "self": "https://localhost:11443/api/sp/v4/mitigation_templates/8"
            },
        }
    },
    "9": {
        "data": {
            "attributes": {
                "description": "Without tms_group",
                "ip_version": 4,
                "name": "No tms_group IPv4",
                "subobject": {
                    "bgp_announce": True,
                    "diversion_prefix_enabled": False,
                    "diversion_prefix_locked": True,
                    "ip_address_filterlist": {
                        "blacklist_sources": True,
                        "blacklist_sources_locked": True,
                    },
                    "ip_location_filterlist": {"drop_matched_or_unmatched": "matched"},
                    "protection_prefixes": [""],
                    "protocol_baselines": {"locked": True},
                },
                "subtype": "tms",
                "system": True,
            },
            "id": "9",
            "type": "mitigation_template",
        }
    },
    "13": {
        "data": {
            "attributes": {
                "description": "Template for Nokia API Testing - IPv4",
                "ip_version": 4,
                "name": "Nokia API Testing - IPv4",
                "subobject": {
                    "aif_http_url_regexp": {
                        "aif_http_level": "low",
                        "blacklist_on_blocked": True,
                    },
                    "bgp_announce": True,
                    "black_white_lists": {
                        "blacklist_sources": False,
                        "blacklist_sources_locked": True,
                    },
                    "diversion_prefix_enabled": False,
                    "diversion_prefix_locked": True,
                    "dns_auth": {"enabled": True, "locked": True, "timeout": 60},
                    "dns_malformed": {"enabled": True, "locked": True},
                    "dns_object_ratelimiting": {
                        "blacklist_enabled": False,
                        "enabled": False,
                        "limit": 100,
                        "locked": True,
                    },
                    "dns_regex": {
                        "match_direction": "query",
                        "match_direction_locked": True,
                    },
                    "http_malformed": {"enabled": True, "level": "low", "locked": True},
                    "http_object": {"enabled": True, "limit": 10, "locked": True},
                    "http_request": {"enabled": True, "limit": 100, "locked": True},
                    "ip_address_filterlist": {
                        "blacklist_sources": True,
                        "blacklist_sources_locked": True,
                    },
                    "ip_location_filterlist": {"drop_matched_or_unmatched": "matched"},
                    "packet_header_filtering": {"locked": True},
                    "payload": {
                        "blacklist_hosts": False,
                        "match_src_port": False,
                        "match_src_port_locked": False,
                    },
                    "per_connection_flood_protection": {
                        "enabled": False,
                        "enforcement": "block",
                        "locked": True,
                        "maximum_bps": 0,
                        "maximum_pps": 0,
                    },
                    "protection_prefixes": [""],
                    "protocol_baselines": {"locked": True},
                    "sip_malformed": {"enabled": True, "locked": True},
                    "sip_request_limiting": {
                        "enabled": True,
                        "limit": 100,
                        "locked": True,
                    },
                    "ssl_negotiation": {
                        "clients_can_alert": True,
                        "max_cipher_suites": 100,
                        "max_early_close": 25,
                        "max_extensions": 10,
                        "max_pend_secs": 30,
                        "min_pend_secs": 15,
                    },
                    "tcp_connection_limiting": {
                        "blacklist": True,
                        "enabled": False,
                        "ignore_idle": True,
                        "locked": True,
                    },
                    "tcp_connection_reset": {
                        "enabled": True,
                        "locked": True,
                        "slow_application_bitrate_interval": 60,
                        "slow_application_header_time": 60,
                        "slow_application_request_bitrate": 200,
                        "timeout": 90,
                        "track_long_lived": True,
                    },
                    "tcp_syn_auth": {
                        "enabled": True,
                        "idle_timeout": 60,
                        "locked": True,
                    },
                    "udp_reflection_amp": {
                        "auto_transfer_misuse": False,
                        "auto_transfer_misuse_dns": False,
                        "blacklist_enabled": True,
                        "dns": {"match_fcap": "bytes " "2049..65535"},
                        "enabled": False,
                        "locked": True,
                    },
                    "zombie_detection": {
                        "all_hosts": {"thresholds": {"bps": 2000000, "pps": 500}},
                        "enabled": True,
                        "locked": True,
                    },
                },
                "subtype": "tms",
                "system": True,
            },
            "id": "13",
            "links": {
                "self": "https://localhost:11443/api/sp/v4/mitigation_templates/13?include=tms_group"
            },
            "relationships": {
                "tms_group": {
                    "data": {"id": "262", "type": "tms_group"},
                    "links": {
                        "related": "https://localhost:11443/api/sp/v4/tms_groups/262"
                    },
                }
            },
            "type": "mitigation_template",
        }
    },
    "15": {
        "data": {
            "relationships": {
                "tms_group": {
                    "data": {"type": "tms_group", "id": "262"},
                    "links": {
                        "related": "https://localhost:11443/api/sp/v4/tms_groups/262"
                    },
                }
            },
            "attributes": {
                "description": "Template for Nokia API Testing - IPv6",
                "system": True,
                "subtype": "tms",
                "ip_version": 6,
                "subobject": {
                    "dns_auth": {
                        "enabled": True,
                        "locked": True,
                        "mode": "passive",
                        "timeout": 60,
                    },
                    "black_white_lists": {
                        "blacklist_sources": False,
                        "blacklist_sources_locked": True,
                    },
                    "bgp_announce": True,
                    "ip_address_filterlist": {
                        "blacklist_sources": True,
                        "blacklist_sources_locked": True,
                    },
                    "tcp_syn_auth": {
                        "locked": True,
                        "idle_timeout": 60,
                        "enabled": True,
                    },
                    "dns_regex": {
                        "match_direction": "query",
                        "match_direction_locked": True,
                    },
                    "zombie_detection": {
                        "all_hosts": {"thresholds": {"pps": 500, "bps": 2000000}},
                        "enabled": True,
                        "locked": True,
                    },
                    "udp_reflection_amp": {
                        "locked": True,
                        "enabled": False,
                        "blacklist_enabled": True,
                        "dns": {"match_fcap": "bytes 2049..65535"},
                        "auto_transfer_misuse_dns": False,
                        "auto_transfer_misuse": False,
                    },
                    "diversion_prefix_enabled": False,
                    "dns_malformed": {"enabled": True, "locked": True},
                    "protection_prefixes": [""],
                    "diversion_prefix_locked": True,
                    "dns_object_ratelimiting": {
                        "locked": True,
                        "enabled": False,
                        "limit": 100,
                        "blacklist_enabled": False,
                    },
                    "payload": {
                        "match_src_port_locked": False,
                        "match_src_port": False,
                        "blacklist_hosts": False,
                    },
                },
                "name": "Nokia API Testing - IPv6",
            },
            "type": "mitigation_template",
            "id": "15",
            "links": {
                "self": "https://localhost:11443/api/sp/v4/mitigation_templates/15"
            },
        }
    },
}


DEFAULT_TMS_GROUPS = {
    "data": [
        {
            "attributes": {
                "bgp_communities": [],
                "check_available_bw": True,
                "check_bgp_peering": True,
                "check_group_allup": True,
                "default_bgp_offramp": True,
                "description": "Default all mitigation group. Mitigations "
                "will use all ports on all configured TMS "
                "devices.",
                "dns_auth_active_secondary_servers": False,
                "fail_open": False,
                "flowspec_communities": [],
                "flowspec_offramp": "",
                "flowspec_redirect_ipv4_destination": "",
                "flowspec_redirect_ipv4_type": "",
                "flowspec_redirect_ipv6_destination": "",
                "flowspec_redirect_ipv6_type": "",
                "member_limits_differ": False,
                "members_cluster": "",
                "name": "All",
                "nexthop": "",
                "nexthop_v6": "",
                "system": True,
                "tms_group_type": "",
            },
            "id": "3",
            "links": {"self": "https://localhost:11443/api/sp/v4/tms_groups/3"},
            "relationships": {
                "tms_ports": {
                    "data": [
                        {"id": "122", "type": "tms_port"},
                        {"id": "123", "type": "tms_port"},
                        {"id": "124", "type": "tms_port"},
                        {"id": "125", "type": "tms_port"},
                        {"id": "126", "type": "tms_port"},
                        {"id": "127", "type": "tms_port"},
                        {"id": "128", "type": "tms_port"},
                        {"id": "146", "type": "tms_port"},
                        {"id": "147", "type": "tms_port"},
                    ],
                    "links": {
                        "related": "https://localhost:11443/api/sp/v4/tms_ports/"
                    },
                }
            },
            "type": "tms_group",
        },
        {
            "attributes": {
                "bgp_communities": [],
                "check_available_bw": True,
                "check_bgp_peering": False,
                "check_group_allup": False,
                "default_bgp_offramp": True,
                "description": "TMS Group for LAB",
                "dns_auth_active_secondary_servers": False,
                "fail_open": False,
                "flowspec_communities": [],
                "flowspec_offramp": "",
                "flowspec_redirect_ipv4_destination": "",
                "flowspec_redirect_ipv4_type": "route_target",
                "flowspec_redirect_ipv6_destination": "",
                "flowspec_redirect_ipv6_type": "route_target",
                "member_limits_differ": False,
                "members_cluster": "",
                "name": "LAB_TMS_GROUP",
                "nexthop": "",
                "nexthop_v6": "",
                "system": False,
                "tms_group_type": "appliance",
            },
            "id": "151",
            "links": {"self": "https://localhost:11443/api/sp/v4/tms_groups/151"},
            "relationships": {
                "tms_ports": {
                    "data": [{"id": "146", "type": "tms_port"}],
                    "links": {
                        "related": "https://localhost:11443/api/sp/v4/tms_ports/"
                    },
                }
            },
            "type": "tms_group",
        },
        {
            "attributes": {
                "bgp_communities": [],
                "check_available_bw": True,
                "check_bgp_peering": True,
                "check_group_allup": True,
                "default_bgp_offramp": True,
                "description": "TMS group for Nokia API Testing",
                "dns_auth_active_secondary_servers": False,
                "fail_open": False,
                "flowspec_communities": [],
                "flowspec_offramp": "",
                "flowspec_redirect_ipv4_destination": "",
                "flowspec_redirect_ipv4_type": "",
                "flowspec_redirect_ipv6_destination": "",
                "flowspec_redirect_ipv6_type": "",
                "member_limits_differ": False,
                "members_cluster": "",
                "name": "All",
                "nexthop": "",
                "nexthop_v6": "",
                "system": True,
                "tms_group_type": "",
            },
            "id": "262",
            "links": {"self": "https://localhost:11443/api/sp/v4/tms_groups/262"},
            "relationships": {
                "tms_ports": {
                    "data": [
                        {"id": "122", "type": "tms_port"},
                        {"id": "123", "type": "tms_port"},
                        {"id": "124", "type": "tms_port"},
                        {"id": "125", "type": "tms_port"},
                        {"id": "126", "type": "tms_port"},
                        {"id": "127", "type": "tms_port"},
                        {"id": "128", "type": "tms_port"},
                        {"id": "146", "type": "tms_port"},
                        {"id": "147", "type": "tms_port"},
                    ],
                    "links": {
                        "related": "https://localhost:11443/api/sp/v4/tms_ports/"
                    },
                }
            },
            "type": "tms_group",
        },
    ]
}

DEFAULT_MITIGATION_TEMPLATES = {
    "data": [
        {
            "id": "1",
            "name": "Default IPv4",
            "description": "Default mitigation values inherited by all new IPv4 mitigations (unless otherwise scoped)",
            "ip_version": 4,
        },
        {
            "id": "2",
            "name": "Auto-Mitigation IPv4",
            "description": "Auto-Mitigation template use by default for all IPv4 auto-mitigations. Auto-mitigation must be enabled for the managed object.",
            "ip_version": 4,
        },
        {
            "id": "3",
            "name": "VoIP Gateway Protection",
            "description": "Template contains countermeasures that support TMS deployments focused on VoIP Gateway Flood Protection",
            "ip_version": 4,
        },
        {
            "description": "Template provides example countermeasures that would support deployments for DNS infrastructure protection",
            "ip_version": 4,
            "name": "DNS Flood Protection",
            "id": "4",
        },
        {
            "id": "5",
            "name": "Rogue DC++ Protection",
            "description": "Rogue DC++ P2P clients have been used to attack HTTP Server infrastructure. This template provides an example of payload REGEX inspection for filtering clients used for a DC++ HTTP attack",
            "ip_version": 4,
        },
        {
            "id": "6",
            "name": "TCP SYN Flood",
            "description": "TCP SYN flood countermeasure",
            "ip_version": 4,
        },
        {
            "id": "7",
            "name": "ICMP Flood",
            "description": "ICMP Flood Countermeasure",
            "ip_version": 4,
        },
        {
            "id": "8",
            "name": "Default IPv6",
            "description": "Default mitigation values inherited by all new IPv6 mitigations (unless otherwise scoped)",
            "ip_version": 6,
        },
        {
            "id": "9",
            "name": "Auto-Mitigation IPv6",
            "description": "Auto-Mitigation template use by default for all IPv6 auto-mitigations. Auto-mitigation must be enabled for the managed object.",
            "ip_version": 6,
        },
        {
            "id": "13",
            "name": "Nokia API Testing - IPv4",
            "description": "Template for Nokia API Testing - IPv4",
            "ip_version": 4,
        },
        {
            "id": "15",
            "name": "Nokia API Testing - IPv6",
            "description": "Template for Nokia API Testing - IPv6",
            "ip_version": 6,
        },
    ]
}

DEFAULT_MITIGATIONS = [
    {
        "attributes": {
            "description": "tms_mitigation 5 for ipv6",
            "ip_version": 6,
            "is_automitigation": False,
            "name": "BGP-Flowspec-SSR-IPv6",
            "ongoing": False,
            "start": "2021-06-18T09:21:04.174260+00:00",
            "subobject": {
                "aif_http_url_regexp": {
                    "active": False,
                    "aif_http_level": "low",
                    "blacklist_on_blocked": True,
                },
                "bgp_announce": True,
                "black_white_lists": {"active": False},
                "diversion_prefix_enabled": False,
                "diversion_prefixes": ["2001::192:168:10:25/128"],
                "dns_auth": {
                    "active": True,
                    "enabled": True,
                    "mode": "passive",
                    "timeout": 60,
                },
                "dns_malformed": {"active": True, "enabled": True},
                "dns_nx_ratelimiting": {"active": False},
                "dns_object_ratelimiting": {"active": False, "limit": 100},
                "dns_ratelimiting": {"active": False, "limit": 100},
                "dns_regex": {"active": False, "match_direction": "query"},
                "dns_scoping": {"active": False, "apply_on_match": True},
                "http_malformed": {"active": True, "enabled": True, "level": "low"},
                "http_object": {"active": True, "enabled": True, "limit": 10},
                "http_request": {"active": True, "enabled": True, "limit": 100},
                "http_scoping": {"active": False, "apply_on_match": True},
                "ip_address_filterlist": {"active": False, "blacklist_sources": True},
                "ip_location_filterlist": {
                    "active": False,
                    "drop_matched_or_unmatched": "matched",
                },
                "ip_location_policing": {"active": False},
                "packet_header_filtering": {"active": False},
                "payload": {"active": False},
                "per_connection_flood_protection": {
                    "active": True,
                    "enabled": False,
                    "enforcement": "block",
                    "maximum_bps": 0,
                    "maximum_pps": 0,
                },
                "protection_prefixes": ["2001::192:168:10:25/128"],
                "protocol_baselines": {"active": False},
                "proxy_list_threshold_exceptions": {"scaling_factor": 1.0},
                "shaping": {"active": False},
                "sip_malformed": {"active": True, "enabled": True},
                "sip_request_limiting": {"active": True, "enabled": True, "limit": 100},
                "ssl_negotiation": {
                    "active": False,
                    "clients_can_alert": True,
                    "max_cipher_suites": 100,
                    "max_early_close": 25,
                    "max_extensions": 10,
                    "max_pend_secs": 30,
                    "min_pend_secs": 15,
                },
                "tcp_connection_limiting": {
                    "active": False,
                    "blacklist": True,
                    "idle_timeout": 60,
                    "ignore_idle": True,
                    "max_connections": 25,
                },
                "tcp_connection_reset": {
                    "active": True,
                    "enabled": True,
                    "slow_application_bitrate_interval": 60,
                    "slow_application_header_time": 60,
                    "slow_application_request_bitrate": 200,
                    "timeout": 90,
                    "track_long_lived": True,
                },
                "tcp_syn_auth": {
                    "active": True,
                    "auto": False,
                    "enabled": True,
                    "idle_timeout": 60,
                },
                "udp_reflection_amp": {
                    "active": False,
                    "auto_transfer_misuse": False,
                    "auto_transfer_misuse_dns": False,
                    "blacklist_enabled": True,
                    "dns": {"match_fcap": "bytes " "2049..65535"},
                },
                "zombie_detection": {
                    "active": True,
                    "all_hosts": {"thresholds": {"bps": 2000000, "pps": 500}},
                    "enabled": True,
                },
            },
            "subtype": "tms",
            "user": "deepfield",
        },
        "id": "tms-5",
        "links": {"self": "https://localhost:11443/api/sp/v4/mitigations/tms-8"},
        "relationships": {
            "mitigation_template": {
                "data": {},
                "links": {
                    "related": "https://localhost:11443/api/sp/v4/mitigation_templates/1"
                },
            },
            "rates": {
                "links": {
                    "related": "https://localhost:11443/api/sp/v4/mitigations/tms-8/rates/"
                }
            },
            "rates_all_devices": {
                "links": {
                    "related": "https://localhost:11443/api/sp/v4/mitigations/tms-8/rates_all_devices"
                }
            },
            "tms_group": {
                "data": {"id": "3", "type": "tms_group"},
                "links": {"related": "https://localhost:11443/api/sp/v4/tms_groups/3"},
            },
        },
        "type": "mitigation",
    }
]
