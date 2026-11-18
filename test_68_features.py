# -*- coding: utf-8 -*-
"""
68 项企业级全特性生成验证脚本 (包含工程加固扩展)
"""
from utils.feature_engine import FeatureConfigEngine

all_68_features = [
    # 1. 系统基础与接口 (10)
    "base", "aaa", "interface", "vlan", "vlan_termination",
    "port_isolate", "lldp", "qinq", "super_password", "header_banner",
    # 2. 可靠性与高可用 (10)
    "lacp", "stp", "vrrp", "bfd", "mirroring", "nqa", "irf_stack", "monitor_link", "ip_frr", "mstp_multi_instance",
    # 3. 路由与转发 (10)
    "static_route", "ospf", "rip", "isis", "bgp", "pbr", "route_policy", "bgp_rr", "route_redistribute", "bgp_community",
    # 4. 安全与准入 (14)
    "acl_nat", "nat_server", "port_security", "ipsec", "dhcp_snooping",
    "radius", "ipsg", "urpf", "mac_address_table", "traffic_filter", "keychain", "arp_defense", "storm_control", "cpcar_defense",
    # 5. 业务与服务 (8)
    "dhcp", "dhcp_relay", "ntp", "dns", "snmp", "syslog", "sflow", "wlan_ac",
    # 6. VPN 与组播 (7)
    "gre", "mpls", "mpls_l3vpn", "igmp_snooping", "vxlan", "pim_sm", "evpn",
    # 7. QoS 与流量工程 (3)
    "qos_car", "qos_remark", "qos_queue",
    # 8. IPv6 演进 (6)
    "ipv6_base", "ospfv3", "ripng", "ipv6_nd", "dhcpv6", "bgp4_plus"
]

print(f"Total features to test: {len(all_68_features)}")
assert len(all_68_features) == 68

engine = FeatureConfigEngine()

# 1. Test H3C
res_h3c = engine.generate({
    "vendor": "h3c",
    "features": all_68_features,
    "params": {}
})
print(f"H3C Success: {res_h3c['success']} | Lines: {res_h3c['total_lines']} | Features Applied: {len(res_h3c['features_applied'])} / 68")
assert res_h3c['success']
assert len(res_h3c['features_applied']) == 68

# 2. Test Huawei
res_hw = engine.generate({
    "vendor": "huawei",
    "features": all_68_features,
    "params": {}
})
print(f"HUAWEI Success: {res_hw['success']} | Lines: {res_hw['total_lines']} | Features Applied: {len(res_hw['features_applied'])} / 68")
assert res_hw['success']
assert len(res_hw['features_applied']) == 68

print("ALL 68 FEATURES TEST PASSED SUCCESSFULLY!")
