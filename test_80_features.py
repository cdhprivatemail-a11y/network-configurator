# -*- coding: utf-8 -*-
"""
80 项企业与运营商级全特性生成与前端 DOM 完整性验证脚本
"""
import re
import urllib.request
import json
from utils.feature_engine import FeatureConfigEngine

all_80_features = [
    # 1. 系统基础与接口 (11)
    "base", "aaa", "interface", "vlan", "vlan_termination",
    "port_isolate", "lldp", "qinq", "super_password", "header_banner", "voice_vlan",
    # 2. 可靠性与高可用 (12)
    "lacp", "stp", "vrrp", "bfd", "mirroring", "nqa", "irf_stack", "monitor_link", "ip_frr", "mstp_multi_instance", "smart_link", "dldp",
    # 3. 路由与转发 (12)
    "static_route", "ospf", "rip", "isis", "bgp", "pbr", "route_policy", "bgp_rr", "route_redistribute", "bgp_community", "ospf_stub_nssa", "ip_prefix_list",
    # 4. 安全与准入 (16)
    "acl_nat", "nat_server", "port_security", "ipsec", "dhcp_snooping",
    "radius", "ipsg", "urpf", "mac_address_table", "traffic_filter", "keychain", "arp_defense", "storm_control", "cpcar_defense", "aaa_tacacs", "zone_firewall",
    # 5. 业务与服务 (10)
    "dhcp", "dhcp_relay", "ntp", "dns", "snmp", "syslog", "sflow", "wlan_ac", "netconf_yang", "port_loopback_detect",
    # 6. VPN 与组播 (8)
    "gre", "mpls", "mpls_l3vpn", "igmp_snooping", "vxlan", "pim_sm", "evpn", "mpls_te",
    # 7. QoS 与流量工程 (4)
    "qos_car", "qos_remark", "qos_queue", "qos_gts",
    # 8. IPv6 演进 (7)
    "ipv6_base", "ospfv3", "ripng", "ipv6_nd", "dhcpv6", "bgp4_plus", "ipv6_acl_filter"
]

print(f"Total features to test: {len(all_80_features)}")
assert len(all_80_features) == 80

engine = FeatureConfigEngine()

# 1. Test H3C Engine
res_h3c = engine.generate({
    "vendor": "h3c",
    "features": all_80_features,
    "params": {}
})
print(f"H3C Engine    -> Success: {res_h3c['success']} | Lines: {res_h3c['total_lines']} | Features Applied: {len(res_h3c['features_applied'])} / 80")
assert res_h3c['success']
assert len(res_h3c['features_applied']) == 80

# 2. Test Huawei Engine
res_hw = engine.generate({
    "vendor": "huawei",
    "features": all_80_features,
    "params": {}
})
print(f"HUAWEI Engine -> Success: {res_hw['success']} | Lines: {res_hw['total_lines']} | Features Applied: {len(res_hw['features_applied'])} / 80")
assert res_hw['success']
assert len(res_hw['features_applied']) == 80

# 3. Validate templates/features.html DOM & 80 feature bindings
with open("templates/features.html", "r", encoding="utf-8") as f:
    html = f.read()

html_part = html.split("<script>")[0]
open_divs = len(re.findall(r"<div\b", html_part))
close_divs = len(re.findall(r"</div>", html_part))
print(f"DOM Balance   -> Open <div>: {open_divs} | Close </div>: {close_divs} | Diff: {open_divs - close_divs}")
assert open_divs == close_divs, f"DOM div mismatch! {open_divs} vs {close_divs}"

for feat in all_80_features:
    assert f'id="chk-{feat}"' in html, f"Missing checkbox for {feat}"
    assert f'id="form-{feat}"' in html, f"Missing form panel for {feat}"
    assert f"'{feat}'" in html, f"Missing domainMap/JS entry for {feat}"
    assert f"params.{feat}" in html, f"Missing collectFormData entry for {feat}"

print("Frontend HTML -> All 80 checkboxes, 80 form panels, domainMap, and collectFormData verified!")

# 4. Live HTTP API verification
req = urllib.request.Request(
    "http://127.0.0.1:5000/api/features/generate",
    data=json.dumps({"vendor": "huawei", "features": all_80_features, "params": {}}).encode("utf-8"),
    headers={"Content-Type": "application/json"},
    method="POST"
)
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode("utf-8"))
    print(f"Live HTTP API -> Status: {resp.status} | Lines: {data['total_lines']} | Applied: {len(data['features_applied'])} / 80")
    assert data["success"] is True
    assert len(data["features_applied"]) == 80

print("ALL 80 FEATURES END-TO-END VERIFICATION PASSED!")
