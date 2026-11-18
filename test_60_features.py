import requests
import json

features = [
    # 1. 系统基础与接口 (10)
    'base', 'aaa', 'interface', 'vlan', 'vlan_termination', 'port_isolate', 'lldp', 'qinq', 'super_password', 'header_banner',
    # 2. 可靠性与高可用 (9)
    'lacp', 'stp', 'vrrp', 'bfd', 'mirroring', 'nqa', 'irf_stack', 'monitor_link', 'ip_frr',
    # 3. 路由与转发 (8)
    'static_route', 'ospf', 'rip', 'isis', 'bgp', 'pbr', 'route_policy', 'bgp_rr',
    # 4. 安全与准入 (11)
    'acl_nat', 'nat_server', 'port_security', 'ipsec', 'dhcp_snooping', 'radius', 'ipsg', 'urpf', 'mac_address_table', 'traffic_filter', 'keychain',
    # 5. 业务与服务 (7)
    'dhcp', 'dhcp_relay', 'ntp', 'dns', 'snmp', 'syslog', 'sflow',
    # 6. VPN 与组播 (7)
    'gre', 'mpls', 'mpls_l3vpn', 'igmp_snooping', 'vxlan', 'pim_sm', 'evpn',
    # 7. QoS (2)
    'qos_car', 'qos_remark',
    # 8. IPv6 (6)
    'ipv6_base', 'ospfv3', 'ripng', 'ipv6_nd', 'dhcpv6', 'bgp4_plus'
]

params = {
    'qinq': {'interface': 'GigabitEthernet0/0/1', 'outer_vlan': 100},
    'super_password': {'level': 3, 'password': 'Admin@Super123'},
    'header_banner': {'banner': 'Authorized access only! All activities are monitored.'},
    'monitor_link': {'group_id': 1, 'uplink_port': 'GigabitEthernet0/0/1', 'downlink_port': 'GigabitEthernet0/0/2'},
    'ip_frr': {'ospf_id': 1},
    'bgp_rr': {'as_number': 65001, 'client_ip': '10.1.1.2'},
    'ipsg': {'interface': 'GigabitEthernet0/0/1', 'mode': 'ip-mac'},
    'urpf': {'interface': 'GigabitEthernet0/0/1', 'mode': 'strict'},
    'mac_address_table': {'static_mac': '5489-98cf-1122', 'static_vlan': 10, 'static_interface': 'GigabitEthernet0/0/1', 'blackhole_mac': '0000-0000-0001'},
    'traffic_filter': {'interface': 'GigabitEthernet0/0/1', 'acl_number': 3000, 'direction': 'inbound'},
    'keychain': {'name': 'kc1', 'key_id': 1, 'key_string': 'AuthKey@123'},
    'sflow': {'agent_ip': '192.168.1.1', 'collector_ip': '192.168.1.200', 'collector_port': 6343, 'rate': 10000, 'interface': 'GigabitEthernet0/0/1'},
    'pim_sm': {'rp_ip': '192.168.1.254', 'interface': 'GigabitEthernet0/0/1'},
    'evpn': {'as_number': 65001, 'peer_ip': '10.1.1.2'},
    'qos_remark': {'acl_number': 3000, 'dscp_value': 'ef', 'interface': 'GigabitEthernet0/0/1'},
    'ipv6_nd': {'interface': 'GigabitEthernet0/0/0'},
    'dhcpv6': {'pool_name': 'pool_v6', 'prefix': '2001:db8:1::/64', 'dns': '2400:3200::1', 'interface': 'GigabitEthernet0/0/0'},
    'bgp4_plus': {'as_number': 65001, 'peer_ipv6': '2001:db8:1::2'}
}

print(f"Total features to test: {len(features)}")
assert len(features) == 60, f"Expected 60 features, got {len(features)}"

for vendor in ['h3c', 'huawei']:
    resp = requests.post('http://127.0.0.1:5000/api/features/generate', json={
        'vendor': vendor,
        'features': features,
        'params': params
    })
    data = resp.json()
    applied = len(data.get('features_applied', []))
    lines = data.get('total_lines', 0)
    print(f"{vendor.upper()} Success: {data.get('success')} | Lines: {lines} | Features Applied: {applied} / {len(features)}")
    cli = data.get('cli_config', '')
    print(f"Sample generated for {vendor.upper()}:\n" + "\n".join(cli.splitlines()[-35:]) + "\n" + "="*50)
