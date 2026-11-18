import requests
import json

features = [
    'base', 'aaa', 'interface', 'vlan', 'vlan_termination', 'port_isolate', 'lldp', 'qinq',
    'lacp', 'stp', 'vrrp', 'bfd', 'mirroring', 'nqa', 'irf_stack', 'monitor_link',
    'static_route', 'ospf', 'rip', 'isis', 'bgp', 'pbr', 'route_policy', 'bgp_rr',
    'acl_nat', 'nat_server', 'port_security', 'ipsec', 'dhcp_snooping', 'radius', 'ipsg', 'urpf',
    'dhcp', 'dhcp_relay', 'ntp', 'dns', 'snmp', 'syslog', 'sflow',
    'gre', 'mpls', 'mpls_l3vpn', 'igmp_snooping', 'vxlan', 'pim_sm',
    'qos_car', 'qos_remark',
    'ipv6_base', 'ospfv3', 'ripng'
]

params = {
    'qinq': {'interface': 'GigabitEthernet0/0/1', 'outer_vlan': 100},
    'monitor_link': {'group_id': 1, 'uplink_port': 'GigabitEthernet0/0/1', 'downlink_port': 'GigabitEthernet0/0/2'},
    'bgp_rr': {'as_number': 65001, 'client_ip': '10.1.1.2'},
    'ipsg': {'interface': 'GigabitEthernet0/0/1', 'mode': 'ip-mac'},
    'urpf': {'interface': 'GigabitEthernet0/0/1', 'mode': 'strict'},
    'sflow': {'agent_ip': '192.168.1.1', 'collector_ip': '192.168.1.200', 'collector_port': 6343, 'rate': 10000, 'interface': 'GigabitEthernet0/0/1'},
    'pim_sm': {'rp_ip': '192.168.1.254', 'interface': 'GigabitEthernet0/0/1'},
    'qos_remark': {'acl_number': 3000, 'dscp_value': 'ef', 'interface': 'GigabitEthernet0/0/1'}
}

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
    print(f"Sample generated for {vendor.upper()}:\n" + "\n".join(cli.splitlines()[-25:]) + "\n" + "="*50)
