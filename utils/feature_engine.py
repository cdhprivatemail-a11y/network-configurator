# -*- coding: utf-8 -*-
"""
特性配置生成引擎 (全功能工业级超能扩展版)
全面依照 HCL Comware V7 命令手册与华为 VRP 规范实现：
1. 系统基础与接口 (基础配置, AAA/SSH, 三层接口, 二层VLAN, 端口隔离, LLDP邻居发现)
2. 可靠性与高可用 (链路聚合 LACP, 生成树 STP/RSTP, 网关冗余 VRRP, 故障检测 BFD, 端口镜像 Mirroring, NQA网络质量联动)
3. 路由与转发 (静态路由, OSPF, RIP, BGP, 策略路由 PBR, IS-IS动态路由)
4. 安全与准入 (ACL访问控制, 端口安全, NAT Easy-IP, NAT Server端口映射, IPsec VPN, DHCP Snooping防私设)
5. 业务与服务 (DHCP全局/接口池, DHCP中继Relay, NTP时间同步, DNS客户端, SNMP网络监控)
6. VPN 与隧道 (GRE 点对点隧道, MPLS 与 LDP, BGP/MPLS L3VPN专网)
7. QoS 与流量工程 (QoS 流量监管与限速 CAR/LR)
8. IPv6 演进与下一代网络 (IPv6 基础接口单播, OSPFv3 动态路由)
"""

import logging
from typing import Dict, List, Any

logger = logging.getLogger("FeatureConfigEngine")


class FeatureConfigEngine:
    """模块化特性配置生成引擎"""

    def __init__(self):
        pass

    @staticmethod
    def _ip_to_wildcard(netmask_str: str) -> str:
        """子网掩码转反掩码 (Wildcard)"""
        try:
            mask_octets = [int(x) for x in netmask_str.split('.')]
            wildcard_octets = [str(255 - x) for x in mask_octets]
            return '.'.join(wildcard_octets)
        except Exception:
            return "0.0.0.255"

    def generate(self, feature_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        根据勾选的特性列表及各特性参数生成 CLI 配置文本
        :param feature_data: {vendor: 'huawei'|'h3c', features: [...], params: {...}}
        """
        vendor = feature_data.get("vendor", "h3c").lower()
        is_huawei = "huawei" in vendor
        selected_features = set(feature_data.get("features", []))
        params = feature_data.get("params", {})

        lines = ["system-view"]

        # ====================================================
        # 1. 系统基础与接口 (System & Interface)
        # ====================================================
        # 1.1 基础配置 (sysname, loopback)
        if "base" in selected_features:
            base_p = params.get("base", {})
            hostname = base_p.get("sysname", "RouterA").strip()
            if hostname:
                lines.append(f"sysname {hostname}")
            loopback_ip = base_p.get("loopback_ip", "1.1.1.1").strip()
            if loopback_ip:
                lines.append("interface LoopBack0")
                lines.append(f" ip address {loopback_ip} 255.255.255.255")
                lines.append(" description Management_LoopBack0")
                lines.append("quit")

        # 1.2 AAA 与管理登录
        if "aaa" in selected_features:
            aaa_p = params.get("aaa", {})
            username = aaa_p.get("username", "admin").strip()
            password = aaa_p.get("password", "admin@123").strip()
            privilege = aaa_p.get("privilege", 3)
            enable_ssh = aaa_p.get("enable_ssh", True)
            enable_telnet = aaa_p.get("enable_telnet", True)

            if enable_telnet:
                lines.append("telnet server enable")

            if enable_ssh:
                if is_huawei:
                    lines.append("stelnet server enable")
                    lines.append("rsa local-key-pair create")
                else:
                    lines.append("ssh server enable")
                    lines.append("public-key local create rsa")

            lines.append("aaa")
            if is_huawei:
                lines.append(f" local-user {username} password cipher {password}")
                lines.append(f" local-user {username} privilege level {privilege}")
                svcs = []
                if enable_ssh: svcs.append("ssh")
                if enable_telnet: svcs.append("telnet")
                if svcs: lines.append(f" local-user {username} service-type {' '.join(svcs)}")
            else:
                lines.append(f" local-user {username} class manage")
                lines.append(f"  password simple {password}")
                lines.append("  authorization-attribute user-role network-admin")
                svcs = []
                if enable_ssh: svcs.append("ssh")
                if enable_telnet: svcs.append("telnet")
                if svcs: lines.append(f"  service-type {' '.join(svcs)}")
                lines.append("  quit")
            lines.append("quit")

            lines.append("user-interface vty 0 4")
            lines.append(" authentication-mode aaa")
            proto_list = []
            if enable_ssh: proto_list.append("ssh")
            if enable_telnet: proto_list.append("telnet")
            lines.append(f" protocol inbound {' '.join(proto_list) if proto_list else 'all'}")
            lines.append("quit")

        # 1.3 二层 VLAN / 接口划分
        if "vlan" in selected_features:
            vlan_p = params.get("vlan", {})
            vlans = vlan_p.get("vlan_list", "").strip()
            if vlans:
                lines.append(f"vlan batch {vlans}" if is_huawei else f"vlan {vlans}")

            for intf_item in vlan_p.get("interfaces", []):
                iname = intf_item.get("name", "").strip()
                imode = intf_item.get("mode", "access").lower()
                if not iname: continue
                lines.append(f"interface {iname}")
                if imode == "access":
                    vid = intf_item.get("vlan_id", 1)
                    lines.append(" port link-type access")
                    lines.append(f" port default vlan {vid}" if is_huawei else f" port access vlan {vid}")
                elif imode == "trunk":
                    allow = intf_item.get("allow_vlans", "all")
                    lines.append(" port link-type trunk")
                    if is_huawei:
                        lines.append(f" port trunk allow-pass vlan {'all' if allow == 'all' else allow}")
                    else:
                        lines.append(f" port trunk permit vlan {'all' if allow == 'all' else allow}")
                lines.append(" undo shutdown")
                lines.append("quit")

        # 1.4 三层物理/逻辑接口
        if "interface" in selected_features:
            intf_p = params.get("interface", {})
            for item in intf_p.get("interfaces", []):
                iname = item.get("name", "").strip()
                ip = item.get("ip", "").strip()
                mask = item.get("mask", "255.255.255.0").strip()
                desc = item.get("description", "").strip()
                if not iname or not ip: continue
                lines.append(f"interface {iname}")
                if desc: lines.append(f" description {desc}")
                lines.append(f" ip address {ip} {mask}")
                lines.append(" undo shutdown")
                lines.append("quit")

        # 1.5 端口隔离 (Port Isolate) [新增]
        if "port_isolate" in selected_features:
            pi_p = params.get("port_isolate", {})
            ports = pi_p.get("ports", ["GigabitEthernet0/0/1", "GigabitEthernet0/0/2"])
            grp_id = pi_p.get("group_id", 1)
            for p in ports:
                p = p.strip()
                if not p: continue
                lines.append(f"interface {p}")
                if is_huawei:
                    lines.append(f" port-isolate enable group {grp_id}")
                else:
                    lines.append(f" port-isolate enable group {grp_id}")
                lines.append("quit")

        # 1.6 LLDP 邻居发现 [新增]
        if "lldp" in selected_features:
            lines.append("lldp enable")

        # 1.7 VLAN 终结 / 单臂路由子接口 [新增]
        if "vlan_termination" in selected_features:
            vt_p = params.get("vlan_termination", {})
            parent_if = vt_p.get("interface", "GigabitEthernet0/0/1").strip()
            sub_id = vt_p.get("sub_id", 10)
            vid = vt_p.get("vlan_id", 10)
            ip_addr = vt_p.get("ip_address", "192.168.10.1").strip()
            mask = vt_p.get("mask", "255.255.255.0").strip()

            lines.append(f"interface {parent_if}.{sub_id}")
            if is_huawei:
                lines.append(f" dot1q termination vid {vid}")
                lines.append(f" ip address {ip_addr} {mask}")
                lines.append(" arp broadcast enable")
            else:
                lines.append(f" vlan-type dot1q vid {vid}")
                lines.append(f" ip address {ip_addr} {mask}")
            lines.append("quit")

        # 1.8 QinQ 802.1Q in 802.1Q 双层标签 [新增]
        if "qinq" in selected_features:
            qinq_p = params.get("qinq", {})
            intf_name = qinq_p.get("interface", "GigabitEthernet0/0/1").strip()
            outer_vlan = qinq_p.get("outer_vlan", 100)

            if intf_name:
                lines.append(f"interface {intf_name}")
                lines.append(" port link-type dot1q-tunnel")
                lines.append(f" port default vlan {outer_vlan}")
                lines.append("quit")

        # 1.9 特权模式密码保护 (Super Password) [新增]
        if "super_password" in selected_features:
            sp_p = params.get("super_password", {})
            level = sp_p.get("level", 3)
            pwd = sp_p.get("password", "Admin@Super123").strip() or "Admin@Super123"
            if is_huawei:
                lines.append(f"super password level {level} cipher {pwd}")
            else:
                lines.append(f"super password level {level} simple {pwd}")

        # 1.10 登录合规与警示标语 (Header Banner) [新增]
        if "header_banner" in selected_features:
            hb_p = params.get("header_banner", {})
            banner_text = hb_p.get("banner", "Authorized access only! All activities are monitored.").strip()
            if is_huawei:
                lines.append(f"header login information % {banner_text} %")
            else:
                lines.append(f"header login % {banner_text} %")

        # ====================================================
        # 2. 可靠性与高可用 (Reliability & HA)
        # ====================================================
        # 2.1 链路聚合与冗余 (LACP)
        if "lacp" in selected_features:
            lacp_p = params.get("lacp", {})
            grp_id = lacp_p.get("group_id", 1)
            mode = lacp_p.get("mode", "dynamic")
            ports = lacp_p.get("ports", ["GigabitEthernet0/0/1", "GigabitEthernet0/0/2"])

            if is_huawei:
                lines.append(f"interface Eth-Trunk {grp_id}")
                if mode == "dynamic": lines.append(" mode lacp-static")
                else: lines.append(" mode manual load-balance")
                lines.append("quit")
                for p in ports:
                    if p.strip():
                        lines.append(f"interface {p.strip()}")
                        lines.append(f" eth-trunk {grp_id}")
                        lines.append("quit")
            else:
                lines.append(f"interface Bridge-Aggregation {grp_id}")
                if mode == "dynamic": lines.append(" link-aggregation mode dynamic")
                lines.append("quit")
                for p in ports:
                    if p.strip():
                        lines.append(f"interface {p.strip()}")
                        lines.append(f" port link-aggregation group {grp_id}")
                        lines.append("quit")

        # 2.2 二层环路防护 (STP / RSTP / MSTP)
        if "stp" in selected_features:
            stp_p = params.get("stp", {})
            stp_mode = stp_p.get("mode", "rstp").lower()
            is_root = stp_p.get("is_root", "none")
            lines.append(f"stp mode {stp_mode}")
            lines.append("stp enable")
            if is_root == "primary": lines.append("stp root primary")
            elif is_root == "secondary": lines.append("stp root secondary")

        # 2.3 网关冗余 (VRRP)
        if "vrrp" in selected_features:
            vrrp_p = params.get("vrrp", {})
            vlan_id = vrrp_p.get("vlan_id", 10)
            vrid = vrrp_p.get("vrid", 1)
            vip = vrrp_p.get("virtual_ip", "192.168.10.254").strip()
            prio = vrrp_p.get("priority", 120)

            if is_huawei:
                lines.append(f"interface Vlanif {vlan_id}")
            else:
                lines.append(f"interface Vlan-interface {vlan_id}")
            lines.append(f" vrrp vrid {vrid} virtual-ip {vip}")
            if prio != 100:
                lines.append(f" vrrp vrid {vrid} priority {prio}")
            lines.append("quit")

        # 2.4 故障检测联动 (BFD)
        if "bfd" in selected_features:
            bfd_p = params.get("bfd", {})
            peer_ip = bfd_p.get("peer_ip", "").strip()
            out_if = bfd_p.get("interface", "").strip()
            sess_name = bfd_p.get("session_name", "to_peer").strip()

            if is_huawei:
                lines.append("bfd")
                lines.append("quit")
                if peer_ip:
                    lines.append(f"bfd {sess_name} bind peer-ip {peer_ip}" + (f" interface {out_if}" if out_if else ""))
                    lines.append(" discriminator local 10")
                    lines.append(" discriminator remote 20")
                    lines.append(" commit")
                    lines.append("quit")
            else:
                if out_if and peer_ip:
                    lines.append("bfd session init-mode active")
                    lines.append(f"interface {out_if}")
                    lines.append(f" bfd destination {peer_ip}")
                    lines.append("quit")

        # 2.5 端口镜像 (Port Mirroring) [新增]
        if "mirroring" in selected_features:
            mir_p = params.get("mirroring", {})
            grp_id = mir_p.get("group_id", 1)
            src_ports = mir_p.get("src_ports", ["GigabitEthernet0/0/1"])
            dst_port = mir_p.get("dst_port", "GigabitEthernet0/0/24").strip()

            if is_huawei:
                if dst_port:
                    lines.append(f"observe-port {grp_id} interface {dst_port}")
                for sp in src_ports:
                    if sp.strip():
                        lines.append(f"interface {sp.strip()}")
                        lines.append(f" port-mirroring to observe-port {grp_id} both")
                        lines.append("quit")
            else:
                lines.append(f"mirroring-group {grp_id} local")
                for sp in src_ports:
                    if sp.strip():
                        lines.append(f"mirroring-group {grp_id} mirroring-port {sp.strip()} both")
                if dst_port:
                    lines.append(f"mirroring-group {grp_id} monitor-port {dst_port}")

        # 2.6 NQA 网络质量探测与静态路由联动 [新增]
        if "nqa" in selected_features:
            nqa_p = params.get("nqa", {})
            admin_name = nqa_p.get("admin", "admin").strip() or "admin"
            test_tag = nqa_p.get("tag", "icmp").strip() or "icmp"
            dst_ip = nqa_p.get("destination_ip", "8.8.8.8").strip()
            freq = int(nqa_p.get("frequency", 5))
            next_hop = nqa_p.get("next_hop", "").strip()

            if is_huawei:
                lines.append(f"nqa test-instance {admin_name} {test_tag}")
                lines.append(" test-type icmp-jitter")
                lines.append(f" destination-address ipv4 {dst_ip}")
                lines.append(f" frequency {freq}")
                lines.append(" start now")
                lines.append("quit")
                if next_hop:
                    lines.append(f"ip route-static 0.0.0.0 0.0.0.0 {next_hop} track nqa {admin_name} {test_tag}")
            else:
                lines.append(f"nqa entry {admin_name} {test_tag}")
                lines.append(" type icmp-echo")
                lines.append(f" destination ip {dst_ip}")
                lines.append(f" frequency {freq * 1000}")
                lines.append(" reaction 1 checked-element probe-fail threshold-type consecutive 3 action-type trigger-only")
                lines.append("quit")
                lines.append(f"nqa schedule {admin_name} {test_tag} start-time now lifetime forever")
                lines.append(f"track 1 nqa entry {admin_name} {test_tag} reaction 1")
                if next_hop:
                    lines.append(f"ip route-static 0.0.0.0 0.0.0.0 {next_hop} track 1")

        # 2.7 堆叠虚拟化 (IRF / iStack) [新增]
        if "irf_stack" in selected_features:
            irf_p = params.get("irf_stack", {})
            member_id = irf_p.get("member_id", 1)
            priority = irf_p.get("priority", 32)

            if is_huawei:
                lines.append(f"stack member {member_id} priority {priority}")
            else:
                lines.append(f"irf member {member_id} priority {priority}")

        # 2.8 Monitor Link 监控链路组 [新增]
        if "monitor_link" in selected_features:
            ml_p = params.get("monitor_link", {})
            group_id = ml_p.get("group_id", 1)
            up_port = ml_p.get("uplink_port", "GigabitEthernet0/0/1").strip()
            down_port = ml_p.get("downlink_port", "GigabitEthernet0/0/2").strip()

            lines.append(f"monitor-link group {group_id}")
            if up_port:
                lines.append(f" port {up_port} uplink")
            if down_port:
                lines.append(f" port {down_port} downlink")
            lines.append("quit")

        # 2.9 IP 快速重路由 (IP FRR / OSPF LFA) [新增]
        if "ip_frr" in selected_features:
            frr_p = params.get("ip_frr", {})
            ospf_id = frr_p.get("ospf_id", 1)
            if is_huawei:
                lines.append(f"ospf {ospf_id}")
                lines.append(" frr")
                lines.append("  loop-free-alternate")
                lines.append(" quit")
            else:
                lines.append(f"ospf {ospf_id}")
                lines.append(" fast-reroute lfa")
                lines.append("quit")

        # 2.10 MSTP 多实例生成树与 VLAN 负载均衡 [工程加固]
        if "mstp_multi_instance" in selected_features:
            mstp_p = params.get("mstp_multi_instance", {})
            region_name = mstp_p.get("region_name", "REGION_CORP").strip() or "REGION_CORP"
            revision = int(mstp_p.get("revision", 1))
            inst1_vlans = mstp_p.get("instance1_vlans", "10 20").strip() or "10 20"
            inst2_vlans = mstp_p.get("instance2_vlans", "30 40").strip() or "30 40"
            inst1_root = mstp_p.get("instance1_root", "primary")
            inst2_root = mstp_p.get("instance2_root", "secondary")

            lines.append("stp mode mstp")
            lines.append("stp region-configuration")
            lines.append(f" region-name {region_name}")
            lines.append(f" revision-level {revision}")
            lines.append(f" instance 1 vlan {inst1_vlans}")
            lines.append(f" instance 2 vlan {inst2_vlans}")
            lines.append(" active region-configuration")
            lines.append("quit")
            if inst1_root in ["primary", "secondary"]:
                lines.append(f"stp instance 1 root {inst1_root}")
            if inst2_root in ["primary", "secondary"]:
                lines.append(f"stp instance 2 root {inst2_root}")

        # ====================================================
        # 3. 路由与转发 (Routing & Forwarding)
        # ====================================================
        # 3.1 静态与默认路由
        if "static_route" in selected_features:
            sr_p = params.get("static_route", {})
            for r in sr_p.get("routes", []):
                dest = r.get("prefix", "0.0.0.0").strip()
                mask = r.get("mask", "0.0.0.0").strip()
                next_hop = r.get("next_hop", "").strip()
                desc = r.get("desc", "").strip()
                if next_hop:
                    desc_str = f" description {desc}" if desc and is_huawei else ""
                    lines.append(f"ip route-static {dest} {mask} {next_hop}{desc_str}")

        # 3.2 OSPF 动态路由
        if "ospf" in selected_features:
            ospf_p = params.get("ospf", {})
            proc_id = ospf_p.get("process_id", 1)
            router_id = ospf_p.get("router_id", "").strip()
            rid_str = f" router-id {router_id}" if router_id else ""
            lines.append(f"ospf {proc_id}{rid_str}")

            for area_item in ospf_p.get("areas", []):
                area_id = area_item.get("area_id", 0)
                lines.append(f" area {area_id}")
                for net_item in area_item.get("networks", []):
                    net_addr = net_item.get("network", "").strip()
                    wildcard = net_item.get("wildcard", "").strip()
                    if not wildcard and net_item.get("mask"):
                        wildcard = self._ip_to_wildcard(net_item.get("mask"))
                    if net_addr and wildcard:
                        lines.append(f"  network {net_addr} {wildcard}")
            lines.append("quit")

        # 3.3 RIP 动态路由 [新增]
        if "rip" in selected_features:
            rip_p = params.get("rip", {})
            proc_id = rip_p.get("process_id", 1)
            nets = rip_p.get("networks", ["192.168.1.0"])
            lines.append(f"rip {proc_id}")
            lines.append(" version 2")
            lines.append(" undo summary")
            for net in nets:
                if net.strip(): lines.append(f" network {net.strip()}")
            lines.append("quit")

        # 3.4 BGP 边界网关路由
        if "bgp" in selected_features:
            bgp_p = params.get("bgp", {})
            as_num = bgp_p.get("as_number", 65001)
            router_id = bgp_p.get("router_id", "").strip()
            peers = bgp_p.get("peers", [])

            lines.append(f"bgp {as_num}")
            if router_id: lines.append(f" router-id {router_id}")

            if is_huawei:
                for p in peers:
                    pip = p.get("peer_ip", "").strip()
                    pas = p.get("as_number", as_num)
                    if pip:
                        lines.append(f" peer {pip} as-number {pas}")
                        if p.get("use_loopback"):
                            lines.append(f" peer {pip} connect-interface LoopBack0")
            else:
                for p in peers:
                    pip = p.get("peer_ip", "").strip()
                    pas = p.get("as_number", as_num)
                    if pip:
                        lines.append(f" peer {pip} as-number {pas}")
                        if p.get("use_loopback"):
                            lines.append(f" peer {pip} connect-interface LoopBack0")
                lines.append(" address-family ipv4 unicast")
                for p in peers:
                    pip = p.get("peer_ip", "").strip()
                    if pip: lines.append(f"  peer {pip} enable")
                lines.append(" quit")
            lines.append("quit")

        # 3.5 策略路由 PBR (Policy-Based Routing) [新增]
        if "pbr" in selected_features:
            pbr_p = params.get("pbr", {})
            node_id = pbr_p.get("node_id", 10)
            acl_num = pbr_p.get("acl_number", 3000)
            next_hop = pbr_p.get("next_hop", "10.0.12.2").strip()
            apply_intf = pbr_p.get("interface", "GigabitEthernet0/0/1").strip()

            if is_huawei:
                lines.append(f"traffic classifier c1 operator and")
                lines.append(f" if-match acl {acl_num}")
                lines.append("quit")
                lines.append("traffic behavior b1")
                lines.append(f" redirect ip-nexthop {next_hop}")
                lines.append("quit")
                lines.append("traffic policy p1")
                lines.append(" classifier c1 behavior b1")
                lines.append("quit")
                if apply_intf:
                    lines.append(f"interface {apply_intf}")
                    lines.append(" traffic-policy p1 inbound")
                    lines.append("quit")
            else:
                lines.append(f"policy-based-route p1 permit node {node_id}")
                lines.append(f" if-match acl {acl_num}")
                lines.append(f" apply next-hop {next_hop}")
                lines.append("quit")
                if apply_intf:
                    lines.append(f"interface {apply_intf}")
                    lines.append(" ip policy-based-route p1")
                    lines.append("quit")

        # 3.6 IS-IS 动态路由 [新增]
        if "isis" in selected_features:
            isis_p = params.get("isis", {})
            process_id = isis_p.get("process_id", 1)
            net_entity = isis_p.get("network_entity", "49.0001.0000.0000.0001.00").strip()
            level = isis_p.get("level", "level-2").strip()
            intfs = isis_p.get("interfaces", ["GigabitEthernet0/0/0"])

            lines.append(f"isis {process_id}")
            lines.append(f" is-level {level}")
            if net_entity:
                lines.append(f" network-entity {net_entity}")
            lines.append("quit")
            for intf in intfs:
                if intf.strip():
                    lines.append(f"interface {intf.strip()}")
                    lines.append(f" isis enable {process_id}")
                    lines.append("quit")

        # 3.7 路由策略与引入过滤 (Route-Policy) [新增]
        if "route_policy" in selected_features:
            rp_p = params.get("route_policy", {})
            pname = rp_p.get("policy_name", "RP_OSPF_IMPORT").strip() or "RP_OSPF_IMPORT"
            node_id = rp_p.get("node_id", 10)
            acl_num = rp_p.get("acl_number", 2000)
            cost_val = rp_p.get("cost", 20)
            ospf_id = rp_p.get("ospf_id", 1)
            import_proto = rp_p.get("import_protocol", "static").strip() or "static"

            lines.append(f"route-policy {pname} permit node {node_id}")
            lines.append(f" if-match acl {acl_num}")
            lines.append(f" apply cost {cost_val}")
            lines.append("quit")
            lines.append(f"ospf {ospf_id}")
            lines.append(f" import-route {import_proto} route-policy {pname}")
            lines.append("quit")

        # 3.8 BGP 路由反射器 (Route Reflector) [新增]
        if "bgp_rr" in selected_features:
            rr_p = params.get("bgp_rr", {})
            as_num = rr_p.get("as_number", 65001)
            client_ip = rr_p.get("client_ip", "10.1.1.2").strip()

            lines.append(f"bgp {as_num}")
            if is_huawei:
                lines.append(f" peer {client_ip} as-number {as_num}")
                lines.append(f" peer {client_ip} reflect-client")
            else:
                lines.append(f" peer {client_ip} as-number {as_num}")
                lines.append(" address-family ipv4 unicast")
                lines.append(f"  peer {client_ip} enable")
                lines.append(f"  peer {client_ip} reflect-client")
                lines.append(" quit")
            lines.append("quit")

        # 3.9 双向路由引入与 Tag 标签防环 [工程加固]
        if "route_redistribute" in selected_features:
            rr_p = params.get("route_redistribute", {})
            ospf_id = int(rr_p.get("ospf_id", 1))
            bgp_as = int(rr_p.get("bgp_as", 65001))
            tag_ospf_to_bgp = int(rr_p.get("tag_out", 100))
            tag_bgp_to_ospf = int(rr_p.get("tag_in", 200))

            lines.append("route-policy OSPF_TO_BGP permit node 10")
            lines.append(f" apply tag {tag_ospf_to_bgp}")
            lines.append("quit")
            lines.append("route-policy BGP_TO_OSPF deny node 10")
            lines.append(f" if-match tag {tag_ospf_to_bgp}")
            lines.append("quit")
            lines.append("route-policy BGP_TO_OSPF permit node 20")
            lines.append(f" apply tag {tag_bgp_to_ospf}")
            lines.append("quit")
            if is_huawei:
                lines.append(f"bgp {bgp_as}")
                lines.append(" ipv4-family unicast")
                lines.append(f"  import-route ospf {ospf_id} route-policy OSPF_TO_BGP")
                lines.append(" quit")
                lines.append("quit")
            else:
                lines.append(f"bgp {bgp_as}")
                lines.append(" address-family ipv4 unicast")
                lines.append(f"  import-route ospf {ospf_id} route-policy OSPF_TO_BGP")
                lines.append(" quit")
                lines.append("quit")
            lines.append(f"ospf {ospf_id}")
            lines.append(f" import-route bgp route-policy BGP_TO_OSPF")
            lines.append("quit")

        # 3.10 BGP 团体属性与流量路径调控 [工程加固]
        if "bgp_community" in selected_features:
            comm_p = params.get("bgp_community", {})
            as_num = int(comm_p.get("as_number", 65001))
            peer_ip = comm_p.get("peer_ip", "10.0.12.2").strip() or "10.0.12.2"
            community_val = comm_p.get("community", "65001:100").strip() or "65001:100"
            loc_pref = int(comm_p.get("local_preference", 200))
            prepend_as = comm_p.get("as_path_prepend", "65001").strip()

            lines.append("route-policy BGP_COMM_POLICY permit node 10")
            lines.append(f" apply community {community_val}")
            lines.append(f" apply local-preference {loc_pref}")
            if prepend_as:
                lines.append(f" apply as-path {prepend_as} additive")
            lines.append("quit")
            lines.append(f"bgp {as_num}")
            if is_huawei:
                lines.append(" ipv4-family unicast")
                lines.append(f"  peer {peer_ip} route-policy BGP_COMM_POLICY export")
                lines.append(f"  peer {peer_ip} advertise-community")
                lines.append(" quit")
            else:
                lines.append(" address-family ipv4 unicast")
                lines.append(f"  peer {peer_ip} route-policy BGP_COMM_POLICY export")
                lines.append(f"  peer {peer_ip} advertise-community")
                lines.append(" quit")
            lines.append("quit")

        # ====================================================
        # 4. 安全与准入 (Security & Access)
        # ====================================================
        # 4.1 ACL 与 NAT 出口上网 (Easy-IP)
        if "acl_nat" in selected_features:
            nat_p = params.get("acl_nat", {})
            acl_num = nat_p.get("acl_number", 2000)
            acl_source = nat_p.get("source_network", "192.168.0.0").strip()
            acl_wildcard = nat_p.get("wildcard", "0.0.255.255").strip()
            out_interface = nat_p.get("outbound_interface", "GigabitEthernet0/0/0").strip()

            if is_huawei:
                lines.append(f"acl number {acl_num}")
                lines.append(f" rule 5 permit source {acl_source} {acl_wildcard}")
                lines.append("quit")
                if out_interface:
                    lines.append(f"interface {out_interface}")
                    lines.append(f" nat outbound {acl_num}")
                    lines.append("quit")
            else:
                lines.append(f"acl basic {acl_num}")
                lines.append(f" rule 5 permit source {acl_source} {acl_wildcard}")
                lines.append("quit")
                if out_interface:
                    lines.append(f"interface {out_interface}")
                    lines.append(f" nat outbound {acl_num}")
                    lines.append("quit")

        # 4.2 NAT Server (端口映射) [新增]
        if "nat_server" in selected_features:
            ns_p = params.get("nat_server", {})
            out_if = ns_p.get("interface", "GigabitEthernet0/0/0").strip()
            proto = ns_p.get("protocol", "tcp").lower()
            pub_ip = ns_p.get("public_ip", "current-interface").strip()
            pub_port = ns_p.get("public_port", 80)
            in_ip = ns_p.get("inside_ip", "192.168.1.100").strip()
            in_port = ns_p.get("inside_port", 80)

            if out_if:
                lines.append(f"interface {out_if}")
                if is_huawei:
                    pub_str = "current-interface" if pub_ip == "current-interface" else pub_ip
                    lines.append(f" nat server protocol {proto} global {pub_str} {pub_port} inside {in_ip} {in_port}")
                else:
                    pub_str = "current-interface" if pub_ip == "current-interface" else pub_ip
                    lines.append(f" nat server protocol {proto} global {pub_str} {pub_port} inside {in_ip} {in_port}")
                lines.append("quit")

        # 4.3 端口安全 (Port Security)
        if "port_security" in selected_features:
            ps_p = params.get("port_security", {})
            intf_name = ps_p.get("interface", "GigabitEthernet0/0/1").strip()
            max_mac = ps_p.get("max_mac", 1)
            action = ps_p.get("action", "restrict")

            lines.append(f"interface {intf_name}")
            lines.append(" port-security enable")
            if is_huawei:
                lines.append(f" port-security max-mac-num {max_mac}")
                lines.append(f" port-security protect-action {action}")
            else:
                lines.append(f" port-security max-mac-count {max_mac}")
                lines.append(f" port-security intrusion-mode {action}")
            lines.append("quit")

        # 4.4 IPsec VPN 安全隧道 [新增]
        if "ipsec" in selected_features:
            ipsec_p = params.get("ipsec", {})
            policy_name = ipsec_p.get("policy_name", "my_ipsec").strip()
            peer_ip = ipsec_p.get("peer_ip", "202.100.1.2").strip()
            psk = ipsec_p.get("pre_shared_key", "vpn@123").strip()
            acl_num = ipsec_p.get("acl_number", 3001)
            out_if = ipsec_p.get("interface", "GigabitEthernet0/0/0").strip()

            if is_huawei:
                lines.append(f"ike proposal 1")
                lines.append("quit")
                lines.append(f"ike peer p1 v1")
                lines.append(" ike-proposal 1")
                lines.append(f" remote-address {peer_ip}")
                lines.append(f" pre-shared-key cipher {psk}")
                lines.append("quit")
                lines.append(f"ipsec proposal tran1")
                lines.append("quit")
                lines.append(f"ipsec policy {policy_name} 10 isakmp")
                lines.append(f" security acl {acl_num}")
                lines.append(" ike-peer p1")
                lines.append(" proposal tran1")
                lines.append("quit")
                if out_if:
                    lines.append(f"interface {out_if}")
                    lines.append(f" ipsec policy {policy_name}")
                    lines.append("quit")
            else:
                lines.append(f"ike keychain k1")
                lines.append(f" pre-shared-key address {peer_ip} 255.255.255.255 key simple {psk}")
                lines.append("quit")
                lines.append(f"ike profile p1")
                lines.append(" keychain k1")
                lines.append(f" match remote identity address {peer_ip} 255.255.255.255")
                lines.append("quit")
                lines.append(f"ipsec transform-set tran1")
                lines.append("quit")
                lines.append(f"ipsec policy {policy_name} 10 isakmp")
                lines.append(f" security acl {acl_num}")
                lines.append(" ike-profile p1")
                lines.append(" transform-set tran1")
                lines.append("quit")
                if out_if:
                    lines.append(f"interface {out_if}")
                    lines.append(f" ipsec apply policy {policy_name}")
                    lines.append("quit")

        # 4.5 DHCP Snooping 防私设与信任端口 [新增]
        if "dhcp_snooping" in selected_features:
            ds_p = params.get("dhcp_snooping", {})
            trust_intf = ds_p.get("trust_interface", "GigabitEthernet0/0/1").strip()
            vlan_id = ds_p.get("vlan_id", 0)

            if is_huawei:
                lines.append("dhcp enable")
                lines.append("dhcp snooping enable")
                if vlan_id:
                    lines.append(f"vlan {vlan_id}")
                    lines.append(" dhcp snooping enable")
                    lines.append("quit")
                if trust_intf:
                    lines.append(f"interface {trust_intf}")
                    lines.append(" dhcp snooping trusted")
                    lines.append("quit")
            else:
                lines.append("dhcp snooping enable")
                if trust_intf:
                    lines.append(f"interface {trust_intf}")
                    lines.append(" dhcp snooping trust")
                    lines.append("quit")

        # 4.6 RADIUS 远端身份认证 [新增]
        if "radius" in selected_features:
            rad_p = params.get("radius", {})
            scheme_name = rad_p.get("scheme_name", "rad1").strip() or "rad1"
            server_ip = rad_p.get("server_ip", "192.168.1.100").strip()
            key = rad_p.get("key", "Admin@123").strip() or "Admin@123"

            if is_huawei:
                lines.append(f"radius-server template {scheme_name}")
                lines.append(f" radius-server authentication {server_ip} 1812")
                lines.append(f" radius-server shared-key cipher {key}")
                lines.append("quit")
            else:
                lines.append(f"radius scheme {scheme_name}")
                lines.append(f" primary authentication {server_ip} 1812")
                lines.append(f" key authentication simple {key}")
                lines.append("quit")

        # 4.7 IP Source Guard (IPSG 防仿冒) [新增]
        if "ipsg" in selected_features:
            ipsg_p = params.get("ipsg", {})
            intf_name = ipsg_p.get("interface", "GigabitEthernet0/0/1").strip()
            check_mode = ipsg_p.get("mode", "ip-mac").strip()

            if intf_name:
                lines.append(f"interface {intf_name}")
                if is_huawei:
                    lines.append(" ip source check user-bind enable")
                else:
                    if check_mode == "ip":
                        lines.append(" ip verify source ip-address")
                    else:
                        lines.append(" ip verify source ip-address mac-address")
                lines.append("quit")

        # 4.8 uRPF 单播反向路径转发校验 [新增]
        if "urpf" in selected_features:
            urpf_p = params.get("urpf", {})
            intf_name = urpf_p.get("interface", "GigabitEthernet0/0/1").strip()
            mode = urpf_p.get("mode", "strict").strip()

            if intf_name:
                lines.append(f"interface {intf_name}")
                if is_huawei:
                    lines.append(f" urpf {mode}")
                else:
                    lines.append(f" ip urpf {mode}")
                lines.append("quit")

        # 4.9 静态 MAC 与黑洞 MAC 绑定 [新增]
        if "mac_address_table" in selected_features:
            mac_p = params.get("mac_address_table", {})
            static_mac = mac_p.get("static_mac", "5489-98cf-1122").strip()
            static_vlan = mac_p.get("static_vlan", 10)
            static_intf = mac_p.get("static_interface", "GigabitEthernet0/0/1").strip()
            blackhole_mac = mac_p.get("blackhole_mac", "0000-0000-0001").strip()

            if static_mac and static_intf:
                if is_huawei:
                    lines.append(f"mac-address static {static_mac} {static_intf} vlan {static_vlan}")
                else:
                    lines.append(f"mac-address static {static_mac} vlan {static_vlan} interface {static_intf}")
            if blackhole_mac:
                lines.append(f"mac-address blackhole {blackhole_mac} vlan {static_vlan}")

        # 4.10 接口报文包过滤 (Traffic Filter) [新增]
        if "traffic_filter" in selected_features:
            tf_p = params.get("traffic_filter", {})
            intf_name = tf_p.get("interface", "GigabitEthernet0/0/1").strip()
            acl_num = tf_p.get("acl_number", 3000)
            direction = tf_p.get("direction", "inbound").strip().lower()

            if intf_name:
                lines.append(f"interface {intf_name}")
                if is_huawei:
                    lines.append(f" traffic-filter {direction} acl {acl_num}")
                else:
                    lines.append(f" packet-filter {acl_num} {direction}")
                lines.append("quit")

        # 4.11 动态密钥链认证 (Keychain) [新增]
        if "keychain" in selected_features:
            kc_p = params.get("keychain", {})
            kc_name = kc_p.get("name", "kc1").strip() or "kc1"
            key_id = kc_p.get("key_id", 1)
            key_val = kc_p.get("key_string", "AuthKey@123").strip() or "AuthKey@123"

            lines.append(f"keychain {kc_name} mode absolute")
            lines.append(f" key-id {key_id}")
            lines.append(f"  key-string cipher {key_val}")
            lines.append("quit")
            lines.append("quit")

        # 4.12 ARP 防欺骗与动态检测 (DAI / Anti-Spoofing) [工程加固]
        if "arp_defense" in selected_features:
            arp_p = params.get("arp_defense", {})
            trust_if = arp_p.get("trust_interface", "GigabitEthernet0/0/1").strip()
            access_if = arp_p.get("access_interface", "GigabitEthernet0/0/2").strip()
            rate_limit = int(arp_p.get("rate_limit", 100))

            if is_huawei:
                lines.append("arp anti-attack check user-bind enable")
                lines.append("arp anti-attack gateway-duplicate enable")
                if trust_if:
                    lines.append(f"interface {trust_if}")
                    lines.append(" arp anti-attack check user-bind enable")
                    lines.append("quit")
                if access_if:
                    lines.append(f"interface {access_if}")
                    lines.append(" arp anti-attack rate-limit enable")
                    lines.append(f" arp anti-attack rate-limit max-record {rate_limit}")
                    lines.append("quit")
            else:
                lines.append("arp detection enable")
                lines.append("arp check enable")
                if trust_if:
                    lines.append(f"interface {trust_if}")
                    lines.append(" arp detection trust")
                    lines.append("quit")
                if access_if:
                    lines.append(f"interface {access_if}")
                    lines.append(f" arp rate-limit {rate_limit}")
                    lines.append("quit")

        # 4.13 广播风暴抑制与端口限速 (Storm Control) [工程加固]
        if "storm_control" in selected_features:
            storm_p = params.get("storm_control", {})
            target_if = storm_p.get("interface", "GigabitEthernet0/0/2").strip() or "GigabitEthernet0/0/2"
            suppress_pct = int(storm_p.get("suppress_percent", 5))
            kbps_val = int(storm_p.get("broadcast_kbps", 1000))

            if target_if:
                lines.append(f"interface {target_if}")
                lines.append(f" broadcast-suppression {suppress_pct}")
                lines.append(f" multicast-suppression {suppress_pct}")
                lines.append(f" unicast-suppression {suppress_pct}")
                if is_huawei:
                    lines.append(f" storm-control broadcast min-rate {kbps_val} max-rate {kbps_val * 2}")
                    lines.append(" storm-control action error-down")
                else:
                    lines.append(f" storm-constrain broadcast kbps {kbps_val} {kbps_val * 2}")
                    lines.append(" storm-constrain control shutdown")
                lines.append("quit")

        # 4.14 控制面保护与 CPU 防攻击 (CPCAR / CoPP) [工程加固]
        if "cpcar_defense" in selected_features:
            cpu_p = params.get("cpcar_defense", {})
            pol_name = cpu_p.get("policy_name", "DEFEND_CORE").strip() or "DEFEND_CORE"
            arp_car = int(cpu_p.get("arp_rate", 64))
            icmp_car = int(cpu_p.get("icmp_rate", 32))
            route_car = int(cpu_p.get("routing_rate", 256))

            if is_huawei:
                lines.append(f"cpu-defend policy {pol_name}")
                lines.append(f" car packet-type arp-request rate-limit {arp_car}")
                lines.append(f" car packet-type icmp rate-limit {icmp_car}")
                lines.append(f" car packet-type ospf rate-limit {route_car}")
                lines.append(f" car packet-type bgp rate-limit {route_car}")
                lines.append("quit")
                lines.append(f"cpu-defend-policy {pol_name} global")
            else:
                lines.append("attack-defense policy 1")
                lines.append(" scan-attack detection enable")
                lines.append(" flood enable")
                lines.append("quit")
                lines.append("security-zone name Management")
                lines.append(" import interface GigabitEthernet0/0/1")
                lines.append("quit")

        # ====================================================
        # 5. 业务与服务 (Services & Management)
        # ====================================================
        # 5.1 DHCP 服务器
        if "dhcp" in selected_features:
            dhcp_p = params.get("dhcp", {})
            lines.append("dhcp enable")
            mode = dhcp_p.get("mode", "global")

            if mode == "global":
                for pool in dhcp_p.get("pools", []):
                    pname = pool.get("name", "pool1").strip()
                    network = pool.get("network", "").strip()
                    mask = pool.get("mask", "255.255.255.0").strip()
                    gateway = pool.get("gateway", "").strip()
                    dns = pool.get("dns", "114.114.114.114").strip()

                    if is_huawei:
                        lines.append(f"ip pool {pname}")
                        if network: lines.append(f" network {network} mask {mask}")
                        if gateway: lines.append(f" gateway-list {gateway}")
                        if dns: lines.append(f" dns-list {dns}")
                        lines.append("quit")
                    else:
                        lines.append(f"dhcp server ip-pool {pname}")
                        if network: lines.append(f" network {network} mask {mask}")
                        if gateway: lines.append(f" gateway-list {gateway}")
                        if dns: lines.append(f" dns-list {dns}")
                        lines.append("quit")
            elif mode == "interface":
                iname = dhcp_p.get("interface_name", "").strip()
                if iname:
                    lines.append(f"interface {iname}")
                    lines.append(" dhcp select interface" if is_huawei else " dhcp select server")
                    lines.append("quit")

        # 5.2 DHCP 中继 (Relay) [新增]
        if "dhcp_relay" in selected_features:
            relay_p = params.get("dhcp_relay", {})
            intf_name = relay_p.get("interface", "Vlanif10" if is_huawei else "Vlan-interface10").strip()
            server_ip = relay_p.get("server_ip", "192.168.100.1").strip()
            lines.append("dhcp enable")
            if intf_name and server_ip:
                lines.append(f"interface {intf_name}")
                if is_huawei:
                    lines.append(" dhcp select relay")
                    lines.append(f" dhcp relay server-ip {server_ip}")
                else:
                    lines.append(" dhcp select relay")
                    lines.append(f" dhcp relay server-address {server_ip}")
                lines.append("quit")

        # 5.3 NTP 时间同步
        if "ntp" in selected_features:
            ntp_p = params.get("ntp", {})
            server_ip = ntp_p.get("server_ip", "pool.ntp.org").strip()
            lines.append(f"ntp-service unicast-server {server_ip}")

        # 5.4 DNS 客户端域名解析 [新增]
        if "dns" in selected_features:
            dns_p = params.get("dns", {})
            primary_dns = dns_p.get("primary_dns", "114.114.114.114").strip()
            if is_huawei:
                lines.append("dns resolve")
                if primary_dns: lines.append(f"dns server {primary_dns}")
            else:
                lines.append("dns resolve")
                if primary_dns: lines.append(f"dns server {primary_dns}")

        # 5.5 SNMP 网络监控管理 [新增]
        if "snmp" in selected_features:
            snmp_p = params.get("snmp", {})
            version = snmp_p.get("version", "v2c").strip() or "v2c"
            community = snmp_p.get("community", "public").strip() or "public"
            trap_server = snmp_p.get("trap_server", "").strip()

            lines.append("snmp-agent")
            lines.append(f"snmp-agent sys-info version {version}")
            lines.append(f"snmp-agent community read {community}")
            if trap_server:
                lines.append(f"snmp-agent target-host trap address udp-domain {trap_server} params securityname {community} {version}")
                lines.append("snmp-agent trap enable")

        # 5.6 Syslog 日志与网络审计 [新增]
        if "syslog" in selected_features:
            log_p = params.get("syslog", {})
            log_host = log_p.get("server_ip", "192.168.1.200").strip()

            lines.append("info-center enable")
            if log_host:
                lines.append(f"info-center loghost {log_host}")

        # 5.7 sFlow 流量采集与监控 [新增]
        if "sflow" in selected_features:
            sf_p = params.get("sflow", {})
            agent_ip = sf_p.get("agent_ip", "192.168.1.1").strip()
            collector_ip = sf_p.get("collector_ip", "192.168.1.200").strip()
            collector_port = sf_p.get("collector_port", 6343)
            sample_rate = sf_p.get("rate", 10000)
            intf_name = sf_p.get("interface", "GigabitEthernet0/0/1").strip()

            if is_huawei:
                lines.append(f"sflow agent ip {agent_ip}")
                lines.append(f"sflow collector 1 ip {collector_ip} udp-port {collector_port}")
                if intf_name:
                    lines.append(f"interface {intf_name}")
                    lines.append(f" sflow flow-sampling collector 1 rate {sample_rate}")
                    lines.append("quit")
            else:
                lines.append(f"sflow agent ip {agent_ip}")
                lines.append(f"sflow collector 1 ip {collector_ip} port {collector_port}")
                if intf_name:
                    lines.append(f"interface {intf_name}")
                    lines.append(" sflow flow collector 1")
                    lines.append(f" sflow sampling-rate {sample_rate}")
                    lines.append("quit")

        # 5.8 无线 AC+AP 集中纳管与 SSID 开局 [工程加固]
        if "wlan_ac" in selected_features:
            ac_p = params.get("wlan_ac", {})
            ssid_name = ac_p.get("ssid", "Enterprise-Corp").strip() or "Enterprise-Corp"
            vlan_id = int(ac_p.get("vlan_id", 100))
            psk_key = ac_p.get("psk_key", "admin@wifi123").strip() or "admin@wifi123"

            if is_huawei:
                lines.append("wlan")
                lines.append(" security-profile name CORP_SEC")
                lines.append(f"  security wpa-wpa2 psk pass-phrase {psk_key} aes")
                lines.append(" quit")
                lines.append(" ssid-profile name CORP_SSID")
                lines.append(f"  ssid {ssid_name}")
                lines.append(" quit")
                lines.append(" vap-profile name CORP_VAP")
                lines.append(f"  service-vlan vlan-id {vlan_id}")
                lines.append("  ssid-profile CORP_SSID")
                lines.append("  security-profile CORP_SEC")
                lines.append(" quit")
                lines.append(" ap-group name default")
                lines.append("  vap-profile CORP_VAP wlan 1 radio all")
                lines.append(" quit")
                lines.append("quit")
            else:
                lines.append("wlan ap-group default-group")
                lines.append("quit")
                lines.append("wlan service-template CORP_WIFI")
                lines.append(f" ssid {ssid_name}")
                lines.append(f" vlan {vlan_id}")
                lines.append(" akm mode psk")
                lines.append(f" preshared-key pass-phrase {psk_key}")
                lines.append(" cipher-suite ccmp")
                lines.append(" security-ie rsn")
                lines.append(" service-template enable")
                lines.append("quit")
                lines.append("wlan ap AP01 model WA6320")
                lines.append(" radio 1")
                lines.append("  service-template CORP_WIFI")
                lines.append("  radio enable")
                lines.append(" quit")
                lines.append("quit")

        # ====================================================
        # 6. VPN 与组播技术 (VPN & Multicast)
        # ====================================================
        # 6.1 GRE 隧道配置
        if "gre" in selected_features:
            gre_p = params.get("gre", {})
            tun_id = gre_p.get("tunnel_id", 0)
            tun_ip = gre_p.get("tunnel_ip", "172.16.1.1").strip()
            tun_mask = gre_p.get("tunnel_mask", "255.255.255.252").strip()
            src_ip = gre_p.get("source_ip", "").strip()
            dst_ip = gre_p.get("destination_ip", "").strip()

            lines.append(f"interface Tunnel{tun_id}")
            lines.append(f" ip address {tun_ip} {tun_mask}")
            lines.append(" tunnel-protocol gre")
            if src_ip: lines.append(f" source {src_ip}")
            if dst_ip: lines.append(f" destination {dst_ip}")
            lines.append("quit")

        # 6.2 MPLS 与 LDP [新增]
        if "mpls" in selected_features:
            mpls_p = params.get("mpls", {})
            lsr_id = mpls_p.get("lsr_id", "1.1.1.1").strip()
            intf_name = mpls_p.get("interface", "GigabitEthernet0/0/0").strip()

            lines.append(f"mpls lsr-id {lsr_id}")
            lines.append("mpls")
            lines.append("quit")
            lines.append("mpls ldp")
            lines.append("quit")
            if intf_name:
                lines.append(f"interface {intf_name}")
                lines.append(" mpls")
                lines.append(" mpls ldp")
                lines.append("quit")

        # 6.3 BGP/MPLS L3VPN 多租户专网 [新增]
        if "mpls_l3vpn" in selected_features:
            vpn_p = params.get("mpls_l3vpn", {})
            vpn_name = vpn_p.get("vpn_name", "VPN1").strip() or "VPN1"
            rd = vpn_p.get("rd", "100:1").strip() or "100:1"
            rt = vpn_p.get("rt", "100:1").strip() or "100:1"
            bind_intf = vpn_p.get("interface", "GigabitEthernet0/0/2").strip()
            intf_ip = vpn_p.get("ip_address", "192.168.200.1").strip()
            intf_mask = vpn_p.get("mask", "255.255.255.0").strip()

            lines.append(f"ip vpn-instance {vpn_name}")
            lines.append(f" route-distinguisher {rd}")
            lines.append(f" vpn-target {rt} both")
            lines.append("quit")
            if bind_intf:
                lines.append(f"interface {bind_intf}")
                lines.append(f" ip binding vpn-instance {vpn_name}")
                if intf_ip:
                    lines.append(f" ip address {intf_ip} {intf_mask}")
                lines.append("quit")

        # 6.4 IGMP Snooping 二层组播监听 [新增]
        if "igmp_snooping" in selected_features:
            igmp_p = params.get("igmp_snooping", {})
            vlan_id = igmp_p.get("vlan_id", 10)

            if is_huawei:
                lines.append("igmp-snooping enable")
                lines.append(f"vlan {vlan_id}")
                lines.append(" igmp-snooping enable")
                lines.append("quit")
            else:
                lines.append("igmp-snooping")
                lines.append(f"vlan {vlan_id}")
                lines.append(" igmp-snooping enable")
                lines.append("quit")

        # 6.5 VXLAN 大二层 Overlay [新增]
        if "vxlan" in selected_features:
            vx_p = params.get("vxlan", {})
            vni = vx_p.get("vni", 10010)

            if is_huawei:
                lines.append("bridge-domain 10")
                lines.append(f" vxlan vni {vni}")
                lines.append("quit")
            else:
                lines.append("l2vpn enable")
                lines.append(f"vsi vpn_{vni}")
                lines.append(f" vxlan {vni}")
                lines.append("quit")

        # 6.6 PIM-SM 组播稀疏模式与静态 RP [新增]
        if "pim_sm" in selected_features:
            pim_p = params.get("pim_sm", {})
            rp_ip = pim_p.get("rp_ip", "192.168.1.254").strip()
            intf_name = pim_p.get("interface", "GigabitEthernet0/0/1").strip()

            if is_huawei:
                lines.append("multicast routing-enable")
                lines.append("pim")
                if rp_ip:
                    lines.append(f" static-rp {rp_ip}")
                lines.append("quit")
                if intf_name:
                    lines.append(f"interface {intf_name}")
                    lines.append(" pim sm")
                    lines.append("quit")
            else:
                lines.append("multicast routing")
                lines.append("pim")
                if rp_ip:
                    lines.append(f" static-rp {rp_ip}")
                lines.append("quit")
                if intf_name:
                    lines.append(f"interface {intf_name}")
                    lines.append(" pim sm")
                    lines.append("quit")

        # 6.7 BGP EVPN 控制面 [新增]
        if "evpn" in selected_features:
            evpn_p = params.get("evpn", {})
            as_num = evpn_p.get("as_number", 65001)
            peer_ip = evpn_p.get("peer_ip", "10.1.1.2").strip()

            lines.append(f"bgp {as_num}")
            if is_huawei:
                lines.append(" l2vpn-family evpn")
                if peer_ip:
                    lines.append(f"  peer {peer_ip} enable")
                lines.append(" quit")
            else:
                lines.append(" address-family l2vpn evpn")
                if peer_ip:
                    lines.append(f"  peer {peer_ip} enable")
                lines.append(" quit")
            lines.append("quit")

        # ====================================================
        # 7. QoS 与流量工程 (QoS & Traffic Engineering)
        # ====================================================
        # 7.1 QoS 流量监管与限速 (CAR / LR) [新增]
        if "qos_car" in selected_features:
            car_p = params.get("qos_car", {})
            intf_name = car_p.get("interface", "GigabitEthernet0/0/1").strip()
            cir_kbps = int(car_p.get("cir", 10000))
            cbs_bytes = int(car_p.get("cbs", 1250000))
            direction = car_p.get("direction", "both").strip().lower()

            if intf_name:
                lines.append(f"interface {intf_name}")
                if is_huawei:
                    if direction in ("inbound", "both"):
                        lines.append(f" qos car inbound cir {cir_kbps} cbs {cbs_bytes}")
                    if direction in ("outbound", "both"):
                        lines.append(f" qos car outbound cir {cir_kbps} cbs {cbs_bytes}")
                else:
                    if direction in ("inbound", "both"):
                        lines.append(f" qos lr inbound cir {cir_kbps} cbs {cbs_bytes}")
                    if direction in ("outbound", "both"):
                        lines.append(f" qos lr outbound cir {cir_kbps} cbs {cbs_bytes}")
                lines.append("quit")

        # 7.2 QoS DSCP 优先级重标记 (Remark) [新增]
        if "qos_remark" in selected_features:
            rm_p = params.get("qos_remark", {})
            acl_num = rm_p.get("acl_number", 3000)
            dscp_val = rm_p.get("dscp_value", "ef").strip() or "ef"
            intf_name = rm_p.get("interface", "GigabitEthernet0/0/1").strip()

            if is_huawei:
                lines.append("traffic classifier c_remark operator or")
                lines.append(f" if-match acl {acl_num}")
                lines.append("quit")
                lines.append("traffic behavior b_remark")
                lines.append(f" remark dscp {dscp_val}")
                lines.append("quit")
                lines.append("traffic policy p_remark")
                lines.append(" classifier c_remark behavior b_remark")
                lines.append("quit")
                if intf_name:
                    lines.append(f"interface {intf_name}")
                    lines.append(" traffic-policy p_remark inbound")
                    lines.append("quit")
            else:
                lines.append("traffic classifier c_remark operator or")
                lines.append(f" if-match acl {acl_num}")
                lines.append("quit")
                lines.append("traffic behavior b_remark")
                lines.append(f" remark dscp {dscp_val}")
                lines.append("quit")
                lines.append("qos policy p_remark")
                lines.append(" classifier c_remark behavior b_remark")
                lines.append("quit")
                if intf_name:
                    lines.append(f"interface {intf_name}")
                    lines.append(" qos apply policy p_remark inbound")
                    lines.append("quit")

        # 7.3 QoS 拥塞管理与队列调度 (PQ / WRR / WRED) [工程加固]
        if "qos_queue" in selected_features:
            qq_p = params.get("qos_queue", {})
            intf_name = qq_p.get("interface", "GigabitEthernet0/0/1").strip() or "GigabitEthernet0/0/1"
            w_high = int(qq_p.get("wrr_weight_high", 40))
            w_low = int(qq_p.get("wrr_weight_low", 20))

            if intf_name:
                lines.append(f"interface {intf_name}")
                if is_huawei:
                    lines.append(" port-queue ef pq")
                    lines.append(f" port-queue af1 wrr weight {w_low}")
                    lines.append(f" port-queue af2 wrr weight {w_high}")
                    lines.append(" qos wred default")
                else:
                    lines.append(" qos wrr")
                    lines.append(" qos wrr 5 group sp")
                    lines.append(f" qos wrr 0 group 1 byte-count {w_low}")
                    lines.append(f" qos wrr 1 group 1 byte-count {w_high}")
                    lines.append(" qos wred enable")
                lines.append("quit")

        # ====================================================
        # 8. IPv6 演进与下一代网络 (IPv6 Next-Generation)
        # ====================================================
        # 8.1 IPv6 基础与单播接口 [新增]
        if "ipv6_base" in selected_features:
            v6_p = params.get("ipv6_base", {})
            intf_name = v6_p.get("interface", "GigabitEthernet0/0/0").strip()
            ipv6_addr = v6_p.get("ipv6_address", "2001:db8:1::1/64").strip()

            lines.append("ipv6")
            if intf_name:
                lines.append(f"interface {intf_name}")
                if is_huawei:
                    lines.append(" ipv6 enable")
                lines.append(f" ipv6 address {ipv6_addr}")
                lines.append("quit")

        # 8.2 OSPFv3 动态路由 [新增]
        if "ospfv3" in selected_features:
            v3_p = params.get("ospfv3", {})
            pid = v3_p.get("process_id", 1)
            rid = v3_p.get("router_id", "1.1.1.1").strip()
            area_id = v3_p.get("area_id", "0").strip()
            intfs = v3_p.get("interfaces", ["GigabitEthernet0/0/0"])

            lines.append(f"ospfv3 {pid}")
            lines.append(f" router-id {rid}")
            lines.append("quit")
            for intf in intfs:
                if intf.strip():
                    lines.append(f"interface {intf.strip()}")
                    lines.append(f" ospfv3 {pid} area {area_id}")
                    lines.append("quit")

        # 8.3 RIPng IPv6 动态路由 [新增]
        if "ripng" in selected_features:
            ripng_p = params.get("ripng", {})
            proc_id = ripng_p.get("process_id", 1)
            intf_name = ripng_p.get("interface", "GigabitEthernet0/0/0").strip()

            lines.append(f"ripng {proc_id}")
            lines.append("quit")
            if intf_name:
                lines.append(f"interface {intf_name}")
                lines.append(f" ripng {proc_id} enable")
                lines.append("quit")

        # 8.4 IPv6 邻居发现与 RA 通告 (ND / SLAAC) [新增]
        if "ipv6_nd" in selected_features:
            nd_p = params.get("ipv6_nd", {})
            intf_name = nd_p.get("interface", "GigabitEthernet0/0/0").strip()

            if intf_name:
                lines.append(f"interface {intf_name}")
                lines.append(" undo ipv6 nd ra halt")
                lines.append(" ipv6 nd autoconfig managed-address-flag")
                lines.append("quit")

        # 8.5 DHCPv6 地址池与服务器 [新增]
        if "dhcpv6" in selected_features:
            d6_p = params.get("dhcpv6", {})
            pool_name = d6_p.get("pool_name", "pool_v6").strip() or "pool_v6"
            prefix = d6_p.get("prefix", "2001:db8:1::/64").strip()
            dns_v6 = d6_p.get("dns", "2400:3200::1").strip()
            intf_name = d6_p.get("interface", "GigabitEthernet0/0/0").strip()

            if is_huawei:
                lines.append("dhcp enable")
                lines.append(f"dhcpv6 pool {pool_name}")
                lines.append(" address-range 2001:db8:1::10 2001:db8:1::200 64")
                if dns_v6:
                    lines.append(f" dns-server {dns_v6}")
                lines.append("quit")
                if intf_name:
                    lines.append(f"interface {intf_name}")
                    lines.append(f" dhcpv6 server {pool_name}")
                    lines.append("quit")
            else:
                lines.append(f"ipv6 dhcp pool {pool_name}")
                if prefix:
                    lines.append(f" network {prefix}")
                if dns_v6:
                    lines.append(f" dns-server {dns_v6}")
                lines.append("quit")
                if intf_name:
                    lines.append(f"interface {intf_name}")
                    lines.append(" ipv6 dhcp select server")
                    lines.append(f" ipv6 dhcp server apply pool {pool_name}")
                    lines.append("quit")

        # 8.6 BGP4+ (MP-BGP IPv6 单播路由) [新增]
        if "bgp4_plus" in selected_features:
            b6_p = params.get("bgp4_plus", {})
            as_num = b6_p.get("as_number", 65001)
            peer_v6 = b6_p.get("peer_ipv6", "2001:db8:1::2").strip()

            lines.append(f"bgp {as_num}")
            if is_huawei:
                lines.append(f" peer {peer_v6} as-number {as_num}")
                lines.append(" ipv6-family unicast")
                lines.append(f"  peer {peer_v6} enable")
                lines.append(" quit")
            else:
                lines.append(f" peer {peer_v6} as-number {as_num}")
                lines.append(" address-family ipv6 unicast")
                lines.append(f"  peer {peer_v6} enable")
                lines.append(" quit")
            lines.append("quit")

        # ====================================================
        # 9. 企业与运营商高阶扩展特性 (69 ~ 80 项)
        # ====================================================
        # 1.11 Voice VLAN 语音专网优先传输 (#69)
        if "voice_vlan" in selected_features:
            vv_p = params.get("voice_vlan", {})
            v_vlan = int(vv_p.get("vlan_id", 200))
            oui_mac = vv_p.get("oui_mac", "00e0-fc00-0000").strip() or "00e0-fc00-0000"
            intf_name = vv_p.get("interface", "GigabitEthernet0/0/3").strip() or "GigabitEthernet0/0/3"

            lines.append(f"vlan {v_vlan}")
            lines.append(" description Voice_VLAN")
            lines.append("quit")
            lines.append(f"voice-vlan mac-address {oui_mac} mask ffff-ff00-0000 description IP-Phone")
            if intf_name:
                lines.append(f"interface {intf_name}")
                lines.append(f" voice-vlan {v_vlan} enable")
                if is_huawei:
                    lines.append(" voice-vlan mode auto")
                lines.append("quit")

        # 2.11 Smart Link 双上行毫秒级主备切换 (#70)
        if "smart_link" in selected_features:
            sl_p = params.get("smart_link", {})
            grp_id = int(sl_p.get("group_id", 1))
            master_if = sl_p.get("master_port", "GigabitEthernet0/0/1").strip() or "GigabitEthernet0/0/1"
            slave_if = sl_p.get("slave_port", "GigabitEthernet0/0/2").strip() or "GigabitEthernet0/0/2"
            ctrl_vlan = int(sl_p.get("control_vlan", 1))

            lines.append(f"smart-link group {grp_id}")
            if is_huawei:
                lines.append(" smart-link enable")
                lines.append(f" port {master_if} master")
                lines.append(f" port {slave_if} slave")
                lines.append(" restore enable")
                lines.append(f" flush send control-vlan {ctrl_vlan} password simple 123456")
            else:
                lines.append(f" port {master_if} master")
                lines.append(f" port {slave_if} slave")
                lines.append(" preemption mode role")
                lines.append(f" flush enable control-vlan {ctrl_vlan}")
            lines.append("quit")

        # 2.12 DLDP 光纤单向链路检测协议 (#71)
        if "dldp" in selected_features:
            dl_p = params.get("dldp", {})
            interval = int(dl_p.get("interval", 5))
            work_mode = dl_p.get("mode", "enhance").strip() or "enhance"
            intf_name = dl_p.get("interface", "GigabitEthernet0/0/1").strip() or "GigabitEthernet0/0/1"

            lines.append("dldp enable")
            lines.append(f"dldp interval {interval}")
            lines.append(f"dldp work-mode {work_mode}")
            if intf_name:
                lines.append(f"interface {intf_name}")
                lines.append(" dldp enable")
                lines.append("quit")

        # 3.11 OSPF 特殊区域优化 (Stub / NSSA & ABR 汇总) (#72)
        if "ospf_stub_nssa" in selected_features:
            osn_p = params.get("ospf_stub_nssa", {})
            pid = int(osn_p.get("process_id", 1))
            area_id = osn_p.get("area_id", "1").strip() or "1"
            area_type = osn_p.get("area_type", "nssa").strip() or "nssa"
            sum_net = osn_p.get("summary_network", "10.1.0.0").strip()
            sum_mask = osn_p.get("summary_mask", "255.255.0.0").strip()

            lines.append(f"ospf {pid}")
            lines.append(f" area {area_id}")
            lines.append(f"  {area_type} no-summary")
            if sum_net and sum_mask:
                lines.append(f"  abr-summary {sum_net} {sum_mask}")
            lines.append(" quit")
            lines.append("quit")

        # 3.12 IP-Prefix 地址前缀列表精确路由过滤 (#73)
        if "ip_prefix_list" in selected_features:
            pf_p = params.get("ip_prefix_list", {})
            pf_name = pf_p.get("name", "PFX_CORP_ROUTES").strip() or "PFX_CORP_ROUTES"
            idx = int(pf_p.get("index", 10))
            action = pf_p.get("action", "permit").strip() or "permit"
            net = pf_p.get("network", "172.16.0.0").strip() or "172.16.0.0"
            mask_len = int(pf_p.get("mask_len", 16))
            ge_len = int(pf_p.get("ge_len", 24))
            le_len = int(pf_p.get("le_len", 24))

            if is_huawei:
                lines.append(f"ip ip-prefix {pf_name} index {idx} {action} {net} {mask_len} greater-equal {ge_len} less-equal {le_len}")
            else:
                lines.append(f"ip prefix-list {pf_name} index {idx} {action} {net} {mask_len} greater-equal {ge_len} less-equal {le_len}")

        # 4.15 HWTACACS / TACACS+ 堡垒机集中命令行审计 (#74)
        if "aaa_tacacs" in selected_features:
            tac_p = params.get("aaa_tacacs", {})
            scheme = tac_p.get("scheme_name", "TAC_AUDIT").strip() or "TAC_AUDIT"
            srv_ip = tac_p.get("server_ip", "192.168.100.200").strip() or "192.168.100.200"
            s_key = tac_p.get("shared_key", "Tacacs@Secret123").strip() or "Tacacs@Secret123"

            if is_huawei:
                lines.append(f"hwtacacs-server template {scheme}")
                lines.append(f" hwtacacs-server authentication {srv_ip}")
                lines.append(f" hwtacacs-server authorization {srv_ip}")
                lines.append(f" hwtacacs-server accounting {srv_ip}")
                lines.append(f" hwtacacs-server shared-key cipher {s_key}")
                lines.append(" undo hwtacacs-server user-name domain-included")
                lines.append("quit")
            else:
                lines.append(f"hwtacacs scheme {scheme}")
                lines.append(f" primary authentication {srv_ip}")
                lines.append(f" primary authorization {srv_ip}")
                lines.append(f" primary accounting {srv_ip}")
                lines.append(f" key authentication simple {s_key}")
                lines.append(f" key authorization simple {s_key}")
                lines.append(f" key accounting simple {s_key}")
                lines.append(" user-name-format without-domain")
                lines.append("quit")

        # 4.16 Zone-Based 基于安全域状态检测防火墙策略 (#75)
        if "zone_firewall" in selected_features:
            zf_p = params.get("zone_firewall", {})
            src_zone = zf_p.get("source_zone", "Trust").strip() or "Trust"
            dst_zone = zf_p.get("dest_zone", "Untrust").strip() or "Untrust"
            src_if = zf_p.get("source_if", "GigabitEthernet0/0/1").strip() or "GigabitEthernet0/0/1"
            dst_if = zf_p.get("dest_if", "GigabitEthernet0/0/0").strip() or "GigabitEthernet0/0/0"

            if is_huawei:
                lines.append(f"firewall zone {src_zone.lower()}")
                lines.append(f" add interface {src_if}")
                lines.append("quit")
                lines.append(f"firewall zone {dst_zone.lower()}")
                lines.append(f" add interface {dst_if}")
                lines.append("quit")
                lines.append("security-policy")
                lines.append(f" rule name PERMIT_{src_zone.upper()}_TO_{dst_zone.upper()}")
                lines.append(f"  source-zone {src_zone.lower()}")
                lines.append(f"  destination-zone {dst_zone.lower()}")
                lines.append("  action permit")
                lines.append(" quit")
                lines.append("quit")
            else:
                lines.append(f"security-zone name {src_zone}")
                lines.append(f" import interface {src_if}")
                lines.append("quit")
                lines.append(f"security-zone name {dst_zone}")
                lines.append(f" import interface {dst_if}")
                lines.append("quit")
                lines.append("security-policy ip")
                lines.append(f" rule 0 name PERMIT_{src_zone.upper()}_TO_{dst_zone.upper()}")
                lines.append(f"  source-zone {src_zone}")
                lines.append(f"  destination-zone {dst_zone}")
                lines.append("  action pass")
                lines.append(" quit")
                lines.append("quit")

        # 5.9 NETCONF / Telemetry SDN 北向网管接口 (#76)
        if "netconf_yang" in selected_features:
            nc_p = params.get("netconf_yang", {})
            nc_port = int(nc_p.get("port", 830))

            if is_huawei:
                lines.append("snetconf server enable")
                lines.append("netconf")
                lines.append(f" protocol inbound ssh port {nc_port}")
                lines.append("quit")
            else:
                lines.append("netconf ssh server enable")
                lines.append(f"netconf ssh server port {nc_port}")

        # 5.10 Loopback-Detection 接入端口自环检测 (#77)
        if "port_loopback_detect" in selected_features:
            lbd_p = params.get("port_loopback_detect", {})
            intf_name = lbd_p.get("interface", "GigabitEthernet0/0/2").strip() or "GigabitEthernet0/0/2"
            interval = int(lbd_p.get("interval", 15))

            if is_huawei:
                lines.append(f"loopback-detect recovery-time {interval}")
                lines.append(f"interface {intf_name}")
                lines.append(" loopback-detect enable")
                lines.append(" loopback-detect action shutdown")
                lines.append("quit")
            else:
                lines.append("loopback-detection global enable vlan all")
                lines.append(f"loopback-detection interval-time {interval}")
                lines.append(f"interface {intf_name}")
                lines.append(" loopback-detection enable vlan all")
                lines.append(" loopback-detection action shutdown")
                lines.append("quit")

        # 6.8 MPLS TE 流量工程显式路径隧道 (RSVP-TE) (#78)
        if "mpls_te" in selected_features:
            te_p = params.get("mpls_te", {})
            tun_if = te_p.get("tunnel_interface", "Tunnel0").strip() or "Tunnel0"
            dst_ip = te_p.get("destination_ip", "2.2.2.2").strip() or "2.2.2.2"
            bw_kbps = int(te_p.get("bandwidth", 10000))

            if is_huawei:
                lines.append("mpls")
                lines.append(" mpls te")
                lines.append(" mpls rsvp-te")
                lines.append("quit")
                lines.append(f"interface {tun_if}")
                lines.append(" tunnel-protocol mpls te")
                lines.append(" ip address unnumbered interface LoopBack0")
                lines.append(f" destination {dst_ip}")
                lines.append(f" mpls te bandwidth ct0 {bw_kbps}")
                lines.append(" mpls te commit")
                lines.append("quit")
            else:
                lines.append("mpls te")
                lines.append("quit")
                lines.append("rsvp")
                lines.append("quit")
                lines.append(f"interface {tun_if} mode mpls-te")
                lines.append(" ip address unnumbered interface LoopBack0")
                lines.append(f" destination {dst_ip}")
                lines.append(f" mpls te bandwidth {bw_kbps}")
                lines.append(" mpls te commit")
                lines.append("quit")

        # 7.4 QoS GTS 通用流量整形与削峰平谷 (#79)
        if "qos_gts" in selected_features:
            gts_p = params.get("qos_gts", {})
            intf_name = gts_p.get("interface", "GigabitEthernet0/0/1").strip() or "GigabitEthernet0/0/1"
            cir_kbps = int(gts_p.get("cir", 20000))
            cbs_bytes = int(gts_p.get("cbs", 2500000))

            if intf_name:
                lines.append(f"interface {intf_name}")
                if is_huawei:
                    lines.append(f" qos gts cir {cir_kbps} cbs {cbs_bytes}")
                else:
                    lines.append(f" qos gts any cir {cir_kbps} cbs {cbs_bytes}")
                lines.append("quit")

        # 8.7 IPv6 ACL6 高级安全访问控制与过滤 (#80)
        if "ipv6_acl_filter" in selected_features:
            v6f_p = params.get("ipv6_acl_filter", {})
            acl6_num = int(v6f_p.get("acl_number", 3000))
            deny_src = v6f_p.get("deny_source", "2001:db8:bad::/48").strip() or "2001:db8:bad::/48"
            intf_name = v6f_p.get("interface", "GigabitEthernet0/0/0").strip() or "GigabitEthernet0/0/0"

            lines.append(f"acl ipv6 number {acl6_num}")
            lines.append(f" rule 10 deny ipv6 source {deny_src}")
            lines.append(" rule 100 permit ipv6")
            lines.append("quit")
            if intf_name:
                lines.append(f"interface {intf_name}")
                if is_huawei:
                    lines.append(f" traffic-filter inbound ipv6 acl {acl6_num}")
                else:
                    lines.append(f" packet-filter ipv6 {acl6_num} inbound")
                lines.append("quit")

        # ====================================================
        # 10. 百项旗舰满配扩展特性 (81 ~ 100 项)
        # ====================================================
        # 1.12 Super-VLAN / VLAN 聚合与代理 ARP (#81)
        if "super_vlan" in selected_features:
            sv_p = params.get("super_vlan", {})
            sup_vid = int(sv_p.get("super_vlan", 100))
            sub_vids = sv_p.get("sub_vlans", "10 20").strip() or "10 20"
            gw_ip = sv_p.get("gateway_ip", "192.168.100.254").strip() or "192.168.100.254"
            gw_mask = sv_p.get("mask", "255.255.255.0").strip() or "255.255.255.0"

            if is_huawei:
                lines.append(f"vlan batch {sub_vids} {sup_vid}")
                lines.append(f"vlan {sup_vid}")
                lines.append(" aggregate-vlan")
                lines.append(f" access-vlan {sub_vids}")
                lines.append("quit")
                lines.append(f"interface Vlanif {sup_vid}")
                lines.append(f" ip address {gw_ip} {gw_mask}")
                lines.append(" arp-proxy inner-sub-vlan-proxy enable")
                lines.append("quit")
            else:
                lines.append(f"vlan {sub_vids} {sup_vid}")
                lines.append(f"vlan {sup_vid}")
                lines.append(" supervlan")
                lines.append(f" subvlan {sub_vids}")
                lines.append("quit")
                lines.append(f"interface Vlan-interface {sup_vid}")
                lines.append(f" ip address {gw_ip} {gw_mask}")
                lines.append(" local-proxy-arp enable")
                lines.append("quit")

        # 1.13 MUX-VLAN / Private-VLAN 政企访客精细二层隔离 (#82)
        if "mux_vlan" in selected_features:
            mv_p = params.get("mux_vlan", {})
            p_vlan = int(mv_p.get("principal_vlan", 100))
            g_vlan = int(mv_p.get("group_vlan", 101))
            s_vlan = int(mv_p.get("separate_vlan", 102))
            intf_name = mv_p.get("interface", "GigabitEthernet0/0/2").strip() or "GigabitEthernet0/0/2"

            if is_huawei:
                lines.append(f"vlan batch {p_vlan} {g_vlan} {s_vlan}")
                lines.append(f"vlan {p_vlan}")
                lines.append(" mux-vlan")
                lines.append(f" subordinate group {g_vlan}")
                lines.append(f" subordinate separate {s_vlan}")
                lines.append("quit")
                lines.append(f"interface {intf_name}")
                lines.append(" port link-type access")
                lines.append(f" port default vlan {s_vlan}")
                lines.append(" port mux-vlan enable")
                lines.append("quit")
            else:
                lines.append(f"vlan {p_vlan}")
                lines.append(" private-vlan primary")
                lines.append(f" private-vlan secondary {g_vlan} {s_vlan}")
                lines.append("quit")
                lines.append(f"vlan {g_vlan}")
                lines.append(" private-vlan community")
                lines.append("quit")
                lines.append(f"vlan {s_vlan}")
                lines.append(" private-vlan isolated")
                lines.append("quit")
                lines.append(f"interface {intf_name}")
                lines.append(" port private-vlan host")
                lines.append(f" port access vlan {s_vlan}")
                lines.append("quit")

        # 1.14 VLAN Mapping 1:1 跨网标签映射转换 (#83)
        if "vlan_mapping" in selected_features:
            vm_p = params.get("vlan_mapping", {})
            intf_name = vm_p.get("interface", "GigabitEthernet0/0/1").strip() or "GigabitEthernet0/0/1"
            orig_vlan = int(vm_p.get("original_vlan", 10))
            trans_vlan = int(vm_p.get("translated_vlan", 200))

            lines.append(f"interface {intf_name}")
            lines.append(" port link-type trunk")
            if is_huawei:
                lines.append(f" port trunk allow-pass vlan {trans_vlan}")
                lines.append(" qnq vlan-translation enable")
                lines.append(f" port vlan-mapping vlan {orig_vlan} map-vlan {trans_vlan}")
            else:
                lines.append(f" port trunk permit vlan {trans_vlan}")
                lines.append(f" vlan-mapping vlan {orig_vlan} translated-vlan {trans_vlan}")
            lines.append("quit")

        # 2.13 VRRP Track 上行接口联动自动降级 (#84)
        if "vrrp_track" in selected_features:
            vt_p = params.get("vrrp_track", {})
            vlan_id = int(vt_p.get("vlan_id", 10))
            vrid = int(vt_p.get("vrid", 1))
            track_if = vt_p.get("track_interface", "GigabitEthernet0/0/1").strip() or "GigabitEthernet0/0/1"
            red_prio = int(vt_p.get("reduced_prio", 30))

            if is_huawei:
                lines.append(f"interface Vlanif {vlan_id}")
                lines.append(f" vrrp vrid {vrid} track interface {track_if} reduced {red_prio}")
                lines.append(f" vrrp vrid {vrid} preempt-mode timer delay 20")
                lines.append("quit")
            else:
                lines.append(f"track 10 interface {track_if}")
                lines.append("quit")
                lines.append(f"interface Vlan-interface {vlan_id}")
                lines.append(f" vrrp vrid {vrid} track 10 priority reduced {red_prio}")
                lines.append(f" vrrp vrid {vrid} preempt-mode delay 20")
                lines.append("quit")

        # 2.14 ERPS G.8032 / RRPP 以太网多环毫秒级保护 (#85)
        if "erps_rrpp" in selected_features:
            er_p = params.get("erps_rrpp", {})
            ring_id = int(er_p.get("ring_id", 1))
            ctrl_vlan = int(er_p.get("control_vlan", 4000))
            p0 = er_p.get("port0", "GigabitEthernet0/0/1").strip() or "GigabitEthernet0/0/1"
            p1 = er_p.get("port1", "GigabitEthernet0/0/2").strip() or "GigabitEthernet0/0/2"

            if is_huawei:
                lines.append(f"erps ring {ring_id}")
                lines.append(f" control-vlan {ctrl_vlan}")
                lines.append(" protected-instance all")
                lines.append(" version v2")
                lines.append("quit")
                lines.append(f"interface {p0}")
                lines.append(f" erps ring {ring_id} rpl owner")
                lines.append("quit")
                lines.append(f"interface {p1}")
                lines.append(f" erps ring {ring_id}")
                lines.append("quit")
            else:
                lines.append(f"rrpp domain {ring_id}")
                lines.append(f" control-vlan {ctrl_vlan}")
                lines.append(" protected-vlan reference-instance 0")
                lines.append(f" ring {ring_id} node-mode master primary-port {p0} secondary-port {p1} level 0")
                lines.append(f" ring {ring_id} enable")
                lines.append("quit")
                lines.append("rrpp enable")

        # 2.15 M-LAG / DRNI 跨设备虚拟化双活链路聚合 (#86)
        if "m_lag" in selected_features:
            mlg_p = params.get("m_lag", {})
            grp_id = int(mlg_p.get("group_id", 1))
            peer_aggr = int(mlg_p.get("peer_link_aggr", 10))
            mem_aggr = int(mlg_p.get("member_aggr", 1))
            ka_ip = mlg_p.get("keepalive_ip", "10.254.254.2").strip() or "10.254.254.2"

            if is_huawei:
                lines.append(f"dfs-group {grp_id}")
                lines.append(" priority 150")
                lines.append(f" dual-active detection source ip {ka_ip}")
                lines.append("quit")
                lines.append(f"interface Eth-Trunk {peer_aggr}")
                lines.append(" mode lacp-static")
                lines.append(" peer-link 1")
                lines.append("quit")
                lines.append(f"interface Eth-Trunk {mem_aggr}")
                lines.append(" mode lacp-static")
                lines.append(f" dfs-group {grp_id} m-lag {mem_aggr}")
                lines.append("quit")
            else:
                lines.append("drni system-mac 000f-e200-0001")
                lines.append("drni system-number 1")
                lines.append(f"drni keepalive ip destination {ka_ip}")
                lines.append(f"interface Bridge-Aggregation {peer_aggr}")
                lines.append(" link-aggregation mode dynamic")
                lines.append(" port drni intra-portal-port 1")
                lines.append("quit")
                lines.append(f"interface Bridge-Aggregation {mem_aggr}")
                lines.append(" link-aggregation mode dynamic")
                lines.append(f" port drni group {mem_aggr}")
                lines.append("quit")

        # 3.13 OSPF 区域 MD5 密文认证与被动静默接口 (#87)
        if "ospf_auth_silent" in selected_features:
            oas_p = params.get("ospf_auth_silent", {})
            pid = int(oas_p.get("process_id", 1))
            area_id = oas_p.get("area_id", "0").strip() or "0"
            silent_if = oas_p.get("silent_interface", "Vlanif10" if is_huawei else "Vlan-interface10").strip() or "Vlanif10"
            auth_key = oas_p.get("auth_key", "Ospf@Md5Key").strip() or "Ospf@Md5Key"

            lines.append(f"ospf {pid}")
            lines.append(f" silent-interface {silent_if}")
            lines.append(f" area {area_id}")
            lines.append(f"  authentication-mode md5 1 cipher {auth_key}")
            lines.append(" quit")
            lines.append("quit")

        # 3.14 BGP 邻居 MD5 认证、最大前缀限制与 GR 优雅重启 (#88)
        if "bgp_security" in selected_features:
            bgps_p = params.get("bgp_security", {})
            as_num = int(bgps_p.get("as_number", 65001))
            peer_ip = bgps_p.get("peer_ip", "2.2.2.2").strip() or "2.2.2.2"
            md5_pwd = bgps_p.get("md5_password", "Bgp@PeerKey").strip() or "Bgp@PeerKey"
            r_limit = int(bgps_p.get("route_limit", 5000))

            lines.append(f"bgp {as_num}")
            lines.append(" graceful-restart")
            lines.append(f" peer {peer_ip} password cipher {md5_pwd}")
            if is_huawei:
                lines.append(" ipv4-family unicast")
                lines.append(f"  peer {peer_ip} route-limit {r_limit} 80 alert-only")
                lines.append(" quit")
            else:
                lines.append(" address-family ipv4 unicast")
                lines.append(f"  peer {peer_ip} route-limit {r_limit} alert-only percentage 80")
                lines.append(" quit")
            lines.append("quit")

        # 3.15 ECMP 等价多路径最大条数与五元组逐流负载分担 (#89)
        if "ecmp_load_balance" in selected_features:
            ecmp_p = params.get("ecmp_load_balance", {})
            max_paths = int(ecmp_p.get("max_paths", 8))

            if is_huawei:
                lines.append("load-balance ecmp")
                lines.append(" ipv4 src-ip dst-ip l4-sport l4-dport")
                lines.append("quit")
                lines.append(f"maximum load-balancing {max_paths}")
            else:
                lines.append("ip load-sharing mode per-flow src-ip dst-ip src-port dst-port")
                lines.append(f"max-ecmp-num {max_paths}")

        # 4.17 802.1X 端口准入与 MAC 旁路认证 (#90)
        if "dot1x_mac_auth" in selected_features:
            dx_p = params.get("dot1x_mac_auth", {})
            intf_name = dx_p.get("interface", "GigabitEthernet0/0/2").strip() or "GigabitEthernet0/0/2"
            guest_vlan = int(dx_p.get("guest_vlan", 999))

            if is_huawei:
                lines.append("dot1x enable")
                lines.append("mac-authen")
                lines.append(f"interface {intf_name}")
                lines.append(" dot1x enable")
                lines.append(" dot1x port-method macbased")
                lines.append(" mac-authen")
                lines.append(f" authentication guest-vlan {guest_vlan}")
                lines.append("quit")
            else:
                lines.append("dot1x")
                lines.append("mac-authentication")
                lines.append(f"interface {intf_name}")
                lines.append(" dot1x")
                lines.append(" dot1x port-method macbased")
                lines.append(" mac-authentication")
                lines.append(f" dot1x guest-vlan {guest_vlan}")
                lines.append("quit")

        # 4.18 等保三级 VTY 登录白名单、超时锁定与防暴力破解 (#91)
        if "vty_acl_hardening" in selected_features:
            vh_p = params.get("vty_acl_hardening", {})
            acl_num = int(vh_p.get("acl_number", 2000))
            subnet = vh_p.get("permit_subnet", "192.168.100.0").strip() or "192.168.100.0"
            wildcard = vh_p.get("wildcard", "0.0.0.255").strip() or "0.0.0.255"
            t_min = int(vh_p.get("timeout_min", 5))

            if is_huawei:
                lines.append(f"acl number {acl_num}")
                lines.append(f" rule 5 permit source {subnet} {wildcard}")
                lines.append(" rule 100 deny")
                lines.append("quit")
                lines.append("ssh server compatible-ssh1x disable")
                lines.append("user-interface vty 0 4")
                lines.append(f" acl {acl_num} inbound")
                lines.append(f" idle-timeout {t_min} 0")
                lines.append(" protocol inbound ssh")
                lines.append("quit")
            else:
                lines.append(f"acl basic {acl_num}")
                lines.append(f" rule 5 permit source {subnet} {wildcard}")
                lines.append(" rule 100 deny")
                lines.append("quit")
                lines.append("undo ssh server compatible-ssh1x")
                lines.append("line vty 0 4")
                lines.append(f" acl {acl_num} inbound")
                lines.append(f" idle-timeout {t_min} 0")
                lines.append(" protocol inbound ssh")
                lines.append("quit")

        # 5.11 NetStream / IPFIX 五元组网络流统计导出 (#92)
        if "netstream" in selected_features:
            ns_p = params.get("netstream", {})
            intf_name = ns_p.get("interface", "GigabitEthernet0/0/1").strip() or "GigabitEthernet0/0/1"
            col_ip = ns_p.get("collector_ip", "192.168.100.180").strip() or "192.168.100.180"
            col_port = int(ns_p.get("collector_port", 9995))
            s_rate = int(ns_p.get("sample_rate", 1000))

            if is_huawei:
                lines.append("ip netstream export source 1.1.1.1")
                lines.append(f"ip netstream export host {col_ip} {col_port}")
                lines.append(f"ip netstream sampler fix-packets {s_rate} inbound")
                lines.append(f"ip netstream sampler fix-packets {s_rate} outbound")
                lines.append(f"interface {intf_name}")
                lines.append(" ip netstream inbound")
                lines.append(" ip netstream outbound")
                lines.append("quit")
            else:
                lines.append("ip netstream export source interface LoopBack0")
                lines.append(f"ip netstream export host {col_ip} {col_port}")
                lines.append(f"sampler netstream_samp mode fixed packet-interval {s_rate}")
                lines.append(f"interface {intf_name}")
                lines.append(" ip netstream inbound sampler netstream_samp")
                lines.append(" ip netstream outbound sampler netstream_samp")
                lines.append("quit")

        # 5.12 FTP / SFTP 安全文件服务与固件升级通道 (#93)
        if "ftp_sftp_server" in selected_features:
            fs_p = params.get("ftp_sftp_server", {})
            uname = fs_p.get("username", "ftpadmin").strip() or "ftpadmin"
            upwd = fs_p.get("password", "Ftp@User123").strip() or "Ftp@User123"
            r_dir = fs_p.get("root_dir", "flash:").strip() or "flash:"

            lines.append("ftp server enable")
            lines.append("sftp server enable")
            if is_huawei:
                lines.append("aaa")
                lines.append(f" local-user {uname} password irreversible-cipher {upwd}")
                lines.append(f" local-user {uname} service-type ftp ssh")
                lines.append(f" local-user {uname} ftp-directory {r_dir}")
                lines.append(f" local-user {uname} privilege level 15")
                lines.append("quit")
            else:
                lines.append(f"local-user {uname} class manage")
                lines.append(f" password simple {upwd}")
                lines.append(" service-type ftp ssh")
                lines.append(f" authorization-attribute work-directory {r_dir}")
                lines.append(" authorization-attribute user-role network-admin")
                lines.append("quit")

        # 5.13 系统时区校准与定时自动保存配置 Job/Kron (#94)
        if "clock_scheduler" in selected_features:
            cs_p = params.get("clock_scheduler", {})
            tz_name = cs_p.get("timezone_name", "BJ").strip() or "BJ"
            tz_off = int(cs_p.get("offset_hours", 8))
            job_name = cs_p.get("job_name", "AUTO_SAVE").strip() or "AUTO_SAVE"
            save_time = cs_p.get("save_time", "02:00").strip() or "02:00"

            lines.append(f"clock timezone {tz_name} add {tz_off:02d}:00:00")
            if is_huawei:
                lines.append("ops")
                lines.append(f" assistant {job_name}")
                lines.append("  condition timer cron 0 2 * * *")
                lines.append('  execute 1 command "save force"')
                lines.append(" quit")
                lines.append("quit")
            else:
                lines.append(f"scheduler job {job_name}")
                lines.append(" command 1 save force")
                lines.append("quit")
                lines.append(f"scheduler schedule {job_name}_SCHED")
                lines.append(" user-role network-admin")
                lines.append(f" job {job_name}")
                lines.append(f" time repeating at {save_time}")
                lines.append("quit")

        # 6.9 MPLS L2VPN / VPLS 二层专线与伪线 PW (#95)
        if "mpls_l2vpn" in selected_features:
            l2_p = params.get("mpls_l2vpn", {})
            vsi_name = l2_p.get("vsi_name", "VSI_CORP").strip() or "VSI_CORP"
            vsi_id = int(l2_p.get("vsi_id", 100))
            peer_ip = l2_p.get("peer_ip", "2.2.2.2").strip() or "2.2.2.2"
            ac_if = l2_p.get("ac_interface", "GigabitEthernet0/0/2").strip() or "GigabitEthernet0/0/2"

            if is_huawei:
                lines.append("mpls l2vpn")
                lines.append(f"vsi {vsi_name} static")
                lines.append(" pwsignal ldp")
                lines.append(f"  vsi-id {vsi_id}")
                lines.append(f"  peer {peer_ip}")
                lines.append(" quit")
                lines.append("quit")
                lines.append(f"interface {ac_if}")
                lines.append(f" l2 binding vsi {vsi_name}")
                lines.append("quit")
            else:
                lines.append("l2vpn enable")
                lines.append(f"vsi {vsi_name}")
                lines.append(" pwsignal ldp")
                lines.append(f"  vsi-id {vsi_id}")
                lines.append(f"  peer {peer_ip}")
                lines.append(" quit")
                lines.append("quit")
                lines.append(f"interface {ac_if}")
                lines.append(" service-instance 1")
                lines.append("  encapsulation s-vid 10")
                lines.append(f"  xconnect vsi {vsi_name}")
                lines.append(" quit")
                lines.append("quit")

        # 6.10 三层接口 IGMPv3 查询器与 SSM 组播映射 (#96)
        if "igmp_ssm" in selected_features:
            is_p = params.get("igmp_ssm", {})
            intf_name = is_p.get("interface", "Vlanif10" if is_huawei else "Vlan-interface10").strip() or "Vlanif10"
            ver = int(is_p.get("version", 3))
            ssm_grp = is_p.get("ssm_group", "232.1.1.0").strip() or "232.1.1.0"
            ssm_msk = is_p.get("ssm_mask", "255.255.255.0").strip() or "255.255.255.0"
            ssm_src = is_p.get("ssm_source", "10.1.1.1").strip() or "10.1.1.1"

            if is_huawei:
                lines.append("multicast routing-enable")
                lines.append("igmp-mapping")
                lines.append(f" ssm-mapping {ssm_grp} {ssm_msk} {ssm_src}")
                lines.append("quit")
                lines.append(f"interface {intf_name}")
                lines.append(" igmp enable")
                lines.append(f" igmp version {ver}")
                lines.append(" igmp ssm-mapping enable")
                lines.append("quit")
            else:
                lines.append("multicast routing")
                lines.append(f"interface {intf_name}")
                lines.append(" igmp enable")
                lines.append(f" igmp version {ver}")
                lines.append(" igmp ssm-mapping enable")
                lines.append("quit")

        # 6.11 DSVPN / ADVPN 动态智能多点 VPN (mGRE + NHRP) (#97)
        if "dsvpn_advpn" in selected_features:
            dv_p = params.get("dsvpn_advpn", {})
            tun_id = int(dv_p.get("tunnel_id", 1))
            nhrp_id = int(dv_p.get("nhrp_id", 100))
            tun_ip = dv_p.get("tunnel_ip", "172.31.0.2").strip() or "172.31.0.2"
            hub_pub = dv_p.get("hub_public_ip", "202.100.1.1").strip() or "202.100.1.1"
            hub_tun = dv_p.get("hub_tunnel_ip", "172.31.0.1").strip() or "172.31.0.1"

            if is_huawei:
                lines.append(f"interface Tunnel0/0/{tun_id}")
                lines.append(f" ip address {tun_ip} 255.255.255.0")
                lines.append(" tunnel-protocol gre p2mp")
                lines.append(" source GigabitEthernet0/0/0")
                lines.append(f" nhrp network-id {nhrp_id}")
                lines.append(f" nhrp entry {hub_tun} {hub_pub} register")
                lines.append("quit")
            else:
                lines.append("vam client name ADVPN_CLIENT")
                lines.append(f" advpn-domain {nhrp_id}")
                lines.append(f" server primary ip-address {hub_pub}")
                lines.append(" client enable")
                lines.append("quit")
                lines.append(f"interface Tunnel{tun_id} mode advpn udp")
                lines.append(f" ip address {tun_ip} 255.255.255.0")
                lines.append(" source GigabitEthernet0/0/0")
                lines.append(" vam client ADVPN_CLIENT")
                lines.append("quit")

        # 7.5 HQoS 层次化流量调度与多租户 SLA 带宽保底 (#98)
        if "hqos_sla" in selected_features:
            hq_p = params.get("hqos_sla", {})
            prof_name = hq_p.get("profile_name", "HQOS_TENANT_A").strip() or "HQOS_TENANT_A"
            vlan_id = int(hq_p.get("vlan_id", 10))
            cir_mbps = int(hq_p.get("cir_mbps", 100))
            pir_mbps = int(hq_p.get("pir_mbps", 200))
            intf_name = hq_p.get("interface", "GigabitEthernet0/0/1").strip() or "GigabitEthernet0/0/1"
            cir_kbps = cir_mbps * 1000
            pir_kbps = pir_mbps * 1000

            if is_huawei:
                lines.append(f"qos-profile {prof_name}")
                lines.append(f" user-queue cir {cir_kbps} pir {pir_kbps}")
                lines.append("quit")
                lines.append(f"interface {intf_name}")
                lines.append(f" qos-profile {prof_name} inbound vlan {vlan_id}")
                lines.append(f" qos-profile {prof_name} outbound vlan {vlan_id}")
                lines.append("quit")
            else:
                lines.append(f"traffic classifier TC_TENANT_{vlan_id} operator and")
                lines.append(f" if-match customer-vlan-id {vlan_id}")
                lines.append("quit")
                lines.append(f"traffic behavior TB_TENANT_{vlan_id}")
                lines.append(f" car cir {cir_kbps} pir {pir_kbps}")
                lines.append(" queue af bandwidth pct 50")
                lines.append("quit")
                lines.append(f"qos policy {prof_name}")
                lines.append(f" classifier TC_TENANT_{vlan_id} behavior TB_TENANT_{vlan_id}")
                lines.append("quit")
                lines.append(f"interface {intf_name}")
                lines.append(f" qos apply policy {prof_name} outbound")
                lines.append("quit")

        # 8.8 IPv6 over IPv4 过渡隧道 (6to4 / GRE6) (#99)
        if "ipv6_tunnel" in selected_features:
            v6t_p = params.get("ipv6_tunnel", {})
            tun_id = int(v6t_p.get("tunnel_id", 6))
            tun_v6 = v6t_p.get("tunnel_ipv6", "2001:db8:tun::1/64").strip() or "2001:db8:tun::1/64"
            src_v4 = v6t_p.get("source_ipv4", "202.100.1.1").strip() or "202.100.1.1"
            dst_v4 = v6t_p.get("dest_ipv4", "202.100.2.1").strip() or "202.100.2.1"

            if is_huawei:
                lines.append(f"interface Tunnel0/0/{tun_id}")
                lines.append(" ipv6 enable")
                lines.append(f" ipv6 address {tun_v6}")
                lines.append(" tunnel-protocol ipv6-ipv4")
                lines.append(f" source {src_v4}")
                lines.append(f" destination {dst_v4}")
                lines.append("quit")
            else:
                lines.append(f"interface Tunnel{tun_id} mode ipv6-ipv4")
                lines.append(f" ipv6 address {tun_v6}")
                lines.append(f" source {src_v4}")
                lines.append(f" destination {dst_v4}")
                lines.append("quit")

        # 8.9 SRv6 (Segment Routing IPv6) 下一代云网底座 (#100)
        if "srv6_be" in selected_features:
            sr_p = params.get("srv6_be", {})
            loc_name = sr_p.get("locator_name", "LOC_CORE").strip() or "LOC_CORE"
            v6_pfx = sr_p.get("ipv6_prefix", "2001:db8:a1::").strip() or "2001:db8:a1::"
            pfx_len = int(sr_p.get("prefix_len", 64))
            bgp_as = int(sr_p.get("bgp_as", 65001))
            peer_v6 = sr_p.get("peer_ipv6", "2001:db8:a2::1").strip() or "2001:db8:a2::1"

            lines.append("segment-routing ipv6")
            lines.append(f" encapsulation source-address {v6_pfx}1")
            lines.append(f" locator {loc_name} ipv6-prefix {v6_pfx} {pfx_len} static 32")
            lines.append("  opcode ::100 end-dt4")
            lines.append(" quit")
            lines.append("quit")
            lines.append(f"bgp {bgp_as}")
            lines.append(f" peer {peer_v6} as-number {bgp_as}")
            if is_huawei:
                lines.append(" ipv6-family unicast")
            else:
                lines.append(" address-family ipv6 unicast")
            lines.append(f"  peer {peer_v6} enable")
            lines.append(f"  segment-routing ipv6 locator {loc_name}")
            lines.append(f"  peer {peer_v6} prefix-sid")
            lines.append(" quit")
            lines.append("quit")

        lines.append("return")

        action_mode = feature_data.get("action_mode", "apply").lower()
        if action_mode == "undo":
            lines = self._convert_to_undo_lines(lines, is_huawei)

        cli_result = "\n".join(lines)

        return {
            "success": True,
            "vendor": vendor,
            "action_mode": action_mode,
            "cli_config": cli_result,
            "total_lines": len(lines),
            "features_applied": list(selected_features)
        }

    @staticmethod
    def _convert_to_undo_lines(lines: List[str], is_huawei: bool) -> List[str]:
        """
        将正向生成的 CLI 配置序列智能转换为逆向撤销 (Undo) 脚本：
        - 保留视图进入命令 (interface / ospf / bgp / vlan / acl 等) 与 quit 层级
        - 将视图内及全局叶子配置命令转换为对应的 undo 命令（已是 undo 的反转为正向，如 undo shutdown -> shutdown）
        - 对可整体销毁的顶层协议/逻辑实例（如 ospf/bgp/rip/isis/vlan/vsi）在退出视图后追加顶层 undo 清理指令
        """
        undo_lines: List[str] = ["system-view"]
        body = [line for line in lines if line.strip() not in ("system-view", "return", "Y", "y")]

        n = len(body)
        view_stack: List[str] = []

        for idx, line in enumerate(body):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("!"):
                continue

            indent = len(line) - len(line.lstrip(" "))
            next_indent = 0
            if idx + 1 < n:
                nxt = body[idx + 1]
                if nxt.strip() and nxt.strip() != "quit":
                    next_indent = len(nxt) - len(nxt.lstrip(" "))

            # 判断是否为进入子视图的语句
            is_view_entry = (
                next_indent > indent
                or stripped.startswith((
                    "interface ", "ospf ", "bgp ", "rip ", "isis ", "vlan ",
                    "acl ", "ip pool ", "dhcp server ip-pool ", "ip vpn-instance ",
                    "vsi ", "line ", "user-interface ", "local-user ",
                    "traffic classifier ", "traffic behavior ", "traffic policy ",
                    "qos policy ", "route-policy ", "policy-based-route ",
                    "segment-routing ipv6", "dfs-group ", "drni", "erps ring ",
                    "rrpp domain ", "smart-link group ", "nqa ", "bfd ",
                    "security-zone ", "zone-pair ", "wlan ", "stp region-configuration"
                ))
            ) and stripped != "quit"

            if stripped == "quit":
                undo_lines.append(" " * indent + "quit")
                if view_stack:
                    closed_view = view_stack.pop()
                    # 若是顶层协议进程或逻辑接口，追加顶层销毁指令以彻底清理
                    if len(view_stack) == 0:
                        tokens = closed_view.split()
                        head = tokens[0].lower() if tokens else ""
                        if head in ("ospf", "bgp", "rip", "isis") and len(tokens) >= 2:
                            undo_lines.append(f"undo {head} {tokens[1]}")
                        elif head == "vsi" and len(tokens) >= 2:
                            undo_lines.append(f"undo vsi {tokens[1]}")
                        elif head == "interface" and len(tokens) >= 2:
                            if_name = tokens[1]
                            if any(if_name.lower().startswith(p) for p in ("loopback", "vlan", "tunnel", "nve", "vsi-interface")) or "." in if_name:
                                undo_lines.append(f"undo interface {if_name}")
                continue

            if is_view_entry:
                view_stack.append(stripped)
                undo_lines.append(line)
                continue

            # 叶子配置指令转换为 undo
            prefix = " " * indent
            if stripped.startswith("undo "):
                # 例如 undo shutdown -> shutdown, undo portswitch -> portswitch
                reversed_cmd = stripped[5:].strip()
                undo_lines.append(f"{prefix}{reversed_cmd}")
            elif stripped.startswith("sysname "):
                undo_lines.append(f"{prefix}undo sysname")
            elif stripped.startswith("header "):
                hdr_parts = stripped.split()
                if len(hdr_parts) >= 2:
                    undo_lines.append(f"{prefix}undo header {hdr_parts[1]}")
            else:
                undo_lines.append(f"{prefix}undo {stripped}")

        undo_lines.append("return")
        return undo_lines

