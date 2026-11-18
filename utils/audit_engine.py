# -*- coding: utf-8 -*-
"""
网络设备结构化运行态巡检与等保 2.0 三级合规基线审计引擎 (Sprint 2)
核心能力：
1. 等保 2.0 三级 / 企业黄金配置基线 (Golden Config) 10 大维度自动扫描、合规打分 (0-100) 与一键修复 CLI 生成
2. 华为 VRP (eNSP) 与华三 Comware V7 (HCL) 运行态协议表结构化解析 (Interface / OSPF / BGP / VRRP / CPU & Memory)
"""

import re
from typing import Dict, List, Any


class AuditAndInspectorEngine:
    """配置合规性审计与运行态结构化巡检引擎"""

    @staticmethod
    def detect_vendor(config_text: str, hint_vendor: str = "") -> str:
        """根据配置文本特征或提示自动识别厂商 ('huawei' 或 'h3c')"""
        hint = (hint_vendor or "").lower()
        if "huawei" in hint:
            return "huawei"
        if "h3c" in hint or "hp" in hint or "comware" in hint:
            return "h3c"
        text_lower = (config_text or "").lower()
        if any(k in text_lower for k in ("stelnet server", "user-interface vty", "vlanif", "eth-trunk", "portswitch")):
            return "huawei"
        return "h3c"

    def audit_config(self, config_text: str, vendor: str = "auto") -> Dict[str, Any]:
        """
        对设备配置文本执行等保 2.0 三级与企业安全基线 10 项黄金规则审计
        返回：总分 (0-100)、评级、各规则明细及一键修复 CLI 脚本
        """
        resolved_vendor = self.detect_vendor(config_text, vendor)
        is_huawei = resolved_vendor == "huawei"
        text = config_text or ""
        text_lower = text.lower()

        rules_spec = [
            {
                "id": "SEC-01",
                "category": "身份鉴别与加密传输",
                "title": "启用 SSH 安全加密登录并限制明文协议",
                "severity": "高危",
                "weight": 15,
                "passed": bool(
                    re.search(r"\b(stelnet\s+server\s+enable|ssh\s+server\s+enable)\b", text_lower)
                    and re.search(r"\bprotocol\s+inbound\s+(ssh|all)\b", text_lower)
                ),
                "desc": "等保三级要求远程管理通道必须采用 SSH 加密协议，防止管理凭据在网络中被嗅探截获。",
                "remediation_huawei": [
                    "stelnet server enable",
                    "user-interface vty 0 4",
                    " authentication-mode aaa",
                    " protocol inbound ssh",
                    "quit",
                ],
                "remediation_h3c": [
                    "ssh server enable",
                    "line vty 0 4",
                    " authentication-mode scheme",
                    " protocol inbound ssh",
                    "quit",
                ],
            },
            {
                "id": "SEC-02",
                "category": "访问控制",
                "title": "VTY 远程终端配置 ACL 源 IP 白名单限制",
                "severity": "高危",
                "weight": 15,
                "passed": bool(re.search(r"\bacl\s+\d+\s+inbound\b", text_lower)),
                "desc": "限制仅允许运维堡垒机或指定网管子网访问设备 VTY 终端，阻断非授权主机暴力破解。",
                "remediation_huawei": [
                    "acl number 2000",
                    " rule 5 permit source 192.168.100.0 0.0.0.255",
                    " rule 100 deny",
                    "quit",
                    "user-interface vty 0 4",
                    " acl 2000 inbound",
                    "quit",
                ],
                "remediation_h3c": [
                    "acl basic 2000",
                    " rule 5 permit source 192.168.100.0 0.0.0.255",
                    " rule 100 deny",
                    "quit",
                    "line vty 0 4",
                    " acl 2000 inbound",
                    "quit",
                ],
            },
            {
                "id": "SEC-03",
                "category": "访问控制",
                "title": "VTY 终端会话空闲自动超时断开 (idle-timeout)",
                "severity": "中危",
                "weight": 10,
                "passed": bool(re.search(r"\bidle-timeout\s+[1-9]\d*", text_lower)),
                "desc": "防止管理员离开座位后终端长连接未关闭导致的越权操作风险。",
                "remediation_huawei": [
                    "user-interface vty 0 4",
                    " idle-timeout 5 0",
                    "quit",
                ],
                "remediation_h3c": [
                    "line vty 0 4",
                    " idle-timeout 5 0",
                    "quit",
                ],
            },
            {
                "id": "SEC-04",
                "category": "身份鉴别",
                "title": "AAA 本地账号采用密文存储与权限分级",
                "severity": "高危",
                "weight": 10,
                "passed": bool(
                    re.search(r"\blocal-user\s+\S+", text_lower)
                    and re.search(r"\bpassword\s+(cipher|irreversible-cipher|hash)\b", text_lower)
                ),
                "desc": "本地管理员口令必须采用不可逆密文或 Cipher 哈希存储，严禁明文 Simple 口令。",
                "remediation_huawei": [
                    "aaa",
                    " local-user admin password irreversible-cipher Admin@Sec123",
                    " local-user admin privilege level 15",
                    " local-user admin service-type ssh terminal",
                    "quit",
                ],
                "remediation_h3c": [
                    "local-user admin class manage",
                    " password cipher Admin@Sec123",
                    " service-type ssh terminal",
                    " authorization-attribute user-role level-15",
                    "quit",
                ],
            },
            {
                "id": "SEC-05",
                "category": "安全审计",
                "title": "配置 Syslog 远端日志审计服务器 (Loghost)",
                "severity": "高危",
                "weight": 10,
                "passed": bool(re.search(r"\binfo-center\s+loghost\s+\d+\.\d+\.\d+\.\d+", text_lower)),
                "desc": "等保三级要求安全事件与操作日志必须实时外发至独立日志审计中心留存不少于 180 天。",
                "remediation_huawei": [
                    "info-center enable",
                    "info-center loghost 192.168.100.200",
                ],
                "remediation_h3c": [
                    "info-center enable",
                    "info-center loghost 192.168.100.200",
                ],
            },
            {
                "id": "SEC-06",
                "category": "安全审计",
                "title": "配置 NTP 权威时钟同步源",
                "severity": "中危",
                "weight": 10,
                "passed": bool(re.search(r"\bntp-service\s+unicast-(server|peer)\s+\d+\.\d+\.\d+\.\d+", text_lower)),
                "desc": "确保全网设备日志时间戳高度一致，满足故障溯源与安全取证要求。",
                "remediation_huawei": [
                    "ntp-service unicast-server 192.168.100.100",
                ],
                "remediation_h3c": [
                    "ntp-service enable",
                    "ntp-service unicast-server 192.168.100.100",
                ],
            },
            {
                "id": "SEC-07",
                "category": "安全审计与网管",
                "title": "SNMP 网管开启且规避默认 public/private 弱口令",
                "severity": "高危",
                "weight": 10,
                "passed": bool(
                    re.search(r"\bsnmp-agent\b", text_lower)
                    and not re.search(r"\bsnmp-agent\s+community\s+(read|write)\s+(cipher\s+)?(public|private)\b", text_lower)
                ),
                "desc": "启用 SNMP 状态监控并严禁使用默认的 public / private 弱团体名。",
                "remediation_huawei": [
                    "snmp-agent",
                    "snmp-agent sys-info version v2c v3",
                    "snmp-agent community read cipher Snmp@RO2026",
                ],
                "remediation_h3c": [
                    "snmp-agent",
                    "snmp-agent sys-info version v2c v3",
                    "snmp-agent community read Snmp@RO2026",
                ],
            },
            {
                "id": "SEC-08",
                "category": "入侵防范与抗攻击",
                "title": "启用控制面保护或接入防欺骗机制 (CPCAR / DHCP Snooping / DAI)",
                "severity": "中危",
                "weight": 10,
                "passed": bool(
                    re.search(
                        r"\b(cpu-defend|control-plane|dhcp\s+snooping|arp\s+anti-attack|arp\s+detection|ip\s+source\s+check|ip\s+verify\s+source)\b",
                        text_lower,
                    )
                ),
                "desc": "抵御针对控制面的协议报文洪泛攻击及内网 DHCP/ARP 中间人仿冒。",
                "remediation_huawei": [
                    "cpu-defend policy SEC_COPP",
                    " car packet-type arp cir 64",
                    " car packet-type icmp cir 32",
                    "quit",
                    "cpu-defend-policy SEC_COPP global",
                ],
                "remediation_h3c": [
                    "dhcp snooping enable",
                    "arp rate-limit enable",
                ],
            },
            {
                "id": "SEC-09",
                "category": "高可用与二层防环",
                "title": "启用生成树防环协议 (STP/RSTP/MSTP) 或环网保护",
                "severity": "中危",
                "weight": 5,
                "passed": bool(re.search(r"\b(stp\s+(global\s+)?enable|erps\s+ring|rrpp\s+enable)\b", text_lower)),
                "desc": "防止二层物理环路引发全网广播风暴导致业务瘫痪。",
                "remediation_huawei": [
                    "stp mode rstp",
                    "stp enable",
                ],
                "remediation_h3c": [
                    "stp mode rstp",
                    "stp global enable",
                ],
            },
            {
                "id": "SEC-10",
                "category": "安全警示",
                "title": "配置登录法律合规警示横幅 (Header Login Banner)",
                "severity": "低危",
                "weight": 5,
                "passed": bool(re.search(r"\bheader\s+(login|shell)\s+information\b", text_lower)),
                "desc": "在用户登录前展示授权访问声明与违规追责警告。",
                "remediation_huawei": [
                    "header login information %WARNING: Authorized Access Only! All activities are monitored.%",
                ],
                "remediation_h3c": [
                    "header login information %WARNING: Authorized Access Only! All activities are monitored.%",
                ],
            },
        ]

        total_score = 0
        passed_count = 0
        failed_count = 0
        remediation_lines: List[str] = ["system-view"]
        evaluated_rules: List[Dict[str, Any]] = []

        for r in rules_spec:
            rem_cmds = r["remediation_huawei"] if is_huawei else r["remediation_h3c"]
            if r["passed"]:
                total_score += r["weight"]
                passed_count += 1
            else:
                failed_count += 1
                remediation_lines.append(f"# [修复 {r['id']}] {r['title']}")
                remediation_lines.extend(rem_cmds)

            evaluated_rules.append({
                "id": r["id"],
                "category": r["category"],
                "title": r["title"],
                "severity": r["severity"],
                "weight": r["weight"],
                "passed": r["passed"],
                "desc": r["desc"],
                "remediation_cli": "\n".join(rem_cmds),
            })

        remediation_lines.append("return")

        if total_score >= 90:
            grade = "A+ (卓越合规)"
            grade_color = "success"
        elif total_score >= 75:
            grade = "B (良好)"
            grade_color = "primary"
        elif total_score >= 60:
            grade = "C (存在风险)"
            grade_color = "warning"
        else:
            grade = "D (高危不合规)"
            grade_color = "danger"

        return {
            "success": True,
            "vendor": resolved_vendor,
            "score": total_score,
            "grade": grade,
            "grade_color": grade_color,
            "passed_count": passed_count,
            "failed_count": failed_count,
            "total_rules": len(rules_spec),
            "rules": evaluated_rules,
            "combined_remediation_cli": "\n".join(remediation_lines) if failed_count > 0 else "",
        }

    def parse_operational_state(self, raw_outputs: Dict[str, str], config_text: str = "") -> Dict[str, Any]:
        """
        将华为 VRP / 华三 Comware 的巡检回显或配置文本解析为结构化状态表：
        - interfaces: [{interface, ip, physical, protocol, source}]
        - ospf_peers: [{process_or_area, interface, neighbor_id, state}]
        - bgp_peers:  [{peer_ip, as_number, state}]
        - vrrp_groups:[{interface, vrid, role, virtual_ip}]
        """
        interfaces: List[Dict[str, str]] = []
        ospf_peers: List[Dict[str, str]] = []
        bgp_peers: List[Dict[str, str]] = []
        vrrp_groups: List[Dict[str, str]] = []

        # 1. 解析 display ip interface brief
        if_brief = raw_outputs.get("ip_interface_brief", "")
        if if_brief:
            for line in if_brief.splitlines():
                s = line.strip()
                m = re.match(
                    r"^([A-Za-z0-9/\-\.]+)\s+(\d+\.\d+\.\d+\.\d+(?:/\d+)?|unassigned)\s+(\*?(?:up|down|administratively down))\s+(\*?(?:up|down)(?:\(s\))?)",
                    s,
                    re.IGNORECASE,
                )
                if m:
                    interfaces.append({
                        "interface": m.group(1),
                        "ip": m.group(2),
                        "physical": m.group(3).upper(),
                        "protocol": m.group(4).upper(),
                    })

        # 2. 解析 display ospf peer brief
        ospf_raw = raw_outputs.get("ospf_peer_brief", "")
        if ospf_raw:
            for line in ospf_raw.splitlines():
                s = line.strip()
                m = re.match(
                    r"^(\S+)\s+([A-Za-z0-9/\-\.]+)\s+(\d+\.\d+\.\d+\.\d+)\s+(Full|2-Way|Init|Down|ExStart|Exchange|Loading)\S*",
                    s,
                    re.IGNORECASE,
                )
                if m:
                    ospf_peers.append({
                        "area": m.group(1),
                        "interface": m.group(2),
                        "neighbor_id": m.group(3),
                        "state": m.group(4).upper(),
                    })

        # 3. 解析 display bgp peer
        bgp_raw = raw_outputs.get("bgp_peer", "")
        if bgp_raw:
            for line in bgp_raw.splitlines():
                s = line.strip()
                m = re.match(
                    r"^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\d+)\s+\d+\s+\d+\s+\S+\s+\S+\s+(Established|Active|Idle|Connect|OpenSent|OpenConfirm)",
                    s,
                    re.IGNORECASE,
                )
                if m:
                    bgp_peers.append({
                        "peer_ip": m.group(1),
                        "as_number": m.group(2),
                        "state": m.group(3),
                    })

        # 4. 解析 display vrrp brief
        vrrp_raw = raw_outputs.get("vrrp_brief", "")
        if vrrp_raw:
            for line in vrrp_raw.splitlines():
                s = line.strip()
                m = re.match(
                    r"^([A-Za-z0-9/\-\.]+)\s+(\d+)\s+(Master|Backup|Initialize)\s+(\d+)\s+\S+\s+\S+\s+(\d+\.\d+\.\d+\.\d+)",
                    s,
                    re.IGNORECASE,
                )
                if m:
                    vrrp_groups.append({
                        "interface": m.group(1),
                        "vrid": m.group(2),
                        "role": m.group(3),
                        "priority": m.group(4),
                        "virtual_ip": m.group(5),
                    })

        # 若设备离线或仅通过配置文件巡检，从配置文件中智能提取结构化接口/OSPF/BGP/VRRP 摘要
        if config_text and not interfaces:
            cur_if = None
            for line in config_text.splitlines():
                s = line.strip()
                if s.startswith("interface "):
                    cur_if = s.split()[1]
                elif cur_if and s.startswith("ip address "):
                    parts = s.split()
                    if len(parts) >= 4:
                        interfaces.append({
                            "interface": cur_if,
                            "ip": f"{parts[2]}/{parts[3]}",
                            "physical": "CONFIGURED",
                            "protocol": "UP (Config)",
                        })
                elif cur_if and "vrrp vrid " in s and "virtual-ip " in s:
                    m_v = re.search(r"vrrp\s+vrid\s+(\d+)\s+virtual-ip\s+(\d+\.\d+\.\d+\.\d+)", s)
                    if m_v:
                        vrrp_groups.append({
                            "interface": cur_if,
                            "vrid": m_v.group(1),
                            "role": "Configured",
                            "priority": "100+",
                            "virtual_ip": m_v.group(2),
                        })
                elif s.startswith("network ") and len(s.split()) >= 3:
                    parts = s.split()
                    ospf_peers.append({
                        "area": "Area 0",
                        "interface": f"Net {parts[1]}",
                        "neighbor_id": parts[2],
                        "state": "CONFIGURED",
                    })
                elif s.startswith("peer ") and "as-number " in s:
                    parts = s.split()
                    if len(parts) >= 4:
                        bgp_peers.append({
                            "peer_ip": parts[1],
                            "as_number": parts[3],
                            "state": "Configured",
                        })

        return {
            "interfaces": interfaces,
            "ospf_peers": ospf_peers,
            "bgp_peers": bgp_peers,
            "vrrp_groups": vrrp_groups,
        }
