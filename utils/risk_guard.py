# -*- coding: utf-8 -*-
"""
高危 CLI 命令防呆防火墙引擎 (CLIRiskGuardrail - Sprint 4)
在批量下发命令或特性编排前进行静态语义预审，精准拦截可能导致设备宕机、管理失联或全网断网的高危指令。
支持华为 VRP (eNSP) 与华三 Comware V7 (HCL) 双栈语法。
"""

import re
from typing import Dict, List, Any, Union


class CLIRiskGuardrail:
    """高危命令防呆预审与拦截引擎"""

    RISK_RULES = [
        {
            "id": "RISK-01",
            "pattern": r"^\s*(reboot|reload|schedule\s+reboot)\b",
            "severity": "CRITICAL",
            "severity_label": "致命风险 (CRITICAL)",
            "title": "设备重启指令",
            "reason": "触发整机重启会导致设备在数分钟内完全中断转发业务，生产环境严禁未经审批批量重启。",
        },
        {
            "id": "RISK-02",
            "pattern": r"^\s*(reset\s+saved-configuration|delete\s+/unreserved|format\s+flash:|erase\s+startup-config)\b",
            "severity": "CRITICAL",
            "severity_label": "致命风险 (CRITICAL)",
            "title": "擦除启动配置或格式化存储",
            "reason": "擦除下次启动配置文件或格式化 Flash 会导致设备重启后丢失全部业务配置并恢复出厂状态。",
        },
        {
            "id": "RISK-03",
            "pattern": r"^\s*undo\s+(ospf|bgp|isis|rip)\b(\s+\d+)?\s*$",
            "severity": "CRITICAL",
            "severity_label": "致命风险 (CRITICAL)",
            "title": "整进程销毁核心动态路由协议",
            "reason": "直接删除 OSPF/BGP/IS-IS 路由进程会导致全网邻居瞬间震荡中断、核心路由表清空。",
        },
        {
            "id": "RISK-04",
            "pattern": r"^\s*undo\s+vlan\s+(all|batch|1\b|1\s+to\s+4094)",
            "severity": "CRITICAL",
            "severity_label": "致命风险 (CRITICAL)",
            "title": "批量销毁全局或默认业务 VLAN",
            "reason": "批量删除全局 VLAN 会导致所有下联接入端口及对应 Vlanif 三层网关立即失效。",
        },
        {
            "id": "RISK-05",
            "pattern": r"^\s*undo\s+(stelnet\s+server\s+enable|ssh\s+server\s+enable|telnet\s+server\s+enable)\b",
            "severity": "HIGH",
            "severity_label": "高危风险 (HIGH)",
            "title": "关闭远程管理服务通道",
            "reason": "关闭 SSH/Telnet 服务可能导致当前自动化管理会话断开且无法再次远程登录。",
        },
        {
            "id": "RISK-06",
            "pattern": r"^\s*shutdown\s*$",
            "severity": "HIGH",
            "severity_label": "高危风险 (HIGH)",
            "title": "关闭物理或逻辑接口 (shutdown)",
            "reason": "若关闭的是上联口或带内管理口 (Vlanif/LoopBack)，将导致目标设备永久脱离网管控制。",
        },
        {
            "id": "RISK-07",
            "pattern": r"^\s*undo\s+ip\s+address\b",
            "severity": "HIGH",
            "severity_label": "高危风险 (HIGH)",
            "title": "清除接口 IPv4 地址",
            "reason": "清除三层接口 IP 地址可能导致管理连接立即中断或三层互联邻居 Down。",
        },
        {
            "id": "RISK-08",
            "pattern": r"^\s*(undo\s+stp\s+enable|stp\s+disable)\b",
            "severity": "HIGH",
            "severity_label": "高危风险 (HIGH)",
            "title": "全局关闭生成树防环协议 (STP)",
            "reason": "在存在物理冗余链路的二层交换网络中关闭 STP 极易引发全网广播风暴。",
        },
    ]

    def inspect_commands(self, commands_input: Union[str, List[str]]) -> Dict[str, Any]:
        """
        对输入的命令列表或脚本字符串进行高危规则扫描
        """
        if isinstance(commands_input, str):
            lines = commands_input.splitlines()
        elif isinstance(commands_input, list):
            lines = []
            for item in commands_input:
                lines.extend(str(item).splitlines())
        else:
            lines = []

        findings: List[Dict[str, Any]] = []
        has_critical = False
        has_high = False
        current_context = "global"

        for idx, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue

            lower_line = line.lower()
            if lower_line.startswith("interface "):
                current_context = line
            elif lower_line in ("quit", "return", "system-view"):
                current_context = "global"

            for rule in self.RISK_RULES:
                if re.search(rule["pattern"], lower_line, re.IGNORECASE):
                    if rule["severity"] == "CRITICAL":
                        has_critical = True
                    else:
                        has_high = True
                    findings.append({
                        "line_no": idx,
                        "command": line,
                        "context": current_context,
                        "rule_id": rule["id"],
                        "severity": rule["severity"],
                        "severity_label": rule["severity_label"],
                        "title": rule["title"],
                        "reason": rule["reason"],
                    })
                    break

        if has_critical:
            risk_level = "critical"
        elif has_high:
            risk_level = "high"
        else:
            risk_level = "safe"

        return {
            "success": True,
            "passed": len(findings) == 0,
            "risk_level": risk_level,
            "total_lines_checked": len(lines),
            "finding_count": len(findings),
            "findings": findings,
        }
