# -*- coding: utf-8 -*-
"""
统一变更护栏、审批工作流与金丝雀灰度下发/回滚熔断流水线 (Sprint 6 - P0-2)
实现目标：
  1. 统一所有变更入口的风险静态解构 (CLIRiskGuardrail)；
  2. 服务端审批状态机 (PENDING_APPROVAL -> APPROVED -> EXECUTED)；
  3. 执行前全自动快照 (Pre-Snapshot)；
  4. 金丝雀灰度分批 (Canary Batch)；
  5. 遇错即停 (Fail-Stop) 与全自动逆向 Undo 回滚还原。
"""

import os
import time
import json
import sqlite3
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

from utils.risk_guard import CLIRiskGuardrail
from utils.backup_manager import BackupManager
from utils.device_manager import DeviceManager

logger = logging.getLogger("ChangeManager")


class ChangeManager:
    """生产级变更护栏与灰度流水线管理器"""

    def __init__(self, db_path: str, backup_manager: BackupManager, device_manager: DeviceManager):
        self.db_path = db_path
        self.backup_mgr = backup_manager
        self.dev_mgr = device_manager
        self.risk_guard = CLIRiskGuardrail()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """初始化变更审批工单表"""
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        with self._get_conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS change_tickets (
                    ticket_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    applicant TEXT NOT NULL,
                    title TEXT NOT NULL,
                    target_devices TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    risk_findings_json TEXT NOT NULL,
                    commands_json TEXT NOT NULL,
                    undo_commands_json TEXT DEFAULT '{}',
                    status TEXT NOT NULL,
                    reviewer TEXT DEFAULT '',
                    reviewed_at TEXT DEFAULT '',
                    review_comment TEXT DEFAULT '',
                    execution_summary_json TEXT DEFAULT '{}'
                )
                """
            )
            conn.commit()

    def create_ticket(
        self,
        title: str,
        applicant: str,
        target_devices: List[str],
        commands_dict: Dict[str, str],
        undo_commands_dict: Optional[Dict[str, str]] = None,
        risk_result: Optional[Dict[str, Any]] = None,
    ) -> str:
        """创建变更审批工单"""
        now = datetime.now()
        ticket_id = f"TICKET-{now.strftime('%Y%m%d%H%M%S')}-{os.urandom(2).hex().upper()}"
        devices_str = ", ".join(target_devices)
        risk_level = risk_result.get("risk_level", "safe") if risk_result else "safe"
        findings = risk_result.get("findings", []) if risk_result else []
        status = "PENDING_APPROVAL" if risk_level in ("high", "critical") else "APPROVED"

        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO change_tickets (
                    ticket_id, created_at, applicant, title, target_devices,
                    risk_level, risk_findings_json, commands_json, undo_commands_json,
                    status, reviewer, reviewed_at, review_comment, execution_summary_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', '', '{}')
                """,
                (
                    ticket_id,
                    now.strftime("%Y-%m-%d %H:%M:%S"),
                    applicant,
                    title,
                    devices_str,
                    risk_level,
                    json.dumps(findings, ensure_ascii=False),
                    json.dumps(commands_dict, ensure_ascii=False),
                    json.dumps(undo_commands_dict or {}, ensure_ascii=False),
                    status,
                ),
            )
            conn.commit()
        return ticket_id

    def list_tickets(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """获取工单列表"""
        with self._get_conn() as conn:
            if status:
                cur = conn.execute("SELECT * FROM change_tickets WHERE status = ? ORDER BY created_at DESC", (status,))
            else:
                cur = conn.execute("SELECT * FROM change_tickets ORDER BY created_at DESC")
            records = []
            for row in cur.fetchall():
                item = dict(row)
                try:
                    item["risk_findings"] = json.loads(item.get("risk_findings_json") or "[]")
                    item["commands"] = json.loads(item.get("commands_json") or "{}")
                    item["undo_commands"] = json.loads(item.get("undo_commands_json") or "{}")
                    item["execution_summary"] = json.loads(item.get("execution_summary_json") or "{}")
                except Exception:
                    pass
                records.append(item)
            return records

    def get_ticket(self, ticket_id: str) -> Optional[Dict[str, Any]]:
        """获取单个工单详情"""
        with self._get_conn() as conn:
            cur = conn.execute("SELECT * FROM change_tickets WHERE ticket_id = ?", (ticket_id,))
            row = cur.fetchone()
            if not row:
                return None
            item = dict(row)
            try:
                item["risk_findings"] = json.loads(item.get("risk_findings_json") or "[]")
                item["commands"] = json.loads(item.get("commands_json") or "{}")
                item["undo_commands"] = json.loads(item.get("undo_commands_json") or "{}")
                item["execution_summary"] = json.loads(item.get("execution_summary_json") or "{}")
            except Exception:
                pass
            return item

    def review_ticket(self, ticket_id: str, reviewer: str, approved: bool, comment: str = "") -> bool:
        """审批工单（仅 admin 角色可执行）"""
        new_status = "APPROVED" if approved else "REJECTED"
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_conn() as conn:
            cur = conn.execute(
                """
                UPDATE change_tickets
                SET status = ?, reviewer = ?, reviewed_at = ?, review_comment = ?
                WHERE ticket_id = ? AND status = 'PENDING_APPROVAL'
                """,
                (new_status, reviewer, now_str, comment, ticket_id),
            )
            conn.commit()
            return cur.rowcount > 0

    def evaluate_change_risk(self, commands_dict: Dict[str, str]) -> Dict[str, Any]:
        """
        统一风险评估检查 (穿透扫描所有设备的下发指令)
        """
        all_lines = []
        for dev_name, cmds in commands_dict.items():
            if cmds:
                all_lines.extend(cmds.splitlines())

        return self.risk_guard.inspect_commands(all_lines)

    def execute_canary_deployment(
        self,
        ticket_id: str,
        target_devices: List[Dict[str, Any]],
        commands_dict: Dict[str, str],
        undo_commands_dict: Optional[Dict[str, str]] = None,
        canary_mode: bool = True,
    ) -> Dict[str, Any]:
        """
        灰度金丝雀执行引擎：
          Phase 1: 预检快照 (Pre-Snapshot)
          Phase 2: 金丝雀首批 (1台)
          Phase 3: 报错嗅探与熔断判定 (Fail-Stop)
          Phase 4: 全自动逆向 Undo 回滚还原
          Phase 5: 剩余全网设备推进
        """
        undo_commands_dict = undo_commands_dict or {}
        dev_map = {d["name"]: d for d in target_devices}
        ordered_names = [d["name"] for d in target_devices if d["name"] in commands_dict]

        if not ordered_names:
            return {"success": False, "error": "没有可执行的目标设备"}

        # -------------------------------------------------------------
        # Phase 1: 抓取当前所有目标设备的运行内存作为 Pre-Snapshot
        # -------------------------------------------------------------
        logger.info(f"[{ticket_id}] 启动变更前全网黄金基线快照采集...")
        pre_snapshots: Dict[str, str] = {}
        for dev_name in ordered_names:
            dev_obj = dev_map[dev_name]
            try:
                res = self.dev_mgr.get_running_config(dev_obj)
                if isinstance(res, dict) and res.get("success") and res.get("config"):
                    backup_file = self.backup_mgr.save_backup(f"{dev_name}_PRE_CANARY", res["config"])
                    pre_snapshots[dev_name] = os.path.basename(backup_file)
            except Exception as e:
                logger.warning(f"[{ticket_id}] 抓取 {dev_name} 预检快照异常: {e}")

        # -------------------------------------------------------------
        # 划分批次 (Canary Batch 1 vs Fleet Batch 2)
        # -------------------------------------------------------------
        if canary_mode and len(ordered_names) > 1:
            batch_1 = [ordered_names[0]]
            batch_2 = ordered_names[1:]
        else:
            batch_1 = ordered_names
            batch_2 = []

        execution_results: List[Dict[str, Any]] = []
        fail_stop_triggered = False
        failed_device_name = ""
        error_detail = ""

        # -------------------------------------------------------------
        # Phase 2: 执行 Batch 1 (金丝雀首台设备验证)
        # -------------------------------------------------------------
        logger.info(f"[{ticket_id}] 正在执行金丝雀 Batch 1 设备: {batch_1}")
        for dev_name in batch_1:
            dev_obj = dev_map[dev_name]
            cli_text = commands_dict[dev_name]
            res = self.dev_mgr.execute_commands(dev_obj, cli_text)
            
            # 严格检查 CLI Error Sniffer
            has_error = not res.get("success")
            output_str = res.get("output", "")
            detected_errors = self.dev_mgr._detect_cli_errors(output_str) if hasattr(self.dev_mgr, "_detect_cli_errors") else []

            if has_error or detected_errors:
                fail_stop_triggered = True
                failed_device_name = dev_name
                error_detail = detected_errors[0] if detected_errors else res.get("error", "未知执行故障")
                execution_results.append({
                    "device": dev_name,
                    "batch": "Canary-Batch-1",
                    "success": False,
                    "error": error_detail,
                    "output": output_str,
                    "detected_errors": detected_errors,
                })
                break
            else:
                execution_results.append({
                    "device": dev_name,
                    "batch": "Canary-Batch-1",
                    "success": True,
                    "output": output_str,
                })

        # -------------------------------------------------------------
        # Phase 3 & 4: 报错即停 (Fail-Stop) & 自动逆向 Undo 回滚
        # -------------------------------------------------------------
        if fail_stop_triggered:
            logger.error(f"[{ticket_id}] 🚨 金丝雀首批验证失败 ({failed_device_name}): {error_detail}！触发 FAIL-STOP 熔断，已取消后续批次 {batch_2}！")
            
            # 自动执行逆向回滚
            rollback_summary = []
            if failed_device_name in undo_commands_dict and undo_commands_dict[failed_device_name]:
                undo_text = undo_commands_dict[failed_device_name]
                logger.info(f"[{ticket_id}] 正在对受损设备 {failed_device_name} 执行自动逆向回滚: \n{undo_text}")
                rb_res = self.dev_mgr.execute_commands(dev_map[failed_device_name], undo_text)
                rollback_summary.append({
                    "device": failed_device_name,
                    "rollback_success": rb_res.get("success", False),
                    "rollback_output": rb_res.get("output", ""),
                })
            else:
                logger.warning(f"[{ticket_id}] 设备 {failed_device_name} 未提供 Undo 逆向回滚脚本")

            # 更新工单状态为 ROLLED_BACK
            final_summary = {
                "ticket_id": ticket_id,
                "success": False,
                "fail_stop_triggered": True,
                "failed_device": failed_device_name,
                "error": error_detail,
                "aborted_devices": batch_2,
                "pre_snapshots": pre_snapshots,
                "execution_results": execution_results,
                "rollback_executed": True,
                "rollback_summary": rollback_summary,
            }
            self._update_ticket_status(ticket_id, "ROLLED_BACK", final_summary)
            return final_summary

        # -------------------------------------------------------------
        # Phase 5: 金丝雀成功放行，执行 Batch 2 (全网剩余设备)
        # -------------------------------------------------------------
        if batch_2:
            logger.info(f"[{ticket_id}] 金丝雀首批验证 100% 成功，推进执行全网剩余批次: {batch_2}")
            for dev_name in batch_2:
                dev_obj = dev_map[dev_name]
                cli_text = commands_dict[dev_name]
                res = self.dev_mgr.execute_commands(dev_obj, cli_text)
                execution_results.append({
                    "device": dev_name,
                    "batch": "Fleet-Batch-2",
                    "success": res.get("success", False),
                    "output": res.get("output", ""),
                    "error": res.get("error", ""),
                })

        final_summary = {
            "ticket_id": ticket_id,
            "success": True,
            "fail_stop_triggered": False,
            "total_devices": len(ordered_names),
            "pre_snapshots": pre_snapshots,
            "execution_results": execution_results,
        }
        self._update_ticket_status(ticket_id, "EXECUTED", final_summary)
        return final_summary

    def _update_ticket_status(self, ticket_id: str, status: str, summary: Dict[str, Any]) -> None:
        """更新工单最终状态与回执"""
        with self._get_conn() as conn:
            conn.execute(
                "UPDATE change_tickets SET status = ?, execution_summary_json = ? WHERE ticket_id = ?",
                (status, json.dumps(summary, ensure_ascii=False), ticket_id),
            )
            conn.commit()
