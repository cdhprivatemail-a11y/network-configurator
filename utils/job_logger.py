# -*- coding: utf-8 -*-
"""
企业级运维变更任务流水与操作审计日志中心 (Sprint 3)
基于线程安全 SQLite 持久化记录每一次批量下发、特性推送、拓扑部署、配置备份与合规巡检流水。
"""

import json
import os
import sqlite3
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional
from contextlib import contextmanager


class JobAuditLogger:
    """线程安全的 SQLite 运维任务审计日志管理器"""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    @contextmanager
    def _get_conn(self):
        """获取 SQLite 连接并确保在上下文退出时显式关闭，杜绝文件句柄泄漏与 WAL 锁锁死"""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._lock:
            os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
            with self._get_conn() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS job_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        job_type TEXT NOT NULL,
                        target_devices TEXT NOT NULL,
                        status TEXT NOT NULL,
                        summary TEXT NOT NULL,
                        cli_config TEXT DEFAULT '',
                        details_json TEXT DEFAULT '[]'
                    )
                    """
                )
                cur = conn.execute("SELECT COUNT(*) AS cnt FROM job_history")
                row = cur.fetchone()
                if row and row["cnt"] == 0:
                    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    conn.execute(
                        """
                        INSERT INTO job_history (timestamp, job_type, target_devices, status, summary, cli_config, details_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            now_str,
                            "系统基线初始化",
                            "R1, SW1, H3C-R1",
                            "success",
                            "v2.0 全栈网络配置与合规审计引擎就绪 (8域·100项特性)",
                            "system-view\n# 平台审计中心初始化完成\nreturn",
                            json.dumps(
                                [
                                    {
                                        "device": "System",
                                        "success": True,
                                        "output": "SQLite Audit DB & Credential Vault initialized successfully.",
                                    }
                                ],
                                ensure_ascii=False,
                            ),
                        ),
                    )

    def log_job(
        self,
        job_type: str,
        target_devices: List[str] | str,
        status: str,
        summary: str,
        cli_config: str = "",
        details: Optional[List[Dict[str, Any]]] = None,
    ) -> int:
        """
        写入一条新的运维变更或巡检审计记录
        :param status: 'success' | 'warning' | 'failed'
        :return: 新增记录的 job_id
        """
        if isinstance(target_devices, list):
            targets_str = ", ".join(str(x) for x in target_devices)
        else:
            targets_str = str(target_devices)

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        details_str = json.dumps(details or [], ensure_ascii=False)

        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute(
                    """
                    INSERT INTO job_history (timestamp, job_type, target_devices, status, summary, cli_config, details_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (now_str, job_type, targets_str, status, summary, cli_config or "", details_str),
                )
                return int(cur.lastrowid or 0)

    def list_jobs(self, limit: int = 30) -> List[Dict[str, Any]]:
        """获取最近的运维审计流水列表（不含大体积 details_json 以加快列表响应）"""
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute(
                    """
                    SELECT id, timestamp, job_type, target_devices, status, summary, cli_config
                    FROM job_history
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
                return [dict(r) for r in cur.fetchall()]

    def get_job(self, job_id: int) -> Optional[Dict[str, Any]]:
        """获取单条历史任务的完整详情与各设备终端回显"""
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute(
                    "SELECT * FROM job_history WHERE id = ?",
                    (job_id,),
                )
                row = cur.fetchone()
                if not row:
                    return None
                item = dict(row)
                try:
                    item["details"] = json.loads(item.get("details_json") or "[]")
                except Exception:
                    item["details"] = []
                return item

    def clear_jobs(self) -> bool:
        """清空历史任务记录"""
        with self._lock:
            with self._get_conn() as conn:
                conn.execute("DELETE FROM job_history")
                return True
