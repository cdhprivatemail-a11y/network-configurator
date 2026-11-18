# -*- coding: utf-8 -*-
"""
配置备份与对比管理模块
负责网络设备配置文件的备份存档、历史版本查询、内容查看以及配置差异对比 (Diff)。
"""

import os
import glob
import difflib
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

logger = logging.getLogger("BackupManager")


class BackupManager:
    """
    设备配置备份及比对管理器
    """

    def __init__(self, backup_dir: str):
        """
        初始化备份管理器

        :param backup_dir: 备份文件存放目录
        """
        self.backup_dir = os.path.abspath(backup_dir)
        os.makedirs(self.backup_dir, exist_ok=True)

    def save_backup(self, device_name: str, config_content: str) -> str:
        """
        保存设备配置备份文件

        :param device_name: 设备名称
        :param config_content: 配置文件正文
        :return: 保存后的备份文件绝对路径
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_device_name = "".join(c for c in device_name if c.isalnum() or c in ("-", "_"))
        filename = f"{safe_device_name}_{timestamp}.cfg"
        filepath = os.path.join(self.backup_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(config_content)

        logger.info(f"设备 {device_name} 配置已备份至: {filepath}")
        return filepath

    def list_backups(self, device_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        列出备份目录中的配置文件列表

        :param device_name: 可选，按设备名称进行过滤
        :return: 包含 filename, device, timestamp, size, filepath 的字典列表，按时间倒序排列
        """
        pattern = os.path.join(self.backup_dir, "*.cfg")
        files = glob.glob(pattern)
        results: List[Dict[str, Any]] = []

        for filepath in files:
            filename = os.path.basename(filepath)
            # 解析文件名: {device_name}_{YYYYMMDD_HHMMSS}.cfg
            name_part, _ = os.path.splitext(filename)
            parts = name_part.rsplit("_", 2)
            
            if len(parts) >= 3:
                # 兼容设备名本身包含下划线的情况: R1_Core_20261011_120000 -> device: R1_Core, date: 20261011, time: 120000
                dev = parts[0]
                ts_str = f"{parts[1]}_{parts[2]}"
            else:
                dev = parts[0]
                ts_str = parts[1] if len(parts) > 1 else ""

            # 过滤设备
            if device_name and dev.lower() != device_name.lower():
                continue

            file_stat = os.stat(filepath)
            formatted_time = ts_str
            try:
                dt = datetime.strptime(ts_str, "%Y%m%d_%H%M%S")
                formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                formatted_time = datetime.fromtimestamp(file_stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")

            results.append({
                "filename": filename,
                "device": dev,
                "timestamp": formatted_time,
                "size": file_stat.st_size,
                "filepath": filepath
            })

        # 按时间倒序排序
        results.sort(key=lambda x: x["timestamp"], reverse=True)
        return results

    def get_backup_content(self, filename: str) -> str:
        """
        读取指定备份文件的文本内容

        :param filename: 备份文件名
        :return: 配置文件内容文本
        :raises FileNotFoundError: 文件不存在
        """
        # 防止路径穿越攻击
        safe_filename = os.path.basename(filename)
        filepath = os.path.join(self.backup_dir, safe_filename)

        if not os.path.exists(filepath):
            raise FileNotFoundError(f"备份文件不存在: {safe_filename}")

        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()

    def delete_backup(self, filename: str) -> bool:
        """
        删除指定的备份文件

        :param filename: 备份文件名
        :return: 是否删除成功
        """
        safe_filename = os.path.basename(filename)
        filepath = os.path.join(self.backup_dir, safe_filename)

        if not os.path.exists(filepath):
            return False

        try:
            os.remove(filepath)
            logger.info(f"已删除备份文件: {safe_filename}")
            return True
        except Exception as e:
            logger.error(f"删除备份文件失败 {safe_filename}: {e}")
            raise e

    def compare_configs(self, config1: str, config2: str) -> List[str]:
        """
        对比两份配置的差异 (Unified Diff)

        :param config1: 原配置文本
        :param config2: 新配置文本
        :return: 差异行列表
        """
        lines1 = config1.splitlines(keepends=True)
        lines2 = config2.splitlines(keepends=True)

        diff = difflib.unified_diff(
            lines1,
            lines2,
            fromfile="Version 1",
            tofile="Version 2",
            lineterm=""
        )

        return [line.rstrip("\r\n") for line in diff]
