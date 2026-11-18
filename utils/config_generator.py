# -*- coding: utf-8 -*-
"""
配置模板生成模块
基于 Jinja2 模板引擎实现网络配置的动态渲染，支持 YAML 与 Excel 变量源解析。
"""

import os
import glob
import logging
from typing import List, Dict, Any, Union
import yaml
from jinja2 import FileSystemLoader, TemplateNotFound, UndefinedError
from jinja2.sandbox import SandboxedEnvironment, SecurityError
import openpyxl

logger = logging.getLogger("ConfigGenerator")


class ConfigGenerator:
    """
    配置模板生成与变量渲染器 (强化安全沙箱与防目录遍历)
    """

    def __init__(self, template_dir: str):
        """
        初始化配置生成器

        :param template_dir: 模板文件存放目录绝对或相对路径
        """
        self.template_dir = os.path.abspath(template_dir)
        os.makedirs(self.template_dir, exist_ok=True)
        # 使用 SandboxedEnvironment 阻断 SSTI 任意代码执行利用
        self.jinja_env = SandboxedEnvironment(
            loader=FileSystemLoader(self.template_dir),
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True
        )

    def _sanitize_name(self, name: str) -> str:
        """
        净化模板文件名，剥离所有相对路径字符 (CWE-22 Path Traversal 防御)
        """
        clean = os.path.basename(name.strip())
        if not clean.endswith(".j2"):
            clean = f"{clean}.j2"
        return clean

    def list_templates(self) -> List[str]:
        """
        获取模板目录下的所有 *.j2 模板文件名列表

        :return: 模板文件名列表 (如 ['vlan_config.j2', ...])
        """
        pattern = os.path.join(self.template_dir, "*.j2")
        files = glob.glob(pattern)
        template_names = [os.path.basename(f) for f in files]
        template_names.sort()
        return template_names

    def get_template_content(self, name: str) -> str:
        """
        获取指定模板文件的原始内容

        :param name: 模板名称（带或不带 .j2 后缀）
        :return: 模板文件内容字符串
        :raises FileNotFoundError: 模板不存在
        """
        safe_name = self._sanitize_name(name)
        file_path = os.path.join(self.template_dir, safe_name)
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"模板文件不存在: {safe_name}")

        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()

    def save_template(self, name: str, content: str) -> bool:
        """
        保存或更新模板文件内容

        :param name: 模板文件名
        :param content: 模板文本内容
        :return: 保存是否成功
        """
        safe_name = self._sanitize_name(name)
        file_path = os.path.join(self.template_dir, safe_name)
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            logger.info(f"成功保存模板: {safe_name}")
            return True
        except Exception as e:
            logger.error(f"保存模板失败 {safe_name}: {e}")
            raise e

    def delete_template(self, name: str) -> bool:
        """
        删除指定的模板文件

        :param name: 模板文件名
        :return: 删除是否成功
        """
        safe_name = self._sanitize_name(name)
        file_path = os.path.join(self.template_dir, safe_name)
        if not os.path.exists(file_path):
            return False

        try:
            os.remove(file_path)
            logger.info(f"成功删除模板: {safe_name}")
            return True
        except Exception as e:
            logger.error(f"删除模板失败 {safe_name}: {e}")
            raise e

    def render_template(self, name: str, variables: Dict[str, Any]) -> str:
        """
        使用变量渲染已有模板文件

        :param name: 模板文件名
        :param variables: 变量字典
        :return: 渲染后的网络配置指令字符串
        """
        safe_name = self._sanitize_name(name)
        try:
            template = self.jinja_env.get_template(safe_name)
            return template.render(**variables)
        except Exception as e:
            logger.error(f"渲染模板 {safe_name} 失败: {e}")
            raise e

    def render_from_string(self, template_str: str, variables: Dict[str, Any]) -> str:
        """
        从字符串模板通过安全沙箱渲染配置

        :param template_str: Jinja2 模板内容字符串
        :param variables: 变量字典
        :return: 渲染后的配置字符串
        """
        try:
            template = self.jinja_env.from_string(template_str)
            return template.render(**variables)
        except Exception as e:
            logger.error(f"渲染字符串模板失败: {e}")
            raise e

    def batch_render(self, name: str, devices_variables: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        根据每个设备专属的变量批量渲染模板

        :param name: 模板文件名
        :param devices_variables: 列表，每个元素包含 device_name 及对应的变量键值，例如:
               [{"device_name": "R1", "variables": {...}}, ...] 或 [{"device_name": "R1", "ip": "1.1.1.1", ...}]
        :return: 列表，包含 [{"device_name": "R1", "config": "..."}, ...]
        """
        results = []
        for item in devices_variables:
            dev_name = item.get("device_name", item.get("device", "Unknown"))
            # 兼容嵌套的 variables 字段或平铺参数
            vars_dict = item.get("variables", {k: v for k, v in item.items() if k not in ("device_name", "device")})
            try:
                rendered = self.render_template(name, vars_dict)
                results.append({
                    "device_name": dev_name,
                    "config": rendered,
                    "success": True,
                    "error": ""
                })
            except Exception as e:
                results.append({
                    "device_name": dev_name,
                    "config": "",
                    "success": False,
                    "error": str(e)
                })
        return results

    @staticmethod
    def parse_yaml_variables(yaml_str: str) -> Union[Dict[str, Any], List[Any]]:
        """
        解析 YAML 字符串为 Python 字典或列表

        :param yaml_str: YAML 格式字符串
        :return: 解析后的字典或列表
        """
        try:
            data = yaml.safe_load(yaml_str)
            return data if data is not None else {}
        except Exception as e:
            logger.error(f"解析 YAML 变量失败: {e}")
            raise ValueError(f"YAML 格式错误: {str(e)}")

    @staticmethod
    def parse_excel_variables(filepath: str) -> List[Dict[str, Any]]:
        """
        从 Excel 文件中解析变量列表，第一行为表头(变量名)，后续每行对应一台设备或一条记录

        :param filepath: Excel 文件路径 (.xlsx)
        :return: 列表，每一项为单行记录解析后的字典
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Excel 文件不存在: {filepath}")

        wb = openpyxl.load_workbook(filepath, data_only=True)
        sheet = wb.active
        rows = list(sheet.iter_rows(values_only=True))

        if not rows:
            return []

        headers = [str(h).strip() if h is not None else "" for h in rows[0]]
        results: List[Dict[str, Any]] = []

        for row in rows[1:]:
            if not any(row):
                continue
            row_dict = {}
            for col_idx, header in enumerate(headers):
                if not header:
                    continue
                val = row[col_idx] if col_idx < len(row) else None
                row_dict[header] = val
            results.append(row_dict)

        wb.close()
        return results
