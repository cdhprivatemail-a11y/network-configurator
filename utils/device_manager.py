# -*- coding: utf-8 -*-
"""
设备连接管理模块
基于 Netmiko 库实现对华为 eNSP (VRP) 和华三 H3C HCL (Comware) 模拟器设备的批量连接与配置管理。
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional
from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoTimeoutException,
    NetmikoAuthenticationException,
    NetmikoBaseException,
)

# 配置日志记录器
logger = logging.getLogger("DeviceManager")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )


class DeviceManager:
    """
    网络设备连接与配置管理类
    支持华为 VRP 和华三 Comware 设备的 Telnet/SSH 连接、命令执行和配置备份。
    """

    def __init__(self, max_workers: int = 10):
        """
        初始化设备管理器

        :param max_workers: 并发线程池最大线程数，默认为 10
        """
        self.max_workers = max_workers

    def _prepare_netmiko_params(self, device_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        根据设备信息字典构造 Netmiko 连接参数字典

        :param device_info: 包含设备连接信息的字典
        :return: 适用于 ConnectHandler 的参数字典
        """
        raw_type = device_info.get("device_type", "huawei_vrp")
        # Netmiko 官方的华为 Telnet 类型是 huawei_telnet，华三 Telnet 是 hp_comware_telnet
        type_mapping = {
            "huawei_vrp_telnet": "huawei_telnet",
            "huawei_vrp": "huawei",
            "hp_comware": "hp_comware",
            "hp_comware_telnet": "hp_comware_telnet"
        }
        device_type = type_mapping.get(raw_type, raw_type)

        params = {
            "device_type": device_type,
            "host": device_info.get("host"),
            "port": int(device_info.get("port", 22)),
            "username": device_info.get("username", ""),
            "password": device_info.get("password", ""),
            "fast_cli": False,
            "timeout": 15,
            "session_timeout": 30,
        }

        # 可选特权密码
        if device_info.get("secret"):
            params["secret"] = device_info.get("secret")

        return params

    def connect(self, device_info: Dict[str, Any]):
        """
        连接至单个网络设备

        :param device_info: 设备参数字典 (name, host, port, username, password, device_type, secret)
        :return: netmiko BaseConnection 连接对象
        :raises Exception: 连接失败时抛出异常
        """
        params = self._prepare_netmiko_params(device_info)
        device_name = device_info.get("name", params["host"])
        logger.info(f"正在连接设备: {device_name} ({params['host']}:{params['port']}) 类型: {params['device_type']}")
        connection = ConnectHandler(**params)
        return connection

    @staticmethod
    def _is_raw_console_port(device_info: Dict[str, Any]) -> bool:
        """判断是否为本地模拟器免密直连 Console 串口 (eNSP 2000~2199 / HCL 30000~31999)"""
        try:
            port = int(device_info.get("port", 22))
            return (2000 <= port <= 2199) or (30000 <= port <= 31999)
        except Exception:
            return False

    def _probe_raw_console(self, host: str, port: int, timeout: float = 0.6) -> Dict[str, Any]:
        """极速探测模拟器 Console 串口在线状态与提示符 (<0.3s)"""
        import socket
        import time
        import re

        t0 = time.time()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(0.4)
            sock.sendall(b"\r\n\r\n")
            time.sleep(0.12)
            banner = ""
            while True:
                try:
                    chunk = sock.recv(4096).decode("utf-8", errors="ignore")
                    if not chunk:
                        break
                    banner += chunk
                    if len(chunk) < 1024:
                        break
                except Exception:
                    break
            elapsed_ms = int((time.time() - t0) * 1000)
            prompts = re.findall(r"(<[A-Za-z0-9_\-\.]+>|\[[A-Za-z0-9_\-\.\~/]+\])", banner)
            prompt = prompts[-1] if prompts else f"<Console:{port}>"
            return {"online": True, "prompt": prompt, "latency_ms": elapsed_ms}

    def test_connection(self, device_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        测试与单个设备的连通性和认证（针对模拟器 Console 端口采用 <0.3s 极速直连通道）

        :param device_info: 设备信息字典
        :return: 包含 success, device, message, prompt, latency_ms 的结果字典
        """
        import time
        device_name = device_info.get("name", device_info.get("host", "Unknown"))
        host = device_info.get("host", "127.0.0.1")
        port = int(device_info.get("port", 22))
        result = {
            "success": False,
            "device": device_name,
            "message": "",
            "prompt": "",
            "latency_ms": 0,
        }

        # Fast-Path: 若为模拟器 Console 串口 (2000~2199 / 30000~31999)，直接走极速串口探针
        if self._is_raw_console_port(device_info):
            try:
                probe = self._probe_raw_console(host, port, timeout=0.6)
                result["success"] = True
                result["prompt"] = probe["prompt"]
                result["latency_ms"] = probe["latency_ms"]
                result["message"] = f"模拟器串口极速直连成功 ({probe['latency_ms']}ms)，当前提示符: {probe['prompt']}"
                logger.info(f"设备 {device_name} 串口极速连接成功: {probe['prompt']} ({probe['latency_ms']}ms)")
                return result
            except Exception as e:
                result["message"] = f"模拟器串口 ({host}:{port}) 未响应或未开机: {str(e)}"
                logger.warning(f"设备 {device_name} 串口探测失败: {e}")
                return result

        # 针对网络 SSH/Telnet 设备进行轻量 TCP 端口可达性探测 (0.6s 超时)，避免离线设备在 Netmiko 中阻塞 10~15 秒
        import socket
        try:
            with socket.create_connection((host, port), timeout=0.6):
                pass
        except Exception as tcp_e:
            result["message"] = f"TCP 端口 ({host}:{port}) 不可达或设备未开机: {str(tcp_e)}"
            logger.warning(f"设备 {device_name} TCP 端口探测失败: {tcp_e}")
            return result

        connection = None
        t0 = time.time()
        try:
            connection = self.connect(device_info)
            prompt = connection.find_prompt()
            elapsed_ms = int((time.time() - t0) * 1000)
            result["success"] = True
            result["prompt"] = prompt
            result["latency_ms"] = elapsed_ms
            result["message"] = f"连接成功 ({elapsed_ms}ms)，当前提示符: {prompt}"
            logger.info(f"设备 {device_name} 连接测试成功: {prompt}")
        except NetmikoAuthenticationException as e:
            result["message"] = f"认证失败，请检查用户名或密码: {str(e)}"
            logger.warning(f"设备 {device_name} 认证失败: {e}")
        except NetmikoTimeoutException as e:
            result["message"] = f"连接超时，请检查 IP/端口可达性: {str(e)}"
            logger.warning(f"设备 {device_name} 连接超时: {e}")
        except NetmikoBaseException as e:
            result["message"] = f"Netmiko 异常: {str(e)}"
            logger.error(f"设备 {device_name} Netmiko 异常: {e}")
        except Exception as e:
            result["message"] = f"未知错误: {str(e)}"
            logger.error(f"设备 {device_name} 未知异常: {e}")
        finally:
            if connection:
                try:
                    connection.disconnect()
                except Exception:
                    pass

        return result

    def batch_test_connections(self, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """并发检测多台设备的在线心跳状态"""
        results: List[Dict[str, Any]] = []
        if not devices:
            return results
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(devices))) as executor:
            future_map = {executor.submit(self.test_connection, dev): dev for dev in devices}
            for future in as_completed(future_map):
                dev = future_map[future]
                try:
                    results.append(future.result())
                except Exception as e:
                    results.append({
                        "success": False,
                        "device": dev.get("name", "Unknown"),
                        "message": f"检测异常: {str(e)}",
                        "prompt": "",
                        "latency_ms": 0,
                    })
        return results

    def _detect_cli_errors(self, output: str) -> List[str]:
        """
        对华为 VRP 与华三 Comware 终端回显进行语义嗅探，捕获 CLI 语法错误与运行期冲突告警
        """
        if not output:
            return []
        import re
        error_patterns = [
            re.compile(r"^\s*Error\s*:\s*.+", re.IGNORECASE),
            re.compile(r"^\s*%\s*(Unrecognized|Wrong|Incomplete|Ambiguous|Too many)\s+.+", re.IGNORECASE),
            re.compile(r".*\b(Unrecognized command|Wrong parameter|Incomplete command|Ambiguous command)\b.*", re.IGNORECASE),
            re.compile(r".*\b(IP address conflicts|address overlaps|Failed to|Operation failed|Invalid IP)\b.*", re.IGNORECASE),
        ]
        matched_errors: List[str] = []
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line or line == "^":
                continue
            for pat in error_patterns:
                if pat.match(line):
                    matched_errors.append(line)
                    break
        return matched_errors

    def execute_commands(self, device_info: Dict[str, Any], commands: List[str]) -> Dict[str, Any]:
        """
        在单个设备上批量执行一组命令，并自动检测回显中的 CLI 报错
        针对本地模拟器 Console 端口直接启用 <0.3s 极速原生通道，免除 Netmiko 15s 认证等待

        :param device_info: 设备信息字典
        :param commands: 待执行的配置命令列表
        :return: 字典包含 success, device, output, error, cli_errors, cli_error_count, has_cli_warning, commands_sent
        """
        device_name = device_info.get("name", device_info.get("host", "Unknown"))
        result = {
            "success": False,
            "device": device_name,
            "output": "",
            "error": "",
            "cli_errors": [],
            "cli_error_count": 0,
            "has_cli_warning": False,
            "commands_sent": len(commands),
        }

        if not commands:
            result["success"] = True
            result["output"] = "未提供待执行的命令"
            return result

        connection = None
        host = device_info.get("host", "127.0.0.1")
        port = int(device_info.get("port", 22))
        is_raw_console = self._is_raw_console_port(device_info)
        is_simulator_telnet = (port == 23) or is_raw_console

        # Fast-Path: 本地模拟器 Console 端口直接走高速原生 Socket 通道
        if is_raw_console:
            try:
                raw_out = self._execute_via_raw_telnet(host, port, commands)
                result["success"] = True
                result["output"] = raw_out
                logger.info(f"设备 {device_name} ({host}:{port}) 极速 Console 通道执行完成 ({len(commands)} 条命令)")
            except Exception as raw_e:
                result["error"] = f"模拟器串口执行失败 ({host}:{port}): {str(raw_e)}"
                logger.error(f"设备 {device_name} 串口执行失败: {raw_e}")
        else:
            try:
                connection = self.connect(device_info)
                logger.info(f"正在对设备 {device_name} 下发命令 (共 {len(commands)} 条)...")

                if any("system-view" in c.lower() for c in commands):
                    output_parts = []
                    for cmd in commands:
                        out = connection.send_command(cmd, expect_string=r'[>\]]', strip_prompt=False, strip_command=False)
                        output_parts.append(out)
                    result["success"] = True
                    result["output"] = "\n".join(output_parts)
                else:
                    output = connection.send_config_set(commands)
                    result["success"] = True
                    result["output"] = output
                logger.info(f"设备 {device_name} 命令通道下发完成")
            except Exception as e:
                logger.warning(f"设备 {device_name} Netmiko 执行失败: {e}，尝试使用原生 Console Socket 通道执行...")
                if is_simulator_telnet:
                    try:
                        raw_out = self._execute_via_raw_telnet(host, port, commands)
                        result["success"] = True
                        result["output"] = raw_out
                        logger.info(f"设备 {device_name} 原生 Console Socket 通道下发成功！")
                    except Exception as raw_e:
                        err_msg = f"Netmiko 失败 ({str(e)}) 且原生 Socket 失败: {str(raw_e)}"
                        result["error"] = err_msg
                        logger.error(f"设备 {device_name} 最终执行失败: {err_msg}")
                else:
                    err_msg = f"执行命令失败: {str(e)}"
                    result["error"] = err_msg
                    logger.error(f"设备 {device_name} 执行失败: {err_msg}")
            finally:
                if connection:
                    try:
                        connection.disconnect()
                    except Exception:
                        pass

        if result["success"] and result["output"]:
            cli_errs = self._detect_cli_errors(result["output"])
            result["cli_errors"] = cli_errs
            result["cli_error_count"] = len(cli_errs)
            result["has_cli_warning"] = len(cli_errs) > 0

        return result

    def _execute_via_raw_telnet(self, host: str, port: int, commands: List[str]) -> str:
        """
        通过原始 Socket 稳定直下命令到模拟器 Console/Telnet 端口
        完美支持：
        1. 无密码极速直连与自动关闭分页
        2. 完整读取长输出 (display current-configuration) 不因 '#' 或 ':' 提前截断
        3. 自动应答交互式确认提示 ([Y/N]、save 文件名确认、---- More ---- 分页)
        4. 支持 ping 等耗时命令的动态超时等待
        """
        import socket
        import time
        import re

        prompt_end_re = re.compile(r"(<[A-Za-z0-9_\-\.]+>|\[[A-Za-z0-9_\-\.\~/]+\])\s*$")
        yn_prompt_re = re.compile(r"\[Y/N\]\s*:?\s*$", re.IGNORECASE)
        filename_prompt_re = re.compile(r"(enter key\):|file name.*:)\s*$", re.IGNORECASE)

        with socket.create_connection((host, port), timeout=1.5) as s:
            s.settimeout(0.25)
            # 唤醒串口并自动解除分页限制
            s.sendall(b"\r\n")
            time.sleep(0.1)
            try:
                s.recv(4096)
            except Exception:
                pass

            full_output: List[str] = []
            for cmd in commands:
                cmd_clean = cmd.strip()
                if not cmd_clean:
                    continue
                low_cmd = cmd_clean.lower()
                is_long_cfg = "display current" in low_cmd or "display saved" in low_cmd
                is_ping = low_cmd.startswith("ping ") or "tracert" in low_cmd

                s.sendall((cmd_clean + "\r\n").encode("utf-8", errors="ignore"))
                time.sleep(0.25 if (is_long_cfg or is_ping) else 0.12)
                s.settimeout(1.6 if is_ping else (0.45 if is_long_cfg else 0.25))

                chunk_text = ""
                max_loops = 40 if is_long_cfg else (15 if is_ping else 10)
                for _ in range(max_loops):
                    try:
                        buf = s.recv(8192)
                        if not buf:
                            break
                        decoded = buf.decode("utf-8", errors="ignore")
                        chunk_text += decoded

                        # 1. 自动处理分页续读 ---- More ----
                        if "---- More ----" in decoded:
                            s.sendall(b" ")
                            continue

                        # 2. 自动处理交互式 [Y/N] 确认 (如 save / reset)
                        if yn_prompt_re.search(chunk_text.strip()):
                            s.sendall(b"Y\r\n")
                            time.sleep(0.15)
                            continue

                        # 3. 自动处理 H3C save 时的默认文件名回车确认
                        if filename_prompt_re.search(chunk_text.strip()):
                            s.sendall(b"\r\n")
                            time.sleep(0.15)
                            continue

                        # 4. 判断命令是否已完整返回到 CLI 提示符
                        stripped_tail = chunk_text.rstrip()
                        if prompt_end_re.search(stripped_tail):
                            if is_long_cfg:
                                # 对于 display current-configuration，确保已读到末尾的 return 关键字
                                if "return" in chunk_text.lower() or len(chunk_text) > 500:
                                    break
                            elif is_ping:
                                # 对于 ping，确保已读到统计摘要 (packet loss / round-trip)
                                if "packet loss" in chunk_text.lower() or "timeout" in chunk_text.lower():
                                    break
                            else:
                                break
                    except socket.timeout:
                        break

                full_output.append(chunk_text)

            return "\n".join(full_output)

    def batch_execute(self, devices: List[Dict[str, Any]], commands: List[str]) -> List[Dict[str, Any]]:
        """
        并发在多个设备上执行相同配置命令
        """
        tasks = [{"device": dev, "commands": commands} for dev in devices]
        return self.batch_execute_per_device(tasks)

    def batch_execute_per_device(self, tasks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        并发在多个设备上执行各自专属的命令列表（支持设备级宏变量差异化下发）

        :param tasks: [{"device": device_dict, "commands": [...], "rendered_cli": "..."}, ...]
        :return: 执行结果字典列表
        """
        results: List[Dict[str, Any]] = []
        if not tasks:
            return results

        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(tasks))) as executor:
            future_to_task = {
                executor.submit(self.execute_commands, item["device"], item["commands"]): item
                for item in tasks
            }
            for future in as_completed(future_to_task):
                item = future_to_task[future]
                dev_name = item["device"].get("name", "Unknown")
                try:
                    res = future.result()
                    if "rendered_cli" in item:
                        res["rendered_cli"] = item["rendered_cli"]
                    if "pre_backup_file" in item:
                        res["pre_backup_file"] = item["pre_backup_file"]
                    results.append(res)
                except Exception as e:
                    results.append({
                        "success": False,
                        "device": dev_name,
                        "output": "",
                        "error": f"线程执行异常: {str(e)}",
                        "cli_errors": [],
                        "cli_error_count": 0,
                        "has_cli_warning": False,
                    })

        return results

    def get_running_config(self, device_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        获取单个设备的当前运行配置（针对本地模拟器串口采用极速完整读取通道）

        :param device_info: 设备信息字典
        :return: 字典包含 success (bool), device (str), config (str), error (str)
        """
        device_name = device_info.get("name", device_info.get("host", "Unknown"))
        result = {
            "success": False,
            "device": device_name,
            "config": "",
            "error": ""
        }

        host = device_info.get("host", "127.0.0.1")
        port = int(device_info.get("port", 22))
        is_raw_console = self._is_raw_console_port(device_info)
        is_simulator_telnet = (port == 23) or is_raw_console
        device_type = device_info.get("device_type", "huawei_vrp").lower()
        disable_page = "screen-length disable" if ("hp" in device_type or "h3c" in device_type or "comware" in device_type or port >= 30000) else "screen-length 0 temporary"

        # Fast-Path: 本地模拟器串口直接走完整配置读取通道 (<0.6s)，不触发 Netmiko 15s 阻塞
        if is_raw_console:
            try:
                raw_cfg = self._execute_via_raw_telnet(host, port, ["return", disable_page, "display current-configuration"])
                result["success"] = True
                result["config"] = raw_cfg
                logger.info(f"设备 {device_name} 通过极速 Console 通道完整获取配置成功 (长度: {len(raw_cfg)} 字符)")
                return result
            except Exception as raw_e:
                result["error"] = f"模拟器串口获取配置失败 ({host}:{port}): {str(raw_e)}"
                logger.error(f"设备 {device_name} 串口配置获取失败: {raw_e}")
                return result

        connection = None
        try:
            connection = self.connect(device_info)
            if "cisco" in device_type:
                cmd = "show running-config"
            else:
                cmd = "display current-configuration"

            logger.info(f"正在获取设备 {device_name} 当前配置: {cmd}")
            config_output = connection.send_command(cmd, read_timeout=60)

            result["success"] = True
            result["config"] = config_output
            logger.info(f"设备 {device_name} 配置获取成功 (长度: {len(config_output)} 字符)")
        except Exception as e:
            if is_simulator_telnet:
                try:
                    raw_cfg = self._execute_via_raw_telnet(host, port, ["return", disable_page, "display current-configuration"])
                    result["success"] = True
                    result["config"] = raw_cfg
                    logger.info(f"设备 {device_name} 通过原生 Socket 获取配置成功 (长度: {len(raw_cfg)} 字符)")
                except Exception as raw_e:
                    err_msg = f"获取设备配置失败: {str(e)} / Socket: {str(raw_e)}"
                    result["error"] = err_msg
                    logger.error(f"设备 {device_name} 配置获取失败: {err_msg}")
            else:
                err_msg = f"获取设备配置失败: {str(e)}"
                result["error"] = err_msg
                logger.error(f"设备 {device_name} 配置获取失败: {err_msg}")
        finally:
            if connection:
                try:
                    connection.disconnect()
                except Exception:
                    pass

        return result

    def batch_get_configs(self, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        并发从多个设备获取当前配置
        """
        results: List[Dict[str, Any]] = []
        if not devices:
            return results

        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(devices))) as executor:
            future_to_device = {
                executor.submit(self.get_running_config, dev): dev.get("name", "Unknown")
                for dev in devices
            }
            for future in as_completed(future_to_device):
                try:
                    res = future.result()
                    results.append(res)
                except Exception as e:
                    dev_name = future_to_device[future]
                    results.append({
                        "success": False,
                        "device": dev_name,
                        "config": "",
                        "error": f"线程获取配置异常: {str(e)}"
                    })

        return results

    def save_device_configs(self, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        并发将多台设备的当前内存运行配置固化保存到 Flash/NVRAM (H3C: save force / Huawei: save + Y)
        防止模拟器重启丢失配置
        """
        tasks = []
        for dev in devices:
            dtype = str(dev.get("device_type", "")).lower()
            port = int(dev.get("port", 22))
            is_h3c = "hp" in dtype or "h3c" in dtype or "comware" in dtype or port >= 30000
            cmds = ["return", "save force"] if is_h3c else ["return", "save"]
            tasks.append({"device": dev, "commands": cmds})
        return self.batch_execute_per_device(tasks)

