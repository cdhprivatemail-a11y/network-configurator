# -*- coding: utf-8 -*-
"""
设备扫描器 - 扫描本地端口并自动识别网络设备
支持识别华为 VRP (eNSP) 和华三 Comware (HCL) 设备
"""

import socket
import threading
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

logger = logging.getLogger(__name__)


class DeviceScanner:
    """网络设备扫描器"""

    # 常见的模拟器端口范围
    DEFAULT_SCAN_CONFIGS = {
        'localhost': {
            'hosts': ['127.0.0.1'],
            'ports': list(range(2000, 2101)) + list(range(3000, 3101)) + list(range(30000, 30051)),
            'description': '本地回环 (eNSP/HCL 映射端口)'
        },
        'virtualbox_host_only': {
            'hosts': [f'192.168.56.{i}' for i in range(1, 255)],
            'ports': [22, 23, 2000, 2001, 2002, 2003, 2004, 2005],
            'description': 'VirtualBox Host-Only 网段'
        },
        'custom_range': {
            'hosts': [],
            'ports': [],
            'description': '自定义扫描范围'
        }
    }

    # 设备识别特征
    DEVICE_SIGNATURES = {
        'huawei_vrp': {
            'banners': [
                r'huawei',
                r'vrp',
                r'versatile routing platform',
                r'quidway',
                r'<\w+>',  # VRP 提示符格式
                r'\[~?\w+\]',  # VRP 系统视图提示符
                r'HUAWEI',
                r'AR\d+',  # AR 系列路由器
                r'S\d{4}',  # S 系列交换机
                r'CE\d{4}',  # CE 系列交换机
                r'NE\d+',  # NE 系列路由器
                r'USG\d+',  # USG 防火墙
            ],
            'probe_commands': ['display version', 'display device'],
            'response_patterns': [
                r'Huawei',
                r'VRP.*Software',
                r'HUAWEI.*Versatile Routing Platform',
                r'HUAWEI.*uptime is',
            ]
        },
        'hp_comware': {
            'banners': [
                r'h3c',
                r'comware',
                r'<\w+>',
                r'HPE?\s',
                r'MSR\d+',  # MSR 系列路由器
                r'S\d{4}[A-Z]',  # H3C S 系列
            ],
            'probe_commands': ['display version', 'display device manuinfo'],
            'response_patterns': [
                r'H3C',
                r'Comware.*Software',
                r'HPE?.*Comware',
                r'H3C.*uptime is',
            ]
        }
    }

    def __init__(self, timeout=2, max_workers=50):
        """
        初始化扫描器
        :param timeout: 连接超时时间（秒）
        :param max_workers: 最大并发扫描线程数
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.scan_results = []
        self._lock = threading.Lock()

    def scan_port(self, host, port):
        """
        扫描单个端口是否开放
        :param host: 目标主机
        :param port: 目标端口
        :return: dict 或 None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()

            if result == 0:
                return {
                    'host': host,
                    'port': port,
                    'status': 'open',
                    'service': self._guess_service(port),
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
        except (socket.error, OSError) as e:
            logger.debug(f"扫描 {host}:{port} 失败: {e}")
        return None

    def _guess_service(self, port):
        """根据端口号猜测服务类型"""
        service_map = {
            22: 'SSH',
            23: 'Telnet',
            80: 'HTTP',
            443: 'HTTPS',
            830: 'NETCONF',
        }
        if port in service_map:
            return service_map[port]
        if 2000 <= port <= 2100:
            return 'Telnet(映射)'
        if 3000 <= port <= 3100:
            return 'SSH(映射)'
        return '未知'

    def scan_range(self, hosts, ports, callback=None):
        """
        批量扫描主机和端口范围
        :param hosts: 主机列表
        :param ports: 端口列表
        :param callback: 进度回调函数 (scanned, total, result)
        :return: 开放端口列表
        """
        open_ports = []
        total = len(hosts) * len(ports)
        scanned = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for host in hosts:
                for port in ports:
                    future = executor.submit(self.scan_port, host, port)
                    futures[future] = (host, port)

            for future in as_completed(futures):
                scanned += 1
                result = future.result()
                if result:
                    open_ports.append(result)
                    logger.info(f"发现开放端口: {result['host']}:{result['port']} ({result['service']})")
                if callback:
                    callback(scanned, total, result)

        # 按主机和端口排序
        open_ports.sort(key=lambda x: (x['host'], x['port']))
        return open_ports

    def identify_device(self, host, port, username='', password=''):
        """
        尝试连接并识别设备类型
        :param host: 主机地址
        :param port: 端口号
        :param username: 用户名（可选）
        :param password: 密码（可选）
        :return: 设备信息字典
        """
        device_info = {
            'host': host,
            'port': port,
            'device_type': 'unknown',
            'device_type_display': '未知设备',
            'protocol': 'unknown',
            'banner': '',
            'hostname': '',
            'model': '',
            'version': '',
            'identified': False,
            'error': ''
        }

        # 先尝试 Telnet 识别
        telnet_result = self._identify_via_telnet(host, port, username, password)
        if telnet_result and telnet_result.get('identified'):
            device_info.update(telnet_result)
            device_info['protocol'] = 'telnet'
            return device_info

        # 再尝试 SSH Banner 识别
        ssh_result = self._identify_via_ssh_banner(host, port)
        if ssh_result and ssh_result.get('identified'):
            device_info.update(ssh_result)
            device_info['protocol'] = 'ssh'
            return device_info

        # 即使未完全识别，也返回 banner 信息
        if telnet_result and telnet_result.get('banner'):
            device_info['banner'] = telnet_result['banner']
            device_info['protocol'] = 'telnet'
        elif ssh_result and ssh_result.get('banner'):
            device_info['banner'] = ssh_result['banner']
            device_info['protocol'] = 'ssh'

        return device_info

    def _identify_via_telnet(self, host, port, username='', password=''):
        """通过 Telnet 原始 Socket 连接识别设备（兼容 Python 3.13+，不依赖 telnetlib）"""
        result = {
            'identified': False,
            'banner': '',
            'hostname': '',
            'model': '',
            'version': '',
            'device_type': 'unknown',
            'device_type_display': '未知设备',
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout + 3)
            sock.connect((host, port))

            # 很多 Console 口连接后需要敲回车激活显示命令行提示符
            try:
                import time
                sock.sendall(b'\r\n')
                time.sleep(0.3)
            except Exception:
                pass

            # 读取初始 Banner（持续读取直到超时或收到提示符）
            banner_data = b''
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    # 过滤 Telnet 协商字节 (IAC 命令, 0xFF 开头的3字节序列)
                    clean_chunk = self._strip_telnet_negotiation(chunk)
                    banner_data += clean_chunk
                    # 检测到命令行提示符则停止
                    if b'>' in banner_data or b']' in banner_data:
                        break
                    if b'ogin' in banner_data or b'sername' in banner_data or b'assword' in banner_data:
                        break
            except socket.timeout:
                pass

            banner = banner_data.decode('utf-8', errors='ignore').strip()
            result['banner'] = banner

            # 如果有登录提示，尝试登录
            if username and any(kw in banner.lower() for kw in ['login', 'username', 'user name', 'password']):
                try:
                    if 'username' in banner.lower() or 'user name' in banner.lower() or 'login' in banner.lower():
                        sock.sendall(username.encode('ascii') + b'\r\n')
                        import time
                        time.sleep(1)
                        resp_data = b''
                        try:
                            while True:
                                chunk = sock.recv(4096)
                                if not chunk:
                                    break
                                resp_data += self._strip_telnet_negotiation(chunk)
                                if b'assword' in resp_data:
                                    break
                        except socket.timeout:
                            pass
                        resp = resp_data.decode('utf-8', errors='ignore')
                        if password and 'assword' in resp:
                            sock.sendall(password.encode('ascii') + b'\r\n')
                            time.sleep(1)
                            login_resp = b''
                            try:
                                while True:
                                    chunk = sock.recv(4096)
                                    if not chunk:
                                        break
                                    login_resp += self._strip_telnet_negotiation(chunk)
                                    if b'>' in login_resp or b']' in login_resp:
                                        break
                            except socket.timeout:
                                pass
                            banner += login_resp.decode('utf-8', errors='ignore')
                            result['banner'] = banner
                except Exception as e:
                    logger.debug(f"Telnet 登录 {host}:{port} 失败: {e}")

            # 尝试从 Banner 和响应中识别设备
            full_text = banner

            # 如果已经到了命令行提示符，尝试发送识别命令
            if '>' in banner or ']' in banner:
                try:
                    sock.sendall(b'display version\r\n')
                    import time
                    time.sleep(1)
                    version_data = b''
                    try:
                        while True:
                            chunk = sock.recv(4096)
                            if not chunk:
                                break
                            version_data += self._strip_telnet_negotiation(chunk)
                            if b'>' in version_data or b']' in version_data:
                                break
                    except socket.timeout:
                        pass
                    version_text = version_data.decode('utf-8', errors='ignore')
                    full_text += '\n' + version_text
                    result['banner'] = full_text
                except Exception:
                    pass

            # 匹配设备类型
            identified_type = self._match_device_type(full_text)
            if identified_type:
                result['identified'] = True
                result['device_type'] = identified_type
                result['device_type_display'] = self._get_type_display(identified_type, port)

                # 提取主机名
                hostname_match = re.search(r'<(\S+?)>', full_text)
                if hostname_match:
                    result['hostname'] = hostname_match.group(1)

                # 提取型号
                model_match = re.search(
                    r'(?:HUAWEI|H3C|Quidway)\s+([\w-]+)',
                    full_text, re.IGNORECASE
                )
                if model_match:
                    result['model'] = model_match.group(1)

                # 提取版本
                version_match = re.search(
                    r'(?:VRP|Comware).*?Version\s+([\d.]+)',
                    full_text, re.IGNORECASE
                )
                if version_match:
                    result['version'] = version_match.group(1)

            sock.close()

        except Exception as e:
            result['error'] = str(e)
            logger.debug(f"Telnet 识别 {host}:{port} 失败: {e}")

        return result

    @staticmethod
    def _strip_telnet_negotiation(data):
        """
        过滤 Telnet 协商字节（IAC 命令序列）
        Telnet 协议中 0xFF (IAC) 开头的命令为 3 字节序列
        """
        result = bytearray()
        i = 0
        while i < len(data):
            if data[i] == 0xFF and i + 2 < len(data):
                # 跳过 IAC + CMD + OPTION (3字节)
                i += 3
            else:
                result.append(data[i])
                i += 1
        return bytes(result)

    def _identify_via_ssh_banner(self, host, port):
        """通过 SSH Banner 识别设备"""
        result = {
            'identified': False,
            'banner': '',
            'device_type': 'unknown',
            'device_type_display': '未知设备',
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout + 1)
            sock.connect((host, port))

            # 读取 SSH Banner
            banner_data = sock.recv(1024)
            banner = banner_data.decode('utf-8', errors='ignore').strip()
            result['banner'] = banner

            # SSH banner 通常包含 "SSH-2.0-xxx"
            if 'SSH' in banner.upper():
                result['protocol'] = 'ssh'

                # 华为设备 SSH banner 特征
                if any(kw in banner.upper() for kw in ['HUAWEI', 'VRP']):
                    result['identified'] = True
                    result['device_type'] = 'huawei_vrp'
                    result['device_type_display'] = '华为 VRP (SSH)'

                # H3C 设备 SSH banner 特征
                elif any(kw in banner.upper() for kw in ['H3C', 'COMWARE', 'HPE']):
                    result['identified'] = True
                    result['device_type'] = 'hp_comware'
                    result['device_type_display'] = 'H3C Comware (SSH)'

            sock.close()

        except Exception as e:
            result['error'] = str(e)
            logger.debug(f"SSH 识别 {host}:{port} 失败: {e}")

        return result

    def _match_device_type(self, text):
        """
        匹配设备类型
        :param text: 待匹配的文本（banner + 命令输出）
        :return: 设备类型字符串或 None
        """
        text_upper = text.upper()

        # 优先检查明确的关键词
        # 华为 VRP
        huawei_keywords = ['HUAWEI', 'VRP', 'VERSATILE ROUTING PLATFORM', 'QUIDWAY']
        for kw in huawei_keywords:
            if kw in text_upper:
                return 'huawei_vrp'

        # H3C Comware
        h3c_keywords = ['H3C', 'COMWARE', 'HPE COMWARE', 'SHELL_LOGIN', 'CON0']
        for kw in h3c_keywords:
            if kw in text_upper:
                return 'hp_comware'

        # 使用正则进一步匹配
        for device_type, sigs in self.DEVICE_SIGNATURES.items():
            for pattern in sigs.get('response_patterns', []):
                if re.search(pattern, text, re.IGNORECASE):
                    return device_type

        # 如果提取到了 <Hostname> 格式的提示符
        if re.search(r'<\S+?>', text):
            # 常见 HCL 设备命名规则
            if any(k in text_upper for k in ['ROUTER', 'SWITCH', 'H3C']):
                return 'hp_comware'
            return 'huawei_vrp'

        return None

    def _get_type_display(self, device_type, port=None):
        """获取设备类型的显示名称"""
        type_map = {
            'huawei_vrp': '华为 VRP',
            'hp_comware': 'H3C Comware',
        }
        base = type_map.get(device_type, device_type)

        # 根据端口判断协议
        if port:
            if port == 22 or (3000 <= port <= 3100):
                return f'{base} (SSH)'
            elif port == 23 or (2000 <= port <= 2100):
                return f'{base} (Telnet)'
        return base

    def scan_and_identify(self, hosts, ports, username='', password='',
                          identify=True, progress_callback=None):
        """
        扫描端口并识别设备（一站式方法）
        :param hosts: 主机列表
        :param ports: 端口列表
        :param username: 尝试登录的用户名
        :param password: 尝试登录的密码
        :param identify: 是否进行设备识别
        :param progress_callback: 进度回调
        :return: 扫描结果列表
        """
        logger.info(f"开始扫描: {len(hosts)} 个主机, {len(ports)} 个端口")

        # 第一步：端口扫描
        open_ports = self.scan_range(hosts, ports, progress_callback)
        logger.info(f"发现 {len(open_ports)} 个开放端口")

        if not identify or not open_ports:
            return open_ports

        # 第二步：设备识别
        logger.info("开始设备识别...")
        results = []

        with ThreadPoolExecutor(max_workers=min(10, len(open_ports))) as executor:
            futures = {}
            for port_info in open_ports:
                future = executor.submit(
                    self.identify_device,
                    port_info['host'],
                    port_info['port'],
                    username,
                    password
                )
                futures[future] = port_info

            for future in as_completed(futures):
                port_info = futures[future]
                try:
                    device_info = future.result()
                    # 合并端口扫描信息和设备识别信息
                    merged = {**port_info, **device_info}
                    results.append(merged)
                except Exception as e:
                    port_info['error'] = str(e)
                    results.append(port_info)

        results.sort(key=lambda x: (x['host'], x['port']))
        logger.info(f"设备识别完成, 共识别 {sum(1 for r in results if r.get('identified'))} 个设备")
        return results

    def quick_scan_local(self, username='', password=''):
        """
        快速扫描本地常见端口（eNSP/HCL 默认端口范围）
        :return: 扫描结果列表
        """
        hosts = ['127.0.0.1']
        # eNSP 通常使用 2000-2050 范围的 Telnet 端口
        # HCL 通常也使用类似端口
        ports = (
            list(range(2000, 2051)) +    # eNSP / 常见 Telnet 映射范围
            list(range(30000, 30051)) +  # HCL Console 端口常见范围 (如 30001, 30002...)
            list(range(3000, 3051)) +    # SSH 映射常见范围
            [22, 23]                     # 标准端口
        )
        return self.scan_and_identify(hosts, ports, username, password)

    def scan_subnet(self, subnet_prefix, start=1, end=254,
                    ports=None, username='', password=''):
        """
        扫描子网
        :param subnet_prefix: 子网前缀，如 '192.168.56'
        :param start: 起始主机号
        :param end: 结束主机号
        :param ports: 端口列表
        :param username: 用户名
        :param password: 密码
        :return: 扫描结果列表
        """
        hosts = [f'{subnet_prefix}.{i}' for i in range(start, end + 1)]
        if ports is None:
            ports = [22, 23, 2000, 2001, 2002, 2003, 2004, 2005]
        return self.scan_and_identify(hosts, ports, username, password)

    @staticmethod
    def parse_host_range(host_input):
        """
        解析主机范围输入
        支持格式:
          - 单个 IP: 192.168.1.1
          - 逗号分隔: 192.168.1.1,192.168.1.2
          - 范围: 192.168.1.1-10
          - 子网: 192.168.1.0/24
          - 混合: 192.168.1.1,192.168.1.10-20
        :return: 主机列表
        """
        hosts = []
        parts = [p.strip() for p in host_input.split(',')]

        for part in parts:
            if '/' in part:
                # CIDR 格式 (简化处理，仅支持 /24)
                prefix = part.split('/')[0].rsplit('.', 1)[0]
                hosts.extend([f'{prefix}.{i}' for i in range(1, 255)])
            elif '-' in part and '.' in part:
                # IP 范围: 192.168.1.1-10
                base_ip, end_suffix = part.rsplit('-', 1)
                if '.' in end_suffix:
                    # 完整结束 IP: 192.168.1.1-192.168.1.10
                    start_num = int(base_ip.rsplit('.', 1)[1])
                    end_num = int(end_suffix.rsplit('.', 1)[1])
                    prefix = base_ip.rsplit('.', 1)[0]
                else:
                    start_num = int(base_ip.rsplit('.', 1)[1])
                    end_num = int(end_suffix)
                    prefix = base_ip.rsplit('.', 1)[0]
                hosts.extend([f'{prefix}.{i}' for i in range(start_num, end_num + 1)])
            else:
                hosts.append(part)

        return hosts

    @staticmethod
    def parse_port_range(port_input):
        """
        解析端口范围输入
        支持格式:
          - 单个端口: 22
          - 逗号分隔: 22,23,2000
          - 范围: 2000-2050
          - 混合: 22,23,2000-2050
        :return: 端口列表
        """
        ports = []
        parts = [p.strip() for p in str(port_input).split(',')]

        for part in parts:
            if '-' in part:
                start, end = part.split('-', 1)
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))

        return sorted(set(ports))

    def get_netmiko_device_type(self, device_type, port):
        """
        将识别到的设备类型转换为 Netmiko device_type
        :return: Netmiko 兼容的 device_type 字符串
        """
        is_telnet_port = (
            port == 23 or 
            (2000 <= port <= 2100) or    # eNSP / 常用 Telnet 映射
            (30000 <= port <= 31000)     # HCL Console 端口 (如 30001-30050)
        )

        if device_type == 'huawei_vrp':
            return 'huawei_vrp_telnet' if is_telnet_port else 'huawei_vrp'
        elif device_type == 'hp_comware':
            return 'hp_comware_telnet' if is_telnet_port else 'hp_comware'
        return device_type
