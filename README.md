# Network Configurator (网络设备批量配置平台) Enterprise v4.0

基于 **Python / Flask / Netmiko / Jinja2** 构建的企业级多厂商网络设备批量配置、自动化拓扑编排、等保 2.0 合规巡检与配置版本管理系统。  
全面兼容 **华为 eNSP (VRP)** 与 **华三 HCL (Comware v7)** 仿真及实机环境。

---

## 🌟 核心特性与架构能力

### 1. 8 大领域 · 100 项全栈网络特性配置引擎
* **基础接口域 (14项)**：Base、AAA、Interface、VLAN、QinQ、Super Password、Banner、Voice VLAN、Super VLAN、Mux VLAN、VLAN Mapping 等
* **高可靠与链路聚合域 (15项)**：LACP、STP、VRRP、BFD、镜像、NQA、IRF 堆叠、Monitor Link、IP FRR、MSTP 多实例、Smart Link、DLDP、M-LAG 等
* **路由协议域 (15项)**：Static Route、OSPFv2/v3、IS-IS、BGP、RIP、路由引入、Route-Policy、Prefix-List、PBR、BFD for OSPF/BGP、Graceful Restart 等
* **安全防护与ACL域 (15项)**：Basic/Advanced ACL、IP Source Guard、DAI、Port Security、Traffic Filter、SSH/Telnet、URPF、CPU 防攻击、防 ARP 欺骗等
* **服务质量 QoS 域 (10项)**：MQC 流分类、DiffServ、LR 流量限速、CAR 监管、GTS 整形、PQ/CQ/WFQ 队列、WRED、802.1p/DSCP 映射等
* **组播与二层协议域 (10项)**：IGMP Snooping、IGMP Proxy、PIM-SM/DM、Multicast VLAN、GVRP、LLDP 发现、MAC 漂移告警等
* **MPLS 与 VPN 域 (11项)**：LDP、MPLS L3VPN、Option A/B/C、VPLS、EoMPLS、MP-BGP、SR-MPLS、VPNv4 反射器等
* **网络管理与监控运维域 (10项)**：SNMPv2c/v3、NTP/SNTP、Syslog、NetStream/sFlow、Telemetry、IP SLA、CWMP、配置保存与重启管理等

### 2. 双厂商语法互译与逆向回滚引擎 (Undo Engine)
* 正向批量生成并下发双厂商 CLI（Huawei VRP 与 H3C Comware 自动转换）。
* **内置逆向撤回引擎**：支持从已渲染配置一键反推对应的 `undo` / `undo ip` 逆向清理脚本，实现配置秒级原子回滚。

### 3. CLI 风险熔断与动态宏变量注入
* **CLIRiskGuardrail**：内置高危指令拦截规则，主动阻断 `format`、`reboot`、`delete /unreserved` 等破坏性误操作。
* **多机动态宏变量**：支持在模板中使用 `{% raw %}{{ ip_prefix }}.{{ id }}{% endraw %}` 等动态宏语法，自动计算多设备递增 IP、掩码与 Router-ID。

### 4. 拓扑 1:1 克隆、连线扫描与 Ping Mesh
* 支持直接导入解析 **华为 eNSP (`.topo`)** 与 **华三 HCL (`.net`)** 工程文件，1:1 还原节点坐标与互联接口。
* **活动端口扫描**：自动探测本机 30001~30004 等模拟器独占串口控制台。
* **Ping Mesh 连通性测试**：端到端并发探测链路时延（RTT）与 OSPF 状态，具备端口级互斥锁，防止并发冲突。

### 5. 黄金基线配置归档与全网漂移比对
* 自动抓取设备 `running-config` 并生成带时间戳快照。
* **双向 Diff 比对**：可视化展示配置新增（`+`）与删减（`-`）。
* **全网配置漂移普查**：比对当前内存配置与黄金基线快照的一致性。

### 6. 等保 2.0 合规巡检与 SQLite 任务流水审计
* 涵盖“身份鉴别、访问控制、安全审计、入侵防范”四大维度自动评分与评级（A/B/C/D）。
* 线程安全 SQLite 日志中心（`JobAuditLogger`），完整追踪历史下发任务、执行人与终端回显。

---

## 🏗️ 目录结构说明

```text
network-configurator/
├── app.py                      # Flask 应用入口与 30+ RESTful API 路由
├── devices.yaml                # 受管设备清单 (密码支持 Vault 静态加密)
├── requirements.txt            # Python 依赖项列表
├── test_100_features.py        # 全量 100 特性与 Sprint 1~5 自动化回归测试
├── .gitignore                  # Git 忽略规则
├── config_templates/           # Jinja2 配置模板 (VLAN, OSPF, Interface 等)
├── backups/                    # 设备配置快照与历史备份归档
├── sample_topologies/          # eNSP (.topo) 与 HCL (.net) 样板拓扑工程
├── static/                     # 前端 CSS、JS 及图标资源
│   ├── css/style.css
│   └── js/main.js
├── templates/                  # 前端 HTML 页面 (Bootstrap + Vis.js/Cytoscape)
│   ├── index.html              # 仪表盘控制台
│   ├── devices.html            # 设备管理与心跳检测
│   ├── topology.html           # 拓扑拓扑画板与 Ping Mesh
│   ├── features.html           # 100 项特性配置向导
│   ├── configure.html          # 批量模板渲染与任务下发
│   ├── backup.html             # 配置备份与差异比对
│   └── audit.html              # 等保合规与巡检报告
└── utils/                      # 核心业务组件
    ├── feature_engine.py       # 100 项特性配置/Undo 引擎
    ├── topology_engine.py      # 拓扑解析、克隆与 Ping Mesh 探测
    ├── device_manager.py       # Netmiko + Raw Socket 并发连接管理器
    ├── config_generator.py     # Jinja2 安全沙箱模板生成器
    ├── backup_manager.py       # 配置文件备份与 Diff 比对引擎
    ├── audit_engine.py         # 等保 2.0 四维合规性审计引擎
    ├── risk_guard.py           # CLI 高危指令熔断防护器
    ├── job_logger.py           # SQLite 任务审计日志中心
    └── device_scanner.py       # 端口扫描与指纹自动发现器
```

---

## 🚀 快速上手指南

### 1. 安装环境依赖

```bash
# 建议使用 Python 3.10+
pip install -r requirements.txt
```

### 2. 启动 Web 平台

```bash
python app.py
```
启动成功后，在浏览器访问：`http://127.0.0.1:5000`

### 3. 执行端到端自动化测试

系统内置包含 100 项全栈网络特性及全流程能力的回归测试套件：

```bash
python test_100_features.py
```

---

## 🔒 安全性说明

* **防 CWE-22 路径遍历**：模板文件与备份文件操作统一进行 `os.path.basename` 白名单清洗。
* **防 SSTI 模板注入**：采用 `jinja2.sandbox.SandboxedEnvironment`，严格阻断沙箱逃逸与代码执行。
* **凭据保险箱 (Vault)**：`devices.yaml` 中设备口令经 `ENC:v1:...` 静态加密，支持通过环境变量 `NETWORK_CONFIG_VAULT_KEY` 动态注入密钥。
* **原子写入机制**：资产文件保存采用 `tempfile` + `os.replace` 原子替换，避免写入中断损坏文件。

---

## 📄 License
MIT License
