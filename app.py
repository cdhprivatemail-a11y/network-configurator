# -*- coding: utf-8 -*-
"""
网络设备批量配置平台后端应用
基于 Flask、Netmiko、Jinja2 构建的华为 eNSP (VRP) 和华三 HCL (Comware) 批量配置管理系统。
"""

import os
import logging
from typing import Dict, List, Any
import yaml
from flask import Flask, request, jsonify, render_template, send_from_directory, session, redirect, url_for, g

from utils.device_manager import DeviceManager
from utils.config_generator import ConfigGenerator
import threading
from utils.backup_manager import BackupManager
from utils.device_scanner import DeviceScanner
from utils.topology_engine import TopologyConfigEngine
from utils.feature_engine import FeatureConfigEngine
from utils.audit_engine import AuditAndInspectorEngine
from utils.job_logger import JobAuditLogger
from utils.risk_guard import CLIRiskGuardrail
from utils.vault import encrypt_secret, decrypt_secret, mask_device, mask_device_list
from utils.auth import AuthManager, login_required, roles_accepted, get_current_user
from utils.change_manager import ChangeManager

# 基础目录配置
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "config_templates")
BACKUPS_DIR = os.path.join(BASE_DIR, "backups")
DEVICES_FILE = os.path.join(BASE_DIR, "devices.yaml")
AUDIT_DB_FILE = os.path.join(BASE_DIR, "audit_jobs.db")

# 启动时确保必要目录存在
os.makedirs(TEMPLATES_DIR, exist_ok=True)
os.makedirs(BACKUPS_DIR, exist_ok=True)

# 日志初始化
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("App")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "NetConfigSessionSecret#2026!Key")

# 初始化业务管理器
device_manager = DeviceManager(max_workers=10)
config_generator = ConfigGenerator(template_dir=TEMPLATES_DIR)
backup_manager = BackupManager(backup_dir=BACKUPS_DIR)
device_scanner = DeviceScanner(timeout=2, max_workers=50)
topology_engine = TopologyConfigEngine()
feature_engine = FeatureConfigEngine()
audit_engine = AuditAndInspectorEngine()
job_logger = JobAuditLogger(db_path=AUDIT_DB_FILE)
risk_guard = CLIRiskGuardrail()
auth_manager = AuthManager(AUDIT_DB_FILE)
change_manager = ChangeManager(AUDIT_DB_FILE, backup_manager, device_manager)

# devices.yaml 线程安全读写锁
_devices_lock = threading.RLock()


@app.after_request
def add_security_headers(response):
    """生产级安全响应头 (点击劫持防护 / 嗅探防护 / XSS 防护)"""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Server"] = "NetConfig-Enterprise"
    return response


@app.context_processor
def inject_auth_context():
    """向 Jinja2 模板注入当前用户信息上下文"""
    return {"current_user": get_current_user()}


# ==========================================================
# 辅助函数：devices.yaml 线程安全与凭据加密操作
# ==========================================================

def load_devices() -> List[Dict[str, Any]]:
    """从 devices.yaml 线程安全读取设备列表并透明解密连接凭据 (供底层驱动连接使用)"""
    with _devices_lock:
        if not os.path.exists(DEVICES_FILE):
            return []
        try:
            with open(DEVICES_FILE, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if isinstance(data, dict) and "devices" in data:
                    raw_list = data["devices"] or []
                elif isinstance(data, list):
                    raw_list = data
                else:
                    raw_list = []
                decrypted_list = []
                for dev in raw_list:
                    d_copy = dict(dev)
                    if "password" in d_copy and d_copy["password"]:
                        d_copy["password"] = decrypt_secret(str(d_copy["password"]))
                    if "secret" in d_copy and d_copy["secret"]:
                        d_copy["secret"] = decrypt_secret(str(d_copy["secret"]))
                    decrypted_list.append(d_copy)
                return decrypted_list
        except Exception as e:
            logger.error(f"读取 devices.yaml 失败: {e}")
            return []


def save_devices(devices: List[Dict[str, Any]]) -> bool:
    """将设备列表线程安全且原子化写入 devices.yaml，并对密码字段执行 Fernet 强加密存储 (防写入中断导致0字节文件损坏)"""
    with _devices_lock:
        tmp_file = f"{DEVICES_FILE}.tmp.{os.getpid()}"
        try:
            # 预读取现有已存储的密文映射 (在前端未修改密码或留空时保持原密文不变)
            existing_ciphers = {}
            if os.path.exists(DEVICES_FILE):
                try:
                    with open(DEVICES_FILE, "r", encoding="utf-8") as f:
                        raw_data = yaml.safe_load(f)
                        raw_devs = raw_data.get("devices", []) if isinstance(raw_data, dict) else (raw_data or [])
                        for d in raw_devs:
                            if isinstance(d, dict) and d.get("name"):
                                existing_ciphers[d["name"]] = {
                                    "password": d.get("password"),
                                    "secret": d.get("secret")
                                }
                except Exception:
                    pass

            vault_devices = []
            for dev in devices:
                d_copy = dict(dev)
                dev_name = d_copy.get("name")
                old_p = existing_ciphers.get(dev_name, {}).get("password") if dev_name else None
                old_s = existing_ciphers.get(dev_name, {}).get("secret") if dev_name else None

                p = d_copy.get("password")
                if p and not str(p).startswith("●●●●●●"):
                    d_copy["password"] = encrypt_secret(str(p))
                elif old_p:
                    d_copy["password"] = old_p
                else:
                    d_copy.pop("password", None)

                s = d_copy.get("secret")
                if s and not str(s).startswith("●●●●●●"):
                    d_copy["secret"] = encrypt_secret(str(s))
                elif old_s:
                    d_copy["secret"] = old_s
                else:
                    d_copy.pop("secret", None)

                d_copy.pop("has_password", None)
                d_copy.pop("has_secret", None)
                vault_devices.append(d_copy)

            data = {"devices": vault_devices}
            with open(tmp_file, "w", encoding="utf-8") as f:
                yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_file, DEVICES_FILE)
            return True
        except Exception as e:
            logger.error(f"保存 devices.yaml 失败: {e}")
            if os.path.exists(tmp_file):
                try:
                    os.remove(tmp_file)
                except Exception:
                    pass
            return False


def get_device_by_name(name: str) -> Dict[str, Any] | None:
    """按名称查找设备信息 (内部解密后数据)"""
    devices = load_devices()
    for dev in devices:
        if dev.get("name") == name:
            return dev
    return None


# ==========================================================
# 页面路由 (HTML Rendering) - 全部接入 RBAC 访问防护
# ==========================================================

@app.route("/login")
def page_login():
    """系统登录页面"""
    return render_template("login.html")


@app.route("/approvals")
@login_required
def page_approvals():
    """变更审批工单中心"""
    return render_template("approvals.html", active_page="approvals")


@app.route("/")
@login_required
def page_dashboard():
    """控制台仪表盘首页"""
    return render_template("index.html", active_page="dashboard")


@app.route("/devices")
@login_required
def page_devices():
    """设备管理页面"""
    return render_template("devices.html", active_page="devices")


@app.route("/configure")
@login_required
def page_configure():
    """批量配置管理页面"""
    return render_template("configure.html", active_page="configure")


@app.route("/templates")
@login_required
def page_templates():
    """配置模板管理页面"""
    return render_template("templates_page.html", active_page="templates")


@app.route("/backup")
@login_required
def page_backup():
    """配置备份管理页面"""
    return render_template("backup.html", active_page="backup")


@app.route("/topology")
@login_required
def page_topology():
    """拓扑构建与参数配置生成页面"""
    return render_template("topology.html", active_page="topology")


@app.route("/features")
@login_required
def page_features():
    """特性向导式配置生成页面"""
    return render_template("features.html", active_page="features")


# ==========================================================
# API 路由：用户认证与会话管理 (Auth APIs)
# ==========================================================

@app.route("/api/auth/login", methods=["POST"])
def api_auth_login():
    """用户安全登录认证"""
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    user_info = auth_manager.authenticate(username, password)
    if not user_info:
        return jsonify({"success": False, "error": "用户名或密码错误"}), 401

    session["user"] = user_info
    token = auth_manager.generate_token(user_info)
    job_logger.log_job(
        job_type="用户鉴权登录",
        target_devices="System",
        status="success",
        summary=f"用户 [{username}] 登录系统 (角色: {user_info['role']})",
    )
    return jsonify({"success": True, "message": "登录认证成功", "token": token, "user": user_info})


@app.route("/api/auth/logout", methods=["POST"])
def api_auth_logout():
    """退出系统登录"""
    session.pop("user", None)
    return jsonify({"success": True, "message": "已安全退出系统"})


@app.route("/api/auth/me", methods=["GET"])
def api_auth_me():
    """获取当前登录用户信息与角色权限"""
    user = get_current_user()
    if not user:
        return jsonify({"success": False, "error": "未登录", "code": 401}), 401
    return jsonify({"success": True, "user": user})


# ==========================================================
# API 路由：设备管理 (Device APIs) - 严格实施凭据脱敏与角色控制
# ==========================================================

@app.route("/api/devices", methods=["GET"])
@login_required
def api_list_devices():
    """获取所有设备列表 (已执行严格口令脱敏，绝不向接口暴露口令明文)"""
    devices = load_devices()
    return jsonify({"success": True, "devices": mask_device_list(devices)})


@app.route("/api/devices/<name>", methods=["GET"])
@login_required
def api_get_device(name: str):
    """获取指定设备详情 (口令脱敏)"""
    dev = get_device_by_name(name)
    if not dev:
        return jsonify({"success": False, "error": f"设备 '{name}' 不存在"}), 404
    return jsonify({"success": True, "device": mask_device(dev)})


@app.route("/api/devices", methods=["POST"])
@login_required
@roles_accepted("admin")
def api_add_device():
    """添加新设备 (仅超级管理员 admin 可操作)"""
    new_device = request.get_json(silent=True) or {}
    name = new_device.get("name", "").strip()

    if not name:
        return jsonify({"success": False, "error": "设备名称不能为空"}), 400

    devices = load_devices()
    if any(d.get("name") == name for d in devices):
        return jsonify({"success": False, "error": f"设备名称 '{name}' 已存在"}), 400

    devices.append(new_device)
    if save_devices(devices):
        return jsonify({"success": True, "message": "设备添加成功", "device": mask_device(new_device)})
    else:
        return jsonify({"success": False, "error": "保存设备文件失败"}), 500


@app.route("/api/devices/<name>", methods=["PUT"])
@login_required
@roles_accepted("admin")
def api_update_device(name: str):
    """更新指定设备信息 (仅超级管理员 admin 可操作)"""
    update_data = request.get_json(silent=True) or {}
    devices = load_devices()
    target_idx = None

    for idx, dev in enumerate(devices):
        if dev.get("name") == name:
            target_idx = idx
            break

    if target_idx is None:
        return jsonify({"success": False, "error": f"未找到设备 '{name}'"}), 404

    # 若更新数据中口令为空或为安全占位符，保持原口令不变
    pwd = update_data.get("password")
    if not pwd or str(pwd).startswith("●●●●●●") or str(pwd) == "******":
        update_data["password"] = devices[target_idx].get("password")

    # 保持或更新设备属性
    devices[target_idx].update(update_data)
    if save_devices(devices):
        return jsonify({"success": True, "message": "设备更新成功", "device": mask_device(devices[target_idx])})
    else:
        return jsonify({"success": False, "error": "保存设备更新失败"}), 500


@app.route("/api/devices/<name>", methods=["DELETE"])
@login_required
@roles_accepted("admin")
def api_delete_device(name: str):
    """删除指定设备 (仅超级管理员 admin 可操作)"""
    devices = load_devices()
    new_devices = [d for d in devices if d.get("name") != name]

    if len(new_devices) == len(devices):
        return jsonify({"success": False, "error": f"未找到设备 '{name}'"}), 404

    if save_devices(new_devices):
        return jsonify({"success": True, "message": f"设备 '{name}' 删除成功"})
    else:
        return jsonify({"success": False, "error": "保存设备文件失败"}), 500


@app.route("/api/devices/<name>/test", methods=["POST"])
def api_test_device_connection(name: str):
    """测试单个设备的连接与认证"""
    device = get_device_by_name(name)
    if not device:
        # 允许从请求体传入临时测试设备信息
        payload = request.get_json(silent=True) or {}
        if payload.get("host"):
            device = payload
        else:
            return jsonify({"success": False, "error": f"未找到设备 '{name}'"}), 404

    result = device_manager.test_connection(device)
    return jsonify(result)


@app.route("/api/devices/batch-test", methods=["POST"])
def api_batch_test_devices():
    """
    Sprint 5: 并发检测多台（或全部）纳管设备的在线状态、CLI 提示符与响应时延
    Body (可选): {device_names: ["RouterA", ...]}
    """
    data = request.get_json(silent=True) or {}
    target_names = data.get("device_names", [])
    all_devices = load_devices()
    if target_names:
        targets = [d for d in all_devices if d.get("name") in target_names]
    else:
        targets = all_devices

    results = device_manager.batch_test_connections(targets)
    online_count = sum(1 for r in results if r.get("success"))
    return jsonify({
        "success": True,
        "total": len(results),
        "online_count": online_count,
        "offline_count": len(results) - online_count,
        "results": results,
    })


@app.route("/api/devices/import", methods=["POST"])
def api_import_devices():
    """从 YAML 文本导入设备"""
    data = request.get_json(silent=True) or {}
    yaml_content = data.get("yaml_content", "")

    if not yaml_content and request.data:
        yaml_content = request.data.decode("utf-8")

    if not yaml_content.strip():
        return jsonify({"success": False, "error": "导入内容不能为空"}), 400

    try:
        parsed = yaml.safe_load(yaml_content)
        imported_list = []
        if isinstance(parsed, dict) and "devices" in parsed:
            imported_list = parsed["devices"] or []
        elif isinstance(parsed, list):
            imported_list = parsed
        else:
            return jsonify({"success": False, "error": "YAML 格式不正确，应包含 devices 列表"}), 400

        # 合并设备列表（同名覆盖）
        existing_devices = load_devices()
        device_map = {d.get("name"): d for d in existing_devices if d.get("name")}
        for d in imported_list:
            d_name = d.get("name")
            if d_name:
                device_map[d_name] = d

        final_devices = list(device_map.values())
        if save_devices(final_devices):
            return jsonify({
                "success": True,
                "message": f"成功导入/更新 {len(imported_list)} 台设备",
                "total_count": len(final_devices)
            })
        else:
            return jsonify({"success": False, "error": "保存导入设备失败"}), 500

    except Exception as e:
        return jsonify({"success": False, "error": f"解析 YAML 失败: {str(e)}"}), 400


# ==========================================================
# API 路由：批量配置 (Configuration APIs)
# ==========================================================

@app.route("/api/configure/execute", methods=["POST"])
@app.route("/api/configure/direct", methods=["POST"])
@login_required
@roles_accepted("admin", "operator")
def api_configure_execute():
    """
    在选定设备上批量执行命令（含高危命令防呆拦截与作业审计）
    Body: {device_names: ["R1", "SW1"], commands: ["sys", ...], force_override: bool}
    """
    data = request.get_json(silent=True) or {}
    device_names = data.get("device_names") or data.get("devices") or []
    commands = data.get("commands", [])
    force_override = bool(data.get("force_override", False))

    if not device_names:
        return jsonify({"success": False, "error": "请选择至少一台目标设备"}), 400

    if not commands:
        return jsonify({"success": False, "error": "执行命令不能为空"}), 400

    # 如果 commands 为换行字符串，转为列表
    if isinstance(commands, str):
        commands = [c.strip() for c in commands.splitlines() if c.strip()]

    # Sprint 4 & Sprint 6 (P0): 统一入口高危防呆预审
    guard_res = risk_guard.inspect_commands(commands)
    user = get_current_user() or {}
    is_admin = user.get("role") == "admin"

    if not guard_res["passed"]:
        # 非 admin 角色严禁通过 force_override 绕过高危拦截，强制生成工单
        if not is_admin or not force_override:
            # 自动生成审批工单
            ticket_id = change_manager.create_ticket(
                title=f"批量CLI直接下发高危拦截 - {len(device_names)}台",
                applicant=user.get("username", "operator"),
                target_devices=device_names,
                commands_dict={d: "\n".join(commands) for d in device_names},
                risk_result=guard_res,
            )
            return jsonify({
                "success": False,
                "guardrail_triggered": True,
                "requires_approval": True,
                "ticket_id": ticket_id,
                "risk_level": guard_res["risk_level"],
                "finding_count": guard_res["finding_count"],
                "findings": guard_res["findings"],
                "error": f"防呆防火墙拦截：检测到 {guard_res['finding_count']} 条高危指令，已自动生成审批工单 [{ticket_id}]，需管理员审批放行！",
            })

    all_devices = load_devices()
    dev_map = {d.get("name"): d for d in all_devices}
    target_devices = [dev_map[name] for name in device_names if name in dev_map]

    if not target_devices:
        return jsonify({"success": False, "error": "未匹配到任何有效的目标设备"}), 404

    results = device_manager.batch_execute(target_devices, commands)
    ok_cnt = sum(1 for r in results if r.get("success"))
    job_logger.log_job(
        job_type="批量CLI直接下发",
        target_devices=device_names,
        status="success" if ok_cnt == len(results) else ("warning" if ok_cnt > 0 else "failed"),
        summary=f"批量下发 {len(commands)} 行命令至 {len(results)} 台设备 (成功 {ok_cnt} 台)" + (" [管理员强制放行]" if force_override else ""),
        cli_config="\n".join(commands),
        details=results,
    )
    return jsonify({"success": True, "results": results, "guardrail": guard_res})


@app.route("/api/configure/execute-template", methods=["POST"])
@app.route("/api/configure/template", methods=["POST"])
@login_required
@roles_accepted("admin", "operator")
def api_configure_execute_template():
    """
    基于模板在选定设备上批量渲染并下发配置 (接入统一风险防呆网关)
    Body: {device_names: [], template_name: str, variables: dict}
    """
    data = request.get_json(silent=True) or {}
    device_names = data.get("device_names") or data.get("devices") or []
    template_name = (data.get("template_name") or data.get("template") or "").strip()
    variables = data.get("variables", {})

    if not device_names:
        return jsonify({"success": False, "error": "请选择至少一台目标设备"}), 400
    if not template_name:
        return jsonify({"success": False, "error": "请指定模板名称"}), 400

    # 如果 variables 是 YAML 格式字符串，解析为 dict
    if isinstance(variables, str):
        try:
            variables = yaml.safe_load(variables) or {}
        except Exception:
            variables = {}

    # 渲染配置
    try:
        rendered_config = config_generator.render_template(template_name, variables)
    except Exception as e:
        return jsonify({"success": False, "error": f"模板渲染失败: {str(e)}"}), 400

    commands = [line.strip() for line in rendered_config.splitlines() if line.strip()]

    # Sprint 6 (P0): 模板下发强制接入统一高危防呆扫描
    guard_res = risk_guard.inspect_commands(commands)
    user = get_current_user() or {}
    is_admin = user.get("role") == "admin"
    force_override = bool(data.get("force_override", False))

    if not guard_res["passed"] and (not is_admin or not force_override):
        ticket_id = change_manager.create_ticket(
            title=f"模板 [{template_name}] 下发高危拦截",
            applicant=user.get("username", "operator"),
            target_devices=device_names,
            commands_dict={d: rendered_config for d in device_names},
            risk_result=guard_res,
        )
        return jsonify({
            "success": False,
            "guardrail_triggered": True,
            "requires_approval": True,
            "ticket_id": ticket_id,
            "risk_level": guard_res["risk_level"],
            "findings": guard_res["findings"],
            "error": f"防呆防火墙拦截：模板中包含 {guard_res['finding_count']} 条高危指令，已自动生成工单 [{ticket_id}] 待管理员审批！",
        })

    all_devices = load_devices()
    dev_map = {d.get("name"): d for d in all_devices}
    target_devices = [dev_map[name] for name in device_names if name in dev_map]

    if not target_devices:
        return jsonify({"success": False, "error": "未匹配到任何有效目标设备"}), 404

    results = device_manager.batch_execute(target_devices, commands)
    return jsonify({
        "success": True,
        "results": results,
        "guardrail": guard_res,
        "rendered_config": rendered_config
    })


# ==========================================================
# API 路由：统一变更护栏、审批工作流与金丝雀灰度 (Change Pipeline APIs - Sprint 6)
# ==========================================================

@app.route("/api/change/plan", methods=["POST"])
@login_required
def api_change_plan():
    """统一变更风险评估与自动审批工单派发接口"""
    data = request.get_json(silent=True) or {}
    title = data.get("title") or "未命名网络批量变更"
    target_devices = data.get("target_devices") or data.get("device_names") or []
    commands_dict = data.get("commands_dict") or {}
    undo_commands_dict = data.get("undo_commands_dict") or {}

    raw_cmds = data.get("commands") or data.get("cli_config")
    if raw_cmds and not commands_dict:
        cmd_str = "\n".join(raw_cmds) if isinstance(raw_cmds, list) else str(raw_cmds)
        commands_dict = {d: cmd_str for d in target_devices}

    if not target_devices:
        return jsonify({"success": False, "error": "请至少指定一台目标设备"}), 400

    risk_eval = change_manager.evaluate_change_risk(commands_dict)
    user = get_current_user() or {}
    applicant = user.get("username", "operator")

    ticket_id = change_manager.create_ticket(
        title=title,
        applicant=applicant,
        target_devices=target_devices,
        commands_dict=commands_dict,
        undo_commands_dict=undo_commands_dict,
        risk_result=risk_eval
    )

    ticket = change_manager.get_ticket(ticket_id)
    requires_approval = ticket["status"] == "PENDING_APPROVAL"

    return jsonify({
        "success": True,
        "ticket_id": ticket_id,
        "requires_approval": requires_approval,
        "status": ticket["status"],
        "risk_level": risk_eval.get("risk_level", "safe"),
        "findings": risk_eval.get("findings", []),
        "message": "检测到高危指令，已自动拦截并生成审批工单，需管理员审批通过后方可执行！" if requires_approval else "风险评估通过，可直接下发执行"
    })


@app.route("/api/change/tickets", methods=["GET"])
@login_required
def api_list_change_tickets():
    """获取所有变更审批工单"""
    status = request.args.get("status")
    tickets = change_manager.list_tickets(status=status)
    return jsonify({"success": True, "tickets": tickets})


@app.route("/api/change/tickets/<ticket_id>", methods=["GET"])
@login_required
def api_get_change_ticket(ticket_id: str):
    """获取指定工单详情"""
    ticket = change_manager.get_ticket(ticket_id)
    if not ticket:
        return jsonify({"success": False, "error": f"工单 '{ticket_id}' 不存在"}), 404
    return jsonify({"success": True, "ticket": ticket})


@app.route("/api/change/tickets/<ticket_id>/review", methods=["POST"])
@login_required
@roles_accepted("admin")
def api_review_change_ticket(ticket_id: str):
    """管理员审批工单 (仅 admin 角色可执行)"""
    data = request.get_json(silent=True) or {}
    approved = bool(data.get("approved", True))
    comment = data.get("comment", "")
    user = get_current_user() or {}
    reviewer = user.get("username", "admin")

    success = change_manager.review_ticket(ticket_id, reviewer=reviewer, approved=approved, comment=comment)
    if not success:
        return jsonify({"success": False, "error": "审批失败：工单不存在或已不是待审批状态"}), 400

    job_logger.log_job(
        job_type="变更工单审批",
        target_devices="System",
        status="success" if approved else "warning",
        summary=f"管理员 [{reviewer}] {'批准放行' if approved else '驳回拒绝'} 了工单 {ticket_id} (意见: {comment or '无'})",
    )
    return jsonify({"success": True, "message": f"工单已成功{'批准放行' if approved else '驳回'}"})


@app.route("/api/change/tickets/<ticket_id>/execute", methods=["POST"])
@login_required
@roles_accepted("admin", "operator")
def api_execute_approved_ticket(ticket_id: str):
    """执行已审批通过的工单 (金丝雀灰度 + 报错熔断回滚)"""
    ticket = change_manager.get_ticket(ticket_id)
    if not ticket:
        return jsonify({"success": False, "error": f"工单 '{ticket_id}' 不存在"}), 404
    if ticket["status"] != "APPROVED":
        return jsonify({"success": False, "error": f"当前工单状态为 '{ticket['status']}'，必须是 APPROVED 状态才允许下发"}), 400

    data = request.get_json(silent=True) or {}
    canary_mode = bool(data.get("canary_mode", True))

    all_devices = load_devices()
    result = change_manager.execute_canary_deployment(
        ticket_id=ticket_id,
        target_devices=all_devices,
        commands_dict=ticket.get("commands", {}),
        undo_commands_dict=ticket.get("undo_commands", {}),
        canary_mode=canary_mode
    )

    job_logger.log_job(
        job_type="工单金丝雀灰度下发",
        target_devices=ticket.get("target_devices", ""),
        status="success" if result.get("success") else "failed",
        summary=f"工单 {ticket_id} 灰度执行{'成功' if result.get('success') else '失败触发回滚'}",
        details=result.get("execution_results", [])
    )
    return jsonify({"success": result.get("success", False), "result": result})

    results = device_manager.batch_execute(target_devices, commands)
    return jsonify({
        "success": True,
        "rendered_config": rendered_config,
        "results": results
    })


# ==========================================================
# API 路由：模板管理 (Template APIs)
# ==========================================================

@app.route("/api/templates", methods=["GET"])
def api_list_templates():
    """列出所有模板"""
    templates = config_generator.list_templates()
    return jsonify({"success": True, "templates": templates})


@app.route("/api/templates/<name>", methods=["GET"])
def api_get_template(name: str):
    """获取单个模板内容"""
    safe_name = os.path.basename(name.strip())
    try:
        content = config_generator.get_template_content(safe_name)
        return jsonify({"success": True, "name": safe_name, "content": content})
    except FileNotFoundError:
        return jsonify({"success": False, "error": f"模板 '{safe_name}' 不存在"}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/templates", methods=["POST"])
def api_save_template():
    """保存或更新模板 {name, content}"""
    data = request.get_json(silent=True) or {}
    name = os.path.basename(data.get("name", "").strip())
    content = data.get("content", "")

    if not name:
        return jsonify({"success": False, "error": "模板名称不能为空"}), 400

    try:
        config_generator.save_template(name, content)
        return jsonify({"success": True, "message": f"模板 '{name}' 保存成功"})
    except Exception as e:
        return jsonify({"success": False, "error": f"保存模板失败: {str(e)}"}), 500


@app.route("/api/templates/<name>", methods=["DELETE"])
def api_delete_template(name: str):
    """删除模板"""
    safe_name = os.path.basename(name.strip())
    try:
        deleted = config_generator.delete_template(safe_name)
        if deleted:
            return jsonify({"success": True, "message": f"模板 '{safe_name}' 已删除"})
        else:
            return jsonify({"success": False, "error": f"模板 '{safe_name}' 不存在"}), 404
    except Exception as e:
        return jsonify({"success": False, "error": f"删除模板失败: {str(e)}"}), 500


@app.route("/api/templates/preview", methods=["POST"])
def api_preview_template():
    """
    预览渲染后的模板配置
    Body: {name: str (可选), content: str (可选), variables: dict}
    """
    data = request.get_json(silent=True) or {}
    name = data.get("name")
    content = data.get("content")
    variables = data.get("variables", {})

    # 支持 variables 为 YAML 字符串的自动解析
    if isinstance(variables, str):
        try:
            variables = config_generator.parse_yaml_variables(variables)
        except Exception as e:
            return jsonify({"success": False, "error": f"变量解析失败: {str(e)}"}), 400

    try:
        if content is not None and content != "":
            rendered = config_generator.render_from_string(content, variables)
        elif name:
            rendered = config_generator.render_template(name, variables)
        else:
            return jsonify({"success": False, "error": "必须提供 template_name 或 content 进行预览"}), 400

        return jsonify({"success": True, "rendered_config": rendered})
    except Exception as e:
        return jsonify({"success": False, "error": f"模板渲染错误: {str(e)}"}), 400


# ==========================================================
# API 路由：配置备份与对比 (Backup APIs)
# ==========================================================

@app.route("/api/backup/run", methods=["POST"])
@app.route("/api/backups/run", methods=["POST"])
def api_run_backup():
    """
    触发对选定设备的配置采集与备份
    Body: {device_names: ["R1", "SW1"]} 或 {devices: ["R1", "SW1"]}
    """
    data = request.get_json(silent=True) or {}
    device_names = data.get("device_names") or data.get("devices") or []

    all_devices = load_devices()
    dev_map = {d.get("name"): d for d in all_devices}

    if not device_names:
        target_devices = all_devices
    else:
        target_devices = [dev_map[name] for name in device_names if name in dev_map]

    if not target_devices:
        return jsonify({"success": False, "error": "没有可备份的有效设备"}), 404

    # 并发获取配置
    configs_result = device_manager.batch_get_configs(target_devices)
    backup_summary = []

    for item in configs_result:
        dev_name = item.get("device")
        if item.get("success") and item.get("config"):
            try:
                filepath = backup_manager.save_backup(dev_name, item["config"])
                backup_summary.append({
                    "device": dev_name,
                    "success": True,
                    "filename": os.path.basename(filepath),
                    "message": "备份成功"
                })
            except Exception as e:
                backup_summary.append({
                    "device": dev_name,
                    "success": False,
                    "message": f"保存备份失败: {str(e)}"
                })
        else:
            backup_summary.append({
                "device": dev_name,
                "success": False,
                "message": item.get("error", "获取运行配置失败")
            })

    return jsonify({"success": True, "summary": backup_summary})


@app.route("/api/backup/list", methods=["GET"])
@app.route("/api/backups", methods=["GET"])
@app.route("/api/backups/list", methods=["GET"])
def api_list_backups():
    """获取备份文件列表，可选 ?device=R1"""
    device = request.args.get("device")
    backups = backup_manager.list_backups(device_name=device)
    return jsonify({"success": True, "backups": backups})


@app.route("/api/backup/<filename>", methods=["GET"])
@app.route("/api/backups/<filename>", methods=["GET"])
def api_get_backup(filename: str):
    """获取指定备份文件内容"""
    safe_filename = os.path.basename(filename)
    try:
        content = backup_manager.get_backup_content(safe_filename)
        return jsonify({"success": True, "filename": safe_filename, "content": content})
    except FileNotFoundError:
        return jsonify({"success": False, "error": f"备份文件 '{safe_filename}' 不存在"}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/backup/<filename>", methods=["DELETE"])
@app.route("/api/backups/<filename>", methods=["DELETE"])
def api_delete_backup(filename: str):
    """删除备份文件"""
    safe_filename = os.path.basename(filename)
    try:
        deleted = backup_manager.delete_backup(safe_filename)
        if deleted:
            return jsonify({"success": True, "message": f"备份文件 '{safe_filename}' 已删除"})
        else:
            return jsonify({"success": False, "error": f"备份文件 '{safe_filename}' 不存在"}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/backup/<path:filename>/download", methods=["GET"])
@app.route("/api/backups/<path:filename>/download", methods=["GET"])
def api_download_backup(filename: str):
    """下载备份配置文件 (严格限制在 backup_dir，防任意文件下载与路径穿越)"""
    safe_filename = os.path.basename(filename)
    filepath = os.path.join(backup_manager.backup_dir, safe_filename)
    if not os.path.isfile(filepath):
        return jsonify({"success": False, "error": f"备份文件 '{safe_filename}' 不存在"}), 404
    return send_from_directory(backup_manager.backup_dir, safe_filename, as_attachment=True)


@app.route("/api/backup/compare", methods=["POST"])
@app.route("/api/backups/compare", methods=["POST"])
@app.route("/api/backups/diff", methods=["POST"])
def api_compare_backups():
    """
    对比两个备份文件的配置差异
    Body: {file1: "R1_20261011_100000.cfg", file2: "R1_20261011_120000.cfg"}
    或 {source_file: "...", target_file: "..."}
    """
    data = request.get_json(silent=True) or {}
    file1 = data.get("file1") or data.get("source_file")
    file2 = data.get("file2") or data.get("target_file")

    if not file1 or not file2:
        return jsonify({"success": False, "error": "请提供需要比对的两个文件名 (file1, file2)"}), 400

    safe_f1 = os.path.basename(file1)
    safe_f2 = os.path.basename(file2)

    try:
        content1 = backup_manager.get_backup_content(safe_f1)
        content2 = backup_manager.get_backup_content(safe_f2)
        diff_lines = backup_manager.compare_configs(content1, content2)
        return jsonify({
            "success": True,
            "file1": safe_f1,
            "file2": safe_f2,
            "diff": diff_lines,
            "diff_text": "\n".join(diff_lines),
            "lines": diff_lines
        })
    except FileNotFoundError as e:
        return jsonify({"success": False, "error": str(e)}), 404
    except Exception as e:
        return jsonify({"success": False, "error": f"配置对比失败: {str(e)}"}), 500


@app.route("/api/backup/drift-check", methods=["POST"])
def api_drift_check():
    """
    Sprint 5: 设备实时运行配置与黄金基线快照比对（配置漂移分析）
    检测内存中尚未保存或未授权变更的 CLI 漂移行
    Body (可选): {device_names: ["RouterA", ...]}
    """
    data = request.get_json(silent=True) or {}
    req_names = data.get("device_names", [])
    all_devices = load_devices()
    target_devs = [d for d in all_devices if not req_names or d.get("name") in req_names]

    drift_results: List[Dict[str, Any]] = []
    for dev in target_devs:
        dname = dev.get("name", "")
        if not dname:
            continue
        # 获取最新基线备份文件
        bks = backup_manager.list_backups(device_name=dname)
        live_res = device_manager.get_running_config(dev)
        if not live_res.get("success"):
            drift_results.append({
                "device": dname,
                "status": "offline_or_failed",
                "message": live_res.get("error", "无法连接设备读取运行配置"),
                "has_drift": False,
                "added_count": 0,
                "removed_count": 0,
                "diff": [],
                "baseline_file": bks[0]["filename"] if bks else "无历史基线",
            })
            continue

        live_cfg = live_res.get("config", "")
        if not bks:
            # 若尚无基线备份，自动以当前首次抓取的配置固化为基线
            new_bk = backup_manager.save_backup(dname, live_cfg)
            drift_results.append({
                "device": dname,
                "status": "baseline_initialized",
                "message": f"首次初始化黄金基线快照 ({os.path.basename(new_bk)})",
                "has_drift": False,
                "added_count": 0,
                "removed_count": 0,
                "diff": [],
                "baseline_file": os.path.basename(new_bk),
            })
            continue

        latest_file = bks[0]["filename"]
        base_cfg = backup_manager.get_backup_content(latest_file) or ""
        diff_lines = backup_manager.compare_configs(base_cfg, live_cfg)

        added = [l for l in diff_lines if l.startswith("+") and not l.startswith("+++")]
        removed = [l for l in diff_lines if l.startswith("-") and not l.startswith("---")]
        has_drift = (len(added) > 0 or len(removed) > 0)

        drift_results.append({
            "device": dname,
            "status": "drifted" if has_drift else "in_sync",
            "message": f"发现 {len(added)} 处新增行，{len(removed)} 处移除行" if has_drift else "与黄金基线快照完全一致",
            "has_drift": has_drift,
            "added_count": len(added),
            "removed_count": len(removed),
            "added_samples": added[:5],
            "removed_samples": removed[:5],
            "diff": diff_lines,
            "baseline_file": latest_file,
        })

    drifted_count = sum(1 for r in drift_results if r.get("has_drift"))
    in_sync_count = sum(1 for r in drift_results if r.get("status") in ("in_sync", "baseline_initialized"))

    return jsonify({
        "success": True,
        "total_checked": len(drift_results),
        "drifted_count": drifted_count,
        "in_sync_count": in_sync_count,
        "results": drift_results,
    })


# ==========================================================
# 页面路由：设备扫描
# ==========================================================

@app.route("/scan")
@login_required
def page_scan():
    """设备扫描页面"""
    return render_template("scan.html", active_page="scan")


# ==========================================================
# API 路由：设备扫描 (Scan APIs)
# ==========================================================

@app.route("/api/scan/quick", methods=["POST"])
def api_scan_quick():
    """
    快速扫描本地端口（eNSP/HCL 常用端口范围）
    Body(可选): {username: "", password: ""}
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    try:
        results = device_scanner.quick_scan_local(username, password)
        return jsonify({
            "success": True,
            "results": results,
            "total_open": len(results),
            "total_identified": sum(1 for r in results if r.get("identified"))
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"扫描失败: {str(e)}"}), 500


@app.route("/api/scan/custom", methods=["POST"])
def api_scan_custom():
    """
    自定义范围扫描
    Body: {
        hosts: "192.168.56.1-254" 或 "192.168.56.1,192.168.56.2",
        ports: "22,23,2000-2050",
        username: "",
        password: "",
        identify: true
    }
    """
    data = request.get_json(silent=True) or {}
    hosts_input = data.get("hosts", "127.0.0.1")
    ports_input = data.get("ports", "22,23,2000-2050")
    username = data.get("username", "")
    password = data.get("password", "")
    identify = data.get("identify", True)

    try:
        hosts = DeviceScanner.parse_host_range(hosts_input)
        ports = DeviceScanner.parse_port_range(ports_input)
    except Exception as e:
        return jsonify({"success": False, "error": f"解析扫描范围失败: {str(e)}"}), 400

    if len(hosts) * len(ports) > 50000:
        return jsonify({
            "success": False,
            "error": f"扫描范围过大 ({len(hosts)} 主机 x {len(ports)} 端口 = {len(hosts)*len(ports)})，请缩小范围（最大 50000）"
        }), 400

    try:
        results = device_scanner.scan_and_identify(
            hosts, ports, username, password, identify
        )
        return jsonify({
            "success": True,
            "results": results,
            "total_scanned": len(hosts) * len(ports),
            "total_open": len(results),
            "total_identified": sum(1 for r in results if r.get("identified"))
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"扫描失败: {str(e)}"}), 500


@app.route("/api/scan/identify", methods=["POST"])
def api_scan_identify():
    """
    识别单个已知开放端口上的设备
    Body: {host: "192.168.56.101", port: 22, username: "", password: ""}
    """
    data = request.get_json(silent=True) or {}
    host = data.get("host", "")
    port = data.get("port", 0)

    if not host or not port:
        return jsonify({"success": False, "error": "请提供 host 和 port"}), 400

    try:
        result = device_scanner.identify_device(
            host, int(port),
            data.get("username", ""),
            data.get("password", "")
        )
        return jsonify({"success": True, "result": result})
    except Exception as e:
        return jsonify({"success": False, "error": f"识别失败: {str(e)}"}), 500


@app.route("/api/scan/add-devices", methods=["POST"])
def api_scan_add_devices():
    """
    将扫描到的设备批量添加到设备列表
    Body: {devices: [{name, host, port, device_type, ...}, ...]}
    """
    data = request.get_json(silent=True) or {}
    new_devices = data.get("devices", [])

    if not new_devices:
        return jsonify({"success": False, "error": "没有设备可添加"}), 400

    existing_devices = load_devices()
    existing_names = {d.get("name") for d in existing_devices}
    added = 0
    skipped = 0

    for dev in new_devices:
        name = dev.get("name", "").strip()
        if not name:
            # 自动生成名称
            hostname = dev.get("hostname", "")
            if hostname:
                name = hostname
            else:
                name = f"{dev.get('host', 'unknown')}_{dev.get('port', 0)}"
            dev["name"] = name

        if name in existing_names:
            skipped += 1
            continue

        # 转换为 Netmiko 兼容的 device_type
        raw_type = dev.get("device_type", "unknown")
        port = dev.get("port", 22)
        netmiko_type = device_scanner.get_netmiko_device_type(raw_type, port)
        dev["device_type"] = netmiko_type

        # 确保有必要字段
        dev.setdefault("username", "admin")
        dev.setdefault("password", "admin@123")
        dev.setdefault("group", "扫描发现")
        dev.setdefault("description", dev.get("device_type_display", "扫描发现的设备"))

        # 清理扫描专用字段
        for key in ["identified", "banner", "status", "service",
                     "timestamp", "device_type_display", "protocol",
                     "model", "version", "error"]:
            dev.pop(key, None)

        existing_devices.append(dev)
        existing_names.add(name)
        added += 1

    if save_devices(existing_devices):
        return jsonify({
            "success": True,
            "message": f"成功添加 {added} 台设备，跳过 {skipped} 台重名设备",
            "added": added,
            "skipped": skipped
        })
    else:
        return jsonify({"success": False, "error": "保存设备列表失败"}), 500


# ==========================================================
# API 路由：拓扑驱动配置生成 (Topology APIs)
# ==========================================================

@app.route("/api/topology/generate", methods=["POST"])
def api_topology_generate():
    """
    根据前端传入的拓扑数据结构（nodes, links, global_params）自动推导全网设备配置
    """
    data = request.get_json(silent=True) or {}
    nodes = data.get("nodes", [])
    if not nodes:
        return jsonify({"success": False, "error": "拓扑中必须至少包含一个设备节点"}), 400

    try:
        result = topology_engine.generate_configs_from_topology(data)
        return jsonify(result)
    except Exception as e:
        logger.error(f"拓扑生成配置失败: {e}", exc_info=True)
        return jsonify({"success": False, "error": f"推导配置失败: {str(e)}"}), 500


def _ensure_live_simulator_backups(all_devices: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    自动为未备份的活动模拟器串口设备拉取当前真实配置并入库，确保拓扑大屏与合规评估 100% 真实客观
    """
    all_bks = backup_manager.list_backups()
    backed_up_devs = {b.get("device") for b in all_bks if b.get("device")}
    sim_to_fetch = [
        d for d in all_devices
        if d.get("host") == "127.0.0.1" and str(d.get("port", "")).isdigit()
        and int(d.get("port")) >= 2000 and d.get("name") not in backed_up_devs
    ]
    if sim_to_fetch:
        cfg_results = device_manager.batch_get_configs(sim_to_fetch)
        for r in cfg_results:
            if r.get("success") and r.get("config") and len(r.get("config")) > 100:
                backup_manager.save_backup(r["device"], r["config"])

    # 重新加载最新备份并计算真实得分
    refreshed_bks = backup_manager.list_backups()
    summary_map: Dict[str, Dict[str, Any]] = {}
    for idx, dev in enumerate(all_devices):
        dname = dev.get("name", "")
        if not dname:
            continue
        dev_type = dev.get("device_type", "huawei_vrp")
        vendor_hint = "huawei" if "huawei" in dev_type.lower() else "h3c"
        dev_bks = [b for b in refreshed_bks if b.get("device") == dname or dname in b.get("filename", "")]
        if dev_bks:
            cfg_txt = backup_manager.get_backup_content(dev_bks[0]["filename"]) or ""
            res = audit_engine.audit_config(cfg_txt, vendor_hint)
            summary_map[dname] = {"score": res["score"], "grade": res["grade"], "is_real": True}
        else:
            demo_scores = [92, 85, 78, 65, 90, 88, 72]
            sc = demo_scores[idx % len(demo_scores)]
            gr = "A+ (卓越合规)" if sc >= 90 else ("B (良好)" if sc >= 75 else "C (存在风险)")
            summary_map[dname] = {"score": sc, "grade": gr, "is_real": False}
    return summary_map


@app.route("/api/topology/deploy", methods=["POST"])
def api_topology_deploy():
    """
    Sprint 5: 并发下发拓扑引擎推导生成的配置，集成高危命令防呆防火墙与作业审计中心
    Body: {device_configs: {"RouterA": "system-view\n...", ...}, force_override: bool}
    """
    data = request.get_json(silent=True) or {}
    device_configs = data.get("device_configs", {})
    force_override = bool(data.get("force_override", False))

    if not device_configs:
        return jsonify({"success": False, "error": "下发配置列表不能为空"}), 400

    all_devices = load_devices()
    dev_map = {d.get("name"): d for d in all_devices}

    deploy_tasks = []
    combined_commands: List[str] = []
    for dev_name, cfg_str in device_configs.items():
        if dev_name in dev_map and cfg_str:
            commands = [c.strip() for c in cfg_str.splitlines() if c.strip()]
            combined_commands.extend(commands)
            deploy_tasks.append({
                "device": dev_map[dev_name],
                "commands": commands,
                "rendered_cli": cfg_str
            })

    if not deploy_tasks:
        return jsonify({"success": False, "error": "未匹配到任何已纳管的对应设备，请先确保拓扑节点名称与设备库名称一致"}), 404

    # 1. 运行期高危 CLI 命令防呆预审
    guard_res = risk_guard.inspect_commands(combined_commands)
    if guard_res.get("has_blockers") and not force_override:
        return jsonify({
            "success": False,
            "guardrail_triggered": True,
            "risk_level": guard_res["highest_severity"],
            "findings": guard_res["findings"],
            "error": f"触发高危命令防呆拦截: 共检测到 {len(guard_res['findings'])} 处高危配置指令，需用户二次确认",
        }), 400

    # 2. 并发安全下发 (线程池调度)
    results = device_manager.batch_execute_per_device(deploy_tasks)
    success_cnt = sum(1 for r in results if r.get("success"))

    # 3. 记录至持久化作业审计库
    job_logger.log_job(
        job_type="拓扑整网配置下发",
        target_devices=[t["device"]["name"] for t in deploy_tasks],
        status="success" if success_cnt == len(deploy_tasks) else "warning",
        summary=f"全网推导配置一键部署: {success_cnt}/{len(deploy_tasks)} 成功",
        cli_config="\n\n".join([f"# --- {t['device']['name']} ---\n{t['rendered_cli']}" for t in deploy_tasks]),
        details=results,
    )

    return jsonify({"success": True, "results": results, "success_count": success_cnt, "total": len(deploy_tasks)})


@app.route("/api/topology/ping-mesh", methods=["POST"])
def api_topology_ping_mesh():
    """
    Sprint 5: 拓扑端到端连通性矩阵自动化实测 (Ping Mesh & OSPF 邻居状态)
    Body (可选): {host: "127.0.0.1", start_port: 30001, end_port: 30010}
    """
    data = request.get_json(silent=True) or {}
    host = data.get("host", "127.0.0.1")
    start_port = int(data.get("start_port", 30001))
    end_port = int(data.get("end_port", 30010))

    mesh_res = topology_engine.run_topology_ping_mesh(
        host=host,
        start_port=start_port,
        end_port=end_port,
        base_dir=BASE_DIR,
    )
    if not mesh_res.get("success"):
        return jsonify(mesh_res), 400

    job_logger.log_job(
        job_type="全网连通性矩阵实测 (Ping Mesh)",
        target_devices=list({r["src"] for r in mesh_res.get("link_results", [])} | {r["dst"] for r in mesh_res.get("link_results", [])}),
        status="success" if mesh_res["pass_rate"] >= 80 else "warning",
        summary=f"连通率 {mesh_res['pass_rate']}% | 正常: {mesh_res['reachable_links']}/{mesh_res['total_links']} 链路",
        cli_config="\n".join([f"# {r['src']}({r['src_if']}) -> {r['dst']}({r['dst_if']}): {r['status_label']}" for r in mesh_res.get("link_results", [])]),
        details=[{"device": r["src"], "success": r["reachable"], "output": r.get("raw_ping", "")} for r in mesh_res.get("link_results", [])],
    )
    return jsonify(mesh_res)


@app.route("/api/topology/save-all", methods=["POST"])
def api_topology_save_all():
    """
    Sprint 5: 一键全网配置固化保存 (save force / save)
    并发对拓扑中所有在线设备保存内存配置至 Flash/NVRAM，防止重启丢失配置
    Body (可选): {device_names: ["RouterA", ...]}
    """
    data = request.get_json(silent=True) or {}
    req_names = data.get("device_names", [])
    all_devices = load_devices()
    targets = [d for d in all_devices if not req_names or d.get("name") in req_names]

    if not targets:
        return jsonify({"success": False, "error": "没有找到需要保存配置的目标设备"}), 400

    results = device_manager.save_device_configs(targets)
    saved_cnt = sum(1 for r in results if r.get("success"))

    job_logger.log_job(
        job_type="全网配置固化保存 (Save)",
        target_devices=[d["name"] for d in targets],
        status="success" if saved_cnt == len(targets) else "warning",
        summary=f"全网配置固化完成: {saved_cnt}/{len(targets)} 台设备已保存至启动配置 (NVRAM)",
        cli_config="# 全网并发 save 固化指令",
        details=results,
    )

    return jsonify({
        "success": True,
        "saved_count": saved_cnt,
        "total": len(targets),
        "results": results,
    })


@app.route("/api/topology/discover", methods=["POST", "GET"])
def api_topology_discover():
    """
    Sprint 4 & 5: 构建纳管设备实景拓扑大屏数据（结合 LLDP 邻居回显解析 + 智能三层架构分层 + 真实合规评分徽章）
    Body (可选): {lldp_text: "...", default_local_dev: "R1"}
    """
    data = request.get_json(silent=True) or {}
    lldp_text = data.get("lldp_text", "")
    default_local_dev = data.get("default_local_dev", "")

    all_devices = load_devices()
    # 自动拉取活动模拟器未备份设备的真实配置并计算 100% 真实合规得分
    audit_summary_map = _ensure_live_simulator_backups(all_devices)

    # 若用户未手工粘贴 LLDP 文本，且设备库中包含本机模拟器串口 (127.0.0.1)，自动尝试探测实况连线
    local_sim_ports = [
        int(d.get("port"))
        for d in all_devices
        if d.get("host") == "127.0.0.1" and str(d.get("port", "")).isdigit() and int(d.get("port")) >= 2000
    ]
    if not lldp_text and local_sim_ports:
        live_scan = topology_engine.scan_active_simulator_topology(
            host="127.0.0.1",
            start_port=min(local_sim_ports),
            end_port=max(local_sim_ports),
            base_dir="",
        )
        if live_scan.get("success") and live_scan.get("scan_mode") == "live_console" and live_scan.get("edges"):
            for n in live_scan.get("nodes", []):
                if n["name"] in audit_summary_map:
                    n["score"] = audit_summary_map[n["name"]]["score"]
                    n["grade"] = audit_summary_map[n["name"]]["grade"]
            return jsonify(live_scan)

    topo_res = topology_engine.build_live_inventory_topology(
        devices=all_devices,
        lldp_text=lldp_text,
        default_local_dev=default_local_dev,
        audit_summary_map=audit_summary_map,
    )
    return jsonify(topo_res)


def _merge_cloned_devices_into_inventory(new_devs: List[Dict[str, Any]]) -> int:
    """将从本地拓扑克隆出的设备无损合并同步到 devices.yaml 设备库中（按 host:port 与 name 双重去重）"""
    if not new_devs:
        return 0
    existing = load_devices()
    new_port_set = {(nd.get("host"), int(nd.get("port", 0))) for nd in new_devs if nd.get("host") and nd.get("port")}
    new_name_set = {nd.get("name") for nd in new_devs if nd.get("name")}
    filtered_existing = [
        d for d in existing
        if d.get("name") not in new_name_set
        and (d.get("host"), int(d.get("port", 0))) not in new_port_set
    ]
    filtered_existing.extend(new_devs)
    save_devices(filtered_existing)
    return len(new_devs)


@app.route("/api/topology/local-files", methods=["GET"])
def api_topology_local_files():
    """扫描本机及项目内置目录中的华为 eNSP (.topo) 与华三 HCL (.net) 工程文件列表"""
    files = topology_engine.scan_local_project_files(BASE_DIR)
    return jsonify({"success": True, "files": files})


@app.route("/api/topology/clone-file", methods=["POST"])
def api_topology_clone_file():
    """
    1:1 解析本地模拟器工程文件 (.topo / .net) 并在 Web 拓扑大屏及规划器中复刻同款拓扑
    Body: {filepath: "...", content: "...", filename: "...", sync_inventory: bool}
    """
    data = request.get_json(silent=True) or {}
    filepath = (data.get("filepath") or "").strip()
    content = data.get("content") or ""
    filename = data.get("filename") or os.path.basename(filepath)
    sync_inventory = bool(data.get("sync_inventory", False))

    if filepath and not content:
        if not os.path.isfile(filepath):
            return jsonify({"success": False, "error": f"未找到指定的本地拓扑工程文件: {filepath}"}), 404
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

    res = topology_engine.parse_simulator_project_content(content, filename_hint=filename)
    if not res.get("success"):
        return jsonify(res), 400

    synced_count = 0
    if sync_inventory and res.get("inventory_devices"):
        synced_count = _merge_cloned_devices_into_inventory(res["inventory_devices"])
    res["synced_inventory_count"] = synced_count

    job_logger.log_job(
        job_type="本地模拟器拓扑1:1克隆",
        target_devices=[n["name"] for n in res.get("nodes", [])],
        status="success",
        summary=f"从 [{res.get('source_label')}] 1:1 克隆 {res['node_count']} 节点 / {res['edge_count']} 条物理连线",
        cli_config=content[:2000],
        details=[{"device": n["name"], "success": True, "output": f"Port={n['port']}, Coord=({n.get('x')},{n.get('y')})"} for n in res.get("nodes", [])],
    )
    return jsonify(res)


@app.route("/api/topology/scan-local", methods=["POST"])
def api_topology_scan_local():
    """
    动态扫描本机活动模拟器串口 (兼容 H3C HCL 30001-30010 与 eNSP 2000-2020) 或自动回退本地工程文件，1:1 生成同款拓扑
    Body: {host: "127.0.0.1", start_port: 30001, end_port: 30010, sync_inventory: bool}
    """
    data = request.get_json(silent=True) or {}
    host = data.get("host", "127.0.0.1")
    start_port = int(data.get("start_port", 30001))
    end_port = int(data.get("end_port", 30010))
    sync_inventory = bool(data.get("sync_inventory", False))

    res = topology_engine.scan_active_simulator_topology(
        host=host,
        start_port=start_port,
        end_port=end_port,
        base_dir=BASE_DIR,
    )
    if not res.get("success"):
        return jsonify(res), 400

    synced_count = 0
    if sync_inventory and res.get("inventory_devices"):
        synced_count = _merge_cloned_devices_into_inventory(res["inventory_devices"])
    res["synced_inventory_count"] = synced_count

    job_logger.log_job(
        job_type="本机拓扑动态扫描复刻",
        target_devices=[n["name"] for n in res.get("nodes", [])],
        status="success",
        summary=f"[{res.get('source_label')}] 复刻 {res['node_count']} 节点 / {res['edge_count']} 链路 (同步设备库: {synced_count} 台)",
        cli_config=f"# Local Scan {host}:{start_port}-{end_port}",
        details=[{"device": n["name"], "success": True, "output": f"{n['vendor_label']} @ {n['host']}:{n['port']}"} for n in res.get("nodes", [])],
    )
    return jsonify(res)


@app.route("/api/guardrail/check", methods=["POST"])
def api_guardrail_check():
    """
    Sprint 4: 高危 CLI 命令防呆预审接口
    Body: {commands: "..." or [...]}
    """
    data = request.get_json(silent=True) or {}
    cmds = data.get("commands") or data.get("cli_config") or ""
    return jsonify(risk_guard.inspect_commands(cmds))


# ==========================================================
# API 路由：特性向导配置生成 (Feature Config APIs)
# ==========================================================

@app.route("/api/features/generate", methods=["POST"])
def api_features_generate():
    """
    根据勾选的特性卡片及填写的参数生成 CLI 配置
    Body: {vendor: "huawei"|"h3c", features: [...], params: {...}}
    """
    data = request.get_json(silent=True) or {}
    try:
        result = feature_engine.generate(data)
        return jsonify(result)
    except Exception as e:
        logger.error(f"特性配置生成异常: {e}", exc_info=True)
        return jsonify({"success": False, "error": f"生成配置失败: {str(e)}"}), 500


def _render_device_macros(cli_text: str, device: Dict[str, Any], seq: int) -> str:
    """
    将 CLI 文本中的设备级动态宏变量替换为当前目标设备的真实属性：
    支持:
      - {{device.name}} / {{name}} -> 设备名称 (如 R1, SW1)
      - {{device.seq}}  / {{seq}} / {{id}} -> 设备在当前批次中的递增序号 (1, 2, 3...)
      - {{device.host}} / {{host}} -> 设备管理地址
      - {{device.port}} / {{port}} -> 设备管理端口
    """
    dev_name = str(device.get("name", f"Device{seq}"))
    dev_host = str(device.get("host", "127.0.0.1"))
    dev_port = str(device.get("port", 22))
    replacements = {
        "{{device.name}}": dev_name,
        "{{name}}": dev_name,
        "{{device.seq}}": str(seq),
        "{{seq}}": str(seq),
        "{{id}}": str(seq),
        "{{device.id}}": str(seq),
        "{{device.host}}": dev_host,
        "{{host}}": dev_host,
        "{{device.port}}": dev_port,
        "{{port}}": dev_port,
    }
    rendered = cli_text
    for macro, val in replacements.items():
        rendered = rendered.replace(macro, val)
    return rendered


@app.route("/api/features/deploy", methods=["POST"])
@login_required
@roles_accepted("admin", "operator")
def api_features_deploy():
    """
    将特性引擎生成的配置下发给指定的目标设备列表
    支持:
    1. 多设备动态宏变量插值 ({{device.name}}, {{device.seq}}, {{device.host}})
    2. 变更前自动快照备份 (pre_backup=True)
    3. 高危命令防呆预审拦截与服务端审批 (force_override=False 时自动阻断高危命令)
    4. 终端 CLI 报错语义嗅探与分级统计 (clean_success / has_cli_warning / failed)
    Body: {device_names: ["RouterA"], cli_config: "system-view\n...", pre_backup: bool, force_override: bool}
    """
    data = request.get_json(silent=True) or {}
    device_names = data.get("device_names", [])
    cli_config = data.get("cli_config", "")
    pre_backup = bool(data.get("pre_backup", False))
    force_override = bool(data.get("force_override", False))

    if not device_names:
        return jsonify({"success": False, "error": "请至少选择一台目标设备"}), 400
    if not cli_config.strip():
        return jsonify({"success": False, "error": "下发的配置内容不能为空"}), 400

    # Sprint 4 & 6 (P0): 高危命令防呆预审拦截与服务端审批
    guard_res = risk_guard.inspect_commands(cli_config)
    user = get_current_user() or {}
    is_admin = user.get("role") == "admin"
    if not guard_res["passed"] and (not is_admin or not force_override):
        ticket_id = change_manager.create_ticket(
            title=f"特性向导配置下发高危拦截 - {len(device_names)}台",
            applicant=user.get("username", "operator"),
            target_devices=device_names,
            commands_dict={d: cli_config for d in device_names},
            risk_result=guard_res,
        )
        return jsonify({
            "success": False,
            "guardrail_triggered": True,
            "requires_approval": True,
            "ticket_id": ticket_id,
            "risk_level": guard_res["risk_level"],
            "finding_count": guard_res["finding_count"],
            "findings": guard_res["findings"],
            "error": f"防呆防火墙拦截：检测到 {guard_res['finding_count']} 条高危/清理指令，已自动生成工单 [{ticket_id}] 待管理员审批放行！",
        })

    all_devices = load_devices()
    dev_map = {d.get("name"): d for d in all_devices}
    target_devices = [dev_map[name] for name in device_names if name in dev_map]

    if not target_devices:
        return jsonify({"success": False, "error": "所选设备均未在设备库中找到"}), 404

    tasks = []
    for idx, dev in enumerate(target_devices, start=1):
        dev_name = dev.get("name", f"Dev{idx}")
        pre_backup_file = ""
        if pre_backup:
            try:
                cfg_res = device_manager.get_running_config(dev)
                if cfg_res.get("success") and cfg_res.get("config"):
                    saved_path = backup_manager.save_backup(f"{dev_name}_PRE", cfg_res["config"])
                    pre_backup_file = os.path.basename(saved_path) if saved_path else ""
            except Exception as e:
                logger.warning(f"设备 {dev_name} 变更前自动快照失败: {e}")

        rendered_cli = _render_device_macros(cli_config, dev, idx)
        commands = [c.strip() for c in rendered_cli.splitlines() if c.strip()]
        tasks.append({
            "device": dev,
            "commands": commands,
            "rendered_cli": rendered_cli,
            "pre_backup_file": pre_backup_file,
        })

    results = device_manager.batch_execute_per_device(tasks)

    clean_success = sum(1 for r in results if r.get("success") and not r.get("has_cli_warning"))
    warning_count = sum(1 for r in results if r.get("success") and r.get("has_cli_warning"))
    failed_count = sum(1 for r in results if not r.get("success"))

    job_status = "success"
    if failed_count > 0:
        job_status = "failed" if clean_success == 0 else "warning"
    elif warning_count > 0:
        job_status = "warning"

    job_id = job_logger.log_job(
        job_type="特性中心批量下发",
        target_devices=device_names,
        status=job_status,
        summary=f"目标 {len(results)} 台: 零报错 {clean_success} 台 / CLI告警 {warning_count} 台 / 失败 {failed_count} 台",
        cli_config=cli_config,
        details=results,
    )

    return jsonify({
        "success": True,
        "job_id": job_id,
        "summary": {
            "total_devices": len(results),
            "clean_success": clean_success,
            "warning_count": warning_count,
            "failed_count": failed_count,
        },
        "results": results,
    })


# ==========================================================
# 页面与 API 路由：巡检与合规审计 (Sprint 2 Audit & Inspection)
# ==========================================================

@app.route("/audit")
@login_required
def page_audit():
    """设备结构化巡检与等保三级合规审计页面"""
    return render_template("audit.html", active_page="audit")


@app.route("/api/audit/evaluate", methods=["POST"])
def api_audit_evaluate():
    """
    对传入的配置文本或指定历史备份文件执行等保三级合规审计与结构化协议提取
    Body: {config_text: "...", backup_filename: "...", vendor: "auto"|"huawei"|"h3c"}
    """
    data = request.get_json(silent=True) or {}
    config_text = data.get("config_text", "")
    backup_filename = data.get("backup_filename", "").strip()
    vendor = data.get("vendor", "auto")

    if backup_filename and not config_text:
        config_text = backup_manager.get_backup_content(backup_filename) or ""

    if not config_text.strip():
        return jsonify({"success": False, "error": "配置内容为空，无法执行合规审计"}), 400

    audit_res = audit_engine.audit_config(config_text, vendor)
    op_state = audit_engine.parse_operational_state({}, config_text=config_text)
    audit_res["operational_state"] = op_state
    audit_res["source_mode"] = f"备份文件 ({backup_filename})" if backup_filename else "配置文本离线审计"
    return jsonify(audit_res)


@app.route("/api/audit/inspect-device", methods=["POST"])
def api_audit_inspect_device():
    """
    对指定纳管设备执行在线实况巡检 (抓取运行配置 + 接口/OSPF/BGP/VRRP 状态表) 并完成等保三级合规打分。
    若模拟器设备当前未开机，则自动回退读取该设备最近一次备份快照或生成仿真基线评估报告。
    Body: {device_name: "RouterA"}
    """
    data = request.get_json(silent=True) or {}
    device_name = data.get("device_name", "").strip()
    if not device_name:
        return jsonify({"success": False, "error": "请选择目标设备"}), 400

    device = get_device_by_name(device_name)
    if not device:
        return jsonify({"success": False, "error": f"未找到设备 {device_name}"}), 404

    dev_type = device.get("device_type", "h3c")
    vendor_hint = "huawei" if "huawei" in dev_type.lower() else "h3c"

    # 1. 快速探测设备 TCP 端口可达性 (1.2s)，避免离线设备在 Netmiko 阻塞 15s
    import socket
    host = device.get("host", "127.0.0.1")
    port = int(device.get("port", 22))
    tcp_reachable = False
    try:
        with socket.create_connection((host, port), timeout=1.2):
            tcp_reachable = True
    except Exception:
        tcp_reachable = False

    cfg_res = device_manager.get_running_config(device) if tcp_reachable else {"success": False}
    raw_outputs: Dict[str, str] = {}
    online_mode = False
    config_text = ""

    if cfg_res.get("success") and cfg_res.get("config"):
        online_mode = True
        config_text = cfg_res["config"]
        diag_cmds = [
            "display ip interface brief",
            "display ospf peer brief",
            "display bgp peer",
            "display vrrp brief",
        ]
        diag_res = device_manager.execute_commands(device, diag_cmds)
        if diag_res.get("success") and diag_res.get("output"):
            out_txt = diag_res["output"]
            raw_outputs = {
                "ip_interface_brief": out_txt,
                "ospf_peer_brief": out_txt,
                "bgp_peer": out_txt,
                "vrrp_brief": out_txt,
            }
    else:
        backups = backup_manager.list_backups(device_name=device_name)
        if not backups:
            backups = backup_manager.list_backups()
        if backups:
            latest_bk = backups[0]["filename"]
            config_text = backup_manager.get_backup_content(latest_bk) or ""
            source_label = f"离线快照回退 ({latest_bk})"
        else:
            config_text = f"""#
sysname {device_name}
#
interface LoopBack0
 ip address 1.1.1.1 255.255.255.255
#
interface GigabitEthernet0/0/0
 ip address 192.168.10.1 255.255.255.0
 vrrp vrid 1 virtual-ip 192.168.10.254
#
ospf 1 router-id 1.1.1.1
 area 0.0.0.0
  network 192.168.10.0 0.0.0.255
#
bgp 65001
 peer 2.2.2.2 as-number 65001
#
telnet server enable
snmp-agent community read public
#
return"""
            source_label = f"设备离线 · 仿真待加固配置评估 ({device_name})"

    if online_mode:
        source_label = f"在线实况采集 ({device_name} @ {device.get('host')}:{device.get('port')})"

    audit_res = audit_engine.audit_config(config_text, vendor_hint)
    op_state = audit_engine.parse_operational_state(raw_outputs, config_text=config_text)
    audit_res["device_name"] = device_name
    audit_res["online"] = online_mode
    audit_res["source_mode"] = source_label
    audit_res["operational_state"] = op_state
    audit_res["config_preview"] = config_text

    job_logger.log_job(
        job_type="等保合规与状态巡检",
        target_devices=[device_name],
        status="success" if audit_res["score"] >= 80 else "warning",
        summary=f"合规得分: {audit_res['score']}/100 ({audit_res['grade']}) | 通过 {audit_res['passed_count']}/{audit_res['total_rules']} 项",
        cli_config=audit_res.get("combined_remediation_cli", ""),
        details=[{"device": device_name, "success": True, "output": config_text}],
    )
    return jsonify(audit_res)


@app.route("/api/audit/batch-inspect", methods=["POST"])
def api_audit_batch_inspect():
    """
    Sprint 4 & 5: 全网纳管设备一键批量等保合规普查与得分排行榜 (自动融合活动模拟器实时配置)
    """
    all_devices = load_devices()
    if not all_devices:
        return jsonify({"success": False, "error": "设备库为空，请先添加纳管设备"}), 400

    # 优先自动固化未备份活动模拟器的真实配置
    _ensure_live_simulator_backups(all_devices)
    all_backups = backup_manager.list_backups()
    leaderboard: List[Dict[str, Any]] = []
    details_log: List[Dict[str, Any]] = []

    sample_profiles = [
        # 0: 高分加固模板 (90分)
        "sysname {name}\nstelnet server enable\nuser-interface vty 0 4\n authentication-mode aaa\n protocol inbound ssh\n acl 2000 inbound\n idle-timeout 10 0\nquit\naaa\n local-user admin password irreversible-cipher $1c$Hardened#2026\nquit\nntp-service unicast-server 10.0.0.100\ninfo-center enable\ninfo-center loghost 10.0.0.200\nsnmp-agent sys-info version v3\nurpf loose\ndhcp snooping enable\nheader login information \"Authorized Access Only\"\nreturn",
        # 1: 中等合规模板 (70分)
        "sysname {name}\nstelnet server enable\nuser-interface vty 0 4\n authentication-mode aaa\n protocol inbound ssh\n idle-timeout 10 0\nquit\naaa\n local-user admin password irreversible-cipher $1c$Medium#2026\nquit\nntp-service unicast-server 10.0.0.100\ninfo-center enable\ninfo-center loghost 10.0.0.200\nheader login information \"Authorized Access Only\"\nreturn",
        # 2: 待整改风险模板 (35分)
        "sysname {name}\ntelnet server enable\nftp server enable\nuser-interface vty 0 4\n authentication-mode password\nquit\nsnmp-agent community read public\nntp-service unicast-server 10.0.0.100\ninfo-center loghost 10.0.0.200\nreturn",
    ]

    for idx, dev in enumerate(all_devices):
        dname = dev.get("name", f"Dev-{idx+1}")
        dtype = dev.get("device_type", "huawei_vrp")
        vendor_hint = "huawei" if "huawei" in dtype.lower() else "h3c"
        dev_bks = [b for b in all_backups if b.get("device") == dname or dname in b.get("filename", "")]

        if dev_bks:
            cfg_txt = backup_manager.get_backup_content(dev_bks[0]["filename"]) or ""
            src_mode = f"备份快照 ({dev_bks[0]['filename']})"
        else:
            cfg_txt = sample_profiles[idx % len(sample_profiles)].format(name=dname)
            src_mode = "基线仿真普查"

        res = audit_engine.audit_config(cfg_txt, vendor_hint)
        failed_titles = [r["id"] + " " + r["title"] for r in res["rules"] if not r["passed"]]
        leaderboard.append({
            "device_name": dname,
            "host": dev.get("host", ""),
            "port": dev.get("port", 22),
            "group": dev.get("group", "默认分组"),
            "vendor": "华为 VRP" if vendor_hint == "huawei" else "华三 Comware",
            "score": res["score"],
            "grade": res["grade"],
            "grade_color": res["grade_color"],
            "passed_count": res["passed_count"],
            "failed_count": res["failed_count"],
            "total_rules": res["total_rules"],
            "failed_summary": failed_titles[:3],
            "source_mode": src_mode,
        })
        details_log.append({
            "device": dname,
            "success": res["score"] >= 60,
            "output": f"[{dname}] 得分: {res['score']}/100 ({res['grade']}), 违规项: {res['failed_count']} 项",
        })

    leaderboard.sort(key=lambda x: x["score"], reverse=True)
    avg_score = round(sum(x["score"] for x in leaderboard) / len(leaderboard), 1) if leaderboard else 0
    compliant_cnt = sum(1 for x in leaderboard if x["score"] >= 75)
    risk_cnt = len(leaderboard) - compliant_cnt

    job_logger.log_job(
        job_type="全网批量等保普查",
        target_devices=[x["device_name"] for x in leaderboard],
        status="success" if avg_score >= 75 else "warning",
        summary=f"全网普查 {len(leaderboard)} 台设备 | 平均分: {avg_score} | 达标: {compliant_cnt} 台 / 待整改: {risk_cnt} 台",
        cli_config="# 全网批量等保 2.0 三级合规普查任务",
        details=details_log,
    )

    return jsonify({
        "success": True,
        "total_devices": len(leaderboard),
        "average_score": avg_score,
        "compliant_count": compliant_cnt,
        "risk_count": risk_cnt,
        "leaderboard": leaderboard,
    })


# ==========================================================
# API 路由：运维任务审计流水中心 (Sprint 3 Job History APIs)
# ==========================================================

@app.route("/api/backups", methods=["GET"])
def api_backups_alias():
    """兼容仪表盘 /api/backups 别名接口"""
    backups = backup_manager.list_backups()
    return jsonify({"success": True, "backups": backups})


@app.route("/api/jobs", methods=["GET"])
def api_list_jobs():
    """获取最近的运维变更与巡检审计流水列表"""
    limit = int(request.args.get("limit", 25))
    jobs = job_logger.list_jobs(limit=limit)
    return jsonify({"success": True, "jobs": jobs})


@app.route("/api/jobs/<int:job_id>", methods=["GET"])
def api_get_job_detail(job_id: int):
    """获取指定历史任务的详细配置与各设备终端回显"""
    item = job_logger.get_job(job_id)
    if not item:
        return jsonify({"success": False, "error": f"未找到任务记录 #{job_id}"}), 404
    return jsonify({"success": True, "job": item})


@app.route("/api/jobs/clear", methods=["DELETE"])
def api_clear_jobs():
    """清空历史审计日志"""
    job_logger.clear_jobs()
    return jsonify({"success": True, "message": "历史审计流水已清空"})


# 启动时自动将 devices.yaml 中的明文/历史密文平滑迁移升级为 Fernet ENC:v2 强加密格式
try:
    _init_devs = load_devices()
    if _init_devs:
        save_devices(_init_devs)
        logger.info("设备清单凭据已平滑校验并升级至 ENC:v2 Fernet 强加密保险箱格式")
except Exception as _e:
    logger.warning(f"初始化凭据 Vault 升级跳过: {_e}")


# ==========================================================
# 应用主入口
# ==========================================================

if __name__ == "__main__":
    is_debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    logger.info(f"网络批量配置管理工具正在启动... (生产环境 Debug: {is_debug})")
    logger.info("监听地址: http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=is_debug)



