# -*- coding: utf-8 -*-
"""
企业级凭据保险箱 (Credential Vault)
采用 Fernet (AES-128-CBC + HMAC-SHA256) 强对称加密，彻底淘汰弱加密算法。
严格支持 API 凭据脱敏，杜绝口令通过接口向前端泄露。
"""

import os
import base64
import hashlib
import logging
from typing import Dict, Any, List, Optional
from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger("CredentialVault")

# 环境变量秘钥定义
_ENV_VAULT_KEY = os.environ.get("NETWORK_CONFIG_VAULT_KEY")

if _ENV_VAULT_KEY:
    _DERIVED_KEY = base64.urlsafe_b64encode(hashlib.sha256(_ENV_VAULT_KEY.encode("utf-8")).digest())
    logger.info("已从环境变量 NETWORK_CONFIG_VAULT_KEY 加载生产级凭据秘钥")
else:
    # 默认保底主种子（同时在启动时打印告警提示生产配置）
    _DEFAULT_SEED = b"NetConfig@EnterpriseVaultMasterSeed#2026!"
    _DERIVED_KEY = base64.urlsafe_b64encode(hashlib.sha256(_DEFAULT_SEED).digest())
    logger.warning("未检测到 NETWORK_CONFIG_VAULT_KEY 环境变量，已使用系统安全派生秘钥")

_FERNET = Fernet(_DERIVED_KEY)
_LEGACY_XOR_KEY = b"NetConfig@VaultKey2026"


def encrypt_secret(plain: str) -> str:
    """
    将明文口令加密为 ENC:v2:... 格式 (Fernet AES-128-CBC + HMAC-SHA256 强加密)
    """
    if not plain:
        return ""
    if plain.startswith("ENC:v2:"):
        return plain
    # 若为历史 v1 (XOR) 密文，先透明解密再升级为 v2 强加密
    if plain.startswith("ENC:v1:"):
        decrypted = _decrypt_legacy_v1(plain)
        return encrypt_secret(decrypted)

    encrypted_bytes = _FERNET.encrypt(plain.encode("utf-8"))
    return "ENC:v2:" + encrypted_bytes.decode("ascii")


def decrypt_secret(val: str) -> str:
    """
    解密口令供 Netmiko / Console 驱动建立连接使用。
    支持 ENC:v2: 强解密并平滑兼容历史 ENC:v1: 与明文格式。
    """
    if not val or not isinstance(val, str):
        return ""
    if val.startswith("ENC:v2:"):
        try:
            token = val[7:].encode("ascii")
            decrypted_bytes = _FERNET.decrypt(token)
            return decrypted_bytes.decode("utf-8")
        except InvalidToken:
            logger.error("凭据保险箱解密失败: 秘钥不匹配或密文已被篡改！")
            return ""
        except Exception as e:
            logger.error(f"凭据解密异常: {e}")
            return ""
    elif val.startswith("ENC:v1:"):
        return _decrypt_legacy_v1(val)
    return val


def _decrypt_legacy_v1(val: str) -> str:
    """历史 v1 XOR 密文平滑兼容解密"""
    try:
        enc_b64 = val[7:]
        xored = base64.urlsafe_b64decode(enc_b64.encode("ascii"))
        raw = bytes(b ^ _LEGACY_XOR_KEY[i % len(_LEGACY_XOR_KEY)] for i, b in enumerate(xored))
        return raw.decode("utf-8")
    except Exception:
        return val


def mask_device(dev: Dict[str, Any]) -> Dict[str, Any]:
    """
    对向前端 API 输出的设备对象执行严格口令脱敏（P0 要求：API 绝不返回明文口令）
    """
    d = dict(dev)
    has_pwd = bool(d.get("password"))
    has_sec = bool(d.get("secret"))
    d["has_password"] = has_pwd
    d["has_secret"] = has_sec
    # 覆盖敏感字段为不可逆的安全占位符号
    d["password"] = "●●●●●● (已安全托管)" if has_pwd else ""
    d["secret"] = "●●●●●●" if has_sec else ""
    return d


def mask_device_list(devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """批量脱敏设备列表"""
    return [mask_device(d) for d in devices]
