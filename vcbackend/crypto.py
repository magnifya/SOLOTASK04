"""ES256 签名与规范化 JSON。

ES256 即 ECDSA over P-256 与 SHA-256。签名以 JWS 约定编码：
64 字节裸 R||S 的 base64url（无填充）。cryptography 库签出的是 DER，
这里在 DER 与 R||S 之间做转换。
"""

import base64
import json
import os
import re
from typing import Any, Dict, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

__all__ = [
    "InvalidSignature",
    "MalformedSignature",
    "BACKUP_CIPHER",
    "BACKUP_KDF",
    "BACKUP_KDF_ITERATIONS",
    "BACKUP_NONCE_BYTES",
    "BACKUP_SALT_BYTES",
    "backup_aad",
    "canonicalize",
    "decode_backup_field",
    "decrypt_key_backup",
    "derive_backup_key",
    "encrypt_key_backup",
    "generate_private_key_pem",
    "public_key_pem_from_private",
    "validate_public_key_pem",
    "validate_signature_format",
    "validate_signature_format_strict",
    "sign",
    "verify",
]


class MalformedSignature(ValueError):
    """签名编码格式非法（无法解码或不是 64 字节裸 R||S）。"""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def canonicalize(body: Dict[str, Any]) -> bytes:
    """正文按 key 升序的规范化 JSON 序列化（紧凑、UTF-8 字节）。"""
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def generate_private_key_pem() -> str:
    """生成 P-256 私钥，返回 PKCS8 PEM 字符串。"""
    private_key = ec.generate_private_key(ec.SECP256R1())
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem.decode("utf-8")


def public_key_pem_from_private(private_pem: str) -> str:
    """从私钥 PEM 导出对应的 SubjectPublicKeyInfo 公钥 PEM。"""
    private_key = serialization.load_pem_private_key(
        private_pem.encode("utf-8"), password=None
    )
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError("私钥不是 P-256 椭圆曲线私钥")
    if not isinstance(private_key.curve, ec.SECP256R1):
        raise ValueError("私钥曲线不是 P-256")
    pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("utf-8")


def _load_public_key(public_pem: str) -> ec.EllipticCurvePublicKey:
    try:
        key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise ValueError(f"公钥 PEM 无法解析: {exc}") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise ValueError("公钥不是 P-256 椭圆曲线公钥")
    return key


def validate_public_key_pem(public_pem: str) -> None:
    """校验公钥 PEM 可解析且为 ES256 所需的 P-256 公钥，否则抛 ValueError。"""
    _load_public_key(public_pem)


def _load_private_key(private_pem: str) -> ec.EllipticCurvePrivateKey:
    try:
        key = serialization.load_pem_private_key(
            private_pem.encode("utf-8"), password=None
        )
    except (ValueError, TypeError) as exc:
        raise ValueError(f"私钥 PEM 无法解析: {exc}") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise ValueError("私钥不是 P-256 椭圆曲线私钥")
    return key


def sign(body: Dict[str, Any], private_pem: str) -> str:
    """对规范化正文做 ES256 签名，返回 base64url(R||S)。"""
    private_key = _load_private_key(private_pem)
    der = private_key.sign(
        canonicalize(body), ec.ECDSA(hashes.SHA256())
    )
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return _b64url(raw)


def validate_signature_format(signature_b64: str) -> None:
    """校验签名编码格式：须为可解码的 base64url 且裸 R||S 恰为 64 字节。

    仅检查格式，不做密码学验签。格式非法抛 MalformedSignature。
    """
    try:
        raw = _b64url_decode(signature_b64)
    except Exception as exc:  # noqa: BLE001 解码异常（含 binascii）均属格式问题
        raise MalformedSignature("签名不是合法的 base64url 编码") from exc
    if len(raw) != 64:
        raise MalformedSignature("签名长度不是 64 字节，非合法 ES256 签名")


# 严格格式：64 字节裸 R||S 的无填充 base64url 恰为 86 个字符
_RAW_RS_B64URL_STRICT_RE = re.compile(r"[A-Za-z0-9_-]{86}")


def validate_signature_format_strict(signature_b64: str) -> None:
    """严格校验签名编码格式：恰为 86 个 base64url 字符（无填充、无字
    母表外字符），解码恰为 64 字节裸 R||S，且无填充 base64url 重编码
    与原文逐字符一致（排除填充与非规范尾位）。

    仅检查格式，不做密码学验签。格式非法抛 MalformedSignature。
    """
    if not isinstance(signature_b64, str) or not (
        _RAW_RS_B64URL_STRICT_RE.fullmatch(signature_b64)
    ):
        raise MalformedSignature(
            "签名不是 86 字符的无填充 base64url 编码"
        )
    raw = _b64url_decode(signature_b64)
    if len(raw) != 64 or _b64url(raw) != signature_b64:
        raise MalformedSignature(
            "签名不是规范的 64 字节裸 R||S 无填充 base64url 编码"
        )


def verify(body: Dict[str, Any], signature_b64: str, public_pem: str) -> None:
    """校验签名：格式非法抛 MalformedSignature，验签失败抛 InvalidSignature。"""
    validate_signature_format(signature_b64)
    public_key = _load_public_key(public_pem)
    raw = _b64url_decode(signature_b64)
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")
    der = encode_dss_signature(r, s)
    public_key.verify(der, canonicalize(body), ec.ECDSA(hashes.SHA256()))


# --------------------------------------------------------------------- #
# DID 私钥口令加密备份
#
# PBKDF2-HMAC-SHA256（310000 迭代）从口令派生 256 位密钥，AES-256-GCM
# 加密（密文尾部含 16 字节认证标签），GCM 附加认证数据（AAD）绑定
# 租户、DID、密钥版本与句柄；salt 16 字节、nonce 12 字节随机生成，
# 序列化均为无填充 base64url。
# --------------------------------------------------------------------- #
BACKUP_KDF = "PBKDF2-HMAC-SHA256"
BACKUP_KDF_ITERATIONS = 310000
BACKUP_CIPHER = "AES-256-GCM"
BACKUP_SALT_BYTES = 16
BACKUP_NONCE_BYTES = 12

# 无填充 base64url 的严格形状（不含填充符与字母表外字符）
_B64URL_UNPADDED_RE = re.compile(r"[A-Za-z0-9_-]*")


def backup_aad(
    tenant_id: str, did: str, key_version: int, key_handle: str
) -> bytes:
    """备份密文的 GCM 附加认证数据：规范化 JSON 绑定租户/DID/版本/句柄。"""
    return canonicalize(
        {
            "tenant": tenant_id,
            "did": did,
            "key_version": key_version,
            "key_handle": key_handle,
        }
    )


def decode_backup_field(text: Any, expected_len: int = 0) -> bytes:
    """严格解码无填充 base64url 备份字段。

    非字符串、含填充或字母表外字符、无填充重编码不一致，或解码长度
    与 expected_len（>0 时）不符，一律抛 ValueError。
    """
    if not isinstance(text, str) or not _B64URL_UNPADDED_RE.fullmatch(text):
        raise ValueError("备份字段不是无填充 base64url 编码")
    try:
        raw = _b64url_decode(text)
    except Exception as exc:  # noqa: BLE001 解码失败均属编码非法
        raise ValueError("备份字段不是合法 base64url 编码") from exc
    if _b64url(raw) != text:
        raise ValueError("备份字段不是规范的无填充 base64url 编码")
    if expected_len > 0 and len(raw) != expected_len:
        raise ValueError("备份字段解码长度非法")
    return raw


def derive_backup_key(passphrase: str, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256（310000 迭代）从口令派生 32 字节加密密钥。"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=BACKUP_KDF_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_key_backup(
    passphrase: str, plaintext: bytes, aad: bytes
) -> Tuple[str, str, str]:
    """加密备份明文，返回 (salt, nonce, ciphertext) 的无填充 base64url。

    密文尾部含 16 字节 GCM 认证标签；salt 16 字节、nonce 12 字节随机。
    """
    salt = os.urandom(BACKUP_SALT_BYTES)
    nonce = os.urandom(BACKUP_NONCE_BYTES)
    key = derive_backup_key(passphrase, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return _b64url(salt), _b64url(nonce), _b64url(ciphertext)


def decrypt_key_backup(
    passphrase: str,
    salt_b64: Any,
    nonce_b64: Any,
    ciphertext_b64: Any,
    aad: bytes,
) -> bytes:
    """解密备份密文；编码非法、口令错误或认证失败一律抛 ValueError。"""
    salt = decode_backup_field(salt_b64, BACKUP_SALT_BYTES)
    nonce = decode_backup_field(nonce_b64, BACKUP_NONCE_BYTES)
    ciphertext = decode_backup_field(ciphertext_b64)
    key = derive_backup_key(passphrase, salt)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:  # noqa: BLE001 认证/解密失败统一对外
        raise ValueError("备份解密或认证失败") from exc
