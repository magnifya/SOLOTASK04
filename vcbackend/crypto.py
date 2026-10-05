"""ES256 签名与规范化 JSON。

ES256 即 ECDSA over P-256 与 SHA-256。签名以 JWS 约定编码：
64 字节裸 R||S 的 base64url（无填充）。cryptography 库签出的是 DER，
这里在 DER 与 R||S 之间做转换。
"""

import base64
import binascii
import os
import json
import re
from typing import Any, Dict

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
    "InvalidKeyBackup",
    "InvalidSignature",
    "MalformedSignature",
    "canonicalize",
    "export_key_backup",
    "generate_private_key_pem",
    "import_key_backup",
    "public_key_pem_from_private",
    "validate_public_key_pem",
    "validate_signature_format",
    "validate_signature_format_strict",
    "sign",
    "verify",
]


class MalformedSignature(ValueError):
    """签名编码格式非法（无法解码或不是 64 字节裸 R||S）。"""


class InvalidKeyBackup(ValueError):
    """密钥备份非法：固定参数不符、绑定不符、口令错误或内容被篡改。"""


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
# DID 私钥的口令加密备份（PBKDF2-HMAC-SHA256 + AES-256-GCM）
# --------------------------------------------------------------------- #

BACKUP_KDF = "PBKDF2-HMAC-SHA256"
BACKUP_KDF_ITERATIONS = 310000
BACKUP_CIPHER = "AES-256-GCM"
BACKUP_SALT_BYTES = 16
BACKUP_NONCE_BYTES = 12

# 备份对象恰含的九个字段（无未知字段，顺序无关）。
BACKUP_FIELDS = (
    "did",
    "key_version",
    "key_handle",
    "kdf",
    "kdf_iterations",
    "salt",
    "cipher",
    "nonce",
    "ciphertext",
)


def _backup_aad(tenant: str, did: str, key_version: int, key_handle: str) -> bytes:
    """备份的附加认证数据：绑定租户、DID、密钥版本与句柄。"""
    return canonicalize(
        {
            "tenant": tenant,
            "did": did,
            "key_version": key_version,
            "key_handle": key_handle,
        }
    )


def _derive_backup_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=BACKUP_KDF_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def export_key_backup(
    passphrase: str,
    private_pem: str,
    *,
    tenant: str,
    did: str,
    key_version: int,
    key_handle: str,
) -> Dict[str, Any]:
    """用口令加密备份 P-256 私钥，返回自描述的九字段备份对象。

    - kdf 固定 PBKDF2-HMAC-SHA256、迭代 310000；cipher 固定 AES-256-GCM；
    - salt 16 字节、nonce 12 字节随机值，无填充 base64url；
    - 密文含 GCM 认证标签，AAD 绑定租户、DID、版本与句柄；
    - 返回对象仅含密文，绝不出现私钥明文。
    """
    salt = os.urandom(BACKUP_SALT_BYTES)
    nonce = os.urandom(BACKUP_NONCE_BYTES)
    key = _derive_backup_key(passphrase, salt)
    aad = _backup_aad(tenant, did, key_version, key_handle)
    ciphertext = AESGCM(key).encrypt(nonce, private_pem.encode("utf-8"), aad)
    return {
        "did": did,
        "key_version": key_version,
        "key_handle": key_handle,
        "kdf": BACKUP_KDF,
        "kdf_iterations": BACKUP_KDF_ITERATIONS,
        "salt": _b64url(salt),
        "cipher": BACKUP_CIPHER,
        "nonce": _b64url(nonce),
        "ciphertext": _b64url(ciphertext),
    }


def _decode_backup_b64(value: Any, expected_len: int) -> bytes:
    """解码备份字段的无填充 base64url；非规范编码或长度不符抛 InvalidKeyBackup。"""
    if not isinstance(value, str):
        raise InvalidKeyBackup("备份字段类型非法")
    try:
        raw = _b64url_decode(value)
    except (binascii.Error, ValueError) as exc:
        raise InvalidKeyBackup("备份字段不是合法 base64url") from exc
    if len(raw) != expected_len or _b64url(raw) != value:
        raise InvalidKeyBackup("备份字段不是规范的无填充 base64url 或长度不符")
    return raw


def import_key_backup(
    passphrase: str,
    backup: Dict[str, Any],
    *,
    tenant: str,
    did: str,
) -> str:
    """解密并校验密钥备份，返回 P-256 私钥 PEM；任何不符抛 InvalidKeyBackup。

    校验固定参数（kdf/迭代次数/cipher）、DID 绑定、salt/nonce 形状，
    并以租户、DID、版本、句柄为 AAD 做 GCM 解密认证；口令错误、绑定
    不符或内容被篡改均表现为认证失败。调用方须先保证 backup 恰含
    BACKUP_FIELDS 且字段类型正确。
    """
    if backup.get("kdf") != BACKUP_KDF:
        raise InvalidKeyBackup("备份 kdf 非法")
    if backup.get("kdf_iterations") != BACKUP_KDF_ITERATIONS:
        raise InvalidKeyBackup("备份 kdf_iterations 非法")
    if backup.get("cipher") != BACKUP_CIPHER:
        raise InvalidKeyBackup("备份 cipher 非法")
    if backup.get("did") != did:
        raise InvalidKeyBackup("备份 DID 绑定不符")
    key_version = backup.get("key_version")
    key_handle = backup.get("key_handle")
    if (
        not isinstance(key_version, int)
        or isinstance(key_version, bool)
        or key_version < 1
        or not isinstance(key_handle, str)
        or not key_handle
    ):
        raise InvalidKeyBackup("备份版本或句柄非法")
    salt = _decode_backup_b64(backup.get("salt"), BACKUP_SALT_BYTES)
    nonce = _decode_backup_b64(backup.get("nonce"), BACKUP_NONCE_BYTES)
    ciphertext_b64 = backup.get("ciphertext")
    if not isinstance(ciphertext_b64, str):
        raise InvalidKeyBackup("备份密文类型非法")
    try:
        ciphertext = _b64url_decode(ciphertext_b64)
    except (binascii.Error, ValueError) as exc:
        raise InvalidKeyBackup("备份密文不是合法 base64url") from exc
    # GCM 密文至少含 16 字节认证标签；重编码比对排除非规范编码。
    if len(ciphertext) < 16 or _b64url(ciphertext) != ciphertext_b64:
        raise InvalidKeyBackup("备份密文不是规范编码或长度过短")
    key = _derive_backup_key(passphrase, salt)
    aad = _backup_aad(tenant, did, key_version, key_handle)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:  # noqa: BLE001 InvalidTag 及底层异常均属认证失败
        raise InvalidKeyBackup("备份解密或认证失败") from exc
    try:
        private_pem = plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidKeyBackup("备份明文不是合法 UTF-8") from exc
    try:
        _load_private_key(private_pem)
    except ValueError as exc:
        raise InvalidKeyBackup("备份明文不是 P-256 私钥") from exc
    return private_pem
