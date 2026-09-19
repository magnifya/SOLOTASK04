"""ES256 签名与规范化 JSON 序列化。

签名约定：
- 曲线：NIST P-256（secp256r1），哈希：SHA-256，即 JWS 中的 ES256。
- 签名编码：64 字节原始 r||s 拼接，base64url（无填充）编码。
- 公钥编码：SubjectPublicKeyInfo DER，base64url（无填充）编码。
- 私钥编码：PKCS8 DER，base64url（无填充）编码。
"""

from __future__ import annotations

import base64
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def canonical_json(obj) -> bytes:
    """按 key 升序的规范化 JSON 序列化，返回 UTF-8 字节串。"""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def generate_keypair() -> tuple[str, str]:
    """生成 P-256 密钥对，返回 (public_key_b64u, private_key_b64u)。"""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_der = private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return _b64u_encode(public_der), _b64u_encode(private_der)


def sign_es256(private_key_b64u: str, payload: bytes) -> str:
    """用私钥对 payload 做 ES256 签名，返回 base64url 编码的 r||s。"""
    private_key = serialization.load_der_private_key(
        _b64u_decode(private_key_b64u), password=None
    )
    der_sig = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der_sig)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return _b64u_encode(raw)


def verify_es256(public_key_b64u: str, payload: bytes, signature_b64u: str) -> bool:
    """校验 ES256 签名，合法返回 True，否则返回 False。"""
    try:
        public_key = serialization.load_der_public_key(_b64u_decode(public_key_b64u))
        raw = _b64u_decode(signature_b64u)
        if len(raw) != 64:
            return False
        r = int.from_bytes(raw[:32], "big")
        s = int.from_bytes(raw[32:], "big")
        der_sig = utils.encode_dss_signature(r, s)
        public_key.verify(der_sig, payload, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
    except (ValueError, TypeError, KeyError):
        # 公钥或签名本身无法解析，同样视为校验失败。
        return False
