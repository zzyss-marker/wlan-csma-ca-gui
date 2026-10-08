"""密码学原语封装（统一基于 ``cryptography`` 库）。

供 VPN / QUIC / DNSSEC / TLS 指纹等项目复用。这里只做**薄封装 + 教学友好的
参数命名**，不自行发明任何密码学算法——课程设计里"自研加密算法"是减分项。
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ------------------------------------------------------------------ 哈希/HMAC
def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha1(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-SHA256。"""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def constant_time_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


# ------------------------------------------------------------------ AEAD
@dataclass
class AEADResult:
    nonce: bytes
    ciphertext: bytes


class AEAD:
    """ChaCha20-Poly1305 / AES-GCM 统一接口。"""

    def __init__(self, algorithm: str = "chacha20poly1305") -> None:
        if algorithm not in ("chacha20poly1305", "aesgcm"):
            raise ValueError(f"不支持的 AEAD：{algorithm}")
        self.algorithm = algorithm
        self.key_size = 32
        #: AES-GCM 支持 128/192/256 位密钥；ChaCha20-Poly1305 只支持 256 位
        self.valid_key_sizes = ((16, 24, 32) if algorithm == "aesgcm" else (32,))
        self.nonce_size = 12
        self.tag_size = 16

    def _impl(self, key: bytes):
        if len(key) not in self.valid_key_sizes:
            raise ValueError(
                f"{self.algorithm} 的密钥长度必须为 {self.valid_key_sizes} 之一，"
                f"实际 {len(key)} 字节")
        return ChaCha20Poly1305(key) if self.algorithm == "chacha20poly1305" else AESGCM(key)

    def encrypt(self, key: bytes, plaintext: bytes, aad: bytes = b"",
                nonce: bytes | None = None) -> AEADResult:
        nonce = nonce or os.urandom(self.nonce_size)
        ct = self._impl(key).encrypt(nonce, plaintext, aad)
        return AEADResult(nonce, ct)

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes,
                aad: bytes = b"") -> bytes:
        return self._impl(key).decrypt(nonce, ciphertext, aad)


# ------------------------------------------------------------------ X25519
class X25519:
    """X25519 ECDH（RFC 7748）。"""

    @staticmethod
    def generate() -> Tuple[bytes, bytes]:
        """返回 ``(私钥, 公钥)``，均为 32 字节。"""
        sk = X25519PrivateKey.generate()
        priv = sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub = sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return priv, pub

    @staticmethod
    def shared_secret(private_key: bytes, peer_public: bytes) -> bytes:
        sk = X25519PrivateKey.from_private_bytes(private_key)
        pk = X25519PublicKey.from_public_bytes(peer_public)
        return sk.exchange(pk)


# ------------------------------------------------------------------ 口令派生
def pbkdf2(password: str, salt: bytes, iterations: int = 200_000,
           length: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, length)


def scrypt(password: str, salt: bytes, n: int = 2 ** 14, r: int = 8,
           p: int = 1, length: int = 32) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=length)


# ------------------------------------------------------------------ 工具
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def random_bytes(n: int) -> bytes:
    return os.urandom(n)


def hexdump(data: bytes, width: int = 16) -> str:
    """生成 ``xxd`` 风格的十六进制转储，便于在终端里肉眼比对报文。"""
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hexpart:<{width * 3}}  |{ascii_part}|")
    return "\n".join(lines)
