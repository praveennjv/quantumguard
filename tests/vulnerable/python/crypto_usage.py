"""Intentionally weak / quantum-vulnerable cryptography for scanner tests."""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES, DES
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dh, dsa, ed25519, x25519
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
import hashlib
import hmac
import ssl
import jwt


def rsa_generate():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def rsa_legacy():
    return RSA.generate(1024)


def ecdsa_p256():
    return ec.generate_private_key(SECP256R1())


def ecdh_key():
    return x25519.X25519PrivateKey.generate()


def dh_params():
    return dh.generate_parameters(generator=2, key_size=2048)


def dsa_key():
    return dsa.generate_private_key(key_size=2048)


def ed_key():
    return ed25519.Ed25519PrivateKey.generate()


def hashes():
    hashlib.md5(b"x")
    hashlib.sha1(b"x")
    hashlib.sha256(b"x")


def weak_symmetric(key: bytes, iv: bytes, data: bytes):
    DES.new(key[:8], DES.MODE_CBC, iv[:8])
    AES.new(key[:16], AES.MODE_CBC, iv)


def jwt_es256(payload, key):
    return jwt.encode(payload, key, algorithm="ES256")


def old_tls():
    return ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
