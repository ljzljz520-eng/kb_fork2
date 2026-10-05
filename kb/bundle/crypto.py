# -*- encoding: utf-8 -*-
# kb v0.1.8

"""
Signature and encryption support for KB Bundles.

Signing is implemented with the standard library only:

* ``hmac-sha256`` - a keyed MAC over the canonical JSON encoding of the
  manifest. Because the manifest contains the sha256 of every payload
  member (and of the DB dump), authenticating the manifest authenticates
  the whole archive.

Encryption is provider based. The optional ``aes-256-gcm-chunked``
provider streams a bundle through authenticated AES-GCM frames and is
only available when the ``cryptography`` package is installed; without
it a clear error is raised instead of silently downgrading security.

Ciphertext framing (all integers big-endian)::

    header: JSON {"alg", "kdf", "salt", "n", "r", "p", "chunk_size"}
    frame:  uint32 length || nonce(12) || ciphertext+tag
    aad of every frame: uint64 frame_index || byte final_flag
    the stream always ends with one empty, final frame
"""

import json
import os
import struct

from kb.bundle.errors import CryptoError, SignatureError
from kb.bundle.hashing import hmac_verify
from kb.bundle import manifest as manifest_mod

ALG_HMAC_SHA256 = "hmac-sha256"
ALG_AES_256_GCM = "aes-256-gcm-chunked"

# Scrypt parameters for passphrase-derived keys.
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32
NONCE_LEN = 12
DEFAULT_ENC_CHUNK = 8 * 1024 * 1024  # 8 MiB frames

_LENGTH_PREFIX = struct.Struct(">I")
_FRAME_AAD = struct.Struct(">Q?")


# ---------------------------------------------------------------------------
# Signatures (stdlib HMAC)
# ---------------------------------------------------------------------------

def sign_manifest(manifest: "manifest_mod.Manifest", key: bytes,
                  kid: str = None):
    """Attach an hmac-sha256 signature block to a manifest."""
    if not key:
        raise SignatureError("A non-empty signing key is required")
    from kb.bundle.hashing import hmac_sign
    value = hmac_sign(manifest_mod.canonical_bytes(manifest), key, "sha256")
    return manifest_mod.SignatureBlock(
        alg=ALG_HMAC_SHA256, value=value, kid=kid)


def verify_manifest_signature(manifest: "manifest_mod.Manifest",
                              key: bytes) -> None:
    """
    Verify the manifest signature with constant-time comparison.

    Raises :class:`SignatureError` if the signature is missing, uses an
    unsupported algorithm or does not match.
    """
    sig = manifest.signature
    if sig is None:
        raise SignatureError("Bundle is not signed")
    if sig.alg != ALG_HMAC_SHA256:
        raise SignatureError(
            "Unsupported signature algorithm: {}".format(sig.alg))
    if not key:
        raise SignatureError("A verification key is required")
    canonical = manifest_mod.canonical_bytes(manifest)
    if not hmac_verify(canonical, key, sig.value, "sha256"):
        raise SignatureError(
            "Manifest signature does not match the provided key")


# ---------------------------------------------------------------------------
# Encryption providers
# ---------------------------------------------------------------------------

class AESGCMChunkedProvider:
    """Streaming authenticated encryption backed by ``cryptography``."""

    alg = ALG_AES_256_GCM

    def __init__(self):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        except ImportError:
            raise CryptoError(
                "Encryption requires the optional 'cryptography' package "
                "(pip install cryptography)")
        self._AESGCM = AESGCM
        self._Scrypt = Scrypt

    @staticmethod
    def available() -> bool:
        try:
            import cryptography  # noqa: F401
            return True
        except ImportError:
            return False

    def derive_key(self, passphrase: bytes, salt: bytes) -> bytes:
        kdf = self._Scrypt(
            salt=salt, length=KEY_LEN, n=SCRYPT_N,
            r=SCRYPT_R, p=SCRYPT_P)
        return kdf.derive(passphrase)

    def make_header(self, chunk_size: int = DEFAULT_ENC_CHUNK) -> dict:
        return {
            "alg": self.alg,
            "kdf": "scrypt",
            "salt": os.urandom(16).hex(),
            "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
            "chunk_size": chunk_size,
        }

    def encrypt_stream(self, src, dst, passphrase: bytes,
                       chunk_size: int = DEFAULT_ENC_CHUNK,
                       header: dict = None) -> dict:
        """Encrypt ``src`` file object into ``dst``; return the header."""
        header = header or self.make_header(chunk_size)
        salt = bytes.fromhex(header["salt"])
        key = self.derive_key(passphrase, salt)
        aes = self._AESGCM(key)

        index = 0
        while True:
            chunk = src.read(chunk_size)
            final = len(chunk) < chunk_size
            nonce = os.urandom(NONCE_LEN)
            aad = _FRAME_AAD.pack(index, final)
            ciphertext = aes.encrypt(nonce, chunk, aad)
            frame = nonce + ciphertext
            dst.write(_LENGTH_PREFIX.pack(len(frame)))
            dst.write(frame)
            index += 1
            if final:
                break
        dst.flush()
        return header

    def decrypt_stream(self, src, dst, passphrase: bytes,
                       header: dict) -> None:
        """Decrypt frames from ``src`` into ``dst``, authenticating each."""
        if header.get("alg") != self.alg:
            raise CryptoError(
                "Unsupported encryption algorithm: {}".format(header.get("alg")))
        salt = bytes.fromhex(header["salt"])
        kdf = self._Scrypt(
            salt=salt, length=KEY_LEN,
            n=int(header.get("n", SCRYPT_N)),
            r=int(header.get("r", SCRYPT_R)),
            p=int(header.get("p", SCRYPT_P)))
        key = kdf.derive(passphrase)
        aes = self._AESGCM(key)
        chunk_size = int(header.get("chunk_size", DEFAULT_ENC_CHUNK))

        pushback = _PushbackReader(src)
        index = 0
        saw_final = False
        while True:
            prefix = _read_exact(pushback, _LENGTH_PREFIX.size)
            if prefix == b"":
                break
            if saw_final:
                raise CryptoError("Trailing data after final encrypted frame")
            (frame_len,) = _LENGTH_PREFIX.unpack(prefix)
            if frame_len <= NONCE_LEN:
                raise CryptoError("Encrypted frame is too short")
            frame = _read_exact(pushback, frame_len)
            if len(frame) != frame_len:
                raise CryptoError("Truncated encrypted frame")
            nonce, ciphertext = frame[:NONCE_LEN], frame[NONCE_LEN:]
            # The penultimate frame is full-sized; only the last frame is
            # marked final. Peek whether another length prefix follows; the
            # pushback reader hands those bytes back on the next iteration.
            peek = pushback.read(_LENGTH_PREFIX.size)
            final = peek == b""
            if not final:
                pushback.push(peek)
            aad = _FRAME_AAD.pack(index, final)
            try:
                plaintext = aes.decrypt(nonce, ciphertext, aad)
            except Exception as err:
                raise CryptoError(
                    "Decryption failed (wrong passphrase or tampered data): "
                    "{}".format(err))
            if final:
                if len(plaintext) >= chunk_size:
                    raise CryptoError("Final frame must be a short frame")
                saw_final = True
            elif len(plaintext) != chunk_size:
                raise CryptoError(
                    "Non-final encrypted frame has an unexpected size")
            dst.write(plaintext)
            index += 1
        if not saw_final:
            raise CryptoError("Encrypted stream ended without a final frame")
        dst.flush()


class FrameEncryptor:
    """
    File-like reader that emits the framed ciphertext of a plaintext
    file on demand, allowing the tar writer to stream an encrypted
    payload without holding plaintext or ciphertext in memory.
    """

    def __init__(self, plain_path, passphrase: bytes,
                 chunk_size: int = DEFAULT_ENC_CHUNK,
                 header: dict = None):
        self._provider = AESGCMChunkedProvider()
        self.chunk_size = chunk_size
        self.header = header or self._provider.make_header(chunk_size)
        salt = bytes.fromhex(self.header["salt"])
        self._aes = self._provider._AESGCM(
            self._provider.derive_key(passphrase, salt))
        self._src = open(str(plain_path), "rb")
        self._index = 0
        self._buf = bytearray()
        self._closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    @property
    def ciphertext_size(self) -> int:
        plain_size = self._src.seek(0, 2)
        self._src.seek(0)
        frames = (plain_size // self.chunk_size) + 1
        return plain_size + frames * (4 + NONCE_LEN + 16)

    def _fill_frame(self) -> None:
        chunk = self._src.read(self.chunk_size)
        final = len(chunk) < self.chunk_size
        nonce = os.urandom(NONCE_LEN)
        aad = _FRAME_AAD.pack(self._index, final)
        ciphertext = self._aes.encrypt(nonce, chunk, aad)
        frame = nonce + ciphertext
        self._buf += _LENGTH_PREFIX.pack(len(frame)) + frame
        self._index += 1
        if final:
            self._closed = True
            self._src.close()

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            while not self._closed:
                self._fill_frame()
            data = bytes(self._buf)
            self._buf = bytearray()
            return data
        # Generate frames until the request can be satisfied or the
        # plaintext source is exhausted. Never short-read except at EOF:
        # tarfile treats any earlier short read as a corrupt archive.
        while len(self._buf) < size and not self._closed:
            self._fill_frame()
        data = bytes(self._buf[:size])
        del self._buf[:size]
        return data

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._src.close()


_PROVIDERS = {
    ALG_AES_256_GCM: AESGCMChunkedProvider,
}


def get_provider(alg: str = ALG_AES_256_GCM):
    """Instantiate an encryption provider by algorithm name."""
    provider_cls = _PROVIDERS.get(alg)
    if provider_cls is None:
        raise CryptoError("Unsupported encryption algorithm: {}".format(alg))
    return provider_cls()


def encryption_header_bytes(header: dict) -> bytes:
    return json.dumps(header, sort_keys=True).encode("utf-8")


def parse_encryption_header(raw: bytes) -> dict:
    try:
        header = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as err:
        raise CryptoError("Invalid encryption header: {}".format(err))
    if "alg" not in header:
        raise CryptoError("Encryption header lacks 'alg'")
    return header


def _read_exact(stream, size: int) -> bytes:
    """Read exactly ``size`` bytes unless EOF is immediately reached."""
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class _PushbackReader:
    """Minimal one-shot pushback wrapper around a binary stream."""

    def __init__(self, stream):
        self._stream = stream
        self._buf = b""

    def push(self, data: bytes) -> None:
        self._buf = data + self._buf

    def read(self, size: int = -1) -> bytes:
        if size == 0:
            return b""
        if self._buf:
            if size is None or size < 0:
                rest = self._stream.read()
                data = self._buf + rest
                self._buf = b""
                return data
            if len(self._buf) >= size:
                data = self._buf[:size]
                self._buf = self._buf[size:]
                return data
            data = self._buf
            self._buf = b""
            data += self._stream.read(size - len(data))
            return data
        return self._stream.read(size)
