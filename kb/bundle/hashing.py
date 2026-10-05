# -*- encoding: utf-8 -*-
# kb v0.1.8

"""
Streaming hashing primitives for KB Bundle verification.

Nothing in this module buffers a whole file: hashes are computed in
fixed-size chunks, which is what makes verification of multi-gigabyte
binaries constant-memory. The same :class:`HashingReader` is used while
exporting (to compute manifest hashes) and while importing (to verify
members byte-by-byte as they are extracted).
"""

import hashlib
import hmac as hmac_lib
from typing import BinaryIO, Tuple

DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB
DEFAULT_ALGORITHM = "sha256"


class HashingReader:
    """
    Wrap a binary stream, transparently updating a hash digest and a
    counter of every byte read through it.

    This works on top of any file-like object (tar member stream,
    encrypted stream, regular file ...) so integrity checking composes
    with the streaming unpacker.
    """

    def __init__(self, stream: BinaryIO, algorithm: str = DEFAULT_ALGORITHM):
        self._stream = stream
        self.hash = hashlib.new(algorithm)
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        chunk = self._stream.read(size)
        if chunk:
            self.hash.update(chunk)
            self.bytes_read += len(chunk)
        return chunk

    def hexdigest(self) -> str:
        return self.hash.hexdigest()

    def close(self) -> None:
        close = getattr(self._stream, "close", None)
        if callable(close):
            close()


class CountingReader:
    """Count raw bytes consumed from a stream (used for ratio guards)."""

    def __init__(self, stream: BinaryIO):
        self._stream = stream
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        chunk = self._stream.read(size)
        if chunk:
            self.bytes_read += len(chunk)
        return chunk

    def close(self) -> None:
        close = getattr(self._stream, "close", None)
        if callable(close):
            close()


def hash_fileobj(
        stream: BinaryIO,
        algorithm: str = DEFAULT_ALGORITHM,
        chunk_size: int = DEFAULT_CHUNK_SIZE) -> Tuple[str, int]:
    """
    Stream-hash a file-like object.

    Returns a ``(hex_digest, bytes_read)`` tuple.
    """
    digest = hashlib.new(algorithm)
    total = 0
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        digest.update(chunk)
        total += len(chunk)
    return digest.hexdigest(), total


def hash_file(
        path,
        algorithm: str = DEFAULT_ALGORITHM,
        chunk_size: int = DEFAULT_CHUNK_SIZE) -> Tuple[str, int]:
    """Stream-hash a file from disk, returns ``(hex_digest, size)``."""
    with open(path, "rb") as handle:
        return hash_fileobj(handle, algorithm, chunk_size)


def hmac_sign(canonical_bytes: bytes, key: bytes,
              algorithm: str = DEFAULT_ALGORITHM) -> str:
    """Return the hex HMAC of ``canonical_bytes`` under ``key``."""
    return hmac_lib.new(key, canonical_bytes, algorithm).hexdigest()


def hmac_verify(canonical_bytes: bytes, key: bytes, expected_hex: str,
                algorithm: str = DEFAULT_ALGORITHM) -> bool:
    """Constant-time HMAC verification."""
    actual = hmac_sign(canonical_bytes, key, algorithm)
    return hmac_lib.compare_digest(actual, expected_hex or "")
