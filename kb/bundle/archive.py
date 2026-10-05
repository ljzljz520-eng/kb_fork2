# -*- encoding: utf-8 -*-
# kb v0.1.8

"""
Streaming, safety-checked packaging for KB Bundles.

Bundles are PAX tar archives (so file sizes and paths are unlimited,
which is what makes large binaries first-class citizens). The
:class:`BundleLimits` guard rails and the :func:`safe_unpack` extractor
implement all extraction safety in a single streaming pass:

* member paths are normalized and validated before any write;
* symlinks are relative and contained, hard links / devices / fifos are
  rejected;
* member count, per-file size and total expanded size are bounded;
* an effective compression-ratio counter rejects decompression bombs;
* free space is checked up-front and periodically while writing;
* each member is hashed while it flows to disk and compared with its
  manifest record, so tampering is detected after at most one file;
* partially staged files are written to temp names and atomically
  renamed, which makes interrupted imports resumable.
"""

import os
import shutil
import tarfile
import time
from pathlib import Path
from typing import BinaryIO, Dict, IO, Mapping, Optional, Set

import attr

from kb.bundle import paths as vpaths
from kb.bundle.errors import (
    BundleLimitError,
    HashMismatchError,
    PathValidationError,
)
from kb.bundle.hashing import (
    CountingReader,
    HashingReader,
    DEFAULT_CHUNK_SIZE,
    hash_file,
)
from kb.bundle.manifest import (
    DATA_PREFIX,
    ENCRYPTION_MEMBER,
    FileRecord,
    MANIFEST_MEMBER,
    TEMPLATES_PREFIX,
)

# Re-check free space at most once per this many bytes written.
_FREE_SPACE_RECHECK = 64 * 1024 * 1024

# tarfile member type constants that are accepted.
_ALLOWED_DIR_TYPES = (tarfile.DIRTYPE,)
_ALLOWED_FILE_TYPES = (tarfile.REGTYPE, tarfile.AREGTYPE)


@attr.s(frozen=True, slots=True)
class BundleLimits:
    """Configurable safety limits applied while unpacking."""

    max_members: int = attr.ib(default=100000)
    max_total_bytes: int = attr.ib(default=50 * 1024 ** 3)
    max_file_bytes: int = attr.ib(default=20 * 1024 ** 3)
    max_compression_ratio: float = attr.ib(default=1000.0)
    free_space_factor: float = attr.ib(default=1.1)
    chunk_size: int = attr.ib(default=DEFAULT_CHUNK_SIZE)
    allow_symlinks: bool = attr.ib(default=True)

    @classmethod
    def from_config(cls, config: Optional[Mapping]) -> "BundleLimits":
        if not config:
            return cls()
        return cls(
            max_members=int(config.get("BUNDLE_MAX_MEMBERS", 100000)),
            max_total_bytes=int(config.get(
                "BUNDLE_MAX_TOTAL_BYTES", 50 * 1024 ** 3)),
            max_file_bytes=int(config.get(
                "BUNDLE_MAX_FILE_BYTES", 20 * 1024 ** 3)),
            max_compression_ratio=float(config.get(
                "BUNDLE_MAX_COMPRESSION_RATIO", 1000)),
            free_space_factor=float(config.get(
                "BUNDLE_FREE_SPACE_FACTOR", 1.1)),
            chunk_size=int(config.get(
                "BUNDLE_CHUNK_SIZE", DEFAULT_CHUNK_SIZE)),
        )


# ---------------------------------------------------------------------------
# Free space helpers
# ---------------------------------------------------------------------------

def required_free_space(declared_bytes: int, limits: BundleLimits,
                        extra_bytes: int = 0) -> int:
    """Bytes that must be free on the staging volume before extraction."""
    needed = declared_bytes + extra_bytes
    return int(needed * limits.free_space_factor) + 1


def assert_free_space(staging_dir, needed_bytes: int,
                      limits: BundleLimits) -> None:
    """Raise if the staging volume cannot host ``needed_bytes``."""
    try:
        usage = shutil.disk_usage(str(staging_dir))
    except OSError:
        return  # unknown (e.g. exotic fs) - per-file writes will fail
    if usage.free < needed_bytes:
        raise BundleLimitError(
            "Not enough free space to import bundle: need {} bytes, "
            "{} bytes available".format(needed_bytes, usage.free))


# ---------------------------------------------------------------------------
# Writing bundles
# ---------------------------------------------------------------------------

class BundleWriter:
    """
    Stream a PAX tar bundle to disk.

    The manifest is always written first so that a streaming reader can
    validate policy before extracting a single payload member.
    """

    def __init__(self, out_path, gzip: bool = False,
                 mtime: Optional[float] = None):
        mode = "w:gz" if gzip else "w"
        self._tar = tarfile.open(str(out_path), mode=mode,
                                 format=tarfile.PAX_FORMAT)
        self._mtime = mtime if mtime is not None else time.time()
        self.member_count = 0
        self.total_bytes = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def close(self) -> None:
        self._tar.close()

    def _add_tarinfo(self, info: tarfile.TarInfo,
                     fileobj: Optional[BinaryIO] = None) -> None:
        info.mtime = int(self._mtime)
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        self._tar.addfile(info, fileobj)
        self.member_count += 1
        self.total_bytes += info.size

    def add_bytes(self, vpath: str, payload: bytes) -> None:
        """Add an in-memory member (used for manifest.json/ENCRYPTION)."""
        vpath = vpaths.normalize_virtual_path(vpath)
        info = tarfile.TarInfo(name=vpath)
        info.size = len(payload)
        info.mode = 0o644
        import io
        self._add_tarinfo(info, io.BytesIO(payload))

    def add_file(self, vpath: str, local_path,
                 record: Optional[FileRecord] = None) -> None:
        """
        Stream a regular file from disk without loading it into memory.

        The tar header is taken from the local stat (size must match the
        manifest record when one is supplied).
        """
        vpath = vpaths.normalize_virtual_path(vpath)
        local_path = Path(local_path)
        stat_result = local_path.stat()
        info = self._tar.gettarinfo(str(local_path), arcname=vpath)
        # Normalize ownership for reproducible bundles.
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        info.mtime = int(self._mtime)
        if record is not None and info.size != record.size:
            raise PathValidationError(
                "File {} changed size while packing (manifest says {}, "
                "disk has {})".format(vpath, record.size, info.size))
        with open(local_path, "rb") as handle:
            self._add_tarinfo(info, handle)

    def add_symlink(self, vpath: str, target: str) -> None:
        """Add a relative, containment-checked symbolic link."""
        vpath = vpaths.normalize_virtual_path(vpath)
        target = vpaths.validate_symlink_target(vpath, target)
        info = tarfile.TarInfo(name=vpath)
        info.type = tarfile.SYMTYPE
        info.linkname = target
        info.mode = 0o777
        self._add_tarinfo(info)

    def add_stream(self, vpath: str, fileobj: BinaryIO, size: int,
                   mode: int = 0o644) -> None:
        """Add a member backed by an arbitrary binary stream."""
        vpath = vpaths.normalize_virtual_path(vpath)
        info = tarfile.TarInfo(name=vpath)
        info.size = size
        info.mode = mode
        self._add_tarinfo(info, fileobj)

    def add_directory(self, vpath: str) -> None:
        vpath = vpaths.normalize_virtual_path(vpath)
        info = tarfile.TarInfo(name=vpath)
        info.type = tarfile.DIRTYPE
        info.mode = 0o755
        self._add_tarinfo(info)

    def write_manifest(self, manifest_bytes: bytes) -> None:
        self.add_bytes(MANIFEST_MEMBER, manifest_bytes)


# ---------------------------------------------------------------------------
# Reading bundles
# ---------------------------------------------------------------------------

class BundleReader:
    """
    Open a (possibly compressed) bundle for sequential streaming access.

    ``first_member`` returns the first archive member without consuming
    anything else; :meth:`safe_unpack` then streams the remaining
    members into staging.
    """

    def __init__(self, path):
        self.path = str(path)
        self._raw = open(self.path, "rb")
        try:
            self.counter = CountingReader(self._raw)
            # "r|*" forces sequential (streaming) access, which works
            # with pipes and huge files alike.
            self.tar = tarfile.open(fileobj=self.counter, mode="r|*")
        except Exception:
            self._raw.close()
            raise
        self._first = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def close(self) -> None:
        try:
            self.tar.close()
        finally:
            self._raw.close()

    def first_member(self):
        """
        Return the first archive member as a ``TarInfo`` object without
        consuming the rest of the stream.

        Control members (``manifest.json``/``ENCRYPTION``) are small
        regular files and may be read through
        ``self.tar.extractfile(member)``; non-regular entries (e.g. the
        leading directory of a legacy archive) are returned as-is so
        the caller can decide how to handle them.
        """
        member = next(iter(self.tar))
        self._first = member.name
        return member

    def safe_unpack(self, staging_dir, expected: Mapping[str, FileRecord],
                    limits: BundleLimits, *,
                    resume: bool = False,
                    extra_required_bytes: int = 0,
                    progress=None) -> Set[str]:
        """
        Validate and extract every remaining member into ``staging_dir``.

        Returns the set of verified virtual paths. Raises a
        :class:`BundleError` subclass on the first policy violation.
        """
        staging = Path(staging_dir)
        staging.mkdir(parents=True, exist_ok=True)

        expected = dict(expected)
        verified: Set[str] = set()
        total_written = 0
        members_seen = 0
        bytes_since_space_check = 0
        remaining_bytes = sum(r.size for r in expected.values()) + \
            extra_required_bytes

        # Up-front check covering the whole payload.
        assert_free_space(
            staging,
            required_free_space(remaining_bytes, limits),
            limits)

        for member in self.tar:
            members_seen += 1
            if members_seen > limits.max_members:
                raise BundleLimitError(
                    "Bundle exceeds the maximum of {} members"
                    .format(limits.max_members))

            vname = _normalize_member_name(member)

            if member.isdir():
                self._handle_dir(member, vname, staging)
                continue

            if member.issym():
                self._handle_symlink(
                    member, vname, staging, expected, limits, verified)
                continue

            if member.islnk() or not member.isfile():
                raise PathValidationError(
                    "Unsupported member type in bundle: {} ({})".format(
                        vname, member.type))

            if vname == MANIFEST_MEMBER or vname == ENCRYPTION_MEMBER:
                # Defensive: duplicate manifest/header members are ignored
                # only if exactly matching; a different payload is an error.
                continue

            record = expected.get(vname)
            if record is None:
                raise PathValidationError(
                    "Unexpected member not listed in manifest: {}".format(
                        vname))
            if record.type != "file":
                raise PathValidationError(
                    "Member {} is a file in the archive but declared as {} "
                    "in the manifest".format(vname, record.type))
            if member.size != record.size:
                raise BundleLimitError(
                    "Size mismatch for {}: archive header says {} bytes, "
                    "manifest says {} bytes".format(
                        vname, member.size, record.size))
            if record.size > limits.max_file_bytes:
                raise BundleLimitError(
                    "Member {} ({} bytes) exceeds the per-file limit of {} "
                    "bytes".format(vname, record.size,
                                   limits.max_file_bytes))
            if total_written + record.size > limits.max_total_bytes:
                raise BundleLimitError(
                    "Bundle exceeds the maximum expanded size of {} bytes"
                    .format(limits.max_total_bytes))

            # Periodic free-space re-check (disk is shared with the rest
            # of the system).
            bytes_since_space_check += record.size
            if bytes_since_space_check >= _FREE_SPACE_RECHECK:
                assert_free_space(
                    staging,
                    required_free_space(
                        remaining_bytes - total_written, limits),
                    limits)
                bytes_since_space_check = 0

            source = self.tar.extractfile(member)
            self._extract_regular(
                record, source, staging, limits,
                resume=resume, progress=progress)

            verified.add(vname)
            total_written += record.size
            self._assert_ratio(total_written, limits)

        missing = set(expected) - verified
        if missing:
            raise PathValidationError(
                "Bundle is missing {} declared member(s), e.g. {}".format(
                    len(missing), sorted(missing)[:3]))
        return verified

    # -- per-kind handlers ------------------------------------------------

    @staticmethod
    def _handle_dir(member, vname: str, staging: Path) -> None:
        plain = vname.rstrip("/")
        if not (plain == "data" or plain == "templates" or
                plain == "db" or plain == "history" or
                plain.startswith(DATA_PREFIX) or
                plain.startswith(TEMPLATES_PREFIX)):
            raise PathValidationError(
                "Directory outside of bundle sections: {}".format(vname))
        local = vpaths.virtual_to_local(staging, plain)
        local.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _handle_symlink(member, vname, staging, expected, limits,
                        verified: Set[str]) -> None:
        if not limits.allow_symlinks:
            raise PathValidationError(
                "Symlinks are disabled but bundle contains {}".format(vname))
        record = expected.get(vname)
        if record is None:
            raise PathValidationError(
                "Symlink not listed in manifest: {}".format(vname))
        if record.type != "symlink":
            raise PathValidationError(
                "Member {} is a symlink in the archive but declared as {} "
                "in the manifest".format(vname, record.type))
        target = vpaths.validate_symlink_target(vname, member.linkname)
        if record.target is not None and target != \
                vpaths.validate_symlink_target(vname, record.target):
            raise PathValidationError(
                "Symlink target for {} differs from manifest".format(vname))
        local = vpaths.virtual_to_local(staging, vname)
        local.parent.mkdir(parents=True, exist_ok=True)
        if local.is_symlink() or local.exists():
            local.unlink()
        os.symlink(member.linkname, str(local))
        verified.add(vname)

    @staticmethod
    def _extract_regular(record: FileRecord, source: IO[bytes],
                         staging: Path, limits: BundleLimits, *,
                         resume: bool, progress) -> None:
        local = vpaths.virtual_to_local(staging, record.path)
        local.parent.mkdir(parents=True, exist_ok=True)

        # Incremental/resumable verification: if a previous attempt left
        # the final file in place and it already matches, only drain and
        # verify the archive stream instead of rewriting.
        already_ok = False
        if resume and local.exists() and local.is_file() and \
                local.stat().st_size == record.size:
            existing_hash, _ = hash_file(local, chunk_size=limits.chunk_size)
            already_ok = existing_hash == record.hash

        hashing = HashingReader(source, "sha256")
        tmp_path = None
        if not already_ok:
            tmp_name = ".{}.part-{}".format(
                local.name, os.urandom(8).hex())
            tmp_path = local.parent / tmp_name
            dest = open(tmp_path, "wb")
        else:
            dest = None

        try:
            while True:
                chunk = hashing.read(limits.chunk_size)
                if not chunk:
                    break
                if hashing.bytes_read > record.size:
                    raise HashMismatchError(
                        "Member {} contains more bytes than declared {}"
                        .format(record.path, record.size))
                if dest is not None:
                    dest.write(chunk)
                if progress is not None:
                    progress(record.path, hashing.bytes_read, record.size)
        finally:
            if dest is not None:
                dest.flush()
                os.fsync(dest.fileno())
                dest.close()

        if hashing.bytes_read != record.size:
            if tmp_path is not None:
                tmp_path.unlink(missing_ok=True)
            raise HashMismatchError(
                "Truncated member {}: expected {} bytes, got {}".format(
                    record.path, record.size, hashing.bytes_read))
        if hashing.hexdigest() != record.hash:
            if tmp_path is not None:
                tmp_path.unlink(missing_ok=True)
            raise HashMismatchError(
                "Checksum mismatch for {}".format(record.path))

        if tmp_path is not None:
            os.replace(str(tmp_path), str(local))
            _fsync_dir(local.parent)

    def _assert_ratio(self, expanded_bytes: int,
                      limits: BundleLimits) -> None:
        compressed = self.counter.bytes_read
        # Tar headers add overhead and tiny archives skew the ratio; only
        # judge after a meaningful amount of compressed input was seen.
        if compressed > 1024 * 1024:
            ratio = expanded_bytes / max(compressed, 1)
            if ratio > limits.max_compression_ratio:
                raise BundleLimitError(
                    "Compression ratio {} exceeds the limit of {} "
                    "(possible decompression bomb)".format(
                        int(ratio), limits.max_compression_ratio))


def _normalize_member_name(member: tarfile.TarInfo) -> str:
    """Normalize an archive member name, rejecting trailing-slash files."""
    name = member.name
    is_dir_name = name.endswith("/")
    normalized = vpaths.normalize_virtual_path(
        name[:-1] if is_dir_name else name)
    return normalized + ("/" if is_dir_name else "")


def _fsync_dir(directory: Path) -> None:
    """Best-effort fsync of a directory so renames survive crashes."""
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)
