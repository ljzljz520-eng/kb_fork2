# -*- encoding: utf-8 -*-
# kb v0.1.8

"""
KB Bundle exporter.

Builds a bundle from a live knowledge base in constant memory:

1. the SQLite database is snapshotted through the online backup API and
   stream-hashed;
2. ``data/`` and ``templates/`` are walked; every regular file and
   self-contained symlink gets a :class:`FileRecord` with POSIX virtual
   path, type, size and sha256 - binaries of any size are streamed one
   chunk at a time;
3. ``recent.hist`` is attached as the history archive (ids in the dump
   are preserved, so the history stays valid after import);
4. feature flags and an optional detached signature are added;
5. the resulting PAX tar can optionally be sealed inside an encrypted
   envelope.
"""

import os
import tempfile
from pathlib import Path
from typing import BinaryIO, Dict, Optional

import kb.db as db
import kb.filesystem as fs
from kb import __version__
from kb.bundle import manifest as manifest_mod
from kb.bundle import paths as vpaths
from kb.bundle.archive import BundleWriter
from kb.bundle.crypto import (
    ALG_AES_256_GCM,
    FrameEncryptor,
    encryption_header_bytes,
    get_provider,
    sign_manifest,
)
from kb.bundle.dbcheck import dump_database
from kb.bundle.hashing import hash_file
from kb.bundle.manifest import (
    DATA_PREFIX,
    DBDump,
    ENCRYPTION_MEMBER,
    FileRecord,
    HISTORY_MEMBER,
    HistoryArchive,
    MANIFEST_MEMBER,
    TEMPLATES_PREFIX,
)

BUNDLE_EXTENSION = ".kbbundle"

# sha256 of the empty content; used for symlink members, which carry no
# content of their own but still need a well-formed hash field.
_EMPTY_SHA256 = ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b"
                 "7852b855")


def export_bundle(config: Dict, out_path: str, *,
                  sign_key: Optional[bytes] = None,
                  sign_kid: Optional[str] = None,
                  passphrase: Optional[bytes] = None,
                  gzip: bool = False,
                  include_history: bool = True,
                  include_templates: bool = True,
                  feature_flags: Optional[Dict[str, bool]] = None,
                  work_dir: Optional[str] = None) -> str:
    """
    Export the current knowledge base as a ``.kbbundle`` archive.

    Returns the final output path.
    """
    out_path = _normalize_out_path(out_path, gzip=gzip,
                                   encrypted=passphrase is not None)
    data_root = Path(config["PATH_KB_DATA"])
    templates_root = Path(config["PATH_KB_TEMPLATES"])
    db_path = Path(config["PATH_KB_DB"])
    hist_path = Path(config["PATH_KB_HIST"])

    conn = db.create_connection(str(db_path))
    try:
        schema_version = db.get_schema_version(conn)
        counts = conn.execute(
            "SELECT "
            "(SELECT COUNT(*) FROM artifacts), "
            "(SELECT COUNT(*) FROM tags);").fetchone()
        artifact_count, tag_count = counts[0], counts[1]
    finally:
        conn.close()

    # Scratch space for the DB dump (and the plaintext tar when
    # encrypting). Default to the system temporary directory so exporting
    # never leaves internal directories inside the live knowledge base.
    tmp_root = work_dir or tempfile.gettempdir()
    if work_dir:
        Path(tmp_root).mkdir(parents=True, exist_ok=True)

    # 1. Consistent, stream-hashed database dump.
    dump_fd, dump_tmp = tempfile.mkstemp(prefix="kbdump-", dir=str(tmp_root))
    os.close(dump_fd)
    try:
        dump_database(db_path, dump_tmp)
        db_hash, db_size = hash_file(dump_tmp)
        db_descriptor = DBDump(
            schema_version=schema_version,
            size=db_size,
            hash=db_hash,
            artifact_count=artifact_count,
            tag_count=tag_count,
        )

        # 2. Walk the content trees.
        file_records = _collect_files(data_root, DATA_PREFIX)
        template_records = (
            _collect_files(templates_root, TEMPLATES_PREFIX)
            if include_templates else ())

        # 3. History archive.
        history_descriptor = None
        if include_history and hist_path.is_file():
            hist_hash, hist_size = hash_file(str(hist_path))
            history_descriptor = HistoryArchive(
                size=hist_size, hash=hist_hash)

        # 4. Feature flags.
        flags = dict(feature_flags or {})
        flags.setdefault("history", history_descriptor is not None)
        flags.setdefault("templates", include_templates)
        flags.setdefault("large_files", True)
        flags.setdefault("streaming_checksums", True)
        required = ["streaming_checksums", "large_files"]

        manifest = manifest_mod.build_manifest(
            schema_version=schema_version,
            db=db_descriptor,
            files=file_records,
            templates=template_records,
            history=history_descriptor,
            features=flags,
            required_features=required,
            kb_version=__version__,
        )
        if sign_key is not None:
            block = sign_manifest(manifest, sign_key, kid=sign_kid)
            manifest = manifest_mod.with_signature(manifest, block)

        # 5. Serialize (plaintext first, sealed afterwards if requested).
        plain_path = out_path
        tmp_cleanup = None
        if passphrase is not None:
            fd, plain_path = tempfile.mkstemp(
                prefix="kbplain-", suffix=BUNDLE_EXTENSION, dir=str(tmp_root))
            os.close(fd)
            tmp_cleanup = plain_path

        try:
            _write_plain_bundle(
                plain_path, manifest, dump_tmp,
                data_root, templates_root,
                hist_path if history_descriptor else None,
                gzip=gzip)

            if passphrase is not None:
                _seal_plain_bundle(plain_path, out_path, passphrase)
        finally:
            if tmp_cleanup and os.path.exists(tmp_cleanup):
                os.unlink(tmp_cleanup)
    finally:
        if os.path.exists(dump_tmp):
            os.unlink(dump_tmp)

    return out_path


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------

def _collect_files(root: Path, prefix: str):
    """Walk a content root and produce normalized FileRecords."""
    records = []
    root = Path(root)
    if not root.exists():
        return tuple(records)

    for current, dirnames, filenames in os.walk(str(root), followlinks=False):
        current_path = Path(current)
        for name in list(filenames):
            local = current_path / name
            vpath = prefix + vpaths.local_to_virtual(root, local)
            if local.is_symlink():
                target = os.readlink(str(local))
                normalized_target = vpaths.validate_symlink_target(
                    vpath, target)
                records.append(FileRecord(
                    path=vpath, size=0,
                    hash=_EMPTY_SHA256,
                    type="symlink", target=normalized_target))
                continue
            digest, size = hash_file(str(local))
            records.append(FileRecord(
                path=vpath, size=size, hash=digest,
                type="file",
                kind="text" if fs.is_text_file(str(local)) else "binary"))
    return tuple(records)


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def _write_plain_bundle(path: str, manifest, dump_tmp: str,
                        data_root: Path, templates_root: Path,
                        hist_path: Optional[Path], *, gzip: bool) -> None:
    with BundleWriter(path, gzip=gzip) as writer:
        writer.write_manifest(manifest_mod.serialize(manifest))

        writer.add_file(manifest.db.path, dump_tmp)

        for record in manifest.files:
            local = data_root / record.path[len(DATA_PREFIX):]
            if record.type == "symlink":
                writer.add_symlink(record.path, record.target)
            else:
                writer.add_file(record.path, local, record)

        for record in manifest.templates:
            local = templates_root / record.path[len(TEMPLATES_PREFIX):]
            if record.type == "symlink":
                writer.add_symlink(record.path, record.target)
            else:
                writer.add_file(record.path, local, record)

        if hist_path is not None:
            writer.add_file(HISTORY_MEMBER, hist_path)


def _seal_plain_bundle(plain_path: str, out_path: str,
                       passphrase: bytes) -> None:
    """Wrap a plaintext bundle tar in the encrypted envelope."""
    provider = get_provider(ALG_AES_256_GCM)  # raises if unavailable
    with FrameEncryptor(plain_path, passphrase) as encrypter:
        header = encrypter.header
        header_bytes = encryption_header_bytes(header)
        with BundleWriter(out_path, gzip=False) as outer:
            outer.add_bytes(ENCRYPTION_MEMBER, header_bytes)
            outer.add_stream("payload.enc", encrypter,
                             size=encrypter.ciphertext_size, mode=0o600)


def _normalize_out_path(out_path: str, *, gzip: bool,
                        encrypted: bool) -> str:
    if not out_path:
        import time
        out_path = time.strftime("%d_%m_%Y-%H%M%S")
    if not out_path.endswith(BUNDLE_EXTENSION):
        if not out_path.endswith(".gz"):
            out_path = out_path + BUNDLE_EXTENSION
    if gzip and not encrypted and not out_path.endswith(".gz"):
        out_path = out_path + ".gz"
    return out_path
