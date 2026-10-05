# -*- encoding: utf-8 -*-
# kb v0.1.8

"""
KB Bundle importer.

Import pipeline (nothing touches the live knowledge base until the very
last step):

1. identify the envelope (plaintext bundle, encrypted bundle or legacy
   ``.tar.gz`` export) and verify the manifest signature when present;
2. allocate an isolated staging directory and pre-check free space
   (payload + the generation checkpoint required at switch time);
3. stream every member through the safety guards while verifying size
   and sha256 against the manifest (resumable across retries);
4. relocate members into the generation layout and run, on the staging
   database only: integrity/foreign-key checks, the schema migration
   chain and DB<->filesystem reference checks;
5. commit atomically through :class:`GenerationStore` and prune old
   generations. Any earlier failure removes staging and leaves the live
   knowledge base byte-for-byte untouched.
"""

import os
import shutil
import tarfile
import tempfile
import uuid
from pathlib import Path
from typing import Dict, Optional

import kb.db as db
from kb.bundle import crypto
from kb.bundle import manifest as manifest_mod
from kb.bundle import paths as vpaths
from kb.bundle.archive import BundleLimits, BundleReader
from kb.bundle.crypto import parse_encryption_header
from kb.bundle.dbcheck import verify_staged_database
from kb.bundle.errors import (
    BundleError,
    CryptoError,
    LegacyArchiveError,
    ManifestError,
    SignatureError,
)
from kb.bundle.generations import GenerationStore
from kb.bundle.hashing import hash_file
from kb.bundle.manifest import (
    DATA_PREFIX,
    DBDump,
    ENCRYPTION_MEMBER,
    FileRecord,
    FORMAT_NAME,
    HISTORY_MEMBER,
    MANIFEST_MEMBER,
    TEMPLATES_PREFIX,
    build_manifest,
)

# Legacy full-KB exports (kb <= 0.1.8) use these archive roots.
_LEGACY_ROOTS = (".kb/", "kb/")
_LEGACY_ALLOWED_TOPS = ("kb.db", "data", "templates", "recent.hist")


def import_bundle(config: Dict, bundle_path: str, *,
                  verify_key: Optional[bytes] = None,
                  passphrase: Optional[bytes] = None,
                  resume: bool = True,
                  keep_staging: bool = False,
                  limits: Optional[BundleLimits] = None,
                  progress=None,
                  _envelope_alg: Optional[str] = None) -> Dict:
    """
    Validate and atomically install a KB Bundle.

    Returns a result dictionary describing the new generation.
    Raises a :class:`BundleError` subclass on any validation failure.
    """
    limits = limits or BundleLimits.from_config(config)
    bundle_path = str(bundle_path)
    staging = _allocate_staging(config)

    try:
        try:
            reader_cm = BundleReader(bundle_path)
        except (OSError, tarfile.TarError) as err:
            raise BundleError(
                "Not a readable kb bundle archive: {} ({})"
                .format(bundle_path, err))
        with reader_cm as reader:
            try:
                first = reader.first_member()
            except (tarfile.TarError, StopIteration) as err:
                raise BundleError(
                    "Not a readable kb bundle archive: {} ({})"
                    .format(bundle_path, err))
            first_name = first.name

            if first_name == ENCRYPTION_MEMBER:
                header_bytes = reader.tar.extractfile(first).read()
                plain_path, alg = _decrypt_envelope(
                    reader, header_bytes, config, passphrase)
                try:
                    return import_bundle(
                        config, plain_path,
                        verify_key=verify_key, passphrase=None,
                        resume=resume, keep_staging=keep_staging,
                        limits=limits, progress=progress,
                        _envelope_alg=alg)
                finally:
                    os.unlink(plain_path)

            if first_name == MANIFEST_MEMBER:
                manifest = manifest_mod.deserialize(
                    reader.tar.extractfile(first).read())
                result = _install_manifest_bundle(
                    reader, manifest, config, staging,
                    verify_key=verify_key, limits=limits,
                    resume=resume, progress=progress,
                    envelope_alg=_envelope_alg)
                return result

            # Anything else must be a legacy export.
            manifest, staging = _install_legacy_bundle(
                reader, first, config, staging, limits)
            result = _commit(config, staging, manifest,
                             note="imported from legacy archive",
                             legacy=True)
            return result
    except Exception:
        if not keep_staging:
            shutil.rmtree(str(staging), ignore_errors=True)
        raise


# ---------------------------------------------------------------------------
# Modern bundle
# ---------------------------------------------------------------------------

def _install_manifest_bundle(reader, manifest, config, staging, *,
                             verify_key, limits, resume, progress,
                             envelope_alg=None) -> Dict:
    """Verify signatures, unpack, validate and commit a modern bundle."""
    _verify_signature_policy(manifest, verify_key)

    payload_bytes = manifest.total_uncompressed_size
    extra = _checkpoint_overhead(config, payload_bytes)
    expected = {record.path: record for record in manifest.all_records()}

    reader.safe_unpack(
        staging, expected, limits,
        resume=resume,
        extra_required_bytes=extra,
        progress=progress)

    _relocate_members(staging, manifest)
    verify_staged_database(
        staging / "kb.db", staging / "data", manifest, config)

    return _commit(config, staging, manifest,
                   note="imported {}".format(FORMAT_NAME),
                   envelope_alg=envelope_alg)


def _verify_signature_policy(manifest, verify_key) -> None:
    if manifest.signature is not None:
        if verify_key is None:
            raise SignatureError(
                "Bundle is signed; a verification key is required "
                "(--verify-key)")
        crypto.verify_manifest_signature(manifest, verify_key)
    elif verify_key is not None:
        raise SignatureError(
            "A verification key was provided but the bundle is not signed")


def _relocate_members(staging, manifest) -> None:
    """
    Move extracted sections onto the generation component layout:

        db/kb.db        -> kb.db
        history/...     -> recent.hist
        data/, templates/ stay in place
    """
    db_dump = staging / Path(manifest.db.path)
    if not db_dump.is_file():
        raise ManifestError(
            "Database dump missing after extraction: {}".format(
                manifest.db.path))
    os.replace(str(db_dump), str(staging / "kb.db"))

    if manifest.history is not None:
        hist = staging / Path(manifest.history.path)
        if not hist.is_file():
            raise ManifestError(
                "History archive missing after extraction: {}".format(
                    manifest.history.path))
        os.replace(str(hist), str(staging / "recent.hist"))

    for leftover in ("db", "history"):
        path = staging / leftover
        if path.is_dir():
            shutil.rmtree(str(path), ignore_errors=True)


def _commit(config, staging, manifest, *, note: str,
            legacy: bool = False,
            envelope_alg: Optional[str] = None) -> Dict:
    store = GenerationStore.open(config)
    summary = {
        "format_version": manifest.format_version,
        "schema_version": manifest.schema_version,
        "artifact_count": manifest.db.artifact_count,
        "tag_count": manifest.db.tag_count,
        "member_count": manifest.member_count,
        "total_uncompressed_size": manifest.total_uncompressed_size,
        "signed": manifest.signature is not None,
        "legacy": legacy,
        "encryption": envelope_alg,
        "features": manifest.feature_map(),
    }
    meta = store.commit_import(staging, summary, note=note)
    keep = int(config.get("BUNDLE_KEEP_GENERATIONS", 5))
    pruned = store.prune(keep)
    return {
        "generation": meta["id"],
        "seq": meta["seq"],
        "strategy": store.strategy,
        "artifact_count": manifest.db.artifact_count,
        "tag_count": manifest.db.tag_count,
        "member_count": manifest.member_count,
        "signed": manifest.signature is not None,
        "legacy": legacy,
        "pruned_generations": pruned,
    }


# ---------------------------------------------------------------------------
# Encrypted envelope
# ---------------------------------------------------------------------------

def _decrypt_envelope(reader, header_bytes, config,
                      passphrase):
    header = parse_encryption_header(header_bytes)
    if passphrase is None:
        raise CryptoError(
            "Bundle is encrypted with {}; a passphrase is required"
            .format(header.get("alg")))

    member = reader.tar.next()
    if vpaths.normalize_virtual_path(member.name) != "payload.enc":
        raise CryptoError(
            "Encrypted bundle is missing the payload member")

    staging_root = Path(config["PATH_KB_STAGING"])
    staging_root.mkdir(parents=True, exist_ok=True)
    fd, plain_path = tempfile.mkstemp(
        prefix="kbplain-", suffix=".tar", dir=str(staging_root))
    os.close(fd)

    provider = crypto.get_provider(header["alg"])
    with open(plain_path, "wb") as dst:
        provider.decrypt_stream(
            reader.tar.extractfile(member), dst, passphrase, header)
    return plain_path, header["alg"]


# ---------------------------------------------------------------------------
# Legacy .tar.gz adapter ("history archive migration")
# ---------------------------------------------------------------------------

def _install_legacy_bundle(reader, first_member,
                           config, staging, limits):
    """
    Adapt a pre-bundle ``kb.tar.gz`` full export to the same pipeline:
    members are policy-checked while streaming, then a synthetic
    manifest is built from the actual content and the database.
    """
    counters = {"n": 0, "bytes": 0}

    def _handle(member):
        counters["n"] += 1
        if counters["n"] > limits.max_members:
            raise BundleError("Legacy archive exceeds the member limit")
        _extract_legacy_member(
            member.name, staging, limits, counters,
            tar=reader.tar, member=member)

    _handle(first_member)
    for member in reader.tar:
        _handle(member)

    _normalize_legacy_tree(staging)

    db_path = staging / "kb.db"
    if not db_path.is_file():
        raise LegacyArchiveError(
            "Legacy archive does not contain a database; data-only "
            "exports cannot be imported as whole knowledge bases")

    conn = db.create_connection(str(db_path))
    try:
        integrity = conn.execute("PRAGMA integrity_check;").fetchall()
        if not integrity or integrity[0][0] != "ok":
            raise LegacyArchiveError(
                "Legacy database failed integrity_check: {}".format(
                    integrity[:3]))
        schema_version = db.get_schema_version(conn)
        artifact_count = conn.execute(
            "SELECT COUNT(*) FROM artifacts;").fetchone()[0]
        tag_count = conn.execute(
            "SELECT COUNT(*) FROM tags;").fetchone()[0]
    finally:
        conn.close()

    db_hash, db_size = hash_file(str(db_path))
    files = []
    templates = []
    history = None
    for local in staging.rglob("*"):
        if not local.is_file() or local == db_path:
            continue
        rel = local.relative_to(staging)
        vpath = "/".join(rel.parts)
        digest, size = hash_file(str(local))
        record = FileRecord(path=vpath, size=size, hash=digest)
        if vpath.startswith(DATA_PREFIX):
            files.append(record)
        elif vpath.startswith(TEMPLATES_PREFIX):
            templates.append(record)
        elif vpath == "recent.hist":
            from kb.bundle.manifest import HistoryArchive
            history = HistoryArchive(size=size, hash=digest,
                                     path=HISTORY_MEMBER)
        else:
            raise LegacyArchiveError(
                "Unexpected file in legacy archive: {}".format(vpath))

    descriptor = DBDump(
        schema_version=schema_version, size=db_size, hash=db_hash,
        artifact_count=artifact_count, tag_count=tag_count)
    manifest = build_manifest(
        schema_version=schema_version,
        db=descriptor,
        files=files,
        templates=templates,
        history=history,
        features={
            "history": history is not None,
            "templates": bool(templates),
            "large_files": True,
            "streaming_checksums": True,
            "legacy_archive": True,
        },
        required_features=["streaming_checksums", "large_files"],
    )

    # Same reference/migration checks as a modern bundle.
    from kb.bundle.dbcheck import verify_staged_database
    verify_staged_database(
        staging / "kb.db", staging / "data", manifest, config)

    return manifest, staging


def _extract_legacy_member(name, staging, limits, counters, *,
                           tar, member):
    """
    Validate and extract one legacy archive member under staging.

    Members arrive as tarfile ``TarInfo`` objects and are streamed to a
    ``.part-*`` temporary name before an atomic replace.
    """
    is_dir = member.isdir()
    declared_size = member.size
    virtual = _legacy_virtual_path(name, member)
    if virtual is None:
        # Archive root or an allowed implicit directory entry.
        return

    counters["bytes"] += declared_size
    if counters["bytes"] > limits.max_total_bytes:
        raise BundleError("Legacy archive exceeds the expanded-size limit")
    if declared_size > limits.max_file_bytes:
        raise BundleError(
            "Legacy member {} exceeds the per-file limit".format(name))

    target = staging.joinpath(*virtual.split("/"))
    if is_dir:
        target.mkdir(parents=True, exist_ok=True)
        return
    if not member.isfile():
        raise LegacyArchiveError(
            "Unsupported member type in legacy archive: {}".format(name))

    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(
        ".{}.part-{}".format(target.name, uuid.uuid4().hex[:8]))
    source = tar.extractfile(member)
    with open(tmp, "wb") as dst:
        while True:
            chunk = source.read(limits.chunk_size)
            if not chunk:
                break
            dst.write(chunk)
    os.replace(str(tmp), str(target))


def _legacy_virtual_path(name, member=None):
    """
    Map a legacy member name to a virtual path inside staging.

    Accepts ``.kb/<component>/...`` and ``kb/<component>/...`` layouts
    and only the known top-level components; rejects everything else
    (``.git``, hooks, absolute/traversal paths ...).
    """
    raw = name[:-1] if name.endswith("/") else name
    normalized = vpaths.normalize_virtual_path(raw)

    root = None
    for candidate in _LEGACY_ROOTS:
        prefix = candidate.rstrip("/")
        if normalized == prefix:
            return None
        if normalized.startswith(candidate):
            root = prefix
            break
    if root is None:
        raise LegacyArchiveError(
            "Legacy archive member outside of .kb/ root: {}".format(name))

    rel = normalized[len(root) + 1:]
    if not rel:
        return None
    top = rel.split("/", 1)[0]
    if top not in _LEGACY_ALLOWED_TOPS:
        raise LegacyArchiveError(
            "Refusing legacy member {} (only {} are migrated)".format(
                name, ", ".join(_LEGACY_ALLOWED_TOPS)))
    return rel


def _normalize_legacy_tree(staging) -> None:
    """Ensure mandatory directories exist after legacy extraction."""
    (staging / "data").mkdir(parents=True, exist_ok=True)
    (staging / "templates").mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Staging / capacity helpers
# ---------------------------------------------------------------------------

def _allocate_staging(config):
    root = Path(config["PATH_KB_STAGING"])
    root.mkdir(parents=True, exist_ok=True)
    staging = root / "import-{}".format(uuid.uuid4().hex)
    staging.mkdir(parents=True)
    return staging


def _checkpoint_overhead(config, payload_bytes: int) -> int:
    """
    Extra bytes the final switch needs beyond the extracted payload:
    symlink strategy copies one live snapshot, flat strategy copies a
    snapshot plus the new generation content into place.
    """
    probe = GenerationStore(config)
    Path(config["PATH_KB_GENERATIONS"]).mkdir(parents=True, exist_ok=True)
    if probe._can_create_symlinks():
        return payload_bytes
    return payload_bytes * 2
