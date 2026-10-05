# -*- encoding: utf-8 -*-
# kb v0.1.8

"""
KB Bundle manifest model.

The manifest (``manifest.json``, always the first member of a bundle)
fully describes the archive:

* ``format`` / ``format_version``  - bundle format identification;
* ``schema_version``               - kb DB schema contained in the dump;
* ``db``                           - DB dump metadata (path, size, hash,
                                     row counts, integrity result);
* ``files`` / ``templates``        - one record per member with virtual
                                     ``path``, ``type`` (file/symlink,
                                     plus an advisory text/binary kind),
                                     ``size`` and ``hash``;
* ``history``                      - optional migrated ``recent.hist``;
* ``features`` / ``required_features`` - feature flags;
* ``encryption``                   - outer-envelope crypto metadata;
* ``signature``                    - detached signature block;
* ``member_count`` / ``total_uncompressed_size`` - pre-extraction limits.

Serialization is canonical JSON (sorted keys, no whitespace) so the
serialized bytes are stable to sign and compare.
"""

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

import attr

from kb.bundle import paths as vpaths
from kb.bundle.errors import (
    ManifestError,
    PathValidationError,
    UnsupportedFeatureError,
)

FORMAT_NAME = "kb-bundle"
FORMAT_VERSION = 1
MANIFEST_MEMBER = "manifest.json"
ENCRYPTION_MEMBER = "ENCRYPTION"

DB_MEMBER = "db/kb.db"
HISTORY_MEMBER = "history/recent.hist"
DATA_PREFIX = "data/"
TEMPLATES_PREFIX = "templates/"

# Feature flags this build understands how to honor.
KNOWN_FEATURES = frozenset({
    "history",            # bundle carries a recent.hist archive
    "templates",          # bundle carries templates/
    "legacy_archive",     # produced from a pre-bundle .tar.gz export
    "streaming_checksums",
    "large_files",
})

# Features the importer must know how to provide. Anything in
# required_features that is not in this set aborts the import.
SUPPORTED_REQUIRED_FEATURES = frozenset({
    "history",
    "templates",
    "streaming_checksums",
    "large_files",
})

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@attr.s(frozen=True, slots=True)
class FileRecord:
    """Metadata of a single bundle member."""

    path: str = attr.ib()
    size: int = attr.ib()
    hash: str = attr.ib()
    # "file" for regular files, "symlink" for symbolic links.
    type: str = attr.ib(default="file")
    # Advisory content kind: "text" or "binary".
    kind: Optional[str] = attr.ib(default=None)
    # Symlink target (virtual POSIX path); only for type == "symlink".
    target: Optional[str] = attr.ib(default=None)
    # Optional unix permission bits (informational).
    mode: Optional[int] = attr.ib(default=None)

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "path": self.path,
            "type": self.type,
            "size": self.size,
            "hash": self.hash,
        }
        if self.kind is not None:
            data["kind"] = self.kind
        if self.target is not None:
            data["target"] = self.target
        if self.mode is not None:
            data["mode"] = self.mode
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "FileRecord":
        try:
            return cls(
                path=data["path"],
                type=data.get("type", "file"),
                size=int(data["size"]),
                hash=data["hash"],
                kind=data.get("kind"),
                target=data.get("target"),
                mode=data.get("mode"),
            )
        except (KeyError, TypeError, ValueError) as err:
            raise ManifestError("Invalid file record: {}".format(err))


@attr.s(frozen=True, slots=True)
class DBDump:
    """Metadata of the SQLite database dump embedded in the bundle."""

    schema_version: int = attr.ib()
    size: int = attr.ib()
    hash: str = attr.ib()
    artifact_count: int = attr.ib(default=0)
    tag_count: int = attr.ib(default=0)
    path: str = attr.ib(default=DB_MEMBER)
    format: str = attr.ib(default="sqlite3")
    integrity: str = attr.ib(default="ok")

    def to_dict(self) -> Dict[str, Any]:
        return attr.asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "DBDump":
        try:
            return cls(
                path=data.get("path", DB_MEMBER),
                format=data.get("format", "sqlite3"),
                schema_version=int(data["schema_version"]),
                size=int(data["size"]),
                hash=data["hash"],
                artifact_count=int(data.get("artifact_count", 0)),
                tag_count=int(data.get("tag_count", 0)),
                integrity=data.get("integrity", "ok"),
            )
        except (KeyError, TypeError, ValueError) as err:
            raise ManifestError("Invalid db dump descriptor: {}".format(err))


@attr.s(frozen=True, slots=True)
class HistoryArchive:
    """Metadata of the migrated view-history archive (recent.hist)."""

    size: int = attr.ib()
    hash: str = attr.ib()
    path: str = attr.ib(default=HISTORY_MEMBER)

    def to_dict(self) -> Dict[str, Any]:
        return attr.asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "HistoryArchive":
        try:
            return cls(
                path=data.get("path", HISTORY_MEMBER),
                size=int(data["size"]),
                hash=data["hash"],
            )
        except (KeyError, TypeError, ValueError) as err:
            raise ManifestError("Invalid history descriptor: {}".format(err))


@attr.s(frozen=True, slots=True)
class SignatureBlock:
    """Detached signature over the canonical manifest bytes."""

    alg: str = attr.ib()
    value: str = attr.ib()
    kid: Optional[str] = attr.ib(default=None)

    def to_dict(self) -> Dict[str, Any]:
        data = {"alg": self.alg, "value": self.value}
        if self.kid is not None:
            data["kid"] = self.kid
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SignatureBlock":
        try:
            return cls(alg=data["alg"], value=data["value"],
                       kid=data.get("kid"))
        except (KeyError, TypeError) as err:
            raise ManifestError("Invalid signature block: {}".format(err))


@attr.s(frozen=True, slots=True)
class Manifest:
    """Full KB Bundle manifest."""

    schema_version: int = attr.ib()
    db: DBDump = attr.ib()
    files: Tuple[FileRecord, ...] = attr.ib(default=())
    templates: Tuple[FileRecord, ...] = attr.ib(default=())
    history: Optional[HistoryArchive] = attr.ib(default=None)
    features: Tuple[Tuple[str, bool], ...] = attr.ib(default=())
    required_features: Tuple[str, ...] = attr.ib(default=())
    format: str = attr.ib(default=FORMAT_NAME)
    format_version: int = attr.ib(default=FORMAT_VERSION)
    kb_version: Optional[str] = attr.ib(default=None)
    created_at: str = attr.ib(factory=_utcnow)
    encryption: Optional[Dict[str, Any]] = attr.ib(default=None)
    signature: Optional[SignatureBlock] = attr.ib(default=None)
    member_count: int = attr.ib(default=0)
    total_uncompressed_size: int = attr.ib(default=0)

    def feature_map(self) -> Dict[str, bool]:
        return dict(self.features)

    def all_records(self) -> Tuple[FileRecord, ...]:
        """Every content member the archive is expected to contain."""
        records = list(self.files) + list(self.templates)
        if self.history is not None:
            records.append(FileRecord(
                path=self.history.path,
                size=self.history.size,
                hash=self.history.hash,
                type="file",
                kind="text",
            ))
        records.append(FileRecord(
            path=self.db.path,
            size=self.db.size,
            hash=self.db.hash,
            type="file",
            kind="binary",
        ))
        return tuple(records)

    def to_dict(self, *, with_signature: bool = True) -> Dict[str, Any]:
        data = {
            "format": self.format,
            "format_version": self.format_version,
            "kb_version": self.kb_version,
            "created_at": self.created_at,
            "schema_version": self.schema_version,
            "member_count": self.member_count,
            "total_uncompressed_size": self.total_uncompressed_size,
            "features": dict(self.features),
            "required_features": list(self.required_features),
            "db": self.db.to_dict(),
            "files": [r.to_dict() for r in self.files],
            "templates": [r.to_dict() for r in self.templates],
            "history": self.history.to_dict() if self.history else None,
            "encryption": self.encryption,
        }
        if with_signature and self.signature is not None:
            data["signature"] = self.signature.to_dict()
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Manifest":
        if not isinstance(data, Mapping):
            raise ManifestError("Manifest must be a JSON object")
        try:
            features_raw = data.get("features", {}) or {}
            if not isinstance(features_raw, Mapping):
                raise ManifestError("'features' must be an object")
            signature_raw = data.get("signature")
            return cls(
                format=data.get("format", FORMAT_NAME),
                format_version=int(data.get(
                    "format_version", FORMAT_VERSION)),
                kb_version=data.get("kb_version"),
                created_at=data.get("created_at", _utcnow()),
                schema_version=int(data["schema_version"]),
                member_count=int(data.get("member_count", 0)),
                total_uncompressed_size=int(
                    data.get("total_uncompressed_size", 0)),
                features=tuple(sorted(
                    (str(k), bool(v)) for k, v in features_raw.items())),
                required_features=tuple(
                    str(f) for f in data.get("required_features", [])),
                db=DBDump.from_dict(data["db"]),
                files=tuple(FileRecord.from_dict(r)
                            for r in data.get("files", [])),
                templates=tuple(FileRecord.from_dict(r)
                                for r in data.get("templates", [])),
                history=(HistoryArchive.from_dict(data["history"])
                         if data.get("history") else None),
                encryption=data.get("encryption"),
                signature=(SignatureBlock.from_dict(signature_raw)
                           if signature_raw else None),
            )
        except (KeyError, TypeError, ValueError) as err:
            raise ManifestError("Invalid manifest: {}".format(err))


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def canonical_bytes(manifest: Manifest) -> bytes:
    """
    Deterministic JSON encoding used for signing and on-disk storage.

    The signature field is excluded: the signature authenticates the
    rest of the manifest and cannot cover itself.
    """
    payload = manifest.to_dict(with_signature=False)
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode("utf-8")


def serialize(manifest: Manifest) -> bytes:
    """Serialize the manifest (pretty form, includes signature)."""
    return json.dumps(
        manifest.to_dict(), sort_keys=True, indent=2,
        ensure_ascii=False).encode("utf-8")


def deserialize(raw: bytes) -> Manifest:
    """Parse, identify and structurally validate a manifest."""
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as err:
        raise ManifestError("Manifest is not valid UTF-8 JSON: {}".format(err))
    manifest = Manifest.from_dict(data)
    validate_manifest(manifest)
    return manifest


def validate_manifest(manifest: Manifest) -> None:
    """
    Cross-field validation of a parsed manifest.

    Paths are normalized and checked for duplicates, hash shapes and
    sizes are verified and the format/feature gate is enforced.
    """
    if manifest.format != FORMAT_NAME:
        raise ManifestError(
            "Unsupported bundle format: {!r}".format(manifest.format))
    if manifest.format_version != FORMAT_VERSION:
        raise ManifestError(
            "Unsupported bundle format version: {} (supported: {})".format(
                manifest.format_version, FORMAT_VERSION))
    if manifest.schema_version < 0:
        raise ManifestError("Negative schema version in manifest")
    if manifest.db.format != "sqlite3":
        raise ManifestError(
            "Unsupported database dump format: {!r}".format(
                manifest.db.format))
    if not _HASH_RE.match(manifest.db.hash):
        raise ManifestError("Database dump hash must be sha256 hex")
    if manifest.db.size < 0:
        raise ManifestError("Negative database dump size")

    seen = set()

    def _check_record(record: FileRecord, allowed_prefix: str) -> None:
        try:
            normalized = vpaths.normalize_virtual_path(record.path)
        except PathValidationError as err:
            raise ManifestError(str(err))
        if normalized != record.path:
            raise ManifestError(
                "Non-canonical member path: {!r} (expected {!r})".format(
                    record.path, normalized))
        if not normalized.startswith(allowed_prefix):
            raise ManifestError(
                "Member {} outside of its section ({})".format(
                    normalized, allowed_prefix))
        if normalized in seen:
            raise ManifestError(
                "Duplicate member path in manifest: {}".format(normalized))
        seen.add(normalized)
        if record.size < 0:
            raise ManifestError(
                "Negative size for member {}".format(normalized))
        if record.type not in ("file", "symlink", "dir"):
            raise ManifestError(
                "Unsupported member type {!r} for {}".format(
                    record.type, normalized))
        if record.type == "file" and not _HASH_RE.match(record.hash):
            raise ManifestError(
                "Member hash must be sha256 hex: {}".format(normalized))
        if record.type == "symlink":
            if not record.target:
                raise ManifestError(
                    "Symlink member without target: {}".format(normalized))
            try:
                vpaths.validate_symlink_target(normalized, record.target)
            except PathValidationError as err:
                raise ManifestError(str(err))

    try:
        db_path = vpaths.normalize_virtual_path(manifest.db.path)
    except PathValidationError as err:
        raise ManifestError(str(err))
    if db_path != DB_MEMBER:
        raise ManifestError(
            "Database dump must live at {}, found {}".format(
                DB_MEMBER, db_path))
    seen.add(db_path)

    for record in manifest.files:
        _check_record(record, DATA_PREFIX)
    for record in manifest.templates:
        _check_record(record, TEMPLATES_PREFIX)
    if manifest.history is not None:
        try:
            hist_path = vpaths.normalize_virtual_path(
                manifest.history.path)
        except PathValidationError as err:
            raise ManifestError(str(err))
        if hist_path != HISTORY_MEMBER:
            raise ManifestError(
                "History archive must live at {}, found {}".format(
                    HISTORY_MEMBER, hist_path))
        if hist_path in seen:
            raise ManifestError("Duplicate member path: {}".format(hist_path))
        seen.add(hist_path)

    unknown_required = [f for f in manifest.required_features
                        if f not in SUPPORTED_REQUIRED_FEATURES]
    if unknown_required:
        raise UnsupportedFeatureError(
            "This kb build does not support required bundle features: {}"
            .format(", ".join(unknown_required)))

    unknown_flags = set(dict(manifest.features)) - KNOWN_FEATURES
    # Unknown *advisory* flags are tolerated (forward compatibility);
    # only unknown required flags are fatal, handled above.
    if unknown_flags:
        pass

    # member_count/size include every payload member plus the manifest
    # itself on disk; here we only verify internal consistency of the
    # declared payload totals.
    payload_size = manifest.db.size + sum(
        r.size for r in manifest.all_records()
        if r.path != manifest.db.path)
    if manifest.total_uncompressed_size not in (0, payload_size) and \
            manifest.total_uncompressed_size < payload_size:
        raise ManifestError(
            "Declared total size {} is below payload size {}".format(
                manifest.total_uncompressed_size, payload_size))


def build_manifest(
        *,
        schema_version: int,
        db: DBDump,
        files: Sequence[FileRecord] = (),
        templates: Sequence[FileRecord] = (),
        history: Optional[HistoryArchive] = None,
        features: Optional[Mapping[str, bool]] = None,
        required_features: Sequence[str] = (),
        kb_version: Optional[str] = None,
        encryption: Optional[Mapping[str, Any]] = None,
        signature: Optional[SignatureBlock] = None) -> Manifest:
    """Assemble a manifest with computed totals and full validation."""
    records = list(files) + list(templates)
    if history is not None:
        records.append(FileRecord(
            path=history.path, size=history.size,
            hash=history.hash, kind="text"))
    total_size = db.size + sum(r.size for r in records)
    # Payload records plus the db dump plus manifest.json itself.
    member_count = len(records) + 2

    manifest = Manifest(
        schema_version=schema_version,
        db=db,
        files=tuple(files),
        templates=tuple(templates),
        history=history,
        features=tuple(sorted((features or {}).items())),
        required_features=tuple(required_features),
        kb_version=kb_version,
        encryption=dict(encryption) if encryption else None,
        signature=signature,
        member_count=member_count,
        total_uncompressed_size=total_size,
    )
    validate_manifest(manifest)
    return manifest


def with_signature(manifest: Manifest, signature: SignatureBlock) -> Manifest:
    """Return a copy of the manifest carrying a signature block."""
    return attr.evolve(manifest, signature=signature)
