#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# kb KB Bundle test suite
# Copyright © 2020, gnc.
# See /LICENSE for licensing information.

"""
Tests for the KB Bundle format and import/export pipeline:

* manifest model and canonical serialization;
* cross-platform path normalization;
* streaming hashing (chunk boundaries);
* safe unpack guards (traversal, symlink escape, size limits,
  checksum tampering, resumable verification);
* DB dump integrity, references and schema migration on import;
* generations adoption, atomic switch, rollback and pruning;
* signed and encrypted envelopes;
* legacy .tar.gz archive migration;
* large binaries and history archives.
"""

import io
import os
import sqlite3
import tarfile
from pathlib import Path

import pytest

import kb.db as db
import kb.initializer as initializer
import kb.cl_parser as cl_parser
from kb.config import DEFAULT_CONFIG
from kb.entities.artifact import Artifact
from kb.bundle import paths as vpaths
from kb.bundle import manifest as mmod
from kb.bundle.archive import BundleLimits, BundleReader, BundleWriter
from kb.bundle.crypto import AESGCMChunkedProvider
from kb.bundle.errors import (
    BundleLimitError,
    DBCheckError,
    HashMismatchError,
    ManifestError,
    PathValidationError,
    SignatureError,
    CryptoError,
    UnsupportedFeatureError,
)
from kb.bundle.exporter import export_bundle
from kb.bundle.generations import GenerationStore
from kb.bundle.hashing import HashingReader, hash_file
from kb.bundle.importer import import_bundle

EMPTY_SHA256 = ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b"
                "7852b855")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def make_config(base) -> dict:
    base = Path(base)
    cfg = dict(DEFAULT_CONFIG)
    cfg.update({
        "PATH_KB": str(base),
        "PATH_KB_DB": str(base / "kb.db"),
        "PATH_KB_HIST": str(base / "recent.hist"),
        "PATH_KB_DATA": str(base / "data"),
        "PATH_KB_GIT": str(base / ".git"),
        "PATH_KB_CONFIG": str(base / "kb.conf.py"),
        "PATH_KB_TEMPLATES": str(base / "templates"),
        "PATH_KB_DEFAULT_TEMPLATE": str(base / "templates" / "default"),
        "PATH_KB_STAGING": str(base / ".staging"),
        "PATH_KB_GENERATIONS": str(base / ".generations"),
    })
    return cfg


def seed_kb(config, artifacts=(), extra_files=None, history=True):
    """Initialize a kb and insert artifacts + files directly."""
    initializer.init(config)
    conn = db.create_connection(config["PATH_KB_DB"])
    for art in artifacts:
        db.insert_artifact(conn, art)
    conn.close()

    for rel, content in (extra_files or ()):
        path = Path(config["PATH_KB_DATA"]) / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(path, mode) as handle:
            handle.write(content)

    if history:
        with open(config["PATH_KB_HIST"], "w") as handle:
            handle.write("view_id,db_id\n0,1\n")


@pytest.fixture
def source_config(tmp_path):
    config = make_config(tmp_path / "src")
    artifacts = [
        Artifact(None, "note", "default",
                 path="default/note.md", tags="cheats;linux",
                 author="alice", status="ok"),
    ]
    seed_kb(
        config,
        artifacts=artifacts,
        extra_files=(
            ("default/note.md", "# hello bundle\n"),
            ("default/blob.bin", bytes(range(256)) * 4),
        ))
    return config


@pytest.fixture
def target_config(tmp_path):
    config = make_config(tmp_path / "dst")
    initializer.init(config)
    return config


def export_path(tmp_path, name="out.kbbundle"):
    return str(tmp_path / name)


# ---------------------------------------------------------------------------
# Path normalization
# ---------------------------------------------------------------------------

class TestPathNormalization:

    @pytest.mark.parametrize("raw,expected", [
        ("data/default/note.md", "data/default/note.md"),
        ("./data/a.txt", "data/a.txt"),
        ("data//a.txt", "data/a.txt"),
        ("data\\default\\note.md", "data/default/note.md"),
        ("data/./b/../c.txt", "data/c.txt"),
    ])
    def test_accepts_portable_paths(self, raw, expected):
        # Note: ".." component is rejected, so the last case raises;
        # handled separately below.
        if ".." in raw:
            with pytest.raises(PathValidationError):
                vpaths.normalize_virtual_path(raw)
        else:
            assert vpaths.normalize_virtual_path(raw) == expected

    @pytest.mark.parametrize("raw", [
        "../evil",
        "data/../../etc/passwd",
        "/etc/passwd",
        "//server/share",
        "C:/Windows/system32",
        "data/nul.txt",
        "data/CON",
        "data/lpt1.log",
        "data/bad:name",
        "data/trailing.",
        "data/trailing ",
        "data/a\x00b",
        "data/pipe|char",
    ])
    def test_rejects_unsafe_paths(self, raw):
        with pytest.raises(PathValidationError):
            vpaths.normalize_virtual_path(raw)

    def test_symlink_target_must_stay_inside(self):
        vpaths.validate_symlink_target("data/a/link", "../b")
        with pytest.raises(PathValidationError):
            vpaths.validate_symlink_target("data/link", "../../etc")
        with pytest.raises(PathValidationError):
            vpaths.validate_symlink_target("data/link", "/etc/passwd")

    def test_local_containment(self, tmp_path):
        local = vpaths.virtual_to_local(tmp_path, "data/a.txt")
        assert str(local).startswith(str(tmp_path))


# ---------------------------------------------------------------------------
# Manifest model
# ---------------------------------------------------------------------------

class TestManifest:

    def _db(self):
        return mmod.DBDump(schema_version=1, size=10, hash="a" * 64,
                           artifact_count=0, tag_count=0)

    def test_roundtrip(self):
        manifest = mmod.build_manifest(
            schema_version=1, db=self._db(),
            files=[mmod.FileRecord(
                path="data/a.txt", size=5, hash="b" * 64)])
        raw = mmod.serialize(manifest)
        parsed = mmod.deserialize(raw)
        assert parsed.schema_version == 1
        assert parsed.files[0].path == "data/a.txt"

    def test_duplicate_member_rejected(self):
        record = mmod.FileRecord(path="data/a.txt", size=1, hash="c" * 64)
        with pytest.raises(ManifestError):
            mmod.build_manifest(
                schema_version=1, db=self._db(),
                files=[record, record])

    def test_non_canonical_path_rejected(self):
        record = mmod.FileRecord(path="data/../a", size=1, hash="c" * 64)
        with pytest.raises(ManifestError):
            mmod.build_manifest(
                schema_version=1, db=self._db(), files=[record])

    def test_bad_format_version(self):
        manifest = mmod.build_manifest(
            schema_version=1, db=self._db())
        data = manifest.to_dict()
        data["format_version"] = 999
        with pytest.raises(ManifestError):
            mmod.deserialize(mmod.json.dumps(data).encode("utf-8"))

    def test_unknown_required_feature_rejected(self):
        # Bypass build_manifest validation to exercise deserialize().
        manifest = mmod.Manifest(
            schema_version=1, db=self._db(),
            required_features=("telepathy",))
        with pytest.raises(UnsupportedFeatureError):
            mmod.deserialize(mmod.serialize(manifest))

    def test_totals_are_computed(self):
        manifest = mmod.build_manifest(
            schema_version=1, db=self._db(),
            files=[mmod.FileRecord(
                path="data/a.txt", size=5, hash="b" * 64)])
        # db(10) + file(5), members = db + file + manifest
        assert manifest.total_uncompressed_size == 15
        assert manifest.member_count == 3


# ---------------------------------------------------------------------------
# Streaming hashing
# ---------------------------------------------------------------------------

def test_hashing_reader_respects_chunk_boundaries(tmp_path):
    payload = bytes((i % 256 for i in range(10000)))
    path = tmp_path / "blob"
    path.write_bytes(payload)

    with open(path, "rb") as handle:
        reader = HashingReader(handle)
        collected = b""
        while True:
            chunk = reader.read(137)  # awkward prime-sized chunks
            if not chunk:
                break
            collected += chunk
    assert collected == payload
    assert reader.bytes_read == len(payload)
    assert reader.hexdigest() == hash_file(str(path))[0]


# ---------------------------------------------------------------------------
# End-to-end export/import
# ---------------------------------------------------------------------------

class TestRoundTrip:

    def test_export_import_roundtrip(self, source_config, target_config,
                                     tmp_path):
        bundle = export_path(tmp_path)
        out = export_bundle(source_config, bundle)
        assert out.endswith(".kbbundle")

        result = import_bundle(target_config, out)
        assert result["artifact_count"] == 1
        assert result["tag_count"] == 2
        assert result["signed"] is False

        note = Path(target_config["PATH_KB_DATA"]) / "default" / "note.md"
        assert note.read_text() == "# hello bundle\n"
        blob = Path(target_config["PATH_KB_DATA"]) / "default" / "blob.bin"
        assert blob.read_bytes() == bytes(range(256)) * 4
        assert Path(target_config["PATH_KB_HIST"]).read_text() == \
            "view_id,db_id\n0,1\n"

        conn = db.create_connection(target_config["PATH_KB_DB"])
        assert db.get_schema_version(conn) == 1
        rows = conn.execute(
            "SELECT title,tags,author FROM artifacts;").fetchall()
        assert rows == [("note", "cheats;linux", "alice")]
        conn.close()

    def test_gzip_bundle(self, source_config, target_config, tmp_path):
        out = export_bundle(
            source_config, str(tmp_path / "gz.kbbundle"), gzip=True)
        assert out.endswith(".gz")
        result = import_bundle(target_config, out)
        assert result["artifact_count"] == 1

    def test_large_binary_small_chunks(self, tmp_path):
        src = make_config(tmp_path / "bigsrc")
        payload = os.urandom(3 * 1024 * 1024 + 123)
        seed_kb(
            src,
            artifacts=[Artifact(None, "big", "default",
                                path="default/big.bin")],
            extra_files=(("default/big.bin", payload),))
        bundle = export_bundle(src, str(tmp_path / "big.kbbundle"))

        dst = make_config(tmp_path / "bigdst")
        initializer.init(dst)
        limits = BundleLimits(chunk_size=4096)
        import_bundle(dst, bundle, limits=limits)
        imported = (Path(dst["PATH_KB_DATA"]) / "default" / "big.bin")
        assert imported.read_bytes() == payload


# ---------------------------------------------------------------------------
# Tampering / extraction guards
# ---------------------------------------------------------------------------

def _rebuild_tar(src_path, dst_path, mutate):
    members = {}
    order = []
    with tarfile.open(src_path, "r:*") as tar:
        for member in tar:
            order.append(member.name)
            if member.isfile():
                members[member.name] = (
                    tar.extractfile(member).read(), member.mode)
            elif member.isdir():
                members[member.name] = (None, member.mode)
    with BundleWriter(dst_path) as writer:
        for name in order:
            payload, mode = members[name]
            if payload is None:
                writer.add_directory(name.rstrip("/"))
                continue
            payload = mutate(name, payload)
            writer.add_bytes(name, payload)


class TestUnpackGuards:

    def test_tampered_member_is_detected(self, source_config, tmp_path):
        bundle = export_bundle(
            source_config, str(tmp_path / "orig.kbbundle"))
        tampered = str(tmp_path / "tampered.kbbundle")

        def mutate(name, payload):
            if name == "data/default/note.md":
                return payload.replace(b"hello", b"HELLO")
            return payload

        _rebuild_tar(bundle, tampered, mutate)

        dst = make_config(tmp_path / "dst")
        initializer.init(dst)
        with pytest.raises(HashMismatchError):
            import_bundle(dst, tampered)

    def test_total_size_limit(self, source_config, target_config, tmp_path):
        bundle = export_bundle(
            source_config, str(tmp_path / "lim.kbbundle"))
        limits = BundleLimits(max_total_bytes=1)
        with pytest.raises(BundleLimitError):
            import_bundle(target_config, bundle, limits=limits)

    def test_path_traversal_member_rejected(self, target_config, tmp_path):
        staging = tmp_path / "stage"
        staging.mkdir()
        evil = str(tmp_path / "evil.kbbundle")
        manifest = mmod.build_manifest(
            schema_version=1,
            db=mmod.DBDump(
                schema_version=1, size=0, hash=EMPTY_SHA256))
        # Build with the raw tarfile API because the BundleWriter itself
        # refuses traversal members; here we simulate a hostile archive.
        with tarfile.open(evil, "w") as tar:
            info = tarfile.TarInfo(name=mmod.MANIFEST_MEMBER)
            raw = mmod.serialize(manifest)
            info.size = len(raw)
            tar.addfile(info, io.BytesIO(raw))
            bad = tarfile.TarInfo(name="../evil")
            bad.size = 1
            tar.addfile(bad, io.BytesIO(b"x"))
        with BundleReader(evil) as reader:
            reader.first_member()
            with pytest.raises(PathValidationError):
                reader.safe_unpack(
                    staging, {}, BundleLimits())

    def test_symlink_escape_rejected(self, tmp_path):
        staging = tmp_path / "stage"
        staging.mkdir()
        evil = str(tmp_path / "sym.kbbundle")
        record = mmod.FileRecord(
            path="data/link", size=0, hash=EMPTY_SHA256,
            type="symlink", target="note.md")
        manifest = mmod.build_manifest(
            schema_version=1,
            db=mmod.DBDump(
                schema_version=1, size=0, hash=EMPTY_SHA256),
            files=[record])
        with tarfile.open(evil, "w") as tar:
            info = tarfile.TarInfo(name=mmod.MANIFEST_MEMBER)
            raw = mmod.serialize(manifest)
            info.size = len(raw)
            tar.addfile(info, io.BytesIO(raw))
            link = tarfile.TarInfo(name="data/link")
            link.type = tarfile.SYMTYPE
            link.linkname = "../../etc"
            tar.addfile(link)
        with BundleReader(evil) as reader:
            reader.first_member()
            with pytest.raises(PathValidationError):
                reader.safe_unpack(
                    staging, {"data/link": record}, BundleLimits())

    def test_resumable_verification(self, tmp_path):
        staging = tmp_path / "stage"
        staging.mkdir()
        bundle = str(tmp_path / "r.kbbundle")
        payload = b"resume me" * 100
        import hashlib
        record_hash = hashlib.sha256(payload).hexdigest()
        record = mmod.FileRecord(
            path="data/a.txt", size=len(payload), hash=record_hash)
        manifest = mmod.build_manifest(
            schema_version=1,
            db=mmod.DBDump(
                schema_version=1, size=0, hash=EMPTY_SHA256),
            files=[record])
        with BundleWriter(bundle) as writer:
            writer.write_manifest(mmod.serialize(manifest))
            writer.add_bytes("data/a.txt", payload)

        for _ in range(2):
            with BundleReader(bundle) as reader:
                reader.first_member()
                verified = reader.safe_unpack(
                    staging, {"data/a.txt": record},
                    BundleLimits(), resume=True)
            assert verified == {"data/a.txt"}

        # A tampered re-delivery must still fail even when the staged
        # file on disk is already correct: the stream is always verified.
        tampered = str(tmp_path / "r-bad.kbbundle")
        bad_payload = payload[:-1] + (b"!" if payload[-1:] != b"!"
                                      else b"?")
        assert len(bad_payload) == len(payload)
        with BundleWriter(tampered) as writer:
            writer.write_manifest(mmod.serialize(manifest))
            writer.add_bytes("data/a.txt", bad_payload)
        with BundleReader(tampered) as reader:
            reader.first_member()
            with pytest.raises(HashMismatchError):
                reader.safe_unpack(
                    staging, {"data/a.txt": record},
                    BundleLimits(), resume=True)


# ---------------------------------------------------------------------------
# Database checks and migration
# ---------------------------------------------------------------------------

def test_v0_database_is_migrated_on_import(target_config, tmp_path):
    # Hand-build a schema v0 database (no template column).
    src_db = tmp_path / "v0.db"
    conn = sqlite3.connect(str(src_db))
    conn.executescript(
        """CREATE TABLE artifacts (
               id integer PRIMARY KEY, title text NOT NULL,
               category text NOT NULL, path text NOT NULL,
               tags text, status text, author text);
           CREATE TABLE tags (
               artifact_id integer, tag text,
               FOREIGN KEY(artifact_id) REFERENCES artifacts(id)
               ON DELETE CASCADE);
           PRAGMA user_version = 0;
           INSERT INTO artifacts VALUES (
               1,'old','default','default/old.md','x',NULL,NULL);
           INSERT INTO tags VALUES (1,'x');
        """)
    conn.commit()
    conn.close()

    note = b"legacy db content\n"
    db_hash = __import__("hashlib").sha256(src_db.read_bytes()).hexdigest()
    file_hash = __import__("hashlib").sha256(note).hexdigest()
    manifest = mmod.build_manifest(
        schema_version=0,
        db=mmod.DBDump(
            schema_version=0, size=src_db.stat().st_size, hash=db_hash,
            artifact_count=1, tag_count=1),
        files=[mmod.FileRecord(
            path="data/default/old.md", size=len(note), hash=file_hash)])
    bundle = str(tmp_path / "v0.kbbundle")
    with BundleWriter(bundle) as writer:
        writer.write_manifest(mmod.serialize(manifest))
        writer.add_file(mmod.DB_MEMBER, src_db)
        writer.add_bytes("data/default/old.md", note)

    result = import_bundle(target_config, bundle)
    assert result["artifact_count"] == 1

    live = sqlite3.connect(target_config["PATH_KB_DB"])
    assert db.get_schema_version(live) == 1
    cols = [r[1] for r in live.execute("PRAGMA table_info(artifacts);")]
    assert "template" in cols
    assert live.execute(
        "SELECT path FROM artifacts;").fetchone()[0] == "default/old.md"
    live.close()
    assert (Path(target_config["PATH_KB_DATA"]) /
            "default/old.md").read_bytes() == note


def test_dangling_reference_rejected(target_config, tmp_path):
    src_db = tmp_path / "dangling.db"
    db.create_kb_database(str(src_db), 1)
    conn = sqlite3.connect(str(src_db))
    conn.execute(
        "INSERT INTO artifacts (id,title,category,path) "
        "VALUES (1,'ghost','default','default/missing.md');")
    conn.commit()
    conn.close()

    db_hash = __import__("hashlib").sha256(src_db.read_bytes()).hexdigest()
    manifest = mmod.build_manifest(
        schema_version=1,
        db=mmod.DBDump(
            schema_version=1, size=src_db.stat().st_size, hash=db_hash,
            artifact_count=1, tag_count=0))
    bundle = str(tmp_path / "dangling.kbbundle")
    with BundleWriter(bundle) as writer:
        writer.write_manifest(mmod.serialize(manifest))
        writer.add_file(mmod.DB_MEMBER, src_db)

    with pytest.raises(DBCheckError):
        import_bundle(target_config, bundle)


# ---------------------------------------------------------------------------
# Signatures and encryption
# ---------------------------------------------------------------------------

class TestSigning:

    def test_signed_roundtrip(self, source_config, target_config, tmp_path):
        key = b"shared-secret"
        keyfile = tmp_path / "key.bin"
        keyfile.write_bytes(key)
        bundle = export_bundle(
            source_config, str(tmp_path / "signed.kbbundle"),
            sign_key=key, sign_kid=str(keyfile))

        with pytest.raises(SignatureError):
            import_bundle(target_config, bundle)  # no key supplied
        with pytest.raises(SignatureError):
            import_bundle(target_config, bundle, verify_key=b"wrong")
        result = import_bundle(target_config, bundle, verify_key=key)
        assert result["signed"] is True

    def test_unsigned_bundle_with_key_fails(self, source_config,
                                            target_config, tmp_path):
        bundle = export_bundle(
            source_config, str(tmp_path / "unsigned.kbbundle"))
        with pytest.raises(SignatureError):
            import_bundle(target_config, bundle, verify_key=b"k")


class TestEncryption:

    def test_encrypted_roundtrip_and_wrong_passphrase(
            self, source_config, target_config, tmp_path):
        second_target = make_config(tmp_path / "dst2")
        initializer.init(second_target)

        bundle = export_bundle(
            source_config, str(tmp_path / "secret.kbbundle"),
            passphrase=b"correct horse")
        with pytest.raises(CryptoError):
            import_bundle(target_config, bundle)
        with pytest.raises(CryptoError):
            import_bundle(target_config, bundle, passphrase=b"wrong")
        result = import_bundle(
            second_target, bundle, passphrase=b"correct horse")
        assert result["artifact_count"] == 1

    def test_chunked_aesgcm_framing(self):
        provider = AESGCMChunkedProvider()
        for size in (0, 1, 1024, 2048, 3000, 5000):
            plaintext = bytes((i % 256 for i in range(size)))
            src = io.BytesIO(plaintext)
            encrypted = io.BytesIO()
            header = provider.encrypt_stream(
                src, encrypted, b"pw", chunk_size=1024)
            encrypted.seek(0)
            decrypted = io.BytesIO()
            provider.decrypt_stream(
                encrypted, decrypted, b"pw", header)
            assert decrypted.getvalue() == plaintext

    def test_tampered_ciphertext_rejected(self):
        provider = AESGCMChunkedProvider()
        encrypted = io.BytesIO()
        header = provider.encrypt_stream(
            io.BytesIO(b"secret payload"), encrypted, b"pw",
            chunk_size=64)
        raw = bytearray(encrypted.getvalue())
        raw[-1] ^= 0xFF  # flip a byte in the final frame
        with pytest.raises(CryptoError):
            provider.decrypt_stream(
                io.BytesIO(bytes(raw)), io.BytesIO(), b"pw", header)


# ---------------------------------------------------------------------------
# Generations
# ---------------------------------------------------------------------------

class TestGenerations:

    def test_adopt_switch_rollback_prune(self, source_config,
                                         target_config, tmp_path):
        bundle = export_bundle(
            source_config, str(tmp_path / "g.kbbundle"))
        result = import_bundle(target_config, bundle)

        store = GenerationStore.open(target_config)
        entries = store.generations()
        sources = [e["source"] for e in entries]
        assert "adopt" in sources
        assert "checkpoint" in sources
        assert "import" in sources

        note = Path(target_config["PATH_KB_DATA"]) / "default" / "note.md"
        assert note.exists()
        assert (target_config and Path(
            target_config["PATH_KB"]).joinpath("gen").is_symlink())

        adopt_id = next(e["id"] for e in entries if e["source"] == "adopt")
        store.rollback(adopt_id)
        assert not note.exists()

        # Rollback adds a checkpoint generation; pruning keeps the cap
        # and always retains the active generation.
        removed = store.prune(2)
        remaining = store.generations()
        current = store.current_id()
        assert current not in removed
        assert current in [e["id"] for e in remaining]
        assert len(remaining) <= 2
        # Re-import to prove the forward path works after a rollback.
        result2 = import_bundle(target_config, bundle)
        assert note.exists()
        assert result2["generation"] != result["generation"]

    def test_rollback_unknown_generation(self, target_config):
        store = GenerationStore.open(target_config)
        with pytest.raises(Exception):
            store.rollback("gen-does-not-exist")

    def test_checkpoint_is_independent_of_later_edits(
            self, source_config, target_config, tmp_path):
        # Retained generations (and the checkpoint taken before a
        # switch) must not drift with edits made to the live knowledge
        # base after the switch. The *active* generation backs the live
        # symlink tree and therefore does drift - that is expected.
        bundle_v1 = export_bundle(
            source_config, str(tmp_path / "v1.kbbundle"))
        r1 = import_bundle(target_config, bundle_v1)

        note_src = Path(
            source_config["PATH_KB_DATA"]) / "default" / "note.md"
        note_src.write_text("# hello bundle v2\n")
        bundle_v2 = export_bundle(
            source_config, str(tmp_path / "v2.kbbundle"))
        r2 = import_bundle(target_config, bundle_v2)
        assert r2["generation"] != r1["generation"]

        live_note = (
            Path(target_config["PATH_KB_DATA"]) / "default" / "note.md")
        assert live_note.read_text() == "# hello bundle v2\n"
        live_note.write_text("# mutated after switch\n")

        store = GenerationStore.open(target_config)
        gens = store.gens_root

        # The v1 import generation stays frozen at the v1 content.
        v1_note = gens / r1["generation"] / "data" / "default" / "note.md"
        assert v1_note.read_text() == "# hello bundle\n"

        # The checkpoint captured before the v2 switch is a real copy
        # of the v1 live state, frozen as well.
        entries = store.generations()
        checkpoint = next(
            e for e in entries
            if e.get("source") == "checkpoint"
            and e.get("seq") == r2["seq"] - 1)
        cp_note = gens / checkpoint["id"] / "data" / "default" / "note.md"
        assert cp_note.read_text() == "# hello bundle\n"

        # The active generation reflects the later live edit.
        active_note = (
            gens / r2["generation"] / "data" / "default" / "note.md")
        assert active_note.read_text() == "# mutated after switch\n"


# ---------------------------------------------------------------------------
# Legacy archive migration
# ---------------------------------------------------------------------------

def _build_legacy_archive(kb_root: Path, out_path: str):
    with tarfile.open(out_path, "w:gz") as tar:
        tar.add(str(kb_root), arcname=".kb")


class TestLegacyAdapter:

    def test_legacy_tar_gz_is_migrated(self, tmp_path):
        kb_root = tmp_path / "oldkb"
        config = make_config(kb_root)
        seed_kb(
            config,
            artifacts=[Artifact(None, "oldnote", "default",
                                path="default/oldnote.md")],
            extra_files=(("default/oldnote.md", "from the past\n"),))

        archive = str(tmp_path / "legacy.kb.tar.gz")
        _build_legacy_archive(Path(config["PATH_KB"]), archive)

        dst = make_config(tmp_path / "legdst")
        initializer.init(dst)
        result = import_bundle(dst, archive)
        assert result["legacy"] is True
        note = Path(dst["PATH_KB_DATA"]) / "default" / "oldnote.md"
        assert note.read_text() == "from the past\n"

    def test_git_directory_is_refused(self, tmp_path):
        kb_root = tmp_path / "oldkb2"
        config = make_config(kb_root)
        initializer.init(config)
        git_dir = Path(config["PATH_KB"]) / ".git"
        (git_dir).mkdir(parents=True)
        (git_dir / "config").write_text("evil")

        archive = str(tmp_path / "evil.kb.tar.gz")
        _build_legacy_archive(Path(config["PATH_KB"]), archive)

        dst = make_config(tmp_path / "legdst2")
        initializer.init(dst)
        from kb.bundle.errors import LegacyArchiveError
        with pytest.raises(LegacyArchiveError):
            import_bundle(dst, archive)

    def test_legacy_export_excludes_bundle_internal_dirs(self, tmp_path):
        # A knowledge base already carrying bundle machinery
        # (.generations/.staging) must not leak those into a legacy
        # archive; the result stays importable.
        kb_root = tmp_path / "oldkb3"
        config = make_config(kb_root)
        seed_kb(
            config,
            artifacts=[Artifact(None, "kept", "default",
                                path="default/kept.md")],
            extra_files=(("default/kept.md", "kept content\n"),))
        (Path(config["PATH_KB"]) / ".generations").mkdir()
        (Path(config["PATH_KB"]) / ".staging").mkdir()

        out = str(tmp_path / "filtered.kb.tar.gz")
        from kb.commands.export import export as cmd_export
        cmd_export({"file": out, "only_data": False, "bundle": False},
                   config)

        with tarfile.open(out, "r:gz") as archive:
            names = archive.getnames()
        assert not any(
            ".generations" in n or ".staging" in n for n in names)
        assert ".kb/data/default/kept.md" in names

        dst = make_config(tmp_path / "legdst3")
        initializer.init(dst)
        result = import_bundle(dst, out)
        assert result["legacy"] is True
        assert (Path(dst["PATH_KB_DATA"]) /
                "default" / "kept.md").read_text() == "kept content\n"


class TestExporterHygiene:

    def test_export_leaves_no_scratch_inside_kb(self, source_config,
                                                tmp_path):
        out = str(tmp_path / "clean.kbbundle")
        export_bundle(source_config, out)
        kb_root = Path(source_config["PATH_KB"])
        assert not (kb_root / ".staging").exists()
        assert Path(out).is_file()


# ---------------------------------------------------------------------------
# CLI parser wiring
# ---------------------------------------------------------------------------

def test_cli_parsers_wire_new_flags():
    export_args = cl_parser.parse_args(
        ["export", "--bundle", "--gzip", "--sign-key", "key.bin",
         "--encrypt", "--no-history"])
    assert export_args.bundle is True
    assert export_args.gzip is True
    assert export_args.sign_key == "key.bin"

    import_args = cl_parser.parse_args(
        ["import", "x.kbbundle", "-y", "--verify-key", "key.bin",
         "--no-resume"])
    assert import_args.yes is True
    assert import_args.verify_key == "key.bin"
    assert import_args.no_resume is True

    gens_args = cl_parser.parse_args(["generations", "rollback", "gen-1"])
    assert gens_args.generations_operation == "rollback"
    assert gens_args.gen_id == "gen-1"
