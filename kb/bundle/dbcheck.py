# -*- encoding: utf-8 -*-
# kb v0.1.8

"""
Database dumping and verification for KB Bundles.

The dump embedded in a bundle is always taken through SQLite's online
backup API, so it is a consistent snapshot even if the source database
is in use. On import the staged dump goes through:

1. ``PRAGMA integrity_check`` and ``PRAGMA foreign_key_check``;
2. the schema migration chain (e.g. v0 -> v1), run on the isolated
   staging copy - never on the live database;
3. cross-platform normalization of artifact paths (POSIX form,
   containment inside the data directory);
4. reference checks between the database and the extracted files, and
   between the tags and artifacts tables;
5. row-count reconciliation against the manifest.
"""

import sqlite3
from pathlib import Path
from typing import Dict, List, Optional

import kb.db as db
from kb.bundle import paths as vpaths
from kb.bundle.errors import DBCheckError


# ---------------------------------------------------------------------------
# Consistent dump
# ---------------------------------------------------------------------------

def dump_database(src_path, dest_path, *, pages: int = 1000) -> None:
    """
    Produce a consistent snapshot of a live SQLite database.

    Uses the online backup API; unlike a raw file copy this is safe
    while writers are active and never reads torn pages. The progress
    callback drives the paged loop so the operation stays responsive
    with very large databases.
    """
    src = sqlite3.connect(str(src_path))
    dst = sqlite3.connect(str(dest_path))
    try:
        # pages bounds the pages copied per internal step; the call
        # still drives the whole backup to completion synchronously.
        src.backup(dst, pages=pages)
    finally:
        dst.close()
        src.close()


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def check_database_integrity(conn) -> None:
    """Reject a physically or logically corrupt database."""
    result = conn.execute("PRAGMA integrity_check;").fetchall()
    if not result or result[0][0] != "ok":
        raise DBCheckError(
            "Database integrity check failed: {}".format(result[:3]))

    fk_violations = conn.execute(
        "PRAGMA foreign_key_check;").fetchall()
    if fk_violations:
        raise DBCheckError(
            "Database has {} foreign key violation(s), first: {}".format(
                len(fk_violations), fk_violations[0]))


def get_table_counts(conn) -> Dict[str, int]:
    cur = conn.cursor()
    artifact_count = cur.execute(
        "SELECT COUNT(*) FROM artifacts;").fetchone()[0]
    tag_count = cur.execute(
        "SELECT COUNT(*) FROM tags;").fetchone()[0]
    return {"artifact_count": artifact_count, "tag_count": tag_count}


def migrate_schema(conn, target_version: int) -> int:
    """
    Run the full migration chain on a staging connection.

    Migrations live in :mod:`kb.db` and are applied strictly in order;
    the starting version must be <= the target version.
    """
    current = db.get_schema_version(conn)
    if current > target_version:
        raise DBCheckError(
            "Bundle database schema v{} is newer than this kb release "
            "(supports up to v{})".format(current, target_version))

    # Ordered migration table; each entry maps version N -> N+1.
    migrations = {
        0: db.migrate_v0_to_v1,
    }
    while current < target_version:
        step = migrations.get(current)
        if step is None:
            raise DBCheckError(
                "No migration available from schema v{} to v{}".format(
                    current, target_version))
        step(conn)
        new_version = db.get_schema_version(conn)
        if new_version == current:
            raise DBCheckError(
                "Migration from v{} did not bump the schema version".format(
                    current))
        current = new_version
    return current


def normalize_artifact_paths(conn) -> List[str]:
    """
    Rewrite artifact paths to canonical cross-platform form.

    Backslashes are converted to POSIX separators, absolute paths,
    drive letters and traversal are rejected. Returns the list of
    updated path values.
    """
    cur = conn.cursor()
    rows = cur.execute("SELECT id, path FROM artifacts;").fetchall()
    updated = []
    for artifact_id, raw_path in rows:
        if not raw_path:
            raise DBCheckError(
                "Artifact {} has an empty path".format(artifact_id))
        normalized = vpaths.normalize_virtual_path(raw_path)
        if normalized != raw_path:
            cur.execute("UPDATE artifacts SET path=? WHERE id=?;",
                        (normalized, artifact_id))
            updated.append(normalized)
    conn.commit()
    return updated


def check_references(conn, data_root) -> Dict[str, List]:
    """
    Cross-check database rows against the extracted staging tree.

    Returns a report with dangling artifact files, orphan tag rows and
    duplicate (title, category) keys. The importer turns a non-empty
    report into a DBCheckError.
    """
    data_path = Path(data_root)
    cur = conn.cursor()

    dangling_paths = []
    seen_keys = set()
    duplicate_keys = []
    empty_fields = []

    for row in cur.execute(
            "SELECT id, title, category, path FROM artifacts;"):
        artifact_id, title, category, rel_path = row
        if not title or not category or not rel_path:
            empty_fields.append(artifact_id)
            continue
        key = (title, category)
        if key in seen_keys:
            duplicate_keys.append(key)
        seen_keys.add(key)

        normalized = vpaths.normalize_virtual_path(rel_path)
        local = vpaths.virtual_to_local(data_path, normalized)
        if not local.exists():
            dangling_paths.append(normalized)

    orphan_tags = [row[0] for row in cur.execute(
        """SELECT DISTINCT tags.artifact_id FROM tags
           LEFT JOIN artifacts ON artifacts.id = tags.artifact_id
           WHERE artifacts.id IS NULL;""")]

    report = {
        "dangling_paths": dangling_paths,
        "orphan_tags": orphan_tags,
        "duplicate_keys": duplicate_keys,
        "empty_fields": empty_fields,
    }
    return report


def verify_staged_database(db_path, data_root, manifest,
                           config) -> Dict[str, int]:
    """
    Full staging pipeline for the bundled database dump.

    Integrity -> migration -> path normalization -> reference checks ->
    manifest reconciliation. Returns the final table counts.
    Raises :class:`DBCheckError` on any inconsistency.
    """
    conn = sqlite3.connect(str(db_path))
    try:
        check_database_integrity(conn)

        original_version = db.get_schema_version(conn)
        if original_version != manifest.schema_version:
            raise DBCheckError(
                "Schema version mismatch: manifest declares v{}, dump is v{}"
                .format(manifest.schema_version, original_version))

        target_version = int(config["DB_SCHEMA_VERSION"])
        final_version = migrate_schema(conn, target_version)
        normalize_artifact_paths(conn)

        counts = get_table_counts(conn)
        if counts["artifact_count"] != manifest.db.artifact_count:
            raise DBCheckError(
                "Artifact count mismatch: manifest {}, database {}".format(
                    manifest.db.artifact_count,
                    counts["artifact_count"]))
        if counts["tag_count"] != manifest.db.tag_count:
            raise DBCheckError(
                "Tag count mismatch: manifest {}, database {}".format(
                    manifest.db.tag_count, counts["tag_count"]))

        report = check_references(conn, data_root)
        problems = []
        if report["dangling_paths"]:
            problems.append(
                "{} artifact(s) point to missing files, e.g. {}".format(
                    len(report["dangling_paths"]),
                    report["dangling_paths"][:3]))
        if report["orphan_tags"]:
            problems.append(
                "{} orphan tag row(s), artifact ids e.g. {}".format(
                    len(report["orphan_tags"]),
                    report["orphan_tags"][:3]))
        if report["duplicate_keys"]:
            problems.append(
                "{} duplicate (title, category) keys, e.g. {}".format(
                    len(report["duplicate_keys"]),
                    report["duplicate_keys"][:3]))
        if report["empty_fields"]:
            problems.append(
                "{} artifact(s) with empty title/category/path, ids e.g. {}"
                .format(len(report["empty_fields"]),
                        report["empty_fields"][:3]))
        if problems:
            raise DBCheckError("; ".join(problems))

        counts["schema_version"] = final_version
        return counts
    finally:
        conn.close()
