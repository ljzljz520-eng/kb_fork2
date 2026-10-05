# -*- encoding: utf-8 -*-
# kb v0.1.8

"""
Generation management: atomic import switches and rollback.

Two switch strategies are supported and selected automatically when an
existing knowledge base is *adopted*:

``symlink`` (preferred on POSIX)
    Every generation lives under ``.generations/<id>/`` as a complete,
    self-contained tree (``kb.db``, ``data/``, ``templates/``,
    ``recent.hist``). The legacy paths are relative symlinks through a
    single ``gen`` symlink, so activating a generation is exactly one
    ``rename(2)`` of that symlink - atomic and crash safe.

``flat`` (fallback when symlink creation is denied, e.g. some Windows
setups)
    Live paths stay real files/directories. Activation copies the new
    generation into ``<name>.new`` siblings and swaps them per component,
    driven by a durable ``switching.json`` marker that a crash recovery
    pass can resume.

Before every switch the current live state is copied into a fresh
*checkpoint* generation, so rollback always restores an exact, immutable
state (never a generation that kept mutating through later edits).
"""

import json
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from kb.bundle.errors import GenerationError

META_FILE = "meta.json"
MANIFEST_FILE = "manifest.json"
CURRENT_FILE = "current.json"
SWITCH_MARKER = "switching.json"
FLAT_MARKER = "FLAT"
GEN_LINK = "gen"
GEN_PREFIX = "gen-"

# (component name, kind) - the complete state of a knowledge base.
COMPONENTS = (
    ("kb.db", "file"),
    ("recent.hist", "file"),
    ("data", "dir"),
    ("templates", "dir"),
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_id(seq: int) -> str:
    return "{}{:07d}-{}".format(GEN_PREFIX, seq, uuid.uuid4().hex[:8])


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

class GenerationStore:
    """Handle adoption, switching, rollback and pruning of generations."""

    def __init__(self, config: Dict):
        self.kb_root = Path(config["PATH_KB"])
        self.gens_root = Path(config.get(
            "PATH_KB_GENERATIONS", str(self.kb_root / ".generations")))
        self.staging_root = Path(config.get(
            "PATH_KB_STAGING", str(self.kb_root / ".staging")))
        self.config = config
        # open() re-evaluates the strategy after the generations root
        # exists and the flat marker can be tested reliably.
        self.strategy = "symlink"

    # -- construction -----------------------------------------------------

    @classmethod
    def open(cls, config: Dict) -> "GenerationStore":
        """
        Open the store, adopting a legacy on-disk layout on first use and
        completing any interrupted flat-mode switch.
        """
        store = cls(config)
        store.gens_root.mkdir(parents=True, exist_ok=True)
        store.staging_root.mkdir(parents=True, exist_ok=True)
        store.strategy = "flat" if (store.gens_root / FLAT_MARKER).exists() \
            else "symlink"

        if not store._is_adopted():
            store._adopt()
        store._recover()
        return store

    def _is_adopted(self) -> bool:
        current = self.gens_root / CURRENT_FILE
        if current.exists():
            return True
        # Pre-current.json adoption layouts still show the gen symlink.
        return (self.strategy == "symlink" and
                (self.kb_root / GEN_LINK).is_symlink())

    @property
    def current_file(self) -> Path:
        return self.gens_root / CURRENT_FILE

    def _can_create_symlinks(self) -> bool:
        probe_dir = self.gens_root
        probe_link = probe_dir / ".symlink-probe-{}".format(uuid.uuid4().hex)
        probe_target = probe_dir / ".symlink-target"
        try:
            probe_target.mkdir(exist_ok=True)
            os.symlink("x", str(probe_link))
        except (OSError, NotImplementedError):
            return False
        else:
            return True
        finally:
            try:
                probe_link.unlink()
            except OSError:
                pass

    def _adopt(self) -> None:
        """Turn a classic kb directory (real files) into the gen layout."""
        can_symlink = self._can_create_symlinks()
        self.strategy = "symlink" if can_symlink else "flat"
        if not can_symlink:
            (self.gens_root / FLAT_MARKER).touch()

        seq = 1
        gen_id = _new_id(seq)
        gen_dir = self.gens_root / gen_id
        gen_dir.mkdir(parents=True)

        for name, _kind in COMPONENTS:
            live = self.kb_root / name
            if not live.exists() and not live.is_symlink():
                continue
            if self.strategy == "symlink":
                # Move: nothing references the legacy path yet, so a move
                # costs no extra space.
                shutil.move(str(live), str(gen_dir / name))
            else:
                self._copy_component(live, gen_dir / name)

        self._materialize(gen_dir)
        self._write_meta(gen_dir, {
            "id": gen_id, "seq": seq, "created_at": _utcnow(),
            "source": "adopt", "note": "pre-bundle knowledge base",
        })

        if self.strategy == "symlink":
            self._link_gen(gen_id)
            for name, _kind in COMPONENTS:
                self._ensure_legacy_link(name)
        self._write_current(gen_id, seq)

    # -- introspection ----------------------------------------------------

    def current_id(self) -> Optional[str]:
        try:
            return json.loads(self.current_file.read_text())["id"]
        except (OSError, ValueError, KeyError):
            return None

    def current_gen_dir(self) -> Path:
        gen_id = self.current_id()
        if not gen_id:
            raise GenerationError("No active generation")
        gen_dir = self.gens_root / gen_id
        if not gen_dir.is_dir():
            raise GenerationError(
                "Active generation {} is missing".format(gen_id))
        return gen_dir

    def generations(self) -> List[Dict]:
        result = []
        current = self.current_id()
        for child in self.gens_root.iterdir():
            meta_path = child / META_FILE
            if not child.is_dir() or not meta_path.exists():
                continue
            try:
                meta = json.loads(meta_path.read_text())
            except (OSError, ValueError):
                continue
            meta["current"] = (meta.get("id") == current)
            result.append(meta)
        result.sort(key=lambda m: m.get("seq", 0))
        return result

    # -- staging ----------------------------------------------------------

    def new_staging_dir(self) -> Path:
        token = "staging-{}".format(uuid.uuid4().hex)
        staging = self.staging_root / token
        staging.mkdir(parents=True)
        return staging

    def cleanup_staging(self, staging_dir) -> None:
        staging_dir = Path(staging_dir)
        if self.staging_root in staging_dir.parents:
            shutil.rmtree(str(staging_dir), ignore_errors=True)

    # -- switching --------------------------------------------------------

    def commit_import(self, staging_dir, manifest_summary: Dict,
                      note: str = "") -> Dict:
        """
        Checkpoint the live state, install the validated staging payload
        as a new generation and atomically switch to it.
        """
        staging_dir = Path(staging_dir)
        if not staging_dir.is_dir():
            raise GenerationError(
                "Staging directory does not exist: {}".format(staging_dir))

        self._materialize(staging_dir)

        # Checkpoint the current live state first.
        checkpoint_meta = self._checkpoint_live("pre-import checkpoint")

        seq = self._next_seq()
        new_id = _new_id(seq)
        gen_dir = self.gens_root / new_id
        os.rename(str(staging_dir), str(gen_dir))
        self._materialize(gen_dir)

        self._write_manifest_snapshot(gen_dir, manifest_summary)
        self._write_meta(gen_dir, {
            "id": new_id, "seq": seq, "created_at": _utcnow(),
            "source": "import", "note": note,
            "checkpoint": checkpoint_meta["id"] if checkpoint_meta else None,
            "bundle": manifest_summary,
        })

        self._switch(gen_dir, new_id, seq)
        return json.loads((gen_dir / META_FILE).read_text())

    def rollback(self, gen_id: str, note: str = "") -> Dict:
        """Atomically restore a retained generation, checkpointing live."""
        target = self.gens_root / gen_id
        if not target.is_dir() or not (target / META_FILE).exists():
            raise GenerationError(
                "Unknown generation: {}".format(gen_id))
        if gen_id == self.current_id():
            raise GenerationError(
                "Generation {} is already active".format(gen_id))

        self._checkpoint_live("pre-rollback checkpoint")
        target_meta = json.loads((target / META_FILE).read_text())
        self._switch(target, target_meta["id"], target_meta["seq"],
                     rollback=True)
        return target_meta

    def prune(self, keep: int) -> List[str]:
        """
        Retain at most ``keep`` generations (the active one is always
        retained even if the limit is smaller).
        """
        if keep < 1:
            raise GenerationError("keep must be >= 1")
        gens = self.generations()
        current = self.current_id()
        removable = [g for g in gens if g["id"] != current]
        removable.sort(key=lambda m: m.get("seq", 0), reverse=True)
        victims = removable[max(keep - 1, 0):]
        removed = []
        for meta in victims:
            shutil.rmtree(str(self.gens_root / meta["id"]), ignore_errors=True)
            removed.append(meta["id"])
        return removed

    # -- internals --------------------------------------------------------

    def _next_seq(self) -> int:
        seqs = [g.get("seq", 0) for g in self.generations()]
        return (max(seqs) if seqs else 0) + 1

    def _checkpoint_live(self, note: str) -> Optional[Dict]:
        seq = self._next_seq()
        gen_id = _new_id(seq)
        gen_dir = self.gens_root / gen_id
        gen_dir.mkdir(parents=True)
        for name, _kind in COMPONENTS:
            live = self.kb_root / name
            if live.exists() or live.is_symlink():
                self._copy_component(live, gen_dir / name)
        self._materialize(gen_dir)
        meta = {
            "id": gen_id, "seq": seq, "created_at": _utcnow(),
            "source": "checkpoint", "note": note,
        }
        self._write_meta(gen_dir, meta)
        return meta

    def _switch(self, gen_dir: Path, gen_id: str, seq: int,
                rollback: bool = False) -> None:
        if self.strategy == "symlink":
            self._link_gen(gen_id)
            for name, _kind in COMPONENTS:
                self._ensure_legacy_link(name)
            self._write_current(gen_id, seq)
        else:
            self._flat_switch(gen_dir, gen_id)
            self._write_current(gen_id, seq)

    # -- symlink strategy -------------------------------------------------

    def _link_gen(self, gen_id: str) -> None:
        tmp = self.kb_root / "{}.tmp-{}".format(GEN_LINK, uuid.uuid4().hex)
        os.symlink(str(Path(self.gens_root.name) / gen_id), str(tmp))
        os.replace(str(tmp), str(self.kb_root / GEN_LINK))

    def _ensure_legacy_link(self, name: str) -> None:
        legacy = self.kb_root / name
        if legacy.is_symlink():
            return
        if legacy.exists():
            # A real file slipped in (e.g. recent.hist recreated by an old
            # build): move it aside into the generation the gen link
            # currently points at (current.json may not be written yet
            # during adoption, so resolve the link directly).
            active = Path(self.kb_root / GEN_LINK).resolve()
            shutil.move(str(legacy), str(active / name))
        os.symlink(str(Path(GEN_LINK) / name), str(legacy))

    # -- flat strategy ----------------------------------------------------

    def _marker_path(self) -> Path:
        return self.gens_root / SWITCH_MARKER

    def _write_marker(self, payload: Dict) -> None:
        tmp = self._marker_path().with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, sort_keys=True))
        os.replace(str(tmp), str(self._marker_path()))

    def _flat_switch(self, gen_dir: Path, gen_id: str) -> None:
        marker = {"new_id": gen_id, "steps": {}}
        self._write_marker(marker)
        for name, _kind in COMPONENTS:
            self._flat_install_component(gen_dir / name, name, marker)
        self._marker_path().unlink(missing_ok=True)

    def _flat_install_component(self, source: Path, name: str,
                                marker: Dict) -> None:
        live = self.kb_root / name
        new_path = self.kb_root / "{}.new".format(name)
        old_path = self.kb_root / "{}.old".format(name)

        steps = marker["steps"]
        state = steps.get(name)

        if state is None:
            if new_path.exists():
                shutil.rmtree(str(new_path), ignore_errors=True)
            if source.exists():
                self._copy_component(source, new_path)
            else:
                self._materialize_component(new_path, name)
            steps[name] = "staged"
            self._write_marker(marker)
            state = "staged"

        if state == "staged":
            if live.exists() or live.is_symlink():
                if old_path.exists():
                    shutil.rmtree(str(old_path), ignore_errors=True)
                os.rename(str(live), str(old_path))
            os.rename(str(new_path), str(live))
            steps[name] = "swapped"
            self._write_marker(marker)

        if state in ("staged", "swapped"):
            if old_path.is_dir() and not old_path.is_symlink():
                shutil.rmtree(str(old_path), ignore_errors=True)
            elif old_path.exists() or old_path.is_symlink():
                old_path.unlink()
            steps[name] = "done"
            self._write_marker(marker)

    def _recover(self) -> None:
        """Resume an interrupted flat switch; clean symlink leftovers."""
        if self.strategy == "symlink":
            for stray in self.kb_root.glob("{}.tmp-*".format(GEN_LINK)):
                stray.unlink(missing_ok=True)
            return

        marker_path = self._marker_path()
        if not marker_path.exists():
            return
        try:
            marker = json.loads(marker_path.read_text())
        except (OSError, ValueError):
            marker_path.unlink(missing_ok=True)
            return
        gen_dir = self.gens_root / marker["new_id"]
        for name, _kind in COMPONENTS:
            state = marker.get("steps", {}).get(name)
            live = self.kb_root / name
            new_path = self.kb_root / "{}.new".format(name)
            old_path = self.kb_root / "{}.old".format(name)
            if state == "staged":
                # The atomic swap never happened; retry it.
                self._flat_install_component(gen_dir / name, name, marker)
            elif state == "swapped":
                if old_path.is_dir() and not old_path.is_symlink():
                    shutil.rmtree(str(old_path), ignore_errors=True)
                elif old_path.exists() or old_path.is_symlink():
                    old_path.unlink()
                marker["steps"][name] = "done"
                self._write_marker(marker)
            else:
                # Half-copied .new from before the first marker update.
                if new_path.exists() and not (live.exists()):
                    self._flat_install_component(gen_dir / name, name, marker)
        marker_path.unlink(missing_ok=True)

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _copy_component(source: Path, dest: Path) -> None:
        """
        Snapshot a component.

        Top-level legacy paths are symlinks in symlink mode: those MUST be
        followed (a checkpoint that links back at the active generation
        would drift with later edits). Inner symlinks inside ``data/``
        are preserved as links because they were validated to be
        self-contained during import.
        """
        source = Path(source)
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        real = source.resolve() if source.is_symlink() else source
        if real.is_dir():
            shutil.copytree(str(real), str(dest), symlinks=True)
        elif real.is_file():
            shutil.copy2(str(real), str(dest))
        else:
            raise GenerationError(
                "Cannot snapshot component {} (missing at switch time)"
                .format(source))

    @staticmethod
    def _materialize_component(path: Path, name: str) -> None:
        if name in ("data", "templates"):
            path.mkdir(parents=True, exist_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.touch()

    def _materialize(self, gen_dir: Path) -> None:
        """Ensure every generation contains all four components."""
        gen_dir = Path(gen_dir)
        gen_dir.mkdir(parents=True, exist_ok=True)
        for name, _kind in COMPONENTS:
            self._materialize_component(gen_dir / name, name)

    def _write_meta(self, gen_dir: Path, meta: Dict) -> None:
        tmp = gen_dir / (META_FILE + ".tmp")
        tmp.write_text(json.dumps(meta, sort_keys=True, indent=2))
        os.replace(str(tmp), str(gen_dir / META_FILE))

    def _write_manifest_snapshot(self, gen_dir: Path, summary: Dict) -> None:
        tmp = gen_dir / (MANIFEST_FILE + ".tmp")
        tmp.write_text(json.dumps(summary, sort_keys=True, indent=2))
        os.replace(str(tmp), str(gen_dir / MANIFEST_FILE))

    def _write_current(self, gen_id: str, seq: int) -> None:
        payload = {"id": gen_id, "seq": seq, "updated_at": _utcnow()}
        tmp = self.current_file.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, sort_keys=True))
        os.replace(str(tmp), str(self.current_file))
