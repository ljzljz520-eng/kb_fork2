# -*- encoding: utf-8 -*-
# kb v0.1.8

"""
Cross-platform path normalization for KB Bundle members.

Every path stored *inside* a bundle is a virtual POSIX path:

* ``/`` is the only path separator (backslashes are normalized to ``/``
  so archives produced on Windows stay portable);
* paths are relative, they never start with ``/`` or a drive letter;
* no ``.`` / ``..`` components are allowed (no traversal, no anchoring
  to the extracting host);
* Windows reserved device names (``NUL``, ``CON``, ``LPT1`` ...) and
  characters that are illegal in Windows file names are rejected, so a
  bundle can always be extracted on Windows, macOS and Linux;
* symbolic links may only point to locations that resolve, lexically,
  inside the bundle root.

The normalization is deliberately strict and host-independent: it never
touches the local filesystem, therefore it can be applied before any
byte is extracted.
"""

import posixpath
import re
from pathlib import Path
from typing import Iterable

from kb.bundle.errors import PathValidationError, SymlinkError

# Characters that are illegal in Windows file names plus NUL.
_INVALID_COMPONENT_CHARS = re.compile(r'[\x00-\x1f<>:"|?*]')

# Windows reserved device names (case-insensitive), with or without
# an extension such as "nul.txt".
_RESERVED_NAMES = {
    "con", "prn", "aux", "nul",
    *("com{}".format(i) for i in range(1, 10)),
    *("lpt{}".format(i) for i in range(1, 10)),
}

# Conservative per-component limit (Windows MAX_PATH with room to spare
# for the hosting prefix).
_MAX_COMPONENT_BYTES = 255

_DRIVE_RE = re.compile(r"^[A-Za-z]:")


def normalize_virtual_path(raw: str) -> str:
    """
    Normalize a bundle member path to its canonical virtual form.

    Backslashes are converted to ``/``, redundant separators and ``.``
    components are dropped. The result is validated and returned as a
    POSIX style relative path without leading ``./``.

    Raises :class:`PathValidationError` for absolute paths, drive
    letters, traversal (``..``), reserved/illegal names or empty paths.
    """
    if raw is None or not isinstance(raw, str):
        raise PathValidationError("Bundle path must be a non-null string")

    path = raw
    if "\x00" in path:
        raise PathValidationError("NUL byte in bundle path: {!r}".format(raw))

    # Backslash is a valid character in POSIX file names but a separator
    # on Windows; bundles treat it as a separator everywhere.
    path = path.replace("\\", "/")

    if path.startswith("//"):
        raise PathValidationError(
            "UNC/network paths are not allowed in a bundle: {!r}".format(raw))
    if path.startswith("/"):
        raise PathValidationError(
            "Absolute paths are not allowed in a bundle: {!r}".format(raw))

    parts = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise PathValidationError(
                "Parent-directory traversal is not allowed: {!r}".format(raw))
        if _DRIVE_RE.match(part) and (len(part) == 2 or part[2] == "/"):
            raise PathValidationError(
                "Drive-letter paths are not allowed in a bundle: {!r}"
                .format(raw))
        _validate_component(part, raw)
        parts.append(part)

    if not parts:
        raise PathValidationError(
            "Empty or dot-only path is not allowed: {!r}".format(raw))

    return "/".join(parts)


def _validate_component(part: str, raw: str) -> None:
    """Reject component names that are unsafe on any target platform."""
    if _INVALID_COMPONENT_CHARS.search(part):
        raise PathValidationError(
            "Bundle path contains illegal characters: {!r}".format(raw))
    if part.endswith((" ", ".")):
        raise PathValidationError(
            "Trailing space/dot is unsafe on Windows: {!r}".format(raw))
    if len(part.encode("utf-8")) > _MAX_COMPONENT_BYTES:
        raise PathValidationError(
            "Path component exceeds {} bytes: {!r}"
            .format(_MAX_COMPONENT_BYTES, raw))
    stem = part.split(".", 1)[0].lower()
    if stem in _RESERVED_NAMES:
        raise PathValidationError(
            "Windows reserved name is not allowed in a bundle: {!r}"
            .format(raw))


def validate_symlink_target(link_vpath: str, raw_target: str) -> str:
    """
    Validate a symlink stored in the bundle.

    The target must be relative and its lexical resolution against the
    link directory must stay inside the bundle root. Returns the
    normalized target path (POSIX, relative).
    """
    if raw_target is None or raw_target == "":
        raise SymlinkError(
            "Symlink {} has no target".format(link_vpath))
    if "\x00" in raw_target:
        raise SymlinkError("NUL byte in symlink target of {}".format(link_vpath))

    target = raw_target.replace("\\", "/")
    if target.startswith("/"):
        raise SymlinkError(
            "Symlink {} points to an absolute path: {!r}"
            .format(link_vpath, raw_target))

    link_dir = posixpath.dirname(link_vpath)
    resolved = posixpath.normpath(posixpath.join(link_dir, target))
    if resolved == ".." or resolved.startswith("../") or resolved.startswith("/"):
        raise SymlinkError(
            "Symlink {} escapes the bundle root via target {!r}"
            .format(link_vpath, raw_target))
    return target


def virtual_to_local(root, vpath: str) -> Path:
    """
    Translate a validated virtual path to a local path under ``root``.

    A final containment assertion guarantees the result cannot escape
    ``root`` even on case-insensitive or odd filesystems (lexical check;
    the caller is responsible for following symlinks safely).
    """
    root_path = Path(root)
    local = root_path.joinpath(*vpath.split("/"))
    try:
        local.relative_to(root_path)
    except ValueError:
        raise PathValidationError(
            "Resolved path escapes the bundle root: {}".format(vpath))
    return local


def local_to_virtual(base, local) -> str:
    """
    Turn a local path under ``base`` into a normalized virtual path
    (POSIX separators, relative to ``base``).
    """
    rel = Path(local).relative_to(Path(base))
    return "/".join(rel.parts)


def is_within(root, candidate) -> bool:
    """Return True if ``candidate`` is lexically inside ``root``."""
    try:
        Path(candidate).resolve().relative_to(Path(root).resolve())
        return True
    except (ValueError, OSError):
        return False


def common_prefix_groups(vpaths: Iterable[str]) -> set:
    """Return the set of implicit directory prefixes of virtual paths."""
    dirs = set()
    for vpath in vpaths:
        parts = vpath.split("/")
        for i in range(1, len(parts)):
            dirs.add("/".join(parts[:i]))
    return dirs
