# -*- encoding: utf-8 -*-
# kb v0.1.8
# A knowledge base organizer
# Copyright © 2020, gnc.
# See /LICENSE for licensing information.

"""
kb export command module

:Copyright: © 2020, gnc.
:License: GPLv3 (see /LICENSE).
"""

import getpass
import time
import tarfile
from typing import Dict

# Internal directories introduced by the generation/staging machinery;
# they must not leak into a legacy .tar.gz archive.
_LEGACY_EXCLUDED_DIRS = (".staging", ".generations")


def _legacy_archive_filter(root_arc: str):
    """Build a tarfile filter that skips bundle-internal top-level dirs."""
    root_arc = root_arc.rstrip("/")
    excluded = tuple(root_arc + "/" + d for d in _LEGACY_EXCLUDED_DIRS)

    def _filter(member: tarfile.TarInfo):
        name = member.name.rstrip("/")
        if name in excluded or any(
                name.startswith(prefix + "/") for prefix in excluded):
            return None
        return member

    return _filter


def export(args: Dict[str, str], config: Dict[str, str]):
    """
    Export the entire kb knowledge base.

    Two formats are supported:

    * the legacy ``.tar.gz`` archive (default, kept for compatibility);
    * a KB Bundle (``--bundle``, ``.kbbundle``): manifest with schema,
      per-file hashes, consistent DB dump, feature flags and optional
      signature/encryption.

    Arguments:
    args:           - a dictionary containing the following fields:
                      file -> a string representing the wished output
                        filename
    config:         - a configuration dictionary containing at least
                      the following keys:
                      PATH_KB           - the main path of KB
    """
    if args.get("bundle"):
        return _export_bundle(args, config)

    fname = args["file"] or time.strftime("%d_%m_%Y-%H%M%S")
    archive_ext = ".kb.tar.gz"
    if not fname.endswith(archive_ext):
        fname = fname + archive_ext

    if args["only_data"]:
        with tarfile.open(fname, mode='w:gz') as archive:
            archive.add(config["PATH_KB_DATA"], arcname="kb",
                        recursive=True)
    else:
        with tarfile.open(fname, mode='w:gz') as archive:
            archive.add(config["PATH_KB"], arcname=".kb", recursive=True,
                        filter=_legacy_archive_filter(".kb"))
    print("kb exported to {fname}".format(fname=fname))


def _export_bundle(args: Dict[str, str], config: Dict[str, str]):
    from kb.bundle.exporter import export_bundle

    sign_key = None
    sign_kid = None
    if args.get("sign_key"):
        with open(args["sign_key"], "rb") as handle:
            sign_key = handle.read()
        sign_kid = args["sign_key"]

    passphrase = None
    if args.get("encrypt"):
        passphrase = getpass.getpass(
            "Passphrase to encrypt the bundle: ").encode("utf-8")
        confirm = getpass.getpass("Confirm passphrase: ").encode("utf-8")
        if passphrase != confirm:
            print("Error: passphrases do not match")
            return

    out_path = export_bundle(
        config,
        args["file"] or time.strftime("%d_%m_%Y-%H%M%S"),
        sign_key=sign_key,
        sign_kid=sign_kid,
        passphrase=passphrase,
        gzip=bool(args.get("gzip")),
        include_history=not args.get("no_history", False),
        include_templates=not args.get("no_templates", False))
    print("kb bundle exported to {fname}".format(fname=out_path))
