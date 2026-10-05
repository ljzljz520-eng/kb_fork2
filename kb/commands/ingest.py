# -*- encoding: utf-8 -*-
# kb v0.1.8
# A knowledge base organizer
# Copyright © 2020, gnc.
# See /LICENSE for licensing information.

"""
kb import command module

:Copyright: © 2020, gnc.
:License: GPLv3 (see /LICENSE).
"""

import getpass
import tarfile
from typing import Dict

from kb.bundle.manifest import ENCRYPTION_MEMBER, MANIFEST_MEMBER


def ingest(args: Dict[str, str], config: Dict[str, str]):
    """
    Import an entire kb knowledge base.

    Both the new KB Bundle format (``.kbbundle``) and legacy
    ``.tar.gz`` exports are supported. Every import goes through
    isolated staging validation, schema migration/reference checks and
    an atomic generation switch; the previous state is retained and
    can be rolled back with ``kb generations rollback``.

    Arguments:
    args:           - a dictionary containing the following fields:
                      file -> a string representing the path to the
                        archive to be imported
    config:         - a configuration dictionary containing at least
                      the following keys:
                      PATH_KB           - the main path of KB
    """
    fname = args["file"]
    is_modern, is_encrypted = _sniff_format(fname)

    if not is_modern and not fname.endswith(".tar.gz") and \
            not args.get("yes"):
        print("Please provide a .kbbundle bundle or a legacy "
              ".kb.tar.gz archive")
        return

    # Legacy archives replace the whole knowledge base; ask for
    # confirmation unless --yes was supplied. Rollback is available
    # afterwards in either case.
    if not is_modern and not args.get("yes"):
        answer = input("You are about to import a whole knowledge base "
                       "(the current state will be retained for rollback). "
                       "Continue? [YES/NO] ")
        if answer.lower() != "yes":
            print("Import aborted")
            return

    verify_key = None
    if args.get("verify_key"):
        with open(args["verify_key"], "rb") as handle:
            verify_key = handle.read()

    passphrase = None
    if is_encrypted or args.get("encrypted"):
        passphrase = getpass.getpass(
            "Bundle passphrase: ").encode("utf-8")

    from kb.bundle.importer import import_bundle
    from kb.bundle.errors import BundleError, SignatureError, CryptoError
    try:
        result = import_bundle(
            config, fname,
            verify_key=verify_key,
            passphrase=passphrase,
            resume=not args.get("no_resume", False),
            keep_staging=bool(args.get("keep_staging", False)))
    except SignatureError as err:
        print("Signature verification failed: {error}".format(error=err))
        return
    except CryptoError as err:
        print("Encryption error: {error}".format(error=err))
        return
    except BundleError as err:
        print("Import failed (knowledge base left unchanged): {error}"
              .format(error=err))
        return

    print("kb archive {fname} imported".format(fname=fname))
    print("  generation:   {gen} (switch strategy: {strategy})".format(
        gen=result["generation"], strategy=result["strategy"]))
    print("  artifacts:    {n}".format(n=result["artifact_count"]))
    print("  tags rows:    {n}".format(n=result["tag_count"]))
    if result["signed"]:
        print("  signature:    verified")
    if result["legacy"]:
        print("  source:       legacy archive (migrated)")
    if result["pruned_generations"]:
        print("  pruned old generations: {}".format(
            ", ".join(result["pruned_generations"])))
    print("Use 'kb generations list' and 'kb generations rollback <id>' "
          "to inspect or undo this import.")


def _sniff_format(fname: str):
    """
    Return ``(is_modern_bundle, is_encrypted)`` by reading the first tar
    member name. Falls back to ``(False, False)`` for non-tar inputs.
    """
    try:
        with tarfile.open(fname, mode="r:*") as archive:
            member = next(iter(archive))
    except (tarfile.TarError, OSError, StopIteration):
        return False, False
    first = member.name.rstrip("/")
    if first == ENCRYPTION_MEMBER:
        return True, True
    if first == MANIFEST_MEMBER:
        return True, False
    return False, False
