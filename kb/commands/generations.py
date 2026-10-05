# -*- encoding: utf-8 -*-
# kb v0.1.8
# A knowledge base organizer
# Copyright © 2020, gnc.
# See /LICENSE for licensing information.

"""
kb generations command module

Inspects retained knowledge-base generations, rolls back to a previous
one and prunes the generations store. Rollback itself checkpoints the
current live state first, so it is always reversible.

:Copyright: © 2020, gnc.
:License: GPLv3 (see /LICENSE).
"""

from typing import Dict

from kb.bundle.errors import BundleError
from kb.bundle.generations import GenerationStore


def generations(args: Dict[str, str], config: Dict[str, str]):
    """
    Manage retained KB generations.

    Arguments:
    args:           - a dictionary containing:
                      generations_operation -> list|rollback|prune
                      gen_id -> target generation for rollback (optional)
                      keep -> how many generations to keep (optional)
    config:         - a configuration dictionary containing at least
                      PATH_KB and PATH_KB_GENERATIONS
    """
    operation = args["generations_operation"]

    if operation == "list":
        _list_generations(config)
    elif operation == "rollback":
        _rollback(args, config)
    elif operation == "prune":
        _prune(args, config)
    else:
        print("Error: No valid operation has been specified "
              "(use list, rollback or prune)")


def _list_generations(config) -> None:
    store = GenerationStore.open(config)
    entries = store.generations()
    if not entries:
        print("No generations found")
        return
    print("{:<28} {:>4}  {:<10}  {}".format(
        "GENERATION ID", "SEQ", "SOURCE", "NOTE"))
    for meta in entries:
        marker = "*" if meta.get("current") else " "
        print("{}{:<27} {:>4}  {:<10}  {}".format(
            marker, meta.get("id", ""), meta.get("seq", 0),
            meta.get("source", ""), meta.get("note", "")))


def _rollback(args, config) -> None:
    gen_id = args.get("gen_id")
    if not gen_id:
        print("Error: specify the generation id to roll back to "
              "(see 'kb generations list')")
        return
    store = GenerationStore.open(config)
    try:
        meta = store.rollback(gen_id)
    except BundleError as err:
        print("Rollback failed: {error}".format(error=err))
        return
    print("Knowledge base rolled back to {gen} (seq {seq})".format(
        gen=meta["id"], seq=meta["seq"]))
    print("The previous live state was checkpointed and can be restored "
          "with 'kb generations rollback <id>'.")


def _prune(args, config) -> None:
    keep = args.get("keep") or int(config.get("BUNDLE_KEEP_GENERATIONS", 5))
    store = GenerationStore.open(config)
    try:
        removed = store.prune(int(keep))
    except BundleError as err:
        print("Prune failed: {error}".format(error=err))
        return
    if removed:
        print("Removed {} old generation(s): {}".format(
            len(removed), ", ".join(removed)))
    else:
        print("Nothing to prune")
