# -*- encoding: utf-8 -*-
# kb v0.1.8
# A knowledge base organizer
# Copyright © 2020, gnc.
# See /LICENSE for licensing information.

"""
kb bundle package

This package implements the KB Bundle format: a portable, verifiable
archive of a whole knowledge base (database dump + artifact files +
templates + history) together with a manifest describing schema,
per-file metadata, feature flags and optional signature/encryption.

Import always happens through an isolated staging area with streaming
validation, followed by schema migration, reference checks and an
atomic generation switch; previous generations are retained for
rollback.

:Copyright: © 2020, gnc.
:License: GPLv3 (see /LICENSE).
"""

__all__ = (
    "manifest",
    "paths",
    "hashing",
    "archive",
    "dbcheck",
    "generations",
    "exporter",
    "importer",
    "errors",
)
