# -*- encoding: utf-8 -*-
# kb v0.1.7
# A knowledge base organizer
# Copyright © 2020, gnc.
# See /LICENSE for licensing information.

"""
kb config module

:Copyright: © 2020, gnc.
:License: GPLv3 (see /LICENSE).
"""

__all__ = ()

import os
from sys import platform
from pathlib import Path
import toml

BASE_PATH = Path(os.environ.get("XDG_DATA_HOME",Path(Path.home(),".local","share")),"kb")


DEFAULT_CONFIG = {
    "PATH_KB": str(Path(BASE_PATH)),
    "PATH_KB_DB": str(Path(BASE_PATH, "kb.db")),
    "PATH_KB_HIST": str(Path(BASE_PATH, "recent.hist")),
    "PATH_KB_DATA": str(Path(BASE_PATH, "data")),
    "PATH_KB_GIT": str(Path(BASE_PATH, ".git")),
    # for future use
    "PATH_KB_CONFIG": str(Path(BASE_PATH, "kb.conf.py")),
    "PATH_KB_TEMPLATES": str(Path(BASE_PATH, "templates")),
    "PATH_KB_DEFAULT_TEMPLATE": str(Path(BASE_PATH, "templates", "default")),
    # KB Bundle machinery (staging + generations)
    "PATH_KB_STAGING": str(Path(BASE_PATH, ".staging")),
    "PATH_KB_GENERATIONS": str(Path(BASE_PATH, ".generations")),
    "BUNDLE_FORMAT_VERSION": 1,
    "BUNDLE_KEEP_GENERATIONS": 5,
    "BUNDLE_CHUNK_SIZE": 1024 * 1024,
    # Import safety limits (zip-bomb / resource exhaustion guards)
    "BUNDLE_MAX_MEMBERS": 100000,
    "BUNDLE_MAX_TOTAL_BYTES": 50 * 1024 ** 3,   # 50 GiB expanded
    "BUNDLE_MAX_FILE_BYTES": 20 * 1024 ** 3,    # a single member
    "BUNDLE_MAX_COMPRESSION_RATIO": 1000,
    "BUNDLE_FREE_SPACE_FACTOR": 1.1,
    "DB_SCHEMA_VERSION": 1,
    "EDITOR": os.environ.get("EDITOR", "vim"),
    "INITIAL_CATEGORIES": ["default", ]
}

# Feature flags advertised/recorded by bundles. These describe optional
# content sections; unknown flags remain advisory for forward
# compatibility.
DEFAULT_FEATURE_FLAGS = {
    "history": True,
    "templates": True,
    "large_files": True,
    "streaming_checksums": True,
}


DEFAULT_TEMPLATE = {
    "TITLES": ("^#.*", "blue"),
    "WARNINGS": ("^!.*", "yellow"),
}


def get_markers(markers_path: str):
    """
    Load markers file

    Arguments:
    markers_path    - the path to the toml markers file

    Returns a dictionary containing markers
    """
    try:
        return toml.load(markers_path)
    except toml.TomlDecodeError:
        print("Error: The provided file is not in the toml format")
    except FileNotFoundError:
        print("Error: The provided file does not exist or cannot be accessed")
