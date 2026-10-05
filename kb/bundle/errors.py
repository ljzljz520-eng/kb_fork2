# -*- encoding: utf-8 -*-
# kb v0.1.8

"""
Error hierarchy for KB Bundle operations.

All failures raised by bundle code derive from :class:`BundleError`
so callers can catch the whole family with a single except clause.
"""


class BundleError(Exception):
    """Base class for every KB Bundle related error."""


class ManifestError(BundleError):
    """The bundle manifest is missing, malformed or unsupported."""


class UnsupportedFeatureError(ManifestError):
    """The bundle requires feature flags this kb version does not provide."""


class PathValidationError(BundleError):
    """An archive member uses an unsafe or non-portable path."""


class SymlinkError(PathValidationError):
    """A symbolic link points outside of the bundle root."""


class BundleLimitError(BundleError):
    """
    An archive exceeded a safety limit.

    This covers zip-bomb style attacks (too many members, too many
    expanded bytes, absurd compression ratio), per-file size caps and
    insufficient free space on the target volume.
    """


class HashMismatchError(BundleError):
    """The streamed content of a member does not match its manifest hash."""


class SignatureError(BundleError):
    """A signature is missing, malformed or fails verification."""


class CryptoError(BundleError):
    """Encryption/decryption failed or a crypto backend is unavailable."""


class DBCheckError(BundleError):
    """The bundled database is corrupt, inconsistent or fails references."""


class GenerationError(BundleError):
    """A generation switch, rollback or adoption operation failed."""


class StagingError(BundleError):
    """The isolated staging area is in an unexpected state."""


class LegacyArchiveError(BundleError):
    """A legacy .tar.gz archive cannot be adapted to a bundle."""
