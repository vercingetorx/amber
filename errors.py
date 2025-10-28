class AmberError(Exception):
    """Base class for Amber-specific errors."""


# Index/trailer related
class IndexLocatorError(AmberError):
    pass


class IndexFrameError(AmberError):
    pass


class IndexSizeError(AmberError):
    pass


class IndexLengthMismatch(AmberError):
    pass


class IndexHashMismatch(AmberError):
    pass


class MerkleMismatch(AmberError):
    pass


class EncryptedIndexRequiresPassword(AmberError):
    pass


# Bounds/consistency
class ChunkBoundsError(AmberError):
    pass


class SymbolBoundsError(AmberError):
    pass


class DuplicateSymbolIndexError(AmberError):
    pass


class SymbolIndexGapError(AmberError):
    pass


class SymbolSizeMismatchError(AmberError):
    pass

