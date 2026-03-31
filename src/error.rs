use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum AmberError {
    Io(std::io::Error),
    Invalid(String),
    NotFound(String),
    Exists(String),
    Rebuild(String),
    IndexLocator(String),
    IndexFrame(String),
    IndexSize(String),
    IndexLengthMismatch(String),
    IndexHashMismatch(String),
    MerkleMismatch(String),
    EncryptedIndexRequiresPassword(String),
    ChunkBounds(String),
    SymbolBounds(String),
    DuplicateSymbolIndex(String),
    SymbolIndexGap(String),
    SymbolSizeMismatch(String),
}

pub type AmberResult<T> = Result<T, AmberError>;

impl Display for AmberError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => Display::fmt(err, f),
            Self::Invalid(msg)
            | Self::NotFound(msg)
            | Self::Exists(msg)
            | Self::Rebuild(msg)
            | Self::IndexLocator(msg)
            | Self::IndexFrame(msg)
            | Self::IndexSize(msg)
            | Self::IndexLengthMismatch(msg)
            | Self::IndexHashMismatch(msg)
            | Self::MerkleMismatch(msg)
            | Self::EncryptedIndexRequiresPassword(msg)
            | Self::ChunkBounds(msg)
            | Self::SymbolBounds(msg)
            | Self::DuplicateSymbolIndex(msg)
            | Self::SymbolIndexGap(msg)
            | Self::SymbolSizeMismatch(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for AmberError {}

impl From<std::io::Error> for AmberError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl AmberError {
    pub fn is_rebuild_index_candidate(&self) -> bool {
        matches!(
            self,
            Self::IndexLocator(_)
                | Self::IndexFrame(_)
                | Self::IndexSize(_)
                | Self::IndexLengthMismatch(_)
                | Self::IndexHashMismatch(_)
                | Self::MerkleMismatch(_)
                | Self::ChunkBounds(_)
                | Self::SymbolBounds(_)
                | Self::DuplicateSymbolIndex(_)
                | Self::SymbolIndexGap(_)
                | Self::SymbolSizeMismatch(_)
        )
    }
}
