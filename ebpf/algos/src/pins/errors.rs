use thiserror::Error;

#[derive(Debug, Error)]
pub enum PinError {
    #[error("File system: {}", 0)]
    Io(#[from] std::io::Error),

    #[error("{}", 0)]
    PathLocation(String),

    #[error("{}", 0)]
    AyaPin(#[from] aya::pin::PinError),

    #[error("{}", 0)]
    InvalidPinObject(String),

    #[error("No pinned objects({})", 0)]
    EmptyPinObject(String),

    #[error("Unpinning a non pinned program {}", 0)]
    NotPinned(String),

    #[error("Unpinning a non pinned program {}", 0)]
    AlreadyPinned(String),
}
