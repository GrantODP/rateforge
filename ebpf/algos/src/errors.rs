use crate::{factory::ProgramFactoryError, pins::PinError, tokenb::TokenBucketError};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Pin(#[from] PinError),

    #[error("{0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    TokenBucket(#[from] TokenBucketError),

    #[error("{0}")]
    EbpfProgram(#[from] aya::programs::ProgramError),

    #[error("{0}")]
    Ebpf(#[from] aya::EbpfError),

    #[error("{0}")]
    EbpfMaps(#[from] aya::maps::MapError),

    #[error("{0}")]
    General(String),

    #[error("{0}")]
    FactoryError(#[from] ProgramFactoryError),

    #[error("{0}")]
    Cgroups(#[from] cgroups_rs::error::Error),
}
