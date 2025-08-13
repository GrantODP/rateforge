use crate::control::RuleId;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Process {name:?} was not found")]
    ProcessNotFound { name: String },

    #[error("I/O error occurred: {0}")]
    Io(#[from] std::io::Error),

    #[cfg(target_os = "linux")]
    #[error("tc error: {0}")]
    Cgroup(String),

    #[error("Policy with Id {given} does not exist")]
    PolicyNotFound { given: RuleId },

    #[error("{message}")]
    PolicyAlreadyExists { message: String },

    #[error("Error occured: {0}")]
    General(String),

    #[error("Ebpf program error: {0}")]
    ProgramError(#[from] ebpf::Error),

    #[error("Unexpected Error occured")]
    Unknown,
}
