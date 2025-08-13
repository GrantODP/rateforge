use crate::{
    ebpf::{CgroupName, ProgramId},
    tokenb::TokenBucketProgram,
    util::get_ebpf,
    Error,
};

pub enum LimitProgram {
    TokenBucket(TokenBucketProgram),
    UnknownProgram,
}

pub enum LimitProgramFactory {
    TokenBucket(ProgramId, CgroupName),
}

impl LimitProgramFactory {
    pub fn get_program(self) -> Result<LimitProgram, Error> {
        match self {
            Self::TokenBucket(id, name) => {
                let program = TokenBucketProgram::new(id, name, get_ebpf()?);
                Ok(LimitProgram::TokenBucket(program))
            }

            _ => Err(ProgramFactoryError::NotImplemented)?,
        }
    }

    pub fn token_bucket(id: ProgramId, name: CgroupName) -> Result<TokenBucketProgram, Error> {
        Ok(TokenBucketProgram::new(id, name, get_ebpf()?))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProgramFactoryError {
    #[error("Unknown program selected")]
    NotImplemented,
}
