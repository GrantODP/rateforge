use thiserror::Error;

#[derive(Debug, Error)]
pub enum TokenBucketError {
    #[error("{0}")]
    NoTrafficDirection(String),
}
