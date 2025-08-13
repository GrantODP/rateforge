pub use ebpf::ebpf::CgroupName;
use ebpf::{
    ebpf::AttachmentKind,
    factory::LimitProgramFactory,
    tokenb::{TokenBucketProgram, TokenLimit},
};

use crate::Error;

use super::Policy;

pub trait RateController {
    fn apply_policy(&mut self, policy: Policy) -> Result<(), Error>;

    fn close(&mut self) -> Result<(), Error>;
}

#[derive(Debug)]
pub struct TokenBucketController {
    program: TokenBucketProgram,
}

impl TokenBucketController {
    pub fn new(cgroup: CgroupName) -> Result<Self, ebpf::Error> {
        let program = LimitProgramFactory::token_bucket(0.into(), cgroup)?;
        Ok(Self { program })
    }
}

impl RateController for TokenBucketController {
    fn apply_policy(&mut self, policy: Policy) -> Result<(), Error> {
        let burst = 10_000; //ns

        if let Some(rate) = policy.down() {
            self.program
                .apply_rate(AttachmentKind::Ingress(TokenLimit::new(
                    policy.id().into(),
                    rate.bytes(),
                    burst,
                )))?;
        }
        if let Some(rate) = policy.up() {
            self.program
                .apply_rate(AttachmentKind::Egress(TokenLimit::new(
                    policy.id().into(),
                    rate.bytes(),
                    burst,
                )))?;
        }

        self.program.load()?;
        Ok(())
    }
    fn close(&mut self) -> Result<(), Error> {
        self.program.close()?;
        Ok(())
    }
}
