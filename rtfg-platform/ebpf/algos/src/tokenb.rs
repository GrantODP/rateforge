use std::path::{Path, PathBuf};

use algos_common::token_bucket::TokenLimit;
use anyhow::Error;
use aya::{pin::PinError, Ebpf};

use crate::{
    ebpf::{Detached, PinLocation, Pinned, Unpinned},
    util::*,
};

#[derive(Debug, Default, Clone)]
pub struct CgroupName(PathBuf);

impl CgroupName {
    fn path(&self) -> &Path {
        &self.0
    }

    fn name(&self) -> Option<&str> {
        match self.0.file_name() {
            Some(file) => file.to_str(),
            None => None,
        }
    }
}
impl From<&str> for CgroupName {
    fn from(value: &str) -> Self {
        let path = PathBuf::from("/sys/fs/cgroup/").join(value);
        Self(path)
    }
}
#[derive(Debug)]
pub enum AttachmentKind<T> {
    Ingress(T),
    Egress(T),

    //ingress, egress
    Both(T, T),
}
pub struct Unpinnable;
#[derive(Debug)]
pub struct TokenBucketProgram<Attach = Detached, Pin = Unpinnable> {
    pin_location: Option<PinLocation>,
    map_location: Option<PinLocation>,
    attachment: AttachmentKind<TokenLimit>,
    state: std::marker::PhantomData<(Attach, Pin)>,
}

impl TokenBucketProgram {
    pub fn new(
        attach_kind: AttachmentKind<TokenLimit>,
    ) -> TokenBucketProgram<Detached, Unpinnable> {
        Self {
            pin_location: None,
            map_location: None,
            attachment: attach_kind,
            state: std::marker::PhantomData::default(),
        }
    }

    pub fn set_pin_location(
        mut self,
        location: PinLocation,
    ) -> TokenBucketProgram<Detached, Unpinned> {
        self.pin_location = Some(location);
        TokenBucketProgram::<Detached, Unpinned> {
            state: Default::default(),
            pin_location: self.pin_location,
            map_location: self.map_location,
            attachment: self.attachment,
        }
    }

    pub fn send_rate(&mut self, ebpf: &mut Ebpf) -> anyhow::Result<()> {
        match self.attachment {
            AttachmentKind::Ingress(rate) => update_token_ingress_rate(rate, ebpf),
            AttachmentKind::Egress(rate) => update_token_egress_rate(rate, ebpf),
            AttachmentKind::Both(ingress, egress) => {
                update_token_ingress_rate(ingress, ebpf)?;
                update_token_egress_rate(egress, ebpf)?;
                Ok(())
            }
        }
    }
}

impl<A> TokenBucketProgram<A, Unpinned> {
    pub fn pin(
        self,
        skb: &mut aya::programs::CgroupSkb,
    ) -> anyhow::Result<TokenBucketProgram<A, Pinned>, (Self, PinError)> {
        let pinned = skb.pin(&self.pin_location.as_ref().unwrap().location());
        match pinned {
            Ok(()) => Ok(TokenBucketProgram::<A, Pinned> {
                state: Default::default(),
                pin_location: self.pin_location,
                map_location: self.map_location,
                attachment: self.attachment,
            }),
            Err(err) => Err((self, err)),
        }
    }
}
