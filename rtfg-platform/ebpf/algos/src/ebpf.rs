use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PinLocation {
    location: PathBuf,
}

//used to hard limit available programs to run
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ProgramKind {
    CgroupIngressTknb,
    CgroupEgressTknb,
}

impl ProgramKind {
    pub fn to_str(&self) -> &str {
        match self {
            Self::CgroupIngressTknb => "cgroup_ingress_tknb",
            Self::CgroupEgressTknb => "cgroup_egress_tknb",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MapKind {
    TokenBucket,
}
impl MapKind {
    pub fn to_str(&self) -> &str {
        match self {
            Self::TokenBucket => "TOKEN_BUCKETS",
        }
    }
}
impl PinLocation {
    #[cfg(target_os = "linux")]
    fn new(name: &str) -> Self {
        Self {
            location: PathBuf::from("/sys/fs/bpf/").join(name),
        }
    }

    fn location(&self) -> &Path {
        &self.location
    }

    fn delete(&self) -> anyhow::Result<()> {
        std::fs::remove_file(&self.location).context("Failed file remove")
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PinType {
    Program(ProgramKind),
    Map(MapKind),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PinnedObject {
    pinned_type: PinType,
    location: PinLocation,
}
