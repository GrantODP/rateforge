use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PinLocation {
    pub location: PathBuf,
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
    pub fn new(name: &str) -> Self {
        Self {
            location: PathBuf::from("/sys/fs/bpf/").join(name),
        }
    }

    pub fn location(&self) -> &Path {
        &self.location
    }

    pub fn delete(&self) -> anyhow::Result<()> {
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
    pin_type: PinType,
    location: PinLocation,
}

impl PinnedObject {
    pub fn new(pin_type: PinType, location: PinLocation) -> Self {
        Self { pin_type, location }
    }

    #[inline]
    pub fn path(&self) -> &Path {
        &self.location.location
    }
    #[inline]
    pub fn pin_type(&self) -> &PinType {
        &self.pin_type
    }
    #[inline]
    pub fn pin_type_mut(&mut self) -> &mut PinType {
        &mut self.pin_type
    }
    #[inline]
    pub fn name(&self) -> Option<&OsStr> {
        self.location.location.file_name()
    }

    #[inline]
    pub fn delete(&mut self) -> anyhow::Result<()> {
        self.location.delete()
    }
}
