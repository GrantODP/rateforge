use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context};
use aya::{maps::MapData, Ebpf, Pod};
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
    Unknown,
}

impl ProgramKind {
    pub fn to_str(&self) -> &str {
        self.into()
    }
}
impl From<&ProgramKind> for &'static str {
    fn from(kind: &ProgramKind) -> Self {
        match kind {
            ProgramKind::CgroupIngressTknb => "cgroup_ingress_tknb",
            ProgramKind::CgroupEgressTknb => "cgroup_egress_tknb",
            ProgramKind::Unknown => "unknown",
        }
    }
}
impl From<ProgramKind> for &'static str {
    fn from(kind: ProgramKind) -> Self {
        match kind {
            ProgramKind::CgroupIngressTknb => "cgroup_ingress_tknb",
            ProgramKind::CgroupEgressTknb => "cgroup_egress_tknb",
            ProgramKind::Unknown => "unknown",
        }
    }
}
impl From<&str> for ProgramKind {
    fn from(value: &str) -> Self {
        match value {
            "cgroup_ingress_tknb" => Self::CgroupIngressTknb,
            "cgroup_egress_tknb" => Self::CgroupEgressTknb,
            _ => Self::Unknown,
        }
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MapKind {
    TokenBucket,
    Unknown,
}

impl MapKind {
    pub fn to_str(&self) -> &str {
        self.into()
    }

    pub fn get_mut<'a, K: Pod, V: Pod>(
        &self,
        ebpf: &'a mut Ebpf,
    ) -> anyhow::Result<aya::maps::HashMap<&'a mut MapData, K, V>> {
        let map = aya::maps::HashMap::try_from(ebpf.map_mut(self.to_str()).unwrap())?;
        Ok(map)
    }
}
impl From<MapKind> for &'static str {
    fn from(kind: MapKind) -> Self {
        match kind {
            MapKind::TokenBucket => "TOKEN_BUCKETS",
            _ => "unknown",
        }
    }
}
impl From<&MapKind> for &'static str {
    fn from(kind: &MapKind) -> Self {
        match kind {
            MapKind::TokenBucket => "TOKEN_BUCKETS",
            _ => "unknown",
        }
    }
}
impl From<&str> for MapKind {
    fn from(value: &str) -> Self {
        match value {
            "TOKEN_BUCKETS" => Self::TokenBucket,
            _ => Self::Unknown,
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
pub struct Attached;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Detached;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Pinned;
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Unpinned;

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
