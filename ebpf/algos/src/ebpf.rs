use std::path::{Path, PathBuf};

use algos_common::token_bucket::TokenLimit;
use anyhow::{anyhow, Error};
use aya::{maps::MapData, Ebpf, Pod};
use cgroups_rs::{cgroup_builder::CgroupBuilder, Cgroup, CgroupPid};
use serde::{Deserialize, Serialize};

use crate::pins::PinLocation;

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct ProgramId(pub u64);

impl From<u64> for ProgramId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}
impl std::fmt::Display for ProgramId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // You can format it however you like — here's a simple decimal representation:
        write!(f, "{}", self.0)
    }
}
#[derive(Debug)]
pub enum AttachmentKind<T> {
    Ingress(T),
    Egress(T),
}
//used to hard limit available programs to run
#[derive(Debug, Clone, Default, Copy, Serialize, Deserialize)]
pub enum ProgramKind {
    CgroupIngressTknb,
    CgroupEgressTknb,
    #[default]
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
        let map = aya::maps::HashMap::try_from(
            ebpf.map_mut(self.to_str())
                .ok_or(anyhow!("No map named: {}", self.to_str()))?,
        )?;
        Ok(map)
    }

    pub fn pin(&mut self, location: &PinLocation, ebpf: &mut Ebpf) -> anyhow::Result<()> {
        match self {
            Self::TokenBucket => {
                let map: aya::maps::HashMap<_, u64, TokenLimit> = self.get_mut(ebpf)?;
                Ok(map.pin(location.location())?)
            }

            _ => Err(anyhow!("Unknown Map to pin")),
        }
    }
}

impl From<MapKind> for &'static str {
    fn from(kind: MapKind) -> Self {
        match kind {
            MapKind::TokenBucket => "TOKEN_BUCKET",
            _ => "unknown",
        }
    }
}
impl From<&MapKind> for &'static str {
    fn from(kind: &MapKind) -> Self {
        match kind {
            MapKind::TokenBucket => "TOKEN_BUCKET",
            _ => "unknown",
        }
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ProgramFlags:u32 {
        const BLOCKED = 0b0000;
        const INGRESS = 0b0001;
        const EGRESS = 0b0010;
        const PINNED = 0b0100;
    }
}
#[derive(Debug, Default, Clone)]
pub struct CgroupName {
    path: PathBuf,
}

impl CgroupName {
    pub fn new(name: &str) -> Result<Self, crate::Error> {
        let name = match name.is_empty() {
            true => "rateforgenamegroup",
            false => name,
        };
        let hier = cgroups_rs::hierarchies::auto();
        let c = CgroupBuilder::new(name).pid().done().build(hier)?;

        Ok(Self {
            path: PathBuf::from(format!("/sys/fs/cgroup/{}", c.path())),
        })
    }

    pub fn name(&self) -> &str {
        self.path
            .file_name()
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default()
    }

    pub fn delete(&self) -> Result<(), crate::Error> {
        let cgroup = self.load_cgroup();
        cgroup.delete()?;
        Ok(())
    }

    pub fn add_task(&mut self, pid: u64) -> Result<(), crate::Error> {
        let pid = CgroupPid::from(pid);
        let cgroup = self.load_cgroup();
        cgroup.add_task_by_tgid(pid)?;
        Ok(())
    }

    fn load_cgroup(&self) -> Cgroup {
        let hier = cgroups_rs::hierarchies::auto();
        let cgroup = CgroupBuilder::new(self.name())
            .pid()
            .done()
            .build(hier)
            .unwrap();
        cgroup
    }
}

impl AsRef<Path> for CgroupName {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}
