use std::path::{Path, PathBuf};

mod errors;
pub use errors::PinError;
use serde::{Deserialize, Serialize};

use crate::ebpf::{MapKind, ProgramId, ProgramKind};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PinLocation(PathBuf);

impl PinLocation {
    #[cfg(target_os = "linux")]
    pub fn new<P: AsRef<Path>>(name: P) -> Self {
        Self(PathBuf::from("/sys/fs/bpf/").join(name))
    }

    pub fn location(&self) -> &Path {
        &self.0
    }

    pub fn delete(&self) -> Result<(), PinError> {
        std::fs::remove_file(&self.0)?;
        Ok(())
    }
}

impl AsRef<Path> for PinLocation {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl TryFrom<PathBuf> for PinLocation {
    type Error = std::io::Error;

    #[cfg(target_os = "linux")]
    fn try_from(value: PathBuf) -> Result<Self, Self::Error> {
        let base = Path::new("/sys/fs/bpf/");
        match value.starts_with(base) {
            true => Ok(Self(value)),
            false => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Path must start with /sys/fs/bpf/. Received {}",
                    value.display()
                ),
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PinType {
    Program(ProgramId, ProgramKind, PinLocation),
    Fd(PinLocation),
    Map(MapKind, PinLocation),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PinnedObject {
    pin_types: Vec<PinType>,
}

pub struct PinnedObjectIter<'a> {
    inner: std::slice::Iter<'a, PinType>,
}

impl<'a> Iterator for PinnedObjectIter<'a> {
    type Item = &'a PinType;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

impl PinnedObject {
    pub fn iter(&self) -> PinnedObjectIter {
        PinnedObjectIter {
            inner: self.pin_types.iter(),
        }
    }
}

impl<'a> IntoIterator for &'a PinnedObject {
    type Item = &'a PinType;
    type IntoIter = std::slice::Iter<'a, PinType>;

    fn into_iter(self) -> Self::IntoIter {
        self.pin_types.iter()
    }
}
#[derive(Debug, Default)]
pub struct PinnedObjectBuilder {
    pub pin_types: Vec<PinType>,
}

impl PinnedObjectBuilder {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
    pub fn pin_type(mut self, typ: PinType) -> Self {
        self.pin_types.push(typ);
        self
    }

    pub fn program(mut self, id: ProgramId, kind: ProgramKind, location: PinLocation) -> Self {
        self.pin_types.push(PinType::Program(id, kind, location));
        self
    }

    pub fn map(mut self, kind: MapKind, location: PinLocation) -> Self {
        self.pin_types.push(PinType::Map(kind, location));
        self
    }

    pub fn fd(mut self, location: PinLocation) -> Self {
        self.pin_types.push(PinType::Fd(location));
        self
    }

    pub fn build(self) -> PinnedObject {
        PinnedObject {
            pin_types: self.pin_types,
        }
    }
}
