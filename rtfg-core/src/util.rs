use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
};

use crate::control::{Rate, RuleId};

/// Generates a RuleId (u16) from two optional Rate references.
///
/// The function builds a hash from the provided Rates using a variant
/// of the FNV-1a hash algorithm. Unique tag values (0x01 for rate1 and 0x02 for rate2)
/// are mixed in so that the same underlying number passed as rate1
/// is distinguished from the same number passed as rate2.
pub fn generate_rid(rate1: Option<&Rate>, rate2: Option<&Rate>) -> RuleId {
    // FNV-1a 32-bit offset basis
    let mut hash: u64 = 2166136261;
    const FNV_PRIME: u64 = 16777619;

    if let Some(r) = rate1 {
        // Use a tag to mark the presence of a rate1 value.
        hash ^= 0x01;
        hash = hash.wrapping_mul(FNV_PRIME);
        hash ^= r.0;
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    if let Some(r) = rate2 {
        // Use a different tag to mark the presence of a rate2 value.
        hash ^= 0x02;
        hash = hash.wrapping_mul(FNV_PRIME);
        hash ^= r.0;
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    (hash & 0xFFFF).into()
}

pub fn write_file(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;

    file.write_all(bytes)
}

pub fn load_file(path: &Path) -> Result<File, std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(path)?;

    Ok(file)
}
