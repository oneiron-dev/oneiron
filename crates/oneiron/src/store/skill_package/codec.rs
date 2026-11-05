//! Core half of `store::skill_package::codec`: its store-layer items live in `oneiron_store::skill_package::codec` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::skill_package::codec::*;

use super::package::{MAX_HUB_FILE_BYTES, MAX_HUB_PACKAGE_TOTAL_BYTES};
use super::{HubFile, HubPackage, SkillCapabilitySurface, SkillPackageFormat};
use crate::error::{ArtifactError, Error, Result};
use crate::side_table::{CodecError, RawValue};
use crate::write_envelope::skill_record::{decode_skill_record, encode_skill_record};
use std::io::{Cursor, Read};

impl RawValue for HubPackage {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_hub_package(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_hub_package(bytes)?)
    }
}

/// Encodes a validated package for bounded local storage or explicit host transport.
/// Does not authorize disclosure: export callers must still run the export gate.
pub fn encode_hub_package(package: &HubPackage) -> Result<Vec<u8>> {
    let hash = package.content_hash()?;
    if package
        .record
        .content_hash
        .is_some_and(|declared| declared != hash)
    {
        return Err(invalid("package hash drift"));
    }
    validate_native_source(package)?;
    let mut out = MAGIC.to_vec();
    out.push(match package.format {
        SkillPackageFormat::Folder => 0,
        SkillPackageFormat::Native => 1,
    });
    let record = encode_skill_record(&package.record)?;
    if record.len() > MAX_RECORD {
        return Err(invalid("package record exceeds bound"));
    }
    field(&mut out, &record)?;
    for set in [
        &package.capabilities.bins,
        &package.capabilities.env,
        &package.capabilities.mcp,
        &package.capabilities.allowed_tools,
    ] {
        out.extend_from_slice(&(set.len() as u32).to_be_bytes());
        for entry in set {
            field(&mut out, entry.as_bytes())?;
        }
    }
    let file_count = u32::try_from(package.files.len())
        .map_err(|_| invalid("package holds more files than its count field names"))?;
    out.extend_from_slice(&file_count.to_be_bytes());
    let mut files = package.files.iter().collect::<Vec<_>>();
    files.sort_by(|a, b| a.path.cmp(&b.path));
    for file in files {
        field(&mut out, file.path.as_bytes())?;
        field(&mut out, &file.content)?;
    }
    if out.len() > MAX_ENCODED {
        return Err(invalid("encoded package exceeds bound"));
    }
    Ok(out)
}

/// Decodes with bounds checked before allocating each field, and rejects trailing data.
pub fn decode_hub_package(raw: &[u8]) -> Result<HubPackage> {
    if raw.len() > MAX_ENCODED || !raw.starts_with(MAGIC) {
        return Err(invalid("invalid package envelope"));
    }
    let mut input = Cursor::new(&raw[MAGIC.len()..]);
    let mut tag = [0];
    input
        .read_exact(&mut tag)
        .map_err(|_| invalid("truncated package format"))?;
    let format = match tag[0] {
        0 => SkillPackageFormat::Folder,
        1 => SkillPackageFormat::Native,
        _ => return Err(invalid("unknown package format")),
    };
    let record = decode_skill_record(&bytes(&mut input, MAX_RECORD)?)?;
    let mut caps = SkillCapabilitySurface::default();
    for set in [
        &mut caps.bins,
        &mut caps.env,
        &mut caps.mcp,
        &mut caps.allowed_tools,
    ] {
        // Each entry takes at least one byte, so a count the bytes left
        // cannot hold is a truncated package; no count is refused for its size.
        let left = input
            .get_ref()
            .len()
            .saturating_sub(input.position() as usize);
        for _ in 0..count(&mut input, left)? {
            if !set.insert(text(&mut input, 512)?) {
                return Err(invalid("duplicate capability"));
            }
        }
    }
    let n = read_file_count(&mut input)?;
    // Grown as each file reads whole, never sized from the count it names.
    let mut files = Vec::new();
    let mut total = 0usize;
    for _ in 0..n {
        let path = text(&mut input, 4096)?;
        let content = bytes(&mut input, MAX_HUB_FILE_BYTES)?;
        total = total
            .checked_add(content.len())
            .ok_or_else(|| invalid("package size overflow"))?;
        if total > MAX_HUB_PACKAGE_TOTAL_BYTES {
            return Err(invalid("package too large"));
        }
        files.push(HubFile::new(path, content));
    }
    if input.position() as usize != raw.len() - MAGIC.len() {
        return Err(invalid("trailing package bytes"));
    }
    let mut package = HubPackage::new(record, files, caps);
    package.format = format;
    let hash = package.content_hash()?;
    if package
        .record
        .content_hash
        .is_some_and(|declared| declared != hash)
    {
        return Err(invalid("package hash drift"));
    }
    validate_native_source(&package)?;
    Ok(package)
}

fn validate_native_source(package: &HubPackage) -> Result<()> {
    if package.format == SkillPackageFormat::Native {
        let source = super::folder::package_from_source(
            &package.record,
            package.files.clone(),
            package.format,
        )?;
        if source.capabilities != package.capabilities {
            return Err(invalid(
                "native package capabilities differ from its source",
            ));
        }
    }
    Ok(())
}
