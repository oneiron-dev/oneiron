//! Package envelope codec and source consistency validation.

use crate::side_table::codec::CodecError;
use crate::side_table::codec::RawValue;
use crate::skill_package::package::HubPackage;
use crate::skill_package::package::MAX_HUB_FILE_BYTES;
use crate::skill_package::package::MAX_HUB_PACKAGE_TOTAL_BYTES;
use crate::skill_package::package::SkillCapabilitySurface;
use crate::write_envelope::skill_record::decode_skill_record;
use crate::write_envelope::skill_record::encode_skill_record;
use crate::write_envelope::skill_source::HubFile;
use crate::write_envelope::skill_source::SkillPackageFormat;
use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use std::io::{Cursor, Read};

pub fn invalid(message: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidSkillBody(message))
}
pub const MAGIC: &[u8] = b"oneiron.hub-package.v1\0";

/// Transport packages do not claim a storage holder. The ASSET guard uses
/// this discriminator to refuse the removed, unshipped holderless shape.
pub fn is_hub_package_envelope(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

pub const MAX_ENCODED: usize = MAX_HUB_PACKAGE_TOTAL_BYTES + 8 * 1024 * 1024;
pub const MAX_RECORD: usize = 1024 * 1024;

pub fn field(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let len = u32::try_from(value.len()).map_err(|_| invalid("package field too large"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}
pub fn count(input: &mut Cursor<&[u8]>, max: usize) -> Result<usize> {
    let mut b = [0; 4];
    input
        .read_exact(&mut b)
        .map_err(|_| invalid("truncated package"))?;
    let n = u32::from_be_bytes(b) as usize;
    if n > max {
        return Err(invalid("package field exceeds bound"));
    }
    Ok(n)
}
/// The bytes one file takes in an encoded package: its path and its content,
/// each after its four-byte length.
pub const fn encoded_file_bytes(path: usize, content: usize) -> usize {
    path.saturating_add(content).saturating_add(8)
}
/// A package's file count, read apart from the bounded field lengths. Each
/// file takes at least its two four-byte lengths, so a count the bytes left
/// cannot hold is a truncated package; no count is refused for its size
/// (FIX 10100).
pub fn read_file_count(input: &mut Cursor<&[u8]>) -> Result<usize> {
    let mut b = [0; 4];
    input
        .read_exact(&mut b)
        .map_err(|_| invalid("truncated package"))?;
    let n = usize::try_from(u32::from_be_bytes(b)).map_err(|_| invalid("truncated package"))?;
    let left = input
        .get_ref()
        .len()
        .saturating_sub(input.position() as usize);
    if n > left / 8 {
        return Err(invalid("truncated package"));
    }
    Ok(n)
}
pub fn bytes(input: &mut Cursor<&[u8]>, max: usize) -> Result<Vec<u8>> {
    let n = count(input, max)?;
    if n > input
        .get_ref()
        .len()
        .saturating_sub(input.position() as usize)
    {
        return Err(invalid("truncated package field"));
    }
    let mut out = vec![0; n];
    input
        .read_exact(&mut out)
        .map_err(|_| invalid("truncated package"))?;
    Ok(out)
}
pub fn text(input: &mut Cursor<&[u8]>, max: usize) -> Result<String> {
    String::from_utf8(bytes(input, max)?).map_err(|_| invalid("package text is not UTF-8"))
}
