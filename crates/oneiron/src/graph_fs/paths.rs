//! Graph-FS path validation and reader-paced normalization.

use super::coreutils_text::{checkpoint, copy_text_parts};
use crate::batch::secret_scan::ContainerReader;
use crate::error::{Error, Result};

pub(super) fn normalize_path(path: &str) -> Result<String> {
    normalize_path_with(path, usize::MAX, || Ok(())).map(str::to_owned)
}

pub(super) fn normalize_path_with_reader(
    path: &str,
    reader: &ContainerReader,
    scan_bytes: usize,
) -> Result<String> {
    let normalized = normalize_path_with(path, scan_bytes.max(char::MAX.len_utf8()), || {
        checkpoint(reader)
    })?;
    copy_text_parts(&[normalized], reader, scan_bytes)
}

fn normalize_path_with(
    path: &str,
    quantum: usize,
    mut checkpoint: impl FnMut() -> Result<()>,
) -> Result<&str> {
    if !path.starts_with('/') {
        return Err(Error::InvalidConfig(
            "graph-fs path must be absolute".to_owned(),
        ));
    }
    let mut end = path.len();
    for chunk in path.as_bytes().rchunks(quantum) {
        checkpoint()?;
        if let Some(last) = chunk.iter().rposition(|byte| *byte != b'/') {
            end = end - chunk.len() + last + 1;
            break;
        }
        end -= chunk.len();
    }
    if end == 0 {
        return Ok("/");
    }
    let normalized = &path[..end];
    path_components_with(normalized, quantum, checkpoint)?;
    Ok(normalized)
}

pub(super) fn path_components(path: &str) -> Result<Vec<&str>> {
    path_components_with(path, usize::MAX, || Ok(()))
}

pub(super) fn path_components_with_reader<'path>(
    path: &'path str,
    reader: &ContainerReader,
    scan_bytes: usize,
) -> Result<Vec<&'path str>> {
    path_components_with(path, scan_bytes.max(char::MAX.len_utf8()), || {
        checkpoint(reader)
    })
}

fn path_components_with(
    path: &str,
    quantum: usize,
    mut checkpoint: impl FnMut() -> Result<()>,
) -> Result<Vec<&str>> {
    if path == "/" {
        return Ok(Vec::new());
    }
    let mut components = Vec::new();
    let mut start = 0;
    let mut leading = true;
    let mut offset = 0;
    for chunk in path.as_bytes().chunks(quantum) {
        checkpoint()?;
        for (within, byte) in chunk.iter().enumerate() {
            let at = offset + within;
            if leading && *byte == b'/' {
                start = at + 1;
                continue;
            }
            leading = false;
            if *byte == b'/' {
                components.push(component(&path[start..at])?);
                start = at + 1;
            }
        }
        offset += chunk.len();
    }
    components.push(component(&path[start..])?);
    Ok(components)
}

fn component(value: &str) -> Result<&str> {
    if value.is_empty() || value == "." || value == ".." {
        Err(Error::InvalidConfig(
            "graph-fs path component is invalid".to_owned(),
        ))
    } else {
        Ok(value)
    }
}
