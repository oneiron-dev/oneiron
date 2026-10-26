//! A skill archive from an agentskills.io discovery index (`type:
//! "archive"`): a `.tar.gz` or `.zip` of the skill folder, `SKILL.md` at its
//! root. Read under the package bounds, a tar as it streams out of its gzip.
//! No count of files refuses an archive (FIX 10100): every file is read, in
//! 1,000-file steps under its host's deadline. As the discovery spec
//! requires, an absolute path, a `..` segment or a link that leaves the
//! folder refuses; a link inside it reads as a copy of the file it names.
use super::HubFile;
use super::package::{MAX_HUB_FILE_BYTES, MAX_HUB_PACKAGE_TOTAL_BYTES};
use super::package_codec::{MAX_ENCODED, encoded_file_bytes, invalid};
use super::package_work::PackageFileProgress;
use crate::error::Result;
use std::io::{Cursor, Read};
use std::time::Instant;

/// A tar block.
const BLOCK: usize = 512;
/// A Unix symbolic link's file type bits.
const SYMLINK_MODE: u32 = 0o120_000;

/// The files of a skill archive, told apart by its leading bytes: gzip (with
/// a tar inside) or zip, read before `deadline`, the host's own.
pub(super) fn skill_archive(bytes: &[u8], deadline: Instant) -> Result<Vec<HubFile>> {
    let mut progress = PackageFileProgress::new(deadline);
    let files = match bytes {
        [0x1f, 0x8b, ..] => tar_gz(bytes, &mut progress)?,
        [b'P', b'K', 3, 4, ..] => zip(bytes, &mut progress)?,
        _ => return Err(invalid("a skill archive is neither .tar.gz nor .zip")),
    };
    if !files.iter().any(|file| file.path == "SKILL.md") {
        return Err(invalid("a skill archive holds no SKILL.md at its root"));
    }
    Ok(files)
}

/// A tar read block by block as its gzip yields it, never held whole: only
/// the files it keeps are, under the package bounds.
fn tar_gz(bytes: &[u8], progress: &mut PackageFileProgress) -> Result<Vec<HubFile>> {
    let mut tar = flate2::read::GzDecoder::new(bytes);
    let mut files = Files::default();
    // A pax record or GNU long name names the entry after it.
    let mut long_name: Option<String> = None;
    // Every entry's own bytes, read or passed over: no more than an encoded
    // package holds.
    let mut bodies = 0_usize;
    let mut header = [0_u8; BLOCK];
    while read_block(&mut tar, &mut header)? {
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        progress.file()?;
        let size =
            octal(&header[124..136]).ok_or_else(|| invalid("a skill archive entry has no size"))?;
        bodies = bodies
            .checked_add(size)
            .filter(|bodies| *bodies <= MAX_ENCODED)
            .ok_or_else(|| invalid("a skill archive exceeds the package bounds"))?;
        let body = match header[156] {
            0 | b'0' | b'7' | b'x' | b'L' => read_body(&mut tar, size)?,
            _ => {
                pass_over(&mut tar, size)?;
                Vec::new()
            }
        };
        pass_padding(&mut tar, size)?;
        let name = long_name.take().unwrap_or_else(|| {
            let name = text(&header[..100]);
            let prefix = if header[257..262] == *b"ustar" {
                text(&header[345..500])
            } else {
                String::new()
            };
            if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            }
        });
        match header[156] {
            0 | b'0' | b'7' => files.push(&name, body)?,
            b'1' => files.link(&name, &text(&header[157..257]), true)?,
            b'2' => files.link(&name, &text(&header[157..257]), false)?,
            b'5' | b'g' => {}
            b'x' => long_name = pax_path(&body),
            b'L' => long_name = Some(text(&body)),
            _ => return Err(invalid("a skill archive holds a device or pipe")),
        }
    }
    files.finish()
}

fn unreadable_gzip() -> crate::error::Error {
    invalid("a skill archive is not readable gzip")
}

/// The next whole block; `false` once fewer than a block's bytes are left.
fn read_block(tar: &mut impl Read, block: &mut [u8; BLOCK]) -> Result<bool> {
    let mut filled = 0;
    while filled < BLOCK {
        match tar.read(&mut block[filled..]) {
            Ok(0) => return Ok(false),
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(unreadable_gzip()),
        }
    }
    Ok(true)
}

/// An entry's `size` bytes.
fn read_body(tar: &mut impl Read, size: usize) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    tar.by_ref()
        .take(size as u64)
        .read_to_end(&mut body)
        .map_err(|_| unreadable_gzip())?;
    if body.len() != size {
        return Err(invalid("a skill archive is cut short"));
    }
    Ok(body)
}

/// An entry's `size` bytes, read and dropped.
fn pass_over(tar: &mut impl Read, size: usize) -> Result<()> {
    let passed = std::io::copy(&mut tar.by_ref().take(size as u64), &mut std::io::sink())
        .map_err(|_| unreadable_gzip())?;
    if passed != size as u64 {
        return Err(invalid("a skill archive is cut short"));
    }
    Ok(())
}

/// The padding to the next block after an entry of `size` bytes; a tar that
/// ends inside it ends there.
fn pass_padding(tar: &mut impl Read, size: usize) -> Result<()> {
    let padding = size.div_ceil(BLOCK) * BLOCK - size;
    std::io::copy(&mut tar.by_ref().take(padding as u64), &mut std::io::sink())
        .map_err(|_| unreadable_gzip())?;
    Ok(())
}

fn zip(bytes: &[u8], progress: &mut PackageFileProgress) -> Result<Vec<HubFile>> {
    let unreadable = |_| invalid("a skill archive is not readable zip");
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(unreadable)?;
    let mut files = Files::default();
    for index in 0..archive.len() {
        progress.file()?;
        let mut entry = archive.by_index(index).map_err(unreadable)?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_owned();
        let link = entry
            .unix_mode()
            .is_some_and(|mode| mode & 0o170_000 == SYMLINK_MODE);
        let mut content = Vec::new();
        entry
            .by_ref()
            .take(MAX_HUB_FILE_BYTES as u64 + 1)
            .read_to_end(&mut content)
            .map_err(|_| invalid("a skill archive is not readable zip"))?;
        if link {
            // A zip link's bytes are the path it names.
            files.link(&name, &String::from_utf8_lossy(&content), false)?;
        } else {
            files.push(&name, content)?;
        }
    }
    files.finish()
}

/// An archive's files as they are read, under the package bounds, and its
/// links, read once every file is in.
#[derive(Default)]
struct Files {
    files: Vec<HubFile>,
    total: usize,
    /// The bytes these files take in an encoded package: a package past the
    /// codec's bound is never stored.
    encoded: usize,
    /// Each link's path and the archive path of the file it names.
    links: Vec<(String, String)>,
}

impl Files {
    fn push(&mut self, path: &str, content: Vec<u8>) -> Result<()> {
        let path = resolve("", path)
            .ok_or_else(|| invalid("a skill archive path leaves the skill folder"))?;
        self.total += content.len();
        self.encoded = self
            .encoded
            .saturating_add(encoded_file_bytes(path.len(), content.len()));
        if content.len() > MAX_HUB_FILE_BYTES
            || self.total > MAX_HUB_PACKAGE_TOTAL_BYTES
            || self.encoded > MAX_ENCODED
        {
            return Err(invalid("a skill archive exceeds the package bounds"));
        }
        self.files.push(HubFile::new(path, content));
        Ok(())
    }

    /// A hard link names an archive path; a symbolic one names a path from
    /// its own folder.
    fn link(&mut self, path: &str, target: &str, hard: bool) -> Result<()> {
        let path = resolve("", path)
            .ok_or_else(|| invalid("a skill archive path leaves the skill folder"))?;
        let base = if hard {
            ""
        } else {
            path.rsplit_once('/').map_or("", |(folder, _)| folder)
        };
        let target = resolve(base, target)
            .ok_or_else(|| invalid("a skill archive link leaves the skill folder"))?;
        self.links.push((path, target));
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<HubFile>> {
        for (path, target) in std::mem::take(&mut self.links) {
            let content = self
                .files
                .iter()
                .find(|file| file.path == target)
                .map(|file| file.content.clone())
                .ok_or_else(|| invalid("a skill archive link names no file in it"))?;
            self.push(&path, content)?;
        }
        Ok(self.files)
    }
}

/// `path` from folder `base` as a path from the archive root, `.` and `..`
/// resolved; `None` when it is absolute or climbs out of the root.
fn resolve(base: &str, path: &str) -> Option<String> {
    if path.starts_with('/') {
        return None;
    }
    let mut parts: Vec<&str> = base.split('/').filter(|part| !part.is_empty()).collect();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            part => parts.push(part),
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// A NUL-ended header field.
fn text(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// A tar header's octal number.
fn octal(bytes: &[u8]) -> Option<usize> {
    let text = text(bytes);
    let digits = text.trim_matches(|c: char| c == ' ' || c == '\0');
    if digits.is_empty() {
        return Some(0);
    }
    usize::from_str_radix(digits, 8).ok()
}

/// The `path` record of a pax extended header (`<length> path=<value>`).
fn pax_path(body: &[u8]) -> Option<String> {
    std::str::from_utf8(body).ok()?.lines().find_map(|line| {
        line.split_once(' ')?
            .1
            .strip_prefix("path=")
            .map(str::to_owned)
    })
}
