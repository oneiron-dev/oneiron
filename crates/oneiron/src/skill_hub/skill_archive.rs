//! A skill archive from an agentskills.io discovery index (`type:
//! "archive"`): a `.tar.gz` or `.zip` of the skill folder, `SKILL.md` at its
//! root. Read in memory under the package bounds. As the discovery spec
//! requires, an absolute path, a `..` segment or a link that leaves the
//! folder refuses; a link inside it reads as a copy of the file it names.
use super::HubFile;
use super::package::{MAX_HUB_FILE_BYTES, MAX_HUB_PACKAGE_FILES, MAX_HUB_PACKAGE_TOTAL_BYTES};
use super::package_codec::invalid;
use crate::error::Result;
use std::io::{Cursor, Read};

/// A tar block.
const BLOCK: usize = 512;
/// A Unix symbolic link's file type bits.
const SYMLINK_MODE: u32 = 0o120_000;

/// The files of a skill archive, told apart by its leading bytes: gzip (with
/// a tar inside) or zip.
pub(super) fn skill_archive(bytes: &[u8]) -> Result<Vec<HubFile>> {
    let files = match bytes {
        [0x1f, 0x8b, ..] => tar_gz(bytes)?,
        [b'P', b'K', 3, 4, ..] => zip(bytes)?,
        _ => return Err(invalid("a skill archive is neither .tar.gz nor .zip")),
    };
    if !files.iter().any(|file| file.path == "SKILL.md") {
        return Err(invalid("a skill archive holds no SKILL.md at its root"));
    }
    Ok(files)
}

fn tar_gz(bytes: &[u8]) -> Result<Vec<HubFile>> {
    // Each file's header and padding beside its bytes.
    let bound = MAX_HUB_PACKAGE_TOTAL_BYTES + (MAX_HUB_PACKAGE_FILES + 2) * 3 * BLOCK;
    let mut tar = Vec::new();
    flate2::read::GzDecoder::new(bytes)
        .take(bound as u64 + 1)
        .read_to_end(&mut tar)
        .map_err(|_| invalid("a skill archive is not readable gzip"))?;
    if tar.len() > bound {
        return Err(invalid("a skill archive exceeds the package bounds"));
    }
    let mut files = Files::default();
    // A pax record or GNU long name names the entry after it.
    let mut long_name: Option<String> = None;
    let mut at = 0;
    while at + BLOCK <= tar.len() {
        let header = &tar[at..at + BLOCK];
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        let size =
            octal(&header[124..136]).ok_or_else(|| invalid("a skill archive entry has no size"))?;
        let start = at + BLOCK;
        let end = start
            .checked_add(size)
            .filter(|end| *end <= tar.len())
            .ok_or_else(|| invalid("a skill archive is cut short"))?;
        let body = &tar[start..end];
        at = start + size.div_ceil(BLOCK) * BLOCK;
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
            0 | b'0' | b'7' => files.push(&name, body.to_vec())?,
            b'1' => files.link(&name, &text(&header[157..257]), true)?,
            b'2' => files.link(&name, &text(&header[157..257]), false)?,
            b'5' | b'g' => {}
            b'x' => long_name = pax_path(body),
            b'L' => long_name = Some(text(body)),
            _ => return Err(invalid("a skill archive holds a device or pipe")),
        }
    }
    files.finish()
}

fn zip(bytes: &[u8]) -> Result<Vec<HubFile>> {
    let unreadable = |_| invalid("a skill archive is not readable zip");
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(unreadable)?;
    let mut files = Files::default();
    for index in 0..archive.len() {
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
    /// Each link's path and the archive path of the file it names.
    links: Vec<(String, String)>,
}

impl Files {
    fn push(&mut self, path: &str, content: Vec<u8>) -> Result<()> {
        let path = resolve("", path)
            .ok_or_else(|| invalid("a skill archive path leaves the skill folder"))?;
        self.total += content.len();
        if self.files.len() >= MAX_HUB_PACKAGE_FILES
            || content.len() > MAX_HUB_FILE_BYTES
            || self.total > MAX_HUB_PACKAGE_TOTAL_BYTES
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
