//! The ustar stream itself: each header checked as it is read, every byte
//! hashed on its way through, the entry data passed on a chunk at a time.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufReader, ErrorKind, Read as _};
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use super::{ArchiveError, CHUNK, DIR_MODE, EXEC_MODE, FILE_MODE, io, malformed, pin};
use crate::oneironer::bundle::Artifact;

const BLOCK: usize = 512;

/// One entry, its header checked.
pub(super) struct Entry {
    /// Relative, built of plain names only.
    pub(super) path: PathBuf,
    pub(super) directory: bool,
    pub(super) size: u64,
    /// The normalized mode it is extracted with.
    pub(super) mode: u32,
}

/// An archive read front to back, hashed as it goes.
pub(super) struct Reader<'a> {
    tar: &'a Path,
    artifact: &'a Artifact,
    input: BufReader<File>,
    hasher: Sha256,
    /// The bytes read so far: the next header's offset.
    offset: u64,
    /// Every entry's path so far, and the directories among them.
    paths: BTreeSet<PathBuf>,
    dirs: BTreeSet<PathBuf>,
}

impl<'a> Reader<'a> {
    /// Opens `tar`, a plain file of the pinned length.
    pub(super) fn open(tar: &'a Path, artifact: &'a Artifact) -> Result<Self, ArchiveError> {
        let metadata = tar.symlink_metadata();
        if !metadata.is_ok_and(|held| held.is_file() && held.len() == artifact.bytes) {
            return Err(pin(artifact));
        }
        let file = File::open(tar).map_err(io("opening", tar))?;
        Ok(Self {
            tar,
            artifact,
            input: BufReader::with_capacity(CHUNK, file),
            hasher: Sha256::new(),
            offset: 0,
            paths: BTreeSet::new(),
            dirs: BTreeSet::new(),
        })
    }

    /// Fills `buffer` from the archive; an archive ending first is
    /// malformed, as `short` says.
    fn fill(&mut self, buffer: &mut [u8], short: &str) -> Result<(), ArchiveError> {
        match self.input.read_exact(buffer) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => {
                return Err(malformed(self.offset, short));
            }
            Err(error) => return Err(io("reading", self.tar)(error)),
        }
        self.hasher.update(&*buffer);
        self.offset += buffer.len() as u64;
        Ok(())
    }

    /// The next entry, its header checked and its path new, under a
    /// directory the archive made; `None` at the two zero end blocks.
    pub(super) fn entry(&mut self) -> Result<Option<Entry>, ArchiveError> {
        let at = self.offset;
        let mut block = [0_u8; BLOCK];
        self.fill(&mut block, "the archive ends without its two end blocks")?;
        if block.iter().all(|&byte| byte == 0) {
            self.fill(&mut block, "the archive ends after one end block")?;
            if block.iter().any(|&byte| byte != 0) {
                return Err(malformed(at, "a header follows a zero block"));
            }
            return Ok(None);
        }
        let entry = header(&block, at)?;
        let shown = || entry.path.display().to_string();
        if self.paths.contains(&entry.path) {
            return Err(ArchiveError::DuplicatePath { path: shown() });
        }
        if let Some(parent) = entry.path.parent()
            && !parent.as_os_str().is_empty()
            && !self.dirs.contains(parent)
        {
            return Err(malformed(at, format!("{:?} comes before its directory", shown())));
        }
        self.paths.insert(entry.path.clone());
        if entry.directory {
            self.dirs.insert(entry.path.clone());
        }
        Ok(Some(entry))
    }

    /// Streams an entry's `size` bytes to `sink` a chunk at a time, then
    /// passes its padding to the next block.
    pub(super) fn data(
        &mut self,
        size: u64,
        buffer: &mut [u8],
        mut sink: impl FnMut(&[u8]) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        let mut left = size;
        while left > 0 {
            let take = left.min(buffer.len() as u64) as usize;
            self.fill(&mut buffer[..take], "the archive ends inside an entry")?;
            sink(&buffer[..take])?;
            left -= take as u64;
        }
        let padding = (BLOCK - (size % BLOCK as u64) as usize) % BLOCK;
        self.fill(&mut buffer[..padding], "the archive ends inside an entry")
    }

    /// Reads what follows the end blocks, zeros only, then holds the whole
    /// archive to its pinned length and SHA-256. Every entry's path.
    pub(super) fn finish(mut self, buffer: &mut [u8]) -> Result<BTreeSet<PathBuf>, ArchiveError> {
        loop {
            let read = match self.input.read(buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(io("reading", self.tar)(error)),
            };
            if buffer[..read].iter().any(|&byte| byte != 0) {
                return Err(malformed(self.offset, "data follows the end blocks"));
            }
            self.hasher.update(&buffer[..read]);
            self.offset += read as u64;
        }
        let digest = format!("{:x}", self.hasher.finalize());
        if self.offset != self.artifact.bytes || digest != self.artifact.sha256 {
            return Err(pin(self.artifact));
        }
        Ok(self.paths)
    }
}

/// One header block, checked: ustar magic and version, the checksum, a
/// file or directory type, an octal size and a plain relative path.
fn header(block: &[u8; BLOCK], at: u64) -> Result<Entry, ArchiveError> {
    if block[257..263] != *b"ustar\0" || block[263..265] != *b"00" {
        return Err(malformed(at, "not a POSIX ustar header"));
    }
    let stated = octal(&block[148..156]).ok_or_else(|| malformed(at, "an unreadable checksum"))?;
    // The checksum counts its own field as eight spaces.
    let sum: u64 = block[..148]
        .iter()
        .chain(&[b' '; 8])
        .chain(&block[156..])
        .map(|&byte| u64::from(byte))
        .sum();
    if sum != stated {
        return Err(malformed(at, "a header checksum that does not match"));
    }
    let (Some(name), Some(prefix)) = (text(&block[..100]), text(&block[345..500])) else {
        return Err(malformed(at, "an entry name that is not UTF-8"));
    };
    let name = if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}/{name}")
    };
    let directory = match block[156] {
        b'0' | b'\0' => false,
        b'5' => true,
        b'1' => return Err(ArchiveError::Hardlink { path: name }),
        b'2' => return Err(ArchiveError::Symlink { path: name }),
        flag => {
            return Err(ArchiveError::UnsupportedEntry {
                path: name,
                flag: char::from(flag),
                kind: entry_kind(flag),
            });
        }
    };
    if block[124] & 0x80 != 0 {
        return Err(ArchiveError::UnsupportedHeader {
            path: name,
            what: "a base-256 size",
        });
    }
    let size = octal(&block[124..136]).ok_or_else(|| malformed(at, "an unreadable size"))?;
    let mode = octal(&block[100..108]).ok_or_else(|| malformed(at, "an unreadable mode"))?;
    if directory && size != 0 {
        return Err(malformed(at, "a directory with a size"));
    }
    let mode = match (directory, mode & 0o111 != 0) {
        (true, _) => DIR_MODE,
        (false, true) => EXEC_MODE,
        (false, false) => FILE_MODE,
    };
    Ok(Entry {
        path: entry_path(&name, at)?,
        directory,
        size,
        mode,
    })
}

/// What an entry type other than a file, directory or link is.
fn entry_kind(flag: u8) -> &'static str {
    match flag {
        b'3' => "character device",
        b'4' => "block device",
        b'6' => "fifo",
        b'7' => "contiguous file",
        b'x' => "PAX extended header",
        b'g' => "PAX global header",
        b'L' => "GNU long name",
        b'K' => "GNU long link name",
        _ => "entry of another type",
    }
}

/// An entry's name as a path of plain names only.
fn entry_path(name: &str, at: u64) -> Result<PathBuf, ArchiveError> {
    let mut path = PathBuf::new();
    for component in Path::new(name).components() {
        match component {
            Component::Normal(part) => path.push(part),
            Component::RootDir | Component::Prefix(_) => {
                return Err(ArchiveError::AbsolutePath {
                    path: name.to_owned(),
                });
            }
            Component::ParentDir => {
                return Err(ArchiveError::ParentComponent {
                    path: name.to_owned(),
                });
            }
            Component::CurDir => return Err(malformed(at, format!("{name:?} has a `.` component"))),
        }
    }
    if path.as_os_str().is_empty() {
        return Err(malformed(at, "an empty entry name"));
    }
    Ok(path)
}

/// A NUL-ended header field as text.
fn text(field: &[u8]) -> Option<&str> {
    let end = field.iter().position(|&byte| byte == 0).unwrap_or(field.len());
    std::str::from_utf8(&field[..end]).ok()
}

/// An octal header number: digits after any spaces, ended by a NUL, a space
/// or the field's end.
fn octal(field: &[u8]) -> Option<u64> {
    let mut value = None;
    for &byte in field.iter().skip_while(|&&byte| byte == b' ') {
        if byte == 0 || byte == b' ' {
            break;
        }
        if !(b'0'..=b'7').contains(&byte) {
            return None;
        }
        let digit = u64::from(byte - b'0');
        value = Some(value.unwrap_or(0_u64).checked_mul(8)?.checked_add(digit)?);
    }
    value
}
