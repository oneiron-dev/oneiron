//! File-backed result bodies beside `data.mdb` (OF-597, OF-190 B++).
//!
//! A body past `[limits] code_result_inline_bytes` lives in one 0700
//! `bodies/` directory under the vault root, opened through the root
//! descriptor the store holds, as `lfs-staging/` is. A file is named by the
//! BLAKE3 of its bytes and written once: into a temp file, synced, renamed
//! into place and the directory synced, so a name that is present is a whole
//! body. Reads come by range straight from the file. Its sparse line index
//! (the newline count before every 64 KiB block, big-endian u64s) is built as
//! the body streams and sits beside it as `<name>.lines`; it is derived, so a
//! checkpoint never carries it and a restore rebuilds it.
//!
//! An off-record run's bodies go to a 0700 directory of its session's under
//! `off-record-bodies/`, never into `bodies/`. Closing the session removes
//! it, and the next writer open of the vault sweeps whatever a crash left
//! there and every unfinished temp file in `bodies/`.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::Path;

use rustix::fs::{
    AtFlags, Dir, Mode, OFlags, fstatvfs, fsync, mkdirat, openat, renameat, unlinkat,
};
use rustix::io::Errno;

use super::Store;
use crate::{Error, Result};

const BODIES_DIR: &str = "bodies";
const SPILL_ROOT: &str = "off-record-bodies";
const TEMP_PREFIX: &str = ".tmp-";
pub(crate) const LINE_INDEX_SUFFIX: &str = ".lines";

/// Bytes per block of a body's sparse line index.
pub(crate) const LINE_INDEX_BLOCK_BYTES: u64 = 64 * 1024;

/// Bytes of a body's head its preview is built from.
const PREVIEW_HEAD_BYTES: usize = 64 * 1024;

fn io(error: Errno) -> Error {
    std::io::Error::from(error).into()
}

/// The file name of the body with `digest`.
pub(crate) fn body_file_name(digest: &[u8; 32]) -> String {
    crate::entity_id::bytes_to_hex_lower(digest)
}

/// One directory of body files, held open by descriptor.
pub(crate) struct BodyDir {
    pub(crate) dir: File,
}

impl BodyDir {
    /// `name` under `parent`, made 0700 when `create` and absent. `None` when
    /// it is absent and not made.
    fn open_in(parent: &File, name: &str, create: bool) -> Result<Option<Self>> {
        if create {
            match mkdirat(parent, name, Mode::RWXU) {
                Ok(()) | Err(Errno::EXIST) => {}
                Err(error) => return Err(io(error)),
            }
        }
        let dir = match openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => File::from(fd),
            Err(Errno::NOENT) if !create => return Ok(None),
            Err(error) => return Err(io(error)),
        };
        if parent.metadata()?.dev() != dir.metadata()?.dev() {
            return Err(Error::InvalidConfig(
                "result bodies cross the vault filesystem".to_owned(),
            ));
        }
        Ok(Some(Self { dir }))
    }

    /// The body directory at `path`, outside any vault (a checkpoint's),
    /// made 0700 when `create`. `None` when it is absent and not made.
    pub(crate) fn at_path(path: &Path, create: bool) -> Result<Option<Self>> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| Error::InvalidConfig("result body directory path".to_owned()))?;
        Self::open_in(
            &super::root_directory::open_root_directory(parent)?,
            name,
            create,
        )
    }

    /// The body with `digest`, checked to be `len` bytes. `None` when this
    /// directory does not hold it.
    pub(crate) fn open_body(&self, digest: &[u8; 32], len: u64) -> Result<Option<File>> {
        let file = match openat(
            &self.dir,
            body_file_name(digest),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => File::from(fd),
            Err(Errno::NOENT) => return Ok(None),
            Err(error) => return Err(io(error)),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() != len {
            return Err(Error::CorruptedIndex("result body file length"));
        }
        Ok(Some(file))
    }

    /// Free bytes on the filesystem this directory is on.
    pub(crate) fn free_bytes(&self) -> Result<u64> {
        let stat = fstatvfs(&self.dir).map_err(io)?;
        Ok(stat.f_bavail.saturating_mul(stat.f_frsize))
    }

    fn create_temp(&self) -> Result<(File, String)> {
        let name = format!("{TEMP_PREFIX}{}", uuid::Uuid::now_v7().simple());
        let fd = openat(
            &self.dir,
            name.as_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(io)?;
        Ok((File::from(fd), name))
    }

    /// Syncs `file`, renames it from `temp` to `name` and syncs the
    /// directory, so `name` is present only once it is whole. An existing
    /// `name` holds the same bytes and is replaced in one step.
    fn publish(&self, file: File, temp: &str, name: &str) -> Result<()> {
        let published = file
            .sync_all()
            .map_err(Error::from)
            .and_then(|()| renameat(&self.dir, temp, &self.dir, name).map_err(io))
            .and_then(|()| fsync(&self.dir).map_err(io));
        if published.is_err() {
            self.discard(temp);
        }
        published
    }

    fn discard(&self, temp: &str) {
        let _ = unlinkat(&self.dir, temp, AtFlags::empty());
    }

    /// Writes the sparse line index of the body `name` beside it. Derived:
    /// a failure leaves it to be rebuilt.
    fn write_line_index(&self, name: &str, index: &[u64]) {
        let Ok((mut file, temp)) = self.create_temp() else {
            return;
        };
        let bytes: Vec<u8> = index.iter().flat_map(|count| count.to_be_bytes()).collect();
        let written = file.write_all(&bytes).is_ok()
            && renameat(
                &self.dir,
                temp.as_str(),
                &self.dir,
                format!("{name}{LINE_INDEX_SUFFIX}"),
            )
            .is_ok();
        if !written {
            self.discard(&temp);
        }
    }

    /// The sparse line index of the body with `digest`, `len` bytes long:
    /// the newline count before each 64 KiB block. `None` when this
    /// directory holds none, or one that is not one count per block.
    pub(crate) fn read_line_index(&self, digest: &[u8; 32], len: u64) -> Option<Vec<u64>> {
        let fd = openat(
            &self.dir,
            format!("{}{LINE_INDEX_SUFFIX}", body_file_name(digest)),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .ok()?;
        let mut file = File::from(fd);
        let size = len.div_ceil(LINE_INDEX_BLOCK_BYTES).checked_mul(8)?;
        let metadata = file.metadata().ok()?;
        if !metadata.is_file() || metadata.len() != size {
            return None;
        }
        let mut bytes = Vec::with_capacity(usize::try_from(size).ok()?);
        file.read_to_end(&mut bytes).ok()?;
        if bytes.len() as u64 != size {
            return None;
        }
        Some(
            bytes
                .chunks_exact(8)
                .map(|count| {
                    let mut word = [0; 8];
                    word.copy_from_slice(count);
                    u64::from_be_bytes(word)
                })
                .collect(),
        )
    }

    /// Copies in the body with `digest` from `source`, checking its digest
    /// and length, unless this directory holds it already.
    pub(crate) fn import(&self, digest: &[u8; 32], len: u64, source: &mut impl Read) -> Result<()> {
        if self.open_body(digest, len)?.is_some() {
            return Ok(());
        }
        let (mut file, temp) = self.create_temp()?;
        let meter = match copy_checked(&mut file, source, digest, len) {
            Ok(meter) => meter,
            Err(error) => {
                self.discard(&temp);
                return Err(error);
            }
        };
        let name = body_file_name(digest);
        self.publish(file, &temp, &name)?;
        self.write_line_index(&name, &meter.line_index);
        Ok(())
    }

    /// Removes the temp files of writers that never finished.
    fn sweep_temps(&self) -> Result<()> {
        for entry in Dir::read_from(&self.dir).map_err(io)? {
            let entry = entry.map_err(io)?;
            if entry
                .file_name()
                .to_bytes()
                .starts_with(TEMP_PREFIX.as_bytes())
            {
                unlinkat(&self.dir, entry.file_name(), AtFlags::empty()).map_err(io)?;
            }
        }
        Ok(())
    }
}

/// Copies `source` into `file`, checking it is `len` bytes with `digest`.
fn copy_checked(
    file: &mut File,
    source: &mut impl Read,
    digest: &[u8; 32],
    len: u64,
) -> Result<BodyMeter> {
    let mut meter = BodyMeter::new();
    let mut buffer = vec![0; LINE_INDEX_BLOCK_BYTES as usize];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        meter.feed(&buffer[..read]);
        file.write_all(&buffer[..read])?;
    }
    if meter.len != len || *meter.hasher.finalize().as_bytes() != *digest {
        return Err(Error::CorruptedIndex("restored result body digest"));
    }
    Ok(meter)
}

/// What one body is, measured as its bytes stream past.
pub(crate) struct BodyMeter {
    hasher: blake3::Hasher,
    len: u64,
    newlines: u64,
    last: Option<u8>,
    text: bool,
    carry: [u8; 4],
    carry_len: usize,
    head: Vec<u8>,
    line_index: Vec<u64>,
    secrets: SecretScan,
}

/// A measured body's facts, for its manifest.
pub(crate) struct BodyFacts {
    pub(crate) digest: [u8; 32],
    pub(crate) len: u64,
    /// Whether the whole body is UTF-8.
    pub(crate) text: bool,
    pub(crate) lines: u64,
    pub(crate) preview: String,
    pub(crate) preview_truncated: bool,
    /// The reason of the secret scan's first hit in the body (ARCH-0069
    /// S5): the body is kept whole and marked, never refused.
    pub(crate) secret: Option<&'static str>,
    line_index: Vec<u64>,
}

impl BodyMeter {
    pub(crate) fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
            len: 0,
            newlines: 0,
            last: None,
            text: true,
            carry: [0; 4],
            carry_len: 0,
            head: Vec::new(),
            line_index: Vec::new(),
            secrets: SecretScan::default(),
        }
    }

    pub(crate) fn feed(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
        self.secrets.feed(bytes);
        let room = PREVIEW_HEAD_BYTES.saturating_sub(self.head.len());
        self.head.extend_from_slice(&bytes[..room.min(bytes.len())]);
        self.feed_utf8(bytes);
        if let Some(last) = bytes.last() {
            self.last = Some(*last);
        }
        let mut rest = bytes;
        while !rest.is_empty() {
            let into_block = self.len % LINE_INDEX_BLOCK_BYTES;
            if into_block == 0 {
                self.line_index.push(self.newlines);
            }
            let room = usize::try_from(LINE_INDEX_BLOCK_BYTES - into_block).unwrap_or(usize::MAX);
            let (piece, after) = rest.split_at(room.min(rest.len()));
            self.newlines += piece.iter().filter(|byte| **byte == b'\n').count() as u64;
            self.len += piece.len() as u64;
            rest = after;
        }
    }

    /// Checks UTF-8 across frames, carrying a character split between two.
    fn feed_utf8(&mut self, mut bytes: &[u8]) {
        if !self.text {
            return;
        }
        while self.carry_len > 0 {
            let Some((first, after)) = bytes.split_first() else {
                return;
            };
            self.carry[self.carry_len] = *first;
            self.carry_len += 1;
            bytes = after;
            match std::str::from_utf8(&self.carry[..self.carry_len]) {
                Ok(_) => self.carry_len = 0,
                Err(error) if error.error_len().is_some() || self.carry_len == 4 => {
                    self.text = false;
                    return;
                }
                Err(_) => {}
            }
        }
        if let Err(error) = std::str::from_utf8(bytes) {
            if error.error_len().is_some() {
                self.text = false;
            } else {
                let tail = &bytes[error.valid_up_to()..];
                self.carry[..tail.len()].copy_from_slice(tail);
                self.carry_len = tail.len();
            }
        }
    }

    pub(crate) fn finish(mut self, preview_chars: usize) -> BodyFacts {
        let secret = self.secrets.finish();
        let (preview, cut) =
            crate::serialize::compressed_code_run_output_preview(&self.head, preview_chars);
        BodyFacts {
            digest: *self.hasher.finalize().as_bytes(),
            len: self.len,
            text: self.text && self.carry_len == 0,
            lines: self.newlines + u64::from(self.last.is_some_and(|byte| byte != b'\n')),
            preview,
            preview_truncated: cut || self.len > self.head.len() as u64,
            secret,
            line_index: self.line_index,
        }
    }
}

/// The recovery-phrase scan of one body as it streams (#1433): its text is
/// read in order, a character split between two frames carried, and bytes
/// that are no UTF-8 read as one replacement character each, so a binary
/// body is scanned too. It keeps the first hit.
#[derive(Default)]
struct SecretScan {
    phrases: crate::batch::secret_scan::PhraseStream,
    carry: Vec<u8>,
    hit: Option<&'static str>,
}

impl SecretScan {
    fn feed(&mut self, mut bytes: &[u8]) {
        while !self.carry.is_empty() && self.hit.is_none() {
            let Some((first, after)) = bytes.split_first() else {
                return;
            };
            self.carry.push(*first);
            bytes = after;
            let carried = std::mem::take(&mut self.carry);
            match std::str::from_utf8(&carried) {
                Ok(text) => self.read(text),
                Err(error) if error.error_len().is_some() || carried.len() == 4 => {
                    self.read(char::REPLACEMENT_CHARACTER.encode_utf8(&mut [0; 4]));
                }
                Err(_) => self.carry = carried,
            }
        }
        while self.hit.is_none() {
            match std::str::from_utf8(bytes) {
                Ok(text) => return self.read(text),
                Err(error) => {
                    let (valid, rest) = bytes.split_at(error.valid_up_to());
                    self.read(std::str::from_utf8(valid).unwrap_or_default());
                    let Some(bad) = error.error_len() else {
                        self.carry.extend_from_slice(rest);
                        return;
                    };
                    self.read(char::REPLACEMENT_CHARACTER.encode_utf8(&mut [0; 4]));
                    bytes = &rest[bad..];
                }
            }
        }
    }

    fn read(&mut self, text: &str) {
        if self.hit.is_none() {
            self.hit = self.phrases.find(text);
        }
    }

    fn finish(&mut self) -> Option<&'static str> {
        if !std::mem::take(&mut self.carry).is_empty() {
            self.read(char::REPLACEMENT_CHARACTER.encode_utf8(&mut [0; 4]));
        }
        if self.hit.is_none() {
            self.hit = self.phrases.find_at_end();
        }
        self.hit
    }
}

/// Where a finished body went.
pub(crate) enum SunkBody {
    /// Within the inline bound: its bytes, for the LMDB row.
    Inline(Vec<u8>),
    /// Past it: a published body file, and the disk left free beside it
    /// once it was written, when that could be read.
    File { free_bytes: Option<u64> },
}

/// One body written as it streams: kept in memory up to the inline bound,
/// then spilled to a temp file in its body directory, and measured all the
/// way. Dropped unfinished, it leaves nothing behind.
pub(crate) struct BodySink {
    dir: BodyDir,
    inline_limit: u64,
    meter: Option<BodyMeter>,
    inline: Vec<u8>,
    spill: Option<(File, String)>,
}

impl BodySink {
    pub(crate) fn new(dir: BodyDir, inline_limit: u64) -> Self {
        Self {
            dir,
            inline_limit,
            meter: Some(BodyMeter::new()),
            inline: Vec::new(),
            spill: None,
        }
    }

    pub(crate) fn write(&mut self, frame: &[u8]) -> Result<()> {
        if let Some(meter) = &mut self.meter {
            meter.feed(frame);
        }
        if let Some((file, _)) = &mut self.spill {
            file.write_all(frame)?;
            return Ok(());
        }
        let inline_after = (self.inline.len() as u64).saturating_add(frame.len() as u64);
        if inline_after <= self.inline_limit {
            self.inline.extend_from_slice(frame);
            return Ok(());
        }
        let (mut file, temp) = self.dir.create_temp()?;
        let written = file
            .write_all(&self.inline)
            .and_then(|()| file.write_all(frame));
        if let Err(error) = written {
            self.dir.discard(&temp);
            return Err(error.into());
        }
        self.inline = Vec::new();
        self.spill = Some((file, temp));
        Ok(())
    }

    /// The digest of the bytes written so far, the body's own once it is
    /// finished: a body's name can depend on it before it is published.
    pub(crate) fn digest(&self) -> Result<[u8; 32]> {
        self.meter
            .as_ref()
            .map(|meter| *meter.hasher.finalize().as_bytes())
            .ok_or(Error::InvariantViolation("result body sink finished twice"))
    }

    /// Finishes the body: a spilled one is published under its digest.
    pub(crate) fn finish(mut self, preview_chars: usize) -> Result<(BodyFacts, SunkBody)> {
        let facts = self
            .meter
            .take()
            .ok_or(Error::InvariantViolation("result body sink finished twice"))?
            .finish(preview_chars);
        let Some((file, temp)) = self.spill.take() else {
            return Ok((facts, SunkBody::Inline(std::mem::take(&mut self.inline))));
        };
        let name = body_file_name(&facts.digest);
        self.dir.publish(file, &temp, &name)?;
        self.dir.write_line_index(&name, &facts.line_index);
        let free_bytes = self.dir.free_bytes().ok();
        Ok((facts, SunkBody::File { free_bytes }))
    }
}

impl Drop for BodySink {
    fn drop(&mut self) {
        if let Some((_, temp)) = self.spill.take() {
            self.dir.discard(&temp);
        }
    }
}

/// Reads `len` bytes of `file` from `offset`.
pub(crate) fn read_body_range(file: &File, offset: u64, len: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0; len];
    file.read_exact_at(&mut bytes, offset)?;
    Ok(bytes)
}

impl Store {
    /// The vault root, held open: the descriptor the environment was opened
    /// through, or the registered path opened no-follow.
    fn body_root(&self) -> Result<File> {
        if let Some(root) = self.owner.env._bound_root_dir.as_ref() {
            return Ok(root.try_clone()?);
        }
        super::root_directory::open_root_directory(&self.owner._registered_path.path)
    }

    /// This vault's `bodies/` directory, made when absent.
    pub(crate) fn body_dir(&self) -> Result<BodyDir> {
        BodyDir::open_in(&self.body_root()?, BODIES_DIR, true)?
            .ok_or(Error::InvariantViolation("result body directory missing"))
    }

    /// The body directory of the off-record session `session_ref`, made when
    /// `create`. `None` when it has none and none is made.
    pub(crate) fn session_body_dir(
        &self,
        session_ref: &str,
        create: bool,
    ) -> Result<Option<BodyDir>> {
        let Some(spill) = BodyDir::open_in(&self.body_root()?, SPILL_ROOT, create)? else {
            return Ok(None);
        };
        BodyDir::open_in(&spill.dir, &session_spill_name(session_ref), create)
    }

    /// Removes the off-record session's body directory and every body in it.
    pub(crate) fn remove_session_bodies(&self, session_ref: &str) -> Result<()> {
        let Some(spill) = BodyDir::open_in(&self.body_root()?, SPILL_ROOT, false)? else {
            return Ok(());
        };
        let name = session_spill_name(session_ref);
        let Some(session) = BodyDir::open_in(&spill.dir, &name, false)? else {
            return Ok(());
        };
        super::root_directory::empty_directory(session.dir.as_fd(), false)?;
        unlinkat(&spill.dir, name.as_str(), AtFlags::REMOVEDIR).map_err(io)
    }

    /// At a writer open: removes the temp files of body writers that never
    /// finished and every off-record session's bodies, none of whose
    /// sessions outlived the process that held them.
    pub(crate) fn sweep_body_debris(&self) -> Result<()> {
        let root = self.body_root()?;
        if let Some(bodies) = BodyDir::open_in(&root, BODIES_DIR, false)? {
            bodies.sweep_temps()?;
        }
        if let Some(spill) = BodyDir::open_in(&root, SPILL_ROOT, false)? {
            super::root_directory::empty_directory(spill.dir.as_fd(), false)?;
        }
        Ok(())
    }
}

/// A session's body directory name: its reference's BLAKE3, so no session
/// reference can name a path.
fn session_spill_name(session_ref: &str) -> String {
    blake3::hash(session_ref.as_bytes()).to_hex().to_string()
}
