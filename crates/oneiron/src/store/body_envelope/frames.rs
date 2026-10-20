//! One body file's envelope (FIX 5348): E0 chunks under the file's own data
//! key.
//!
//! ```text
//! "ONEIRONB" ‖ u16be version ‖ instance (16) ‖ u32be overhead   the clear head
//!   ‖ chunk*      E0 envelopes of 64 KiB of the body each; the last holds
//!                 the rest, 0 to 64 KiB, and an empty body has one, empty
//!   ‖ terminal    E0 envelope: u64be length ‖ BLAKE3 ‖ u64be chunk count
//! ```
//!
//! Every envelope is `overhead` bytes longer than its plaintext, so a chunk's
//! place follows from its index and a range read opens only the chunks it
//! touches. Each envelope binds, in its key id, the format version, the
//! file's instance, its index and its role (a chunk, the last chunk, the
//! terminal record), and the vault as its vault id; each is sealed with a
//! fresh salt and nonce. A reader checks the file's whole length before it
//! reads a chunk, and authenticates a chunk before it returns a byte of it:
//! a file cut short, reordered or appended to does not read.
//!
//! The bound is per chunk only: a body of any length takes as many chunks as
//! it needs (Rule 5).

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::fs::FileExt;
use std::sync::Arc;

use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, Kek, OpenKey, OpenPolicy, Purpose, SealKey, SealParams, SuiteId,
    WrapType, seal,
};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

const MAGIC: &[u8; 8] = b"ONEIRONB";
/// The format version a file's head, its chunks and its key row carry.
pub(super) const FORMAT_VERSION: u16 = 1;
const HEAD_LEN: usize = MAGIC.len() + 2 + 16 + 4;
/// Plaintext per chunk: one block of the line index.
const CHUNK: u64 = 64 * 1024;
const _: () = assert!(CHUNK == crate::store::LINE_INDEX_BLOCK_BYTES);
const TERMINAL_LEN: u64 = 8 + 32 + 8;
const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
const EPOCH: u64 = 1;
const RECIPIENT: &[u8] = b"oneiron/body-file/chunk";
/// The domain the line index's key is derived under from the file's key.
const LINES_CONTEXT: &str = "oneiron/body-file-lines/v1";
/// No E0 envelope's header and tag come near this far past its plaintext.
const MAX_OVERHEAD: u64 = 4096;

fn corrupt() -> Error {
    Error::CorruptedIndex("body file envelope")
}

/// What one envelope of a file is.
#[derive(Clone, Copy)]
enum Role {
    Chunk = 0,
    Last = 1,
    Terminal = 2,
}

/// Which of a file's keys an envelope is under: the body's, or its line
/// index's.
#[derive(Clone, Copy)]
pub(super) enum Domain {
    Body,
    Lines,
}

/// One body file's opened data key, with the vault and instance every
/// envelope of it binds. Never printed, wiped on drop.
pub(crate) struct FileKey {
    vault_id: [u8; 32],
    instance: [u8; 16],
    raw: Zeroizing<[u8; 32]>,
    body: Kek,
    lines: Kek,
}

impl std::fmt::Debug for FileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FileKey(..)")
    }
}

impl FileKey {
    /// The key `raw` of the file `instance` in vault `vault_id`.
    pub(super) fn from_raw(
        vault_id: [u8; 32],
        instance: [u8; 16],
        raw: Zeroizing<[u8; 32]>,
    ) -> Self {
        let lines = crate::world_keys::derive_guarded(LINES_CONTEXT, &[&raw[..]]);
        Self {
            vault_id,
            instance,
            body: Kek::from_bytes_ref(&raw),
            lines: Kek::from_zeroizing(lines),
            raw,
        }
    }

    /// A fresh random key for a new file of vault `vault_id`, under a fresh
    /// random instance.
    pub(super) fn generate(vault_id: [u8; 32]) -> Result<Self> {
        let mut raw = Zeroizing::new([0u8; 32]);
        crate::world_keys::os_fill(&mut raw[..])?;
        let mut instance = [0u8; 16];
        crate::world_keys::os_fill(&mut instance)?;
        Ok(Self::from_raw(vault_id, instance, raw))
    }

    pub(super) const fn instance(&self) -> &[u8; 16] {
        &self.instance
    }

    /// The key's bytes, for its wrap only.
    pub(super) fn raw(&self) -> &[u8] {
        &self.raw[..]
    }

    const fn kek(&self, domain: Domain) -> &Kek {
        match domain {
            Domain::Body => &self.body,
            Domain::Lines => &self.lines,
        }
    }
}

/// Version ‖ instance ‖ u64be index ‖ role: each envelope's key id.
fn key_id(key: &FileKey, index: u64, role: Role) -> [u8; 27] {
    let mut out = [0u8; 27];
    out[..2].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
    out[2..18].copy_from_slice(&key.instance);
    out[18..26].copy_from_slice(&index.to_be_bytes());
    out[26] = role as u8;
    out
}

fn seal_frame(
    key: &FileKey,
    domain: Domain,
    index: u64,
    role: Role,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let key_id = key_id(key, index, role);
    let params = SealParams {
        suite: AEAD,
        purpose: Purpose::BodyFileChunk,
        epoch: EPOCH,
        key_id: &key_id,
        recipient: RECIPIENT,
        vault_id: &key.vault_id,
    };
    Ok(seal(
        &params,
        SealKey::SymmetricKek(key.kek(domain)),
        plaintext,
        &mut SysRng,
    )
    .map_err(|_| crate::world_keys::refused("sealing a body file failed"))?
    .to_bytes())
}

/// The plaintext of `frame`, authenticated as envelope `index` of `role`
/// before a byte of it is returned, and checked to be `len` bytes.
fn open_frame(
    key: &FileKey,
    domain: Domain,
    index: u64,
    role: Role,
    frame: &[u8],
    len: u64,
) -> Result<Zeroizing<Vec<u8>>> {
    let key_id = key_id(key, index, role);
    let policy = OpenPolicy {
        purpose: Purpose::BodyFileChunk,
        vault_id: &key.vault_id,
        recipient: RECIPIENT,
        key_id: &key_id,
        wraps: &[WrapType::SymmetricKek],
        aead_suites: &[AEAD],
        kem_suites: &[],
        min_epoch: EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    let plaintext = Envelope::parse(frame)
        .map_err(|_| corrupt())?
        .open(OpenKey::SymmetricKek(key.kek(domain)), &policy)
        .map_err(|_| corrupt())?;
    if plaintext.len() as u64 != len {
        return Err(corrupt());
    }
    Ok(plaintext)
}

fn terminal_bytes(len: u64, digest: &[u8; 32], chunks: u64) -> [u8; TERMINAL_LEN as usize] {
    let mut out = [0u8; TERMINAL_LEN as usize];
    out[..8].copy_from_slice(&len.to_be_bytes());
    out[8..40].copy_from_slice(digest);
    out[40..].copy_from_slice(&chunks.to_be_bytes());
    out
}

/// Where each envelope of a file `len` bytes long, whose envelopes are
/// `overhead` bytes past their plaintext, lies.
#[derive(Clone, Copy)]
pub(super) struct Layout {
    overhead: u64,
    len: u64,
    chunks: u64,
}

impl Layout {
    fn new(overhead: u64, len: u64) -> Result<Self> {
        if !(1..=MAX_OVERHEAD).contains(&overhead) {
            return Err(corrupt());
        }
        Ok(Self {
            overhead,
            len,
            chunks: len.div_ceil(CHUNK).max(1),
        })
    }

    /// Plaintext bytes in chunk `index`.
    const fn chunk_len(&self, index: u64) -> u64 {
        if index + 1 < self.chunks {
            CHUNK
        } else {
            self.len - (self.chunks - 1) * CHUNK
        }
    }

    const fn role(&self, index: u64) -> Role {
        if index + 1 < self.chunks {
            Role::Chunk
        } else {
            Role::Last
        }
    }

    /// Where chunk `index` starts: every chunk before it is whole.
    fn chunk_at(&self, index: u64) -> Result<u64> {
        index
            .checked_mul(self.overhead + CHUNK)
            .and_then(|at| at.checked_add(HEAD_LEN as u64))
            .ok_or(Error::ArithmeticOverflow("body file chunk offset"))
    }

    fn terminal_at(&self) -> Result<u64> {
        self.chunks
            .checked_mul(self.overhead)
            .and_then(|frames| frames.checked_add(self.len))
            .and_then(|at| at.checked_add(HEAD_LEN as u64))
            .ok_or(Error::ArithmeticOverflow("body file length"))
    }

    /// The file's whole length on disk.
    pub(super) fn physical(&self) -> Result<u64> {
        self.terminal_at()?
            .checked_add(self.overhead + TERMINAL_LEN)
            .ok_or(Error::ArithmeticOverflow("body file length"))
    }
}

/// The head of a file of `key`'s, checked: its envelopes' overhead.
fn parse_head(head: &[u8; HEAD_LEN], key: &FileKey) -> Result<u64> {
    let (magic, rest) = head.split_at(MAGIC.len());
    if magic != MAGIC || rest[..2] != FORMAT_VERSION.to_be_bytes() || rest[2..18] != key.instance {
        return Err(corrupt());
    }
    let mut overhead = [0u8; 4];
    overhead.copy_from_slice(&rest[18..22]);
    Ok(u64::from(u32::from_be_bytes(overhead)))
}

/// The head of a sealed file in place: its envelopes' overhead, after the
/// file's length is checked against the body's `len`.
pub(super) fn checked_layout(file: &File, key: &FileKey, len: u64) -> Result<Layout> {
    let mut head = [0u8; HEAD_LEN];
    file.read_exact_at(&mut head, 0).map_err(|_| corrupt())?;
    let layout = Layout::new(parse_head(&head, key)?, len)?;
    if file.metadata()?.len() != layout.physical()? {
        return Err(corrupt());
    }
    Ok(layout)
}

/// Chunk `index` of a checked file, authenticated.
pub(super) fn read_chunk(
    file: &File,
    key: &FileKey,
    layout: &Layout,
    index: u64,
) -> Result<Zeroizing<Vec<u8>>> {
    let len = layout.chunk_len(index);
    let mut frame = vec![0u8; usize::try_from(layout.overhead + len).map_err(|_| corrupt())?];
    file.read_exact_at(&mut frame, layout.chunk_at(index)?)
        .map_err(|_| corrupt())?;
    open_frame(key, Domain::Body, index, layout.role(index), &frame, len)
}

/// Checks a checked file's terminal record against the body's `digest`.
pub(super) fn check_terminal(
    file: &File,
    key: &FileKey,
    layout: &Layout,
    digest: &[u8; 32],
) -> Result<()> {
    let mut frame =
        vec![0u8; usize::try_from(layout.overhead + TERMINAL_LEN).map_err(|_| corrupt())?];
    file.read_exact_at(&mut frame, layout.terminal_at()?)
        .map_err(|_| corrupt())?;
    let terminal = open_frame(
        key,
        Domain::Body,
        layout.chunks,
        Role::Terminal,
        &frame,
        TERMINAL_LEN,
    )?;
    if terminal[..] != terminal_bytes(layout.len, digest, layout.chunks)[..] {
        return Err(corrupt());
    }
    Ok(())
}

pub(super) const fn chunk_of(offset: u64) -> (u64, u64) {
    (offset / CHUNK, offset % CHUNK)
}

/// A file sealed as it is written: each chunk is sealed once the next byte
/// shows it is not the last, and the head goes out with the first envelope.
pub(super) struct FrameWriter {
    out: File,
    key: Arc<FileKey>,
    domain: Domain,
    buffer: Zeroizing<Vec<u8>>,
    index: u64,
    len: u64,
    hasher: blake3::Hasher,
    overhead: Option<u64>,
}

impl FrameWriter {
    pub(super) fn new(out: File, key: Arc<FileKey>, domain: Domain) -> Self {
        Self {
            out,
            key,
            domain,
            buffer: Zeroizing::new(Vec::with_capacity(CHUNK as usize)),
            index: 0,
            len: 0,
            hasher: blake3::Hasher::new(),
            overhead: None,
        }
    }

    pub(super) fn key(&self) -> &Arc<FileKey> {
        &self.key
    }

    pub(super) fn write(&mut self, mut bytes: &[u8]) -> Result<()> {
        while !bytes.is_empty() {
            if self.buffer.len() as u64 == CHUNK {
                self.seal_buffer(Role::Chunk)?;
            }
            let room = CHUNK as usize - self.buffer.len();
            let (take, rest) = bytes.split_at(room.min(bytes.len()));
            self.buffer.extend_from_slice(take);
            self.hasher.update(take);
            self.len += take.len() as u64;
            bytes = rest;
        }
        Ok(())
    }

    fn seal_buffer(&mut self, role: Role) -> Result<()> {
        let frame = seal_frame(&self.key, self.domain, self.index, role, &self.buffer)?;
        self.put(&frame, self.buffer.len())?;
        self.buffer.clear();
        self.index += 1;
        Ok(())
    }

    fn put(&mut self, frame: &[u8], plaintext: usize) -> Result<()> {
        let overhead = (frame.len() - plaintext) as u64;
        match self.overhead {
            None => {
                let mut head = Vec::with_capacity(HEAD_LEN);
                head.extend_from_slice(MAGIC);
                head.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
                head.extend_from_slice(&self.key.instance);
                head.extend_from_slice(
                    &u32::try_from(overhead)
                        .map_err(|_| corrupt())?
                        .to_be_bytes(),
                );
                self.out.write_all(&head)?;
                self.overhead = Some(overhead);
            }
            Some(sealed) if sealed != overhead => {
                return Err(Error::InvariantViolation(
                    "a body file's envelopes differ in overhead",
                ));
            }
            Some(_) => {}
        }
        self.out.write_all(frame)?;
        Ok(())
    }

    /// Seals the last chunk and the terminal record. The file, and the
    /// length and BLAKE3 of what was written.
    pub(super) fn finish(mut self) -> Result<(File, u64, [u8; 32])> {
        self.seal_buffer(Role::Last)?;
        let digest = *self.hasher.finalize().as_bytes();
        let terminal = terminal_bytes(self.len, &digest, self.index);
        let frame = seal_frame(
            &self.key,
            self.domain,
            self.index,
            Role::Terminal,
            &terminal,
        )?;
        self.put(&frame, terminal.len())?;
        Ok((self.out, self.len, digest))
    }
}

/// The newline count before each 64 KiB block of a body read in order: its
/// line index, built a chunk at a time.
#[derive(Default)]
pub(super) struct LineCounter {
    newlines: u64,
    index: Vec<u64>,
}

impl LineCounter {
    /// Counts one whole chunk, the last one excepted.
    pub(super) fn chunk(&mut self, chunk: &[u8]) {
        if chunk.is_empty() {
            return;
        }
        self.index.push(self.newlines);
        self.newlines += chunk.iter().filter(|byte| **byte == b'\n').count() as u64;
    }

    pub(super) fn index(&self) -> &[u64] {
        &self.index
    }
}

/// A sealed file read in order from any source, each envelope authenticated
/// before its bytes go on: its ciphertext exactly as it is, for a copy or a
/// checkpoint, or its plaintext. The head, the length of every envelope, the
/// terminal record and the end of the source are all checked, so a stream
/// that reads to its end was the whole file `key` sealed for this body.
pub(crate) struct SealedStream<R> {
    source: R,
    key: Arc<FileKey>,
    domain: Domain,
    len: u64,
    digest: Option<[u8; 32]>,
    ciphertext: bool,
    layout: Option<Layout>,
    next: u64,
    done: bool,
    hasher: blake3::Hasher,
    lines: LineCounter,
    out: Zeroizing<Vec<u8>>,
    at: usize,
}

impl<R: Read> SealedStream<R> {
    fn new(
        source: R,
        key: Arc<FileKey>,
        domain: Domain,
        len: u64,
        digest: Option<[u8; 32]>,
        ciphertext: bool,
    ) -> Self {
        Self {
            source,
            key,
            domain,
            len,
            digest,
            ciphertext,
            layout: None,
            next: 0,
            done: false,
            hasher: blake3::Hasher::new(),
            lines: LineCounter::default(),
            out: Zeroizing::new(Vec::new()),
            at: 0,
        }
    }

    /// The body `digest` of `len` bytes that `source` holds sealed under
    /// `key`, passed on as its ciphertext.
    pub(crate) fn ciphertext(source: R, key: Arc<FileKey>, digest: [u8; 32], len: u64) -> Self {
        Self::new(source, key, Domain::Body, len, Some(digest), true)
    }

    /// [`Self::ciphertext`], passed on as its plaintext.
    pub(crate) fn plaintext(source: R, key: Arc<FileKey>, digest: [u8; 32], len: u64) -> Self {
        Self::new(source, key, Domain::Body, len, Some(digest), false)
    }

    /// The line index of what has streamed so far: the whole body's once it
    /// has read to its end.
    pub(super) fn line_index(&self) -> &[u64] {
        self.lines.index()
    }

    fn take(&mut self, len: u64) -> Result<Vec<u8>> {
        let mut bytes = vec![0u8; usize::try_from(len).map_err(|_| corrupt())?];
        self.source.read_exact(&mut bytes).map_err(|_| corrupt())?;
        Ok(bytes)
    }

    /// Reads the next part of the file into `out`; `false` at its end.
    fn step(&mut self) -> Result<bool> {
        if self.done {
            return Ok(false);
        }
        let Some(layout) = self.layout else {
            let mut head = [0u8; HEAD_LEN];
            self.source.read_exact(&mut head).map_err(|_| corrupt())?;
            self.layout = Some(Layout::new(parse_head(&head, &self.key)?, self.len)?);
            self.out = Zeroizing::new(if self.ciphertext {
                head.to_vec()
            } else {
                Vec::new()
            });
            return Ok(true);
        };
        if self.next < layout.chunks {
            let len = layout.chunk_len(self.next);
            let frame = self.take(layout.overhead + len)?;
            let chunk = open_frame(
                &self.key,
                self.domain,
                self.next,
                layout.role(self.next),
                &frame,
                len,
            )?;
            self.hasher.update(&chunk);
            self.lines.chunk(&chunk);
            self.next += 1;
            self.out = if self.ciphertext {
                Zeroizing::new(frame)
            } else {
                chunk
            };
            return Ok(true);
        }
        let frame = self.take(layout.overhead + TERMINAL_LEN)?;
        let terminal = open_frame(
            &self.key,
            self.domain,
            layout.chunks,
            Role::Terminal,
            &frame,
            TERMINAL_LEN,
        )?;
        let digest = *self.hasher.finalize().as_bytes();
        if self.digest.is_some_and(|expected| expected != digest)
            || terminal[..] != terminal_bytes(self.len, &digest, layout.chunks)[..]
        {
            return Err(corrupt());
        }
        // Nothing follows the terminal record.
        let mut probe = [0u8; 1];
        if self.source.read(&mut probe)? != 0 {
            return Err(corrupt());
        }
        self.done = true;
        self.out = Zeroizing::new(if self.ciphertext { frame } else { Vec::new() });
        Ok(true)
    }
}

impl<R: Read> Read for SealedStream<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.at < self.out.len() {
                let read = out.len().min(self.out.len() - self.at);
                out[..read].copy_from_slice(&self.out[self.at..self.at + read]);
                self.at += read;
                return Ok(read);
            }
            if out.is_empty() || !self.step().map_err(io::Error::other)? {
                return Ok(0);
            }
            self.at = 0;
        }
    }
}

/// A plaintext body read out sealed: exactly the envelope a [`FrameWriter`]
/// writes for it under `key`, head, chunks and terminal record, a frame at a
/// time, so a checkpoint carries a plain body sealed under its instance's
/// key with no plaintext temp file (KS-2A). The source must hold exactly
/// `len` bytes, and `digest` when one is given: anything else fails the read.
pub(crate) struct SealingStream<R> {
    source: R,
    key: Arc<FileKey>,
    layout: Layout,
    digest: Option<[u8; 32]>,
    next: u64,
    done: bool,
    hasher: blake3::Hasher,
    out: Vec<u8>,
    at: usize,
}

impl<R: Read> SealingStream<R> {
    /// The body of `len` bytes `source` holds, sealed under `key` as it is
    /// read.
    ///
    /// # Errors
    ///
    /// Sealing errors.
    pub(crate) fn new(
        source: R,
        key: Arc<FileKey>,
        len: u64,
        digest: Option<[u8; 32]>,
    ) -> Result<Self> {
        Ok(Self {
            layout: Layout::new(overhead(&key)?, len)?,
            source,
            key,
            digest,
            next: 0,
            done: false,
            hasher: blake3::Hasher::new(),
            out: Vec::new(),
            at: 0,
        })
    }

    /// The envelope's whole length, known before a byte is read.
    ///
    /// # Errors
    ///
    /// [`Error::ArithmeticOverflow`] past `u64`.
    pub(crate) fn sealed_len(&self) -> Result<u64> {
        self.layout.physical()
    }

    /// Seals the next part into `out`; `false` at the end.
    fn step(&mut self) -> Result<bool> {
        if self.done {
            return Ok(false);
        }
        if self.next < self.layout.chunks {
            let len = self.layout.chunk_len(self.next);
            let mut chunk = Zeroizing::new(vec![0u8; usize::try_from(len).map_err(|_| corrupt())?]);
            self.source.read_exact(&mut chunk).map_err(|_| corrupt())?;
            self.hasher.update(&chunk);
            let frame = seal_frame(
                &self.key,
                Domain::Body,
                self.next,
                self.layout.role(self.next),
                &chunk,
            )?;
            self.out.clear();
            if self.next == 0 {
                self.out.extend_from_slice(MAGIC);
                self.out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
                self.out.extend_from_slice(&self.key.instance);
                self.out.extend_from_slice(
                    &u32::try_from(self.layout.overhead)
                        .map_err(|_| corrupt())?
                        .to_be_bytes(),
                );
            }
            self.out.extend_from_slice(&frame);
            self.next += 1;
            return Ok(true);
        }
        let digest = *self.hasher.finalize().as_bytes();
        let mut probe = [0u8; 1];
        if self.digest.is_some_and(|expected| expected != digest)
            || self.source.read(&mut probe)? != 0
        {
            return Err(corrupt());
        }
        let terminal = terminal_bytes(self.layout.len, &digest, self.layout.chunks);
        self.out = seal_frame(
            &self.key,
            Domain::Body,
            self.layout.chunks,
            Role::Terminal,
            &terminal,
        )?;
        self.done = true;
        Ok(true)
    }
}

impl<R: Read> Read for SealingStream<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.at < self.out.len() {
                let read = out.len().min(self.out.len() - self.at);
                out[..read].copy_from_slice(&self.out[self.at..self.at + read]);
                self.at += read;
                return Ok(read);
            }
            if out.is_empty() || !self.step().map_err(io::Error::other)? {
                return Ok(0);
            }
            self.at = 0;
        }
    }
}

/// How many bytes each of `key`'s envelopes adds to its plaintext: one
/// empty frame, sealed to measure.
fn overhead(key: &FileKey) -> Result<u64> {
    Ok(seal_frame(key, Domain::Body, 0, Role::Chunk, &[])?.len() as u64)
}

/// Writes `index`, the line index of a body sealed under `key`, sealed
/// under the key's line-index domain into `out`.
pub(super) fn write_line_index(out: File, key: Arc<FileKey>, index: &[u64]) -> Result<File> {
    let mut writer = FrameWriter::new(out, key, Domain::Lines);
    for count in index {
        writer.write(&count.to_be_bytes())?;
    }
    Ok(writer.finish()?.0)
}

/// The line index of a body `len` bytes long sealed under `key`, read whole
/// from `file`. `None` when it does not read whole: it is derived.
pub(super) fn read_line_index(file: File, key: &Arc<FileKey>, len: u64) -> Option<Vec<u64>> {
    let size = len.div_ceil(CHUNK).checked_mul(8)?;
    let mut stream = SealedStream::new(file, Arc::clone(key), Domain::Lines, size, None, false);
    let mut bytes = Vec::with_capacity(usize::try_from(size).ok()?);
    stream.read_to_end(&mut bytes).ok()?;
    Some(
        bytes
            .chunks_exact(8)
            .map(|count| {
                let mut word = [0u8; 8];
                word.copy_from_slice(count);
                u64::from_be_bytes(word)
            })
            .collect(),
    )
}
