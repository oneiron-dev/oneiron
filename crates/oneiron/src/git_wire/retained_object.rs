//! Retained Git object IO (FIX 7608 slice 2b-i, Rule 5).
//!
//! A captured GitWire read holds its whole answer in memory under the
//! process bounds, and a captured write takes its payload as an owned
//! buffer. A retained read spools the child's stdout whole into an
//! anonymous file instead, and a retained write feeds the child's stdin
//! from one. No byte, object, count or wall-clock bound ends either, and
//! both run through the one child constructor (`spawn_git`) with the same
//! repository binding, effect class and coordinator checks as every other
//! call. The ordinary captured readers, writers and their bounds are
//! unchanged.
//!
//! A spool is written once by its pump and sealed with its length and
//! BLAKE3; every read of it is checked against that seal, so bytes that
//! changed after it closed fail the read. [`GitRetainedObject`] is one git
//! object held in a spool, built only by a read of a store (its stored size
//! checked) or by the structural encoders of `projected_object`.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;

use super::argv::FrozenGitArgv;
use super::config::GIT_WIRE_READ_CHUNK_BYTES;
use super::failure::invalid;
use super::objects::parse_tree_entry;
use super::{
    GitOid, GitTreeEntry, GitWire, GitWireOperation, GitWirePlan, GitWireRepo, GitWireResult,
};
use crate::error::{Error, Result};

/// A git object's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GitObjectKind {
    Blob,
    Tree,
    Commit,
    Tag,
}

impl GitObjectKind {
    /// Git's own name for the type.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::Tree => "tree",
            Self::Commit => "commit",
            Self::Tag => "tag",
        }
    }

    /// The type git names `kind`.
    ///
    /// # Errors
    /// Any name but the four.
    pub fn parse(kind: &str) -> GitWireResult<Self> {
        match kind {
            "blob" => Ok(Self::Blob),
            "tree" => Ok(Self::Tree),
            "commit" => Ok(Self::Commit),
            "tag" => Ok(Self::Tag),
            _ => Err(invalid("git object type is not blob, tree, commit or tag")),
        }
    }

    /// The object write a retained payload of this type runs as.
    pub(super) const fn write_operation(self) -> GitWireOperation {
        match self {
            Self::Blob => GitWireOperation::WriteBlob,
            Self::Tree => GitWireOperation::WriteTree,
            Self::Commit => GitWireOperation::WriteCommit,
            Self::Tag => GitWireOperation::WriteTag,
        }
    }
}

/// One sealed spool file.
#[derive(Debug)]
struct SpoolFile {
    file: Mutex<File>,
    len: u64,
    blake3: [u8; 32],
}

/// A sealed, immutable spool: the bytes one pump wrote into an anonymous
/// file (no path names it), read back only against the length and BLAKE3
/// it was sealed with. Clones share the one file.
#[derive(Debug, Clone)]
pub(crate) struct GitSpool(Arc<SpoolFile>);

impl PartialEq for GitSpool {
    fn eq(&self, other: &Self) -> bool {
        self.0.len == other.0.len && self.0.blake3 == other.0.blake3
    }
}

impl Eq for GitSpool {}

impl GitSpool {
    /// Pumps `reader` to its end into a fresh anonymous file under `dir`
    /// and seals it. Nothing bounds it: the pump ends only at the reader's
    /// end or an IO failure.
    ///
    /// # Errors
    /// An IO failure.
    pub(crate) fn pump<R: Read>(dir: &Path, mut reader: R) -> Result<Self> {
        let mut file = tempfile::tempfile_in(dir)?;
        let mut hasher = blake3::Hasher::new();
        let mut len: u64 = 0;
        let mut chunk = vec![0_u8; GIT_WIRE_READ_CHUNK_BYTES];
        loop {
            let read = match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            file.write_all(&chunk[..read])?;
            hasher.update(&chunk[..read]);
            len = len
                .checked_add(read as u64)
                .ok_or(Error::ArithmeticOverflow("a git spool's length"))?;
        }
        file.flush()?;
        Ok(Self(Arc::new(SpoolFile {
            file: Mutex::new(file),
            len,
            blake3: *hasher.finalize().as_bytes(),
        })))
    }

    /// The sealed length in bytes.
    pub(crate) fn len(&self) -> u64 {
        self.0.len
    }

    /// The sealed BLAKE3 of the whole spool.
    pub(crate) fn blake3(&self) -> [u8; 32] {
        self.0.blake3
    }

    /// Hands `visit` the spool's bytes in order, and fails when what it
    /// read back is not what was sealed.
    ///
    /// # Errors
    /// An IO failure, a changed spool, or `visit`'s own.
    pub(crate) fn for_each_chunk(&self, visit: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let mut hasher = blake3::Hasher::new();
        let mut chunk = vec![0_u8; GIT_WIRE_READ_CHUNK_BYTES];
        let mut offset: u64 = 0;
        while offset < self.0.len {
            let read = self.read_at(offset, &mut chunk)?;
            if read == 0 {
                return Err(invalid("a git spool ended before its sealed length"));
            }
            hasher.update(&chunk[..read]);
            visit(&chunk[..read])?;
            offset += read as u64;
        }
        if *hasher.finalize().as_bytes() != self.0.blake3 {
            return Err(invalid("a git spool changed after it was sealed"));
        }
        Ok(())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let left = self.0.len.saturating_sub(offset);
        let want = usize::try_from(left).map_or(buf.len(), |left| left.min(buf.len()));
        let mut file = self.0.file.lock().unwrap_or_else(PoisonError::into_inner);
        file.seek(SeekFrom::Start(offset))?;
        loop {
            match file.read(&mut buf[..want]) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                other => return Ok(other?),
            }
        }
    }

    /// The whole spool in memory, for a caller that reads it whole.
    ///
    /// # Errors
    /// As [`Self::for_each_chunk`].
    pub(crate) fn read_all(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.for_each_chunk(&mut |chunk| {
            out.extend_from_slice(chunk);
            Ok(())
        })?;
        Ok(out)
    }

    /// The spool into `hasher` under `record::hash_field`'s framing: its
    /// length as a big-endian `u32` (saturating), then its bytes.
    ///
    /// # Errors
    /// As [`Self::for_each_chunk`].
    pub(super) fn hash_framed(&self, hasher: &mut blake3::Hasher) -> Result<()> {
        let length = u32::try_from(self.0.len).unwrap_or(u32::MAX);
        hasher.update(&length.to_be_bytes());
        self.for_each_chunk(&mut |chunk| {
            hasher.update(chunk);
            Ok(())
        })
    }

    fn write_into<W: Write>(&self, sink: &mut W) -> Result<()> {
        self.for_each_chunk(&mut |chunk| {
            sink.write_all(chunk)?;
            Ok(())
        })?;
        sink.flush()?;
        Ok(())
    }
}

/// What one call moves through a spool instead of memory: its stdin, its
/// stdout, or both. Only `FrozenGitArgv`'s typed constructors set it, so no
/// caller names a path or an argv through it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct RetainedGitIo {
    stdin: Option<GitSpool>,
    stdout: bool,
}

impl RetainedGitIo {
    /// The child reads `spool` on its stdin.
    pub(super) fn with_stdin(mut self, spool: GitSpool) -> Self {
        self.stdin = Some(spool);
        self
    }

    /// The child's stdout is spooled whole.
    pub(super) fn with_spooled_stdout(mut self) -> Self {
        self.stdout = true;
        self
    }

    /// Whether anything here is retained: such a child runs with no
    /// wall-clock bound (Rule 5).
    pub(super) const fn is_retained(&self) -> bool {
        self.stdin.is_some() || self.stdout
    }

    pub(super) const fn stdin(&self) -> Option<&GitSpool> {
        self.stdin.as_ref()
    }

    pub(super) const fn spools_stdout(&self) -> bool {
        self.stdout
    }
}

/// Feeds a child's stdin from `spool` on its own thread, so a large payload
/// cannot deadlock against a full output pipe; the pipe closes when the
/// thread ends. `false` when the bytes did not all reach the child.
pub(super) fn spawn_spool_writer(child: &mut Child, spool: GitSpool) -> JoinHandle<bool> {
    let sink = child.stdin.take();
    std::thread::spawn(move || match sink {
        Some(mut pipe) => spool.write_into(&mut pipe).is_ok(),
        None => false,
    })
}

/// Pumps a child's stdout whole into a fresh spool under `dir` on its own
/// thread; `None` when the pump failed.
pub(super) fn spawn_spool_reader<R>(pipe: R, dir: PathBuf) -> JoinHandle<Option<GitSpool>>
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || GitSpool::pump(&dir, pipe).ok())
}

/// One git object held whole in a sealed spool: its type and bytes, and
/// the OID a store holds it at when it was read from one. Built only by a
/// retained read, which checks the store's own size, or by the structural
/// encoders, which seal what they wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitRetainedObject {
    kind: GitObjectKind,
    spool: GitSpool,
    source: Option<GitOid>,
}

impl GitRetainedObject {
    /// An object read from a store: its spool must hold exactly the size
    /// the store reported for it.
    fn read_from(kind: GitObjectKind, spool: GitSpool, size: u64, source: GitOid) -> Result<Self> {
        if spool.len() != size {
            return Err(invalid(
                "a retained git object's bytes are not its stored size",
            ));
        }
        Ok(Self {
            kind,
            spool,
            source: Some(source),
        })
    }

    /// An object an encoder wrote: it names no store OID until it is
    /// written.
    pub(super) const fn encoded(kind: GitObjectKind, spool: GitSpool) -> Self {
        Self {
            kind,
            spool,
            source: None,
        }
    }

    /// The object's type.
    pub const fn kind(&self) -> GitObjectKind {
        self.kind
    }

    /// The object's size in bytes.
    pub fn size(&self) -> u64 {
        self.spool.len()
    }

    /// The BLAKE3 of the object's whole bytes: the hash a repo mark keeps
    /// for a blob.
    pub fn content_blake3(&self) -> [u8; 32] {
        self.spool.blake3()
    }

    /// The OID the store it was read from holds it at; `None` for an
    /// encoded object not yet written.
    pub fn source_oid(&self) -> Option<&GitOid> {
        self.source.as_ref()
    }

    /// The object's whole bytes in memory.
    ///
    /// # Errors
    /// An IO failure, or a spool that changed after it was sealed.
    pub fn read_bytes(&self) -> GitWireResult<Vec<u8>> {
        self.spool.read_all()
    }

    pub(super) const fn spool(&self) -> &GitSpool {
        &self.spool
    }
}

impl GitWire<'_> {
    /// The anonymous spools' directory: the process baseline's own temp
    /// directory, as every scratch store uses.
    pub(super) fn spool_dir(&self) -> &Path {
        &self.process_env.tmpdir
    }

    /// Runs a read with its stdout spooled whole, through the same
    /// repository binding and read-effect checks as every read.
    pub(super) fn read_spooled(&self, repo: &GitWireRepo, argv: FrozenGitArgv) -> Result<GitSpool> {
        let argv = argv.with_spooled_stdout();
        let output = self.run_read(repo, &argv)?;
        output
            .spooled
            .ok_or_else(|| invalid("a retained git read returned no spool"))
    }

    /// One object's type and stored size, `None` when this store lacks it.
    ///
    /// # Errors
    /// A failed or malformed read.
    pub fn object_kind_and_size(
        &self,
        repo: &GitWireRepo,
        oid: &GitOid,
    ) -> GitWireResult<Option<(GitObjectKind, u64)>> {
        let output = self.run_read(repo, &FrozenGitArgv::object_info(std::slice::from_ref(oid)))?;
        let text = String::from_utf8_lossy(&output.stdout);
        let Some(line) = text.lines().next() else {
            return Ok(None);
        };
        let mut fields = line.split(' ');
        if fields.next() != Some(oid.as_str()) {
            return Err(invalid("git object info answered another object"));
        }
        match (fields.next(), fields.next()) {
            (Some("missing"), _) => Ok(None),
            (Some(kind), Some(size)) => Ok(Some((
                GitObjectKind::parse(kind)?,
                size.parse()
                    .map_err(|_| invalid("git object size is not a number"))?,
            ))),
            _ => Err(invalid("git object info line is malformed")),
        }
    }

    /// The whole stored bytes of one object, spooled: no size, time or
    /// count bound (Rule 5). Its type and size come from the store first,
    /// and the spool must hold exactly that size.
    ///
    /// # Errors
    /// An object this store lacks, or a failed read.
    pub fn read_object_to_spool(
        &self,
        repo: &GitWireRepo,
        oid: &GitOid,
    ) -> GitWireResult<GitRetainedObject> {
        let (kind, size) = self
            .object_kind_and_size(repo, oid)?
            .ok_or_else(|| invalid("git object is not present in this object store"))?;
        let spool = self.read_spooled(repo, FrozenGitArgv::read_object(kind.as_str(), oid))?;
        GitRetainedObject::read_from(kind, spool, size, oid.clone())
    }

    /// Hands `visit` each direct entry of one tree, its `ls-tree -z`
    /// listing spooled whole and read one NUL record at a time: no tree is
    /// too wide (Rule 5), and each name keeps its stored bytes.
    ///
    /// # Errors
    /// A failed read, a malformed record, or `visit`'s own.
    pub fn for_each_tree_entry_retained(
        &self,
        repo: &GitWireRepo,
        tree: &GitOid,
        visit: &mut dyn FnMut(GitTreeEntry) -> Result<()>,
    ) -> GitWireResult<()> {
        let spool = self.read_spooled(repo, FrozenGitArgv::read_tree(tree))?;
        let mut pending: Vec<u8> = Vec::new();
        spool.for_each_chunk(&mut |chunk| {
            let mut rest = chunk;
            while let Some(end) = rest.iter().position(|byte| *byte == 0) {
                pending.extend_from_slice(&rest[..end]);
                if !pending.is_empty() {
                    visit(parse_tree_entry(&pending)?)?;
                }
                pending.clear();
                rest = &rest[end + 1..];
            }
            pending.extend_from_slice(rest);
            Ok(())
        })?;
        if !pending.is_empty() {
            visit(parse_tree_entry(&pending)?)?;
        }
        Ok(())
    }

    /// Writes one retained object into `repo` through a one-object plan:
    /// the ordinary object-write path (binding, effect, write, parsed OID,
    /// keep-ref pin), its payload streamed from the spool. Each object is
    /// its own plan, so no plan bound limits a copy. An object read from a
    /// store must land at the OID it was read at.
    ///
    /// # Errors
    /// A failed write, or a copy that landed at another OID.
    pub fn write_retained_object(
        &self,
        repo: &GitWireRepo,
        object: &GitRetainedObject,
        now: u64,
    ) -> GitWireResult<GitOid> {
        let mut plan = GitWirePlan::new();
        plan.write_retained(object.clone())?;
        let oid = self
            .write_objects(repo, &plan, now)?
            .into_iter()
            .next()
            .ok_or_else(|| invalid("a retained object write named no object"))?;
        if object.source_oid().is_some_and(|source| *source != oid) {
            return Err(invalid(
                "a retained copy of a stored object landed at another object id",
            ));
        }
        Ok(oid)
    }
}
