//! Core half of `git_wire::retained_object`: its store-layer items live in `oneiron_store::git_wire::retained_object` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::git_wire::retained_object::*;

use super::argv::FrozenGitArgv;
use super::config::GIT_WIRE_READ_CHUNK_BYTES;
use super::failure::invalid;
use super::objects::parse_tree_entry;
use super::{
    GitOid, GitTreeEntry, GitWire, GitWireOperation, GitWirePlan, GitWireRepo, GitWireResult,
};
use crate::error::{Error, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;

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
