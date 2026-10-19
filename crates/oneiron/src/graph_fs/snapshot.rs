//! Historical file resolution over retained codebase snapshots. The manifest
//! selects bytes; the caller's live scoped read still admits both the artifact
//! and each blob before a path, name, length or body is returned.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::claim::{PointRead, ScopedRead};
use crate::codebase::{read_asset_blob_in_txn, snapshot_asset_entity_id};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::model::{
    GraphFsEntry, GraphFsFile, GraphFsMount, GraphFsOptions, GraphFsPage, GraphFsResolver,
};
use super::paging::{PageBuilder, SealedPosition};
use super::readdir::GraphFsFileRead;

/// A reference selects content, never authority. Historical references name
/// retained imported snapshots, not a local folder on the serving host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GraphFsReference {
    LiveHead,
    ForkHash { repo: EntityId, hash: String },
    RepoSnapshot { snapshot: EntityId },
}

impl<'vault> ScopedRead<'vault> {
    /// Opens the file face under this read's own credential. Snapshot ids
    /// resolve to a content-addressed fork before any operation can run.
    pub fn mount_graph_fs(
        &self,
        reference: &GraphFsReference,
        options: GraphFsOptions,
    ) -> Result<GraphFsResolver<'_, 'vault>> {
        let (repo, expected) = match reference {
            GraphFsReference::LiveHead => return Ok(self.graph_fs(options)),
            GraphFsReference::ForkHash { repo, hash } => (
                *repo,
                Some(crate::artifact_hosting::parse_codebase_fork_hash_hex(hash)?),
            ),
            GraphFsReference::RepoSnapshot { snapshot } => (*snapshot, None),
        };
        let selected = self.read_projected_opaque(
            &[PointRead::id(repo)],
            None,
            |_, _| Ok::<_, Error>(true),
            |txn, rows| {
                if rows.into_iter().next().flatten().is_none() {
                    return Err(Error::EntityNotFound);
                }
                let snapshot = self
                    .vault()
                    .get_codebase_snapshot_in_txn(txn, &repo)?
                    .ok_or(Error::EntityNotFound)?;
                if expected.is_some_and(|hash| hash != snapshot.fork_hash) {
                    return Err(Error::EntityNotFound);
                }
                Ok(snapshot.fork_hash)
            },
        )?;
        let mut resolver =
            self.graph_fs(options.with_mount(GraphFsMount::ForkHash(selected.value)));
        resolver.snapshot = Some((repo, selected.value));
        Ok(resolver)
    }
}

impl GraphFsResolver<'_, '_> {
    /// The reference an operation actually resolved. Return it to the caller
    /// so a snapshot id never silently re-resolves to different bytes.
    pub fn reference(&self) -> GraphFsReference {
        match self.snapshot {
            Some((repo, hash)) => GraphFsReference::ForkHash {
                repo,
                hash: crate::entity_id::bytes_to_hex_lower(&hash),
            },
            None => GraphFsReference::LiveHead,
        }
    }

    /// Binds a public continuation even when the underlying coreutil uses a
    /// byte offset or a fixed-directory name internally.
    pub(crate) fn open_public_cursor(
        &self,
        call: &str,
        cursor: Option<&str>,
    ) -> Result<Option<String>> {
        self.cursor_scope(call).open(cursor)
    }

    pub(crate) fn seal_public_cursor(&self, call: &str, cursor: &str) -> String {
        self.cursor_scope(call).seal(&cursor.to_owned())
    }

    /// Imported file states share their snapshot's recorded transaction
    /// time. No host filesystem mtime is inferred for retained bytes.
    pub(super) fn snapshot_newer_than(&self, newer_than: u64) -> Result<bool> {
        let (repo, hash) = self.snapshot.ok_or(Error::EntityNotFound)?;
        let read = self.scoped_read.read_projected_opaque(
            &[PointRead::id(repo)],
            None,
            |_, _| Ok::<_, Error>(true),
            |txn, rows| {
                let Some(row) = rows.into_iter().next().flatten() else {
                    return Ok(false);
                };
                let Some(snapshot) = self
                    .scoped_read
                    .vault()
                    .get_codebase_snapshot_in_txn(txn, &repo)?
                else {
                    return Ok(false);
                };
                if snapshot.fork_hash != hash {
                    return Err(Error::EntityNotFound);
                }
                Ok(row.learned_at > newer_than)
            },
        )?;
        Ok(read.value)
    }

    pub(super) fn snapshot_visible(&self, path: &str) -> Result<bool> {
        let Some(_) = self.snapshot else {
            return Ok(true);
        };
        if path == "/" {
            return self
                .snapshot_entries(path)
                .map(|entries| !entries.is_empty());
        }
        if self.snapshot_file(path)?.value.is_some() {
            return Ok(true);
        }
        self.snapshot_entries(path)
            .map(|entries| !entries.is_empty())
    }

    pub(super) fn snapshot_readdir(&self, path: &str, cursor: Option<&str>) -> Result<GraphFsPage> {
        let entries = self.snapshot_entries(path)?;
        let scope = self.cursor_scope(&format!("snapshot readdir {path}"));
        let after: Option<String> = scope.open(cursor)?;
        let mut page = PageBuilder::new(path, self.options);
        let mut last = None;
        let mut next = None;
        for entry in entries {
            if after.as_deref().is_some_and(|after| entry.name() <= after) {
                continue;
            }
            if !page.try_push(entry.clone()) {
                next = last.as_ref().map(|last| scope.seal(last));
                break;
            }
            last = Some(entry.name().to_owned());
        }
        Ok(page.finish(next))
    }

    fn snapshot_entries(&self, path: &str) -> Result<Vec<GraphFsEntry>> {
        let (repo, hash) = self.snapshot.ok_or(Error::EntityNotFound)?;
        self.scoped_read
            .read_projected_opaque(
                &[PointRead::id(repo)],
                None,
                |_, _| Ok::<_, Error>(true),
                |txn, rows| {
                    if rows.into_iter().next().flatten().is_none() {
                        return Ok(Vec::new());
                    }
                    let Some(snapshot) = self
                        .scoped_read
                        .vault()
                        .get_codebase_snapshot_in_txn(txn, &repo)?
                    else {
                        return Ok(Vec::new());
                    };
                    if snapshot.fork_hash != hash {
                        return Err(Error::EntityNotFound);
                    }
                    let withheld = self
                        .scoped_read
                        .vault()
                        .codebase_withheld_paths_in_txn(txn, &hash)?;
                    let prefix = if path == "/" {
                        String::new()
                    } else {
                        format!("{}/", path.trim_start_matches('/'))
                    };
                    let mut entries = BTreeMap::new();
                    for file in &snapshot.files {
                        if withheld.contains(&file.path) {
                            continue;
                        }
                        let Some(rest) = file.path.strip_prefix(&prefix) else {
                            continue;
                        };
                        let asset = snapshot_asset_entity_id(&file.content_hash)?;
                        if !self.scoped_read.entities_readable_in_txn(txn, &[asset])?[0] {
                            continue;
                        }
                        let (name, directory) = match rest.split_once('/') {
                            Some((name, _)) => (name, true),
                            None => (rest, false),
                        };
                        let entry = if directory {
                            GraphFsEntry::directory(name)
                        } else {
                            GraphFsEntry::file(name, usize::try_from(file.size_bytes).ok())
                        };
                        entries.insert(name.to_owned(), entry);
                    }
                    Ok(entries.into_values().collect())
                },
            )
            .map(|read| read.value)
    }

    pub(super) fn snapshot_file(&self, path: &str) -> Result<GraphFsFileRead> {
        let (repo, hash) = self.snapshot.ok_or(Error::EntityNotFound)?;
        let read = self.scoped_read.read_projected_opaque(
            &[PointRead::id(repo)],
            None,
            |_, _| Ok::<_, Error>(true),
            |txn, rows| {
                if rows.into_iter().next().flatten().is_none() {
                    return Ok(None);
                }
                let Some(snapshot) = self
                    .scoped_read
                    .vault()
                    .get_codebase_snapshot_in_txn(txn, &repo)?
                else {
                    return Ok(None);
                };
                if snapshot.fork_hash != hash {
                    return Err(Error::EntityNotFound);
                }
                let relative = path.trim_start_matches('/');
                let Some(file) = snapshot.files.iter().find(|file| file.path == relative) else {
                    return Ok(None);
                };
                let withheld = self
                    .scoped_read
                    .vault()
                    .codebase_withheld_paths_in_txn(txn, &hash)?;
                let asset = snapshot_asset_entity_id(&file.content_hash)?;
                if withheld.contains(relative)
                    || !self.scoped_read.entities_readable_in_txn(txn, &[asset])?[0]
                {
                    return Ok(None);
                }
                Ok(Some(GraphFsFile {
                    path: path.to_owned(),
                    mount: self.options.mount,
                    bytes: crate::secret_custody::sighted_bytes_in_txn(
                        &self.scoped_read.vault().store,
                        txn,
                        read_asset_blob_in_txn(self.scoped_read.vault(), txn, &file.content_hash)?,
                        if self.scoped_read.actor_key().reads_as_vault_owner() {
                            crate::secret_custody::SecretSight::Owner
                        } else {
                            crate::secret_custody::SecretSight::Masked
                        },
                    )?,
                }))
            },
        )?;
        // Withheld entries and their denial counts are absent, not an oracle.
        Ok(GraphFsFileRead {
            value: read.value,
            receipt: None,
        })
    }
}

impl SealedPosition for String {
    fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        String::from_utf8(bytes.to_vec()).ok()
    }
}
