//! Index-only handles to the instruction files on a returned code unit's
//! ancestor path in its mounted snapshot. A handle names the file and its
//! content hash, never its body, and a pack lists each file once.

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;

use crate::Vault;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{EdgeDirection, EntityStoreRead};
use crate::registry::{ENTITY_TYPE_CODE_ARTIFACT, ENTITY_TYPE_CODE_SYMBOL};
use crate::store::StoreRead;

use super::CodebaseSnapshot;

/// File names read as scoped instructions for everything beneath their directory.
pub const CODE_INSTRUCTION_FILE_NAMES: [&str; 2] = ["AGENTS.md", "CLAUDE.md"];

/// One instruction file in one snapshot, and the returned units it governs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CodeInstructionHandle {
    /// The CODE_ARTIFACT whose snapshot holds the file.
    pub code_artifact_id: EntityId,
    /// Canonical pinned repository ref of that snapshot.
    pub repo_ref: String,
    pub path: String,
    /// Lower-case hex of the file's snapshot content hash.
    pub content_hash: String,
    /// The returned units on whose ancestor path the file sits.
    pub units: Vec<EntityId>,
}

impl Vault {
    /// The instruction files on the ancestor paths of the code units among
    /// `entities`, each listed once however many units share it: call once per
    /// pack. A symbol resolves in a snapshot that `entities` also returns, else
    /// in its newest owning snapshot; an artifact brings its root files. Other
    /// entity kinds are skipped. Sorted by snapshot, then path. Reads the
    /// vault's own rows and admits every one; a pack resolves its handles with
    /// [`code_instruction_handles_in`] under its own read instead.
    pub fn code_instruction_handles(
        &self,
        entities: &[EntityId],
    ) -> Result<Vec<CodeInstructionHandle>> {
        let rtxn = self.store.env.read_txn()?;
        code_instruction_handles_in(&self.store.read(), &rtxn, entities, |_| Ok(true))
    }
}

/// [`Vault::code_instruction_handles`] through `read`, the content the caller
/// reads, in its snapshot `txn`. `admits` judges each unit and each owning
/// CODE_ARTIFACT before any of its body or snapshot metadata is read: a unit
/// it refuses brings no file, and a symbol resolves only in an owner it
/// admits, a returned one first, else the newest. The snapshot is the
/// owner's CODEBASE_SNAPSHOT side row as `read` holds it.
pub(crate) fn code_instruction_handles_in(
    read: &StoreRead<'_>,
    txn: &RoTxn<'_>,
    entities: &[EntityId],
    mut admits: impl FnMut(&EntityId) -> Result<bool>,
) -> Result<Vec<CodeInstructionHandle>> {
    let mut units = Vec::new();
    let mut seen = BTreeSet::new();
    for id in entities {
        if !seen.insert(*id) {
            continue;
        }
        let Some(raw) = read.port_entity_record(txn, id)? else {
            continue;
        };
        if !matches!(
            raw.entity_type,
            ENTITY_TYPE_CODE_ARTIFACT | ENTITY_TYPE_CODE_SYMBOL
        ) || !admits(id)?
        {
            continue;
        }
        units.push((*id, raw.entity_type, raw.body));
    }
    let returned: BTreeSet<EntityId> = units
        .iter()
        .filter(|(_, kind, _)| *kind == ENTITY_TYPE_CODE_ARTIFACT)
        .map(|(id, _, _)| *id)
        .collect();
    let mut owner_admitted: BTreeMap<EntityId, bool> = BTreeMap::new();
    let mut snapshots: BTreeMap<EntityId, Option<CodebaseSnapshot>> = BTreeMap::new();
    let mut handles: BTreeMap<(EntityId, String), CodeInstructionHandle> = BTreeMap::new();
    for (unit, kind, body) in units {
        let (artifact, unit_path) = if kind == ENTITY_TYPE_CODE_ARTIFACT {
            (unit, None)
        } else {
            let mut owners = Vec::new();
            for owner in crate::vault::filtered_edge_peers_in(
                read,
                txn,
                EdgeDirection::Out,
                &unit,
                EdgeKind::PartOf,
                Some(ENTITY_TYPE_CODE_ARTIFACT),
            )? {
                let admitted = match owner_admitted.get(&owner) {
                    Some(admitted) => *admitted,
                    None => {
                        let admitted = returned.contains(&owner) || admits(&owner)?;
                        owner_admitted.insert(owner, admitted);
                        admitted
                    }
                };
                if admitted {
                    owners.push(owner);
                }
            }
            let Some(artifact) = owners
                .iter()
                .find(|owner| returned.contains(owner))
                .or_else(|| owners.iter().max())
                .copied()
            else {
                continue;
            };
            (
                artifact,
                Some(crate::code_symbol::code_symbol_entity_path(&body)?),
            )
        };
        if !snapshots.contains_key(&artifact) {
            snapshots.insert(
                artifact,
                super::store::codebase_snapshot_in_txn(read, txn, &artifact)?,
            );
        }
        let Some(snapshot) = snapshots.get(&artifact).and_then(Option::as_ref) else {
            continue;
        };
        for path in ancestor_instruction_paths(unit_path.as_deref()) {
            let Ok(index) = snapshot
                .files
                .binary_search_by(|entry| entry.path.as_str().cmp(path.as_str()))
            else {
                continue;
            };
            let content_hash =
                crate::entity_id::bytes_to_hex_lower(&snapshot.files[index].content_hash);
            let handle =
                handles
                    .entry((artifact, path.clone()))
                    .or_insert_with(|| CodeInstructionHandle {
                        code_artifact_id: artifact,
                        repo_ref: snapshot.repo_ref.canonical(),
                        path,
                        content_hash,
                        units: Vec::new(),
                    });
            if !handle.units.contains(&unit) {
                handle.units.push(unit);
            }
        }
    }
    Ok(handles.into_values().collect())
}

/// The instruction file candidates from the root down to the unit's directory.
fn ancestor_instruction_paths(unit: Option<&str>) -> Vec<String> {
    let mut dirs = vec![String::new()];
    if let Some(unit) = unit {
        let parts: Vec<&str> = unit.split('/').collect();
        for depth in 1..parts.len() {
            dirs.push(parts[..depth].join("/"));
        }
    }
    dirs.iter()
        .flat_map(|dir| {
            CODE_INSTRUCTION_FILE_NAMES.iter().map(move |name| {
                if dir.is_empty() {
                    (*name).to_owned()
                } else {
                    format!("{dir}/{name}")
                }
            })
        })
        .collect()
}
