//! The catalog of the inference snapshots a vault keeps sealed on disk
//! (DESIGN-V2 §7, V2-R3): one row per snapshot under a random catalog id,
//! carrying what the snapshot was computed from and under, never what it
//! holds. The sealed body and its wrapped key live apart from the row; a
//! restore checks the row first, and its absence denies an open.
//!
//! A row keeps ids, digests, enums, counts and pins only: no prompt text,
//! tokens, tensors, credentials or keys. Its manifest names every field the
//! design binds: the vault and the read it was admitted under, the branch
//! and its frontier, the token digest, and the model, quant, tokenizer,
//! template, state schema, attention, build and cache precision it ran
//! with. A field the producer could not name is `None`, and a row with one
//! is never reused. Its compatibility leaves out the backend epoch: a
//! restore binds the new incarnation's own.
//!
//! An erase scans every row's dependency set (its conversation and branch
//! tip, its sources, worlds, authors and erase subjects, and the quoted or
//! folded records it derives from), not the requester's session alone, and
//! takes every row of each conversation it reaches: a later state of the
//! same session carries what an earlier one did. A row whose dependency set
//! is not precise, or that does not decode, goes on any erase.
use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
use crate::llm::{
    CacheDigest, CacheIdentity, ConditioningDigest, ScopeDigest, TokenDigest, VaultRef,
};
use crate::side_table::{self, FixedSideKey, Named, SideKey, SideTable};
use crate::store::Store;

/// The catalog row's format version.
pub const SNAPSHOT_RECORD_SCHEMA: u32 = 1;

/// Key: the catalog id (16 random bytes).
pub(super) const CATALOG: SideTable<SnapshotId, SnapshotRecord, Named> =
    SideTable::new(&side_table::INFERENCE_SNAPSHOT_CATALOG);

/// A snapshot's catalog id: 16 random bytes, never taken from a digest, and
/// not the sealed body's own id. The body's file name derives from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SnapshotId(pub [u8; 16]);

impl SnapshotId {
    /// A fresh id from the OS CSPRNG.
    ///
    /// # Errors
    /// The OS entropy source failed.
    pub fn random() -> Result<Self> {
        let mut id = [0u8; 16];
        crate::world_keys::os_fill(&mut id)?;
        Ok(Self(id))
    }

    /// Its 32 lowercase hex characters.
    #[must_use]
    pub fn to_hex(&self) -> String {
        bytes_to_hex_lower(&self.0)
    }
}

impl SideKey for SnapshotId {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(Self)
    }
}

impl FixedSideKey for SnapshotId {
    const WIDTH: usize = 16;
}

/// What a snapshot's state was computed with, less the backend's epoch: a
/// restore matches it against the new incarnation's identity and binds that
/// incarnation's own epoch. A field no source named is `None`, and forbids
/// reuse.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotCompatibility {
    /// The loaded weights.
    pub model: Option<CacheDigest>,
    /// The weights' quantization.
    pub quant: Option<CacheDigest>,
    pub tokenizer: Option<CacheDigest>,
    /// The chat template's bytes.
    pub template: Option<CacheDigest>,
    /// The effective template arguments and execution settings.
    pub execution_mode: Option<CacheDigest>,
    /// The cache's layout, precision and sizes.
    pub cache_mode: Option<CacheDigest>,
    /// The backend's implementation and build.
    pub runtime: Option<CacheDigest>,
    /// The attention and position settings: rope, sliding window, sinks.
    pub attention: Option<CacheDigest>,
    /// The worker's state serialization schema.
    pub state_schema: Option<u32>,
    /// The state kinds the body holds (target KV, recurrent, convolution,
    /// sliding-window ring), in the worker's names, sorted.
    pub state_kinds: Option<Vec<String>>,
}

impl SnapshotCompatibility {
    /// The compatibility `identity` names, less its epoch. The quant,
    /// attention, state schema and kinds are the producer's to add: an
    /// identity does not carry them.
    #[must_use]
    pub fn from_identity(identity: &CacheIdentity) -> Self {
        Self {
            model: identity.model.clone(),
            quant: None,
            tokenizer: identity.tokenizer.clone(),
            template: identity.template.clone(),
            execution_mode: identity.execution_mode.clone(),
            cache_mode: identity.cache_mode.clone(),
            runtime: identity.runtime.clone(),
            attention: None,
            state_schema: None,
            state_kinds: None,
        }
    }

    /// Whether every field is named.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.model.is_some()
            && self.quant.is_some()
            && self.tokenizer.is_some()
            && self.template.is_some()
            && self.execution_mode.is_some()
            && self.cache_mode.is_some()
            && self.runtime.is_some()
            && self.attention.is_some()
            && self.state_schema.is_some()
            && self.state_kinds.is_some()
    }

    /// Whether a worker answering with `identity` computes what this
    /// compatibility names: every field named here, and the identity's
    /// fields equal. The epoch is never compared.
    #[must_use]
    pub fn matches(&self, identity: &CacheIdentity) -> bool {
        let same =
            |kept: &Option<CacheDigest>, now: &Option<CacheDigest>| kept.is_some() && kept == now;
        self.complete()
            && same(&self.model, &identity.model)
            && same(&self.tokenizer, &identity.tokenizer)
            && same(&self.template, &identity.template)
            && same(&self.execution_mode, &identity.execution_mode)
            && same(&self.cache_mode, &identity.cache_mode)
            && same(&self.runtime, &identity.runtime)
    }
}

/// The checkpoint a snapshot holds, as the manifest the seal binds names
/// it: the vault and read, the conversation's branch and frontier, the
/// token digest and its parent, the non-token conditioning, and what the
/// state was computed with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifest {
    pub vault: VaultRef,
    /// The read the canonical path was admitted under.
    pub read_scope: ScopeDigest,
    pub conversation: EntityId,
    /// The branch's tip: the HEAD the canonical path ends at.
    pub head: Option<EntityId>,
    /// The fold epoch of the newest summary standing in the log.
    pub fold_epoch: u64,
    /// The token frontier the worker verified.
    pub frontier_tokens: u64,
    /// The worker's digest of the canonical path's token ids.
    pub token_digest: TokenDigest,
    /// The checkpoint it was staged on.
    pub parent: Option<TokenDigest>,
    /// Template arguments, tool definitions and any non-token input.
    pub conditioning: ConditioningDigest,
    pub compatibility: SnapshotCompatibility,
}

/// Everything a snapshot was read or derived from, each named by its id,
/// so an erase of any of them reaches it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotDependencies {
    /// The records whose bytes the canonical path holds.
    pub sources: Vec<EntityId>,
    /// The worlds those records sit in, explicit: a world under a pad kept
    /// local, an erased or withdrawn world, reaches the snapshot by its id.
    pub worlds: Vec<EntityId>,
    /// The actors who wrote them.
    pub authors: Vec<EntityId>,
    /// Anyone else whose erase the content must follow.
    pub erase_subjects: Vec<EntityId>,
    /// The quoted replies, tool results and fold summaries it holds, and
    /// what they in turn were derived from.
    pub derived: Vec<EntityId>,
    /// Whether the lists are known whole. A set that is not is never
    /// persisted, and a row that holds one goes on any erase.
    pub precise: bool,
}

impl SnapshotDependencies {
    fn names(&self, id: &EntityId) -> bool {
        [
            &self.sources,
            &self.worlds,
            &self.authors,
            &self.erase_subjects,
            &self.derived,
        ]
        .iter()
        .any(|list| list.contains(id))
    }
}

/// Which work a snapshot serves: background state yields first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SnapshotClass {
    /// Dreamer consolidation and other background work.
    Background,
    /// An owner's or agent's live conversation.
    Interactive,
}

/// What the snapshot was published under, compared before it is used.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotPins {
    /// The vault's snapshot admission generation at publish: a lock since
    /// starts another.
    pub admission_generation: u64,
    /// The vault's erase generation at publish.
    pub erase_generation: u64,
    /// The authority generation the read was admitted at, when known.
    pub authority_generation: Option<u64>,
}

/// One catalog row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRecord {
    /// [`SNAPSHOT_RECORD_SCHEMA`].
    pub schema: u32,
    pub id: SnapshotId,
    /// The sealed body's own id, which its header carries.
    pub seal_id: [u8; 16],
    pub manifest: SnapshotManifest,
    pub dependencies: SnapshotDependencies,
    /// The worker's serialized state's length.
    pub plaintext_bytes: u64,
    /// The sealed body file's length.
    pub sealed_bytes: u64,
    /// The worker's SHA-256 of its serialized state.
    pub snapshot_sha256: [u8; 32],
    pub class: SnapshotClass,
    /// When it was published and last restored, in unix milliseconds.
    pub created_ms: u64,
    pub last_used_ms: u64,
    /// How many restores it served.
    pub reuse_count: u64,
    /// What recomputing it from source measured, in milliseconds, when a
    /// native measurement exists.
    pub recompute_ms: Option<u64>,
    pub pins: SnapshotPins,
}

impl SnapshotRecord {
    /// Whether this row may serve a restore at all: the current format, a
    /// precise dependency set, and every required manifest field named.
    #[must_use]
    pub fn reusable(&self) -> bool {
        self.schema == SNAPSHOT_RECORD_SCHEMA
            && self.dependencies.precise
            && self.manifest.compatibility.complete()
    }

    /// Whether an erase of `id` reaches this row.
    #[must_use]
    pub fn depends_on(&self, id: &EntityId) -> bool {
        self.manifest.conversation == *id
            || self.manifest.head == Some(*id)
            || self.dependencies.names(id)
    }
}

/// One catalog row as read: its id, and its record, `None` when the row
/// does not decode.
pub(super) type CatalogRow = (SnapshotId, Option<SnapshotRecord>);

/// Every row of the catalog, in id order. A key of the wrong width, which
/// no writer here makes, is skipped.
pub(super) fn rows(store: &Store, txn: &RoTxn<'_>) -> Result<Vec<CatalogRow>> {
    let mut out = Vec::new();
    for row in CATALOG.iter_raw_from(store, txn, &[])? {
        let (key, bytes) = row?;
        let Some(id) = SnapshotId::decode_key(&key) else {
            continue;
        };
        out.push((id, CATALOG.decode_value(&bytes).ok()));
    }
    Ok(out)
}

/// Takes the row `id` out of the catalog in `wtxn`: from the commit on, no
/// open finds it. The body file and the custody entry go after the commit.
/// `true` when a row was there.
pub(super) fn retire_in_txn(store: &Store, wtxn: &mut RwTxn<'_>, id: &SnapshotId) -> Result<bool> {
    CATALOG.delete(store, wtxn, id)
}

/// The rows an erase of `id` takes: every row whose dependency set names
/// it, whose set is not precise or that does not decode, and every other
/// row of each conversation those reach.
fn erased_rows(rows: &[CatalogRow], id: &EntityId) -> Vec<SnapshotId> {
    let mut gone = BTreeSet::new();
    let mut conversations = BTreeSet::new();
    for (key, record) in rows {
        match record {
            Some(record) if record.dependencies.precise && !record.depends_on(id) => {}
            Some(record) => {
                gone.insert(*key);
                conversations.insert(record.manifest.conversation);
            }
            None => {
                gone.insert(*key);
            }
        }
    }
    for (key, record) in rows {
        if record
            .as_ref()
            .is_some_and(|record| conversations.contains(&record.manifest.conversation))
        {
            gone.insert(*key);
        }
    }
    gone.into_iter().collect()
}

/// The erase of `id` takes every snapshot it reaches (FIX 10466), in the
/// erase's own transaction at both delete doors: every row whose
/// dependency set names it, whose set is not precise, or that does not
/// decode, and the rest of each conversation those reach. Bodies, custody
/// entries and live copies go after the commit.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_in_txn(store: &Store, wtxn: &mut RwTxn<'_>, id: &EntityId) -> Result<()> {
    let rows = rows(store, &*wtxn)?;
    for key in erased_rows(&rows, id) {
        retire_in_txn(store, wtxn, &key)?;
    }
    Ok(())
}

/// An erase of `actor` takes every snapshot it authored or is a subject of,
/// as [`erase_in_txn`] does for any id: a row records an actor as an id in
/// its dependency set, never apart from it.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    erase_in_txn(&vault.store, wtxn, actor)
}
