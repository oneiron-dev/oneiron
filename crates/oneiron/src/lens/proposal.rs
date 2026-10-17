//! Pack lens proposals (OF-250): one frozen compiled tree bound to an
//! installed pack's skill, with its authored intent, and the vault's list of
//! them.
//!
//! A proposal never mounts. Only the owner's selection of its exact revision
//! for its slot (`activation`) does, and the slot is rechecked against the
//! live install on every read. The first compiled payload is the validated
//! [`GeneratedLens`] tree: no lens DSL, renderer inventory or wasm component.

use std::ops::Bound;

use serde::{Deserialize, Serialize};

use super::intent::INTENTS;
use super::{GeneratedLens, LensIntentRecord, LensLoadAction, LensVersionStamp, lens_load_action};
use crate::claim::{ClaimReadStatus, ScopedRead, ScopedReadActorKey};
use crate::federation::ScopeAxis;
use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::receipt::{LensApproval, LensProposalReceipt};
use crate::side_table::{self, Named, SideTable};
use crate::skill_hub::pack_catalog::{PackInstallReceipt, PackInstallStatus};
use crate::{EntityId, Error, Result, Vault};

/// Proposals by lens id. Key: id16.
pub(super) const PROPOSALS: SideTable<EntityId, LensProposalRecord, Named> =
    SideTable::new(&side_table::LENS_PROPOSAL);
/// The owner's selected revision per pack/skill slot. Key: [`slot_key`].
pub(super) const SLOTS: SideTable<String, LensSlotRecord, Named> =
    SideTable::new(&side_table::LENS_SLOT);
/// The largest frozen tree a proposal stores, as canonical JSON.
pub const LENS_PROPOSAL_MAX_BYTES: usize = 1024 * 1024;
/// The most rows one `vault.lenses.list` page returns.
pub const LENS_LIST_MAX_PAGE: usize = 200;

/// One pack lens slot: an installed pack and one of its skills.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LensSlot {
    pub pack_name: String,
    /// The SKILL's 32-hex entity id.
    pub skill_id: String,
}

impl LensSlot {
    pub(super) fn skill(&self) -> MemoryResult<EntityId> {
        EntityId::from_hex(&self.skill_id)
            .map_err(|_| MemoryError::bad_request("slot.skill_id is a 32-hex SKILL id"))
    }
}

/// `vault.lenses.propose`'s input: a frozen compiled tree for one slot, the
/// pack content it was compiled against, and its authored intent. The host
/// derives the proposer, the lens id and the time; nothing here approves.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LensProposeRequest {
    pub slot: LensSlot,
    /// The installed pack's content hash the tree was compiled against.
    pub pack_content_hash: String,
    /// The frozen generated-lens envelope (`kit_version`,
    /// `apps_contract_version`, `root`), validated as the renderer reads it.
    pub compiled: serde_json::Value,
    /// The authored prompt the tree was compiled from; regeneration reruns it.
    pub intent_prompt: String,
}

/// What a narrowed reader's page of `vault.lenses.list` carries (OF-250; a
/// call, canon silent). A proposal record carries no scope of its own, so a
/// reader whose credential is narrowed to some worlds or facets sees a
/// proposal only while its own read admits both records the proposal is bound
/// to: the slot's SKILL and the source of the pack installed under the slot's
/// pack name. A proposal whose pack has no installed, live source shows to no
/// narrowed reader. The frozen tree is never carried to such a reader, even
/// on `with_compiled`: an admitted SKILL does not make every literal of an
/// arbitrary compiled tree its reader's to see.
pub const LENS_LIST_NARROWED_CARRIES_COMPILED: bool = false;

/// `vault.lenses.list`'s input: one page of proposals in lens-id order.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LensListRequest {
    /// Only this pack's proposals.
    #[serde(default)]
    pub pack_name: Option<String>,
    /// The `next_after` of the page before.
    #[serde(default)]
    pub after: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
    /// Carry each proposal's frozen tree. A reader narrowed to some worlds
    /// or facets gets none ([`LENS_LIST_NARROWED_CARRIES_COMPILED`]).
    #[serde(default)]
    pub with_compiled: bool,
}

/// Where a proposal stands in its slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LensProposalState {
    /// Waiting for the owner, or cleared from its slot.
    Proposed,
    /// The owner's current selection for its slot.
    Active,
}

/// One proposal: neutral ids, its binding, its state and whether it mounts
/// now. Never a screen.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LensListRow {
    pub lens_ref: String,
    pub pack_name: String,
    pub skill_id: String,
    pub pack_content_hash: String,
    pub compiled_hash: String,
    pub kit_version: u16,
    pub apps_contract_version: u16,
    pub proposed_by: String,
    pub proposed_at: u64,
    pub state: LensProposalState,
    /// Active, and its pack is still installed Active at the content it was
    /// proposed against, with the skill still loading.
    pub mounted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiled: Option<GeneratedLens>,
}

/// One page of `vault.lenses.list`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LensListPage {
    pub rows: Vec<LensListRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_after: Option<String>,
}

/// The stored proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LensProposalRecord {
    pub(super) pack_name: String,
    pub(super) skill_id: String,
    pub(super) pack_content_hash: String,
    /// The validated tree's canonical JSON, the bytes `compiled_hash` names.
    pub(super) compiled_json: String,
    pub(super) compiled_hash: String,
    pub(super) proposed_by: String,
    pub(super) proposed_at: u64,
}

impl LensProposalRecord {
    pub(super) fn compiled(&self) -> Result<GeneratedLens> {
        if lens_hash(&self.compiled_json) != self.compiled_hash {
            return Err(Error::CorruptedIndex("lens proposal record"));
        }
        serde_json::from_str(&self.compiled_json)
            .map_err(|_| Error::CorruptedIndex("lens proposal record"))
    }

    pub(super) fn receipt(&self, lens_ref: &EntityId) -> LensProposalReceipt {
        LensProposalReceipt {
            lens_ref: lens_ref.to_hex(),
            pack_name: self.pack_name.clone(),
            skill_id: self.skill_id.clone(),
            pack_content_hash: self.pack_content_hash.clone(),
            compiled_hash: self.compiled_hash.clone(),
            approval: LensApproval::Proposed,
            proposed_by: self.proposed_by.clone(),
            proposed_at: self.proposed_at,
        }
    }
}

/// The owner's stored selection for one slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LensSlotRecord {
    pub(super) lens_ref: String,
    pub(super) compiled_hash: String,
    pub(super) pack_content_hash: String,
    pub(super) decided_by: String,
    pub(super) decision_ref: String,
    pub(super) authenticated_under: String,
    pub(super) decided_at: u64,
}

pub(super) fn slot_key(pack_name: &str, skill_id: &EntityId) -> String {
    format!("{pack_name}\0{}", skill_id.to_hex())
}

pub(super) fn lens_hash(compiled_json: &str) -> String {
    blake3::hash(compiled_json.as_bytes()).to_hex().to_string()
}

/// Whether `install` is the Active installation at `content_hash`. A
/// Candidate pack carries no lens: nothing here promotes one.
pub(super) fn active_at(install: &PackInstallReceipt, content_hash: &str) -> bool {
    install.status == PackInstallStatus::Active && install.content_hash == content_hash
}

pub(super) fn invalid_state(message: &str, suggestion: &str) -> MemoryError {
    MemoryError::new(MEMORY_CODE_INVALID_STATE, message, &[suggestion])
}

impl Memory<'_> {
    /// `vault.lenses.propose`: store one frozen compiled tree for a slot,
    /// with its intent, as this actor's proposal. It lands `proposed` for
    /// every caller and mounts only once the owner selects it.
    ///
    /// The slot's pack must be installed Active at `pack_content_hash`, with
    /// the skill one of its skills and still loading, all in the writer that
    /// stores the proposal, its intent and its receipt together.
    pub fn lenses_propose(&self, input: LensProposeRequest) -> MemoryResult<LensProposalReceipt> {
        let skill_id = input.slot.skill()?;
        let compiled: GeneratedLens = serde_json::from_value(input.compiled).map_err(|error| {
            MemoryError::bad_request(format!("compiled is not a frozen lens tree: {error}"))
        })?;
        if !matches!(
            lens_load_action(compiled.version_stamp(), LensVersionStamp::current()),
            LensLoadAction::MountCurrent
        ) {
            return Err(MemoryError::bad_request(
                "compiled must target this vault's lens atom kit and apps contract",
            ));
        }
        let compiled_json = serde_json::to_string(&compiled)
            .map_err(|_| Error::InvalidConfig("lens tree did not encode".into()))?;
        if compiled_json.len() > LENS_PROPOSAL_MAX_BYTES {
            return Err(MemoryError::bad_request(format!(
                "compiled is at most {LENS_PROPOSAL_MAX_BYTES} bytes"
            )));
        }
        let intent = LensIntentRecord::new(input.intent_prompt)
            .map_err(|error| MemoryError::bad_request(error.to_string()))?;
        let lens_ref = EntityId::now();
        let vault = self.vault();
        let record = LensProposalRecord {
            pack_name: input.slot.pack_name,
            skill_id: skill_id.to_hex(),
            pack_content_hash: input.pack_content_hash,
            compiled_hash: lens_hash(&compiled_json),
            compiled_json,
            proposed_by: self.actor().to_hex(),
            proposed_at: crate::unix_seconds_now(),
        };
        self.with_verified_actor_write_txn(|txn| {
            let live = vault.live_pack_skill_in_txn(txn, &record.pack_name, &skill_id)?;
            if !live
                .as_ref()
                .is_some_and(|install| active_at(install, &record.pack_content_hash))
            {
                return Err(invalid_state(
                    "the slot's pack is not installed Active at pack_content_hash with that skill loading",
                    "Read the installed pack's content hash and skills, then propose against them.",
                ));
            }
            PROPOSALS.put(&vault.store, txn, &lens_ref, &record)?;
            INTENTS.put(&vault.store, txn, &lens_ref, &intent)?;
            Ok(record.receipt(&lens_ref))
        })
    }

    /// `vault.lenses.list`: one page of the vault's lens proposals, each with
    /// its slot state derived from the owner's current selection and the
    /// live install, never from a second registry.
    ///
    /// A reader narrowed to some worlds or facets (OF-250) pages only the
    /// proposals its own read admits, judged before the page counts them and
    /// in the page's own snapshot, and gets no frozen trees
    /// ([`LENS_LIST_NARROWED_CARRIES_COMPILED`]).
    pub fn lenses_list(&self, input: LensListRequest) -> MemoryResult<LensListPage> {
        let limit = input
            .limit
            .map_or(LENS_LIST_MAX_PAGE, |limit| limit as usize)
            .clamp(1, LENS_LIST_MAX_PAGE);
        let after = input
            .after
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()
            .map_err(|_| MemoryError::bad_request("after is a lens_ref from a page before"))?;
        let read = self.read_lane(ClaimReadStatus::Recorded)?;
        let vault = self.vault();
        if !reads_narrowed(read.actor_key()) {
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            return Ok(vault.lens_proposals_page_in(
                &txn,
                input.pack_name.as_deref(),
                after,
                limit,
                input.with_compiled,
                |_, _, _| Ok(true),
            )?);
        }
        let with_compiled = input.with_compiled && LENS_LIST_NARROWED_CARRIES_COMPILED;
        Ok(read
            .read_projected(&[], None, |txn, _| {
                vault.lens_proposals_page_in(
                    txn,
                    input.pack_name.as_deref(),
                    after,
                    limit,
                    with_compiled,
                    |txn, record, skill_id| proposal_admitted_in(vault, &read, txn, record, skill_id),
                )
            })?
            .value)
    }
}

/// Whether `key` reads under a credential narrowed to some worlds or facets,
/// or asked for some worlds only: a reader `vault.lenses.list` serves a
/// filtered projection.
fn reads_narrowed(key: &ScopedReadActorKey) -> bool {
    key.has_world_ceiling()
        || key.asked_world_ceiling().is_some()
        || key
            .authority_scope()
            .is_some_and(|scope| !matches!(scope.facets, ScopeAxis::All))
}

/// Whether `read` admits, in `txn`, both records a proposal is bound to: the
/// slot's SKILL and the live source of the pack installed under its pack
/// name. A pack with no installed, live source admits nothing.
fn proposal_admitted_in(
    vault: &Vault,
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    record: &LensProposalRecord,
    skill_id: &EntityId,
) -> Result<bool> {
    let Some(install) = vault.mounted_pack_in_txn(txn, &record.pack_name)? else {
        return Ok(false);
    };
    let source = EntityId::from_hex(&install.source_id)
        .map_err(|_| Error::CorruptedIndex("pack install catalog"))?;
    Ok(read.is_entity_readable_in(txn, skill_id)? && read.is_entity_readable_in(txn, &source)?)
}

impl Vault {
    /// One page of proposals in `txn`. `admits` judges each proposal the
    /// pack filter keeps before the page counts it, so a withheld proposal
    /// neither fills a page nor sets its cursor.
    fn lens_proposals_page_in(
        &self,
        txn: &heed::RoTxn<'_>,
        pack_name: Option<&str>,
        after: Option<EntityId>,
        limit: usize,
        with_compiled: bool,
        mut admits: impl FnMut(&heed::RoTxn<'_>, &LensProposalRecord, &EntityId) -> Result<bool>,
    ) -> Result<LensListPage> {
        let start = after.as_ref().map_or(Bound::Unbounded, Bound::Excluded);
        let mut rows = Vec::new();
        let mut next_after = None;
        for entry in PROPOSALS.iter_range(&self.store, txn, start, Bound::Unbounded)? {
            let (lens_ref, record) =
                entry.map_err(|_| Error::CorruptedIndex("lens proposal record"))?;
            if pack_name.is_some_and(|name| name != record.pack_name) {
                continue;
            }
            let skill_id = EntityId::from_hex(&record.skill_id)
                .map_err(|_| Error::CorruptedIndex("lens proposal record"))?;
            if !admits(txn, &record, &skill_id)? {
                continue;
            }
            if rows.len() == limit {
                next_after = rows.last().map(|row: &LensListRow| row.lens_ref.clone());
                break;
            }
            let selected = SLOTS
                .get(&self.store, txn, &slot_key(&record.pack_name, &skill_id))?
                .is_some_and(|slot| {
                    slot.lens_ref == lens_ref.to_hex() && slot.compiled_hash == record.compiled_hash
                });
            let mounted = selected
                && self
                    .live_pack_skill_in_txn(txn, &record.pack_name, &skill_id)?
                    .is_some_and(|install| active_at(&install, &record.pack_content_hash));
            let compiled = record.compiled()?;
            let stamp = compiled.version_stamp();
            rows.push(LensListRow {
                lens_ref: lens_ref.to_hex(),
                pack_name: record.pack_name,
                skill_id: record.skill_id,
                pack_content_hash: record.pack_content_hash,
                compiled_hash: record.compiled_hash,
                kit_version: stamp.kit_version(),
                apps_contract_version: stamp.apps_contract_version(),
                proposed_by: record.proposed_by,
                proposed_at: record.proposed_at,
                state: if selected {
                    LensProposalState::Active
                } else {
                    LensProposalState::Proposed
                },
                mounted,
                compiled: with_compiled.then_some(compiled),
            });
        }
        Ok(LensListPage { rows, next_after })
    }
}
