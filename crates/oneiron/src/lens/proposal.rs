//! Pack lens proposals (OF-250): one frozen compiled tree bound to an
//! installed pack's skill, with its authored intent, and the vault's list of
//! them.
//!
//! A proposal never mounts. Only the owner's selection of its exact revision
//! for its slot (`activation`) does, and the slot is rechecked against the
//! live install on every read. The first compiled payload is the validated
//! [`GeneratedLens`] tree: no lens DSL, renderer inventory or wasm component.
//!
//! The lens itself is vault data (FIX 9896): a CODE kind=lens row carrying
//! the tree, born from a `lens/intent` NOTE holding its prompt
//! ([`super::artifact`]). The proposal, intent and slot rows index them.
//! Where the lens is read is its declared scope (FIX 2136, [`super::scope`]).

use std::ops::Bound;

use serde::{Deserialize, Serialize};

use super::artifact::{LensArtifacts, lens_tree_in};
use super::intent::{INTENTS, LensIntentIndex};
use super::scope::{
    LensAdmission, LensScope, declared_position, placed_in, proposal_admission_in,
    tree_admitted_in,
};
use super::{GeneratedLens, LensIntentRecord, LensLoadAction, LensVersionStamp, lens_load_action};
use crate::claim::{ClaimReadStatus, ScopedReadActorKey};
use crate::federation::ScopeAxis;
use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::provenance::made_by::MadeByTrigger;
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
    /// What caused this proposal: a live task, ask, run or skill. The lens
    /// row's birth names it; omitted, the birth names no trigger.
    #[serde(default)]
    pub trigger: Option<MadeByTrigger>,
    /// Where the lens's frozen tree is read (FIX 2136): the world and facet
    /// it belongs to. Omitted, where this credential is bound to author.
    #[serde(default)]
    pub scope: Option<LensScope>,
}

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
    /// or facets gets the trees of the proposals whose scope its read
    /// admits, each whole and only while it reads every row the tree names
    /// (FIX 2136).
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

/// The stored proposal: an index of the lens's CODE kind=lens row, keyed by
/// that row's id (the lens ref), and of its prompt NOTE.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LensProposalRecord {
    pub(super) pack_name: String,
    pub(super) skill_id: String,
    pub(super) pack_content_hash: String,
    /// The hash of the tree the lens row carries.
    pub(super) compiled_hash: String,
    /// The `lens/intent` NOTE the lens row was born from.
    pub(super) prompt_ref: String,
    pub(super) proposed_by: String,
    pub(super) proposed_at: u64,
    /// Where the lens is read: where its prompt NOTE is placed (FIX 2136).
    pub(super) scope: LensScope,
}

impl LensProposalRecord {
    /// The frozen tree, read from the lens row `lens_ref` in `txn`.
    pub(super) fn compiled_in(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        lens_ref: &EntityId,
    ) -> Result<GeneratedLens> {
        let tree = lens_tree_in(vault, txn, lens_ref, &self.compiled_hash)?;
        serde_json::from_str(&tree).map_err(|_| Error::CorruptedIndex("lens proposal record"))
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
    /// stores the lens row, its prompt NOTE, the lens row's birth, the
    /// proposal and intent indexes and its receipt together (FIX 9896).
    /// The same writer places the prompt NOTE at the lens's scope: `scope`
    /// over where this credential is bound to author (FIX 2136).
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
        // The tree is stored whole, whatever its size: its author holds it
        // and sent it whole (FIX 11257).
        let compiled_json = serde_json::to_string(&compiled)
            .map_err(|_| Error::InvalidConfig("lens tree did not encode".into()))?;
        let intent = LensIntentRecord::new(input.intent_prompt)
            .map_err(|error| MemoryError::bad_request(error.to_string()))?;
        // An axis the credential's binding leaves open is declared only by an
        // author whose read is not narrowed; only a declaration asks.
        let declared = input.scope;
        let vault_wide = match &declared {
            Some(_) => !reads_narrowed(self.read_lane(ClaimReadStatus::Recorded)?.actor_key()),
            None => false,
        };
        let position = declared_position(declared.as_ref(), self.birth_position(), vault_wide)?;
        let lens_ref = EntityId::now();
        let prompt_ref = EntityId::now();
        let vault = self.vault();
        let mut record = LensProposalRecord {
            pack_name: input.slot.pack_name,
            skill_id: skill_id.to_hex(),
            pack_content_hash: input.pack_content_hash,
            compiled_hash: lens_hash(&compiled_json),
            prompt_ref: prompt_ref.to_hex(),
            proposed_by: self.actor().to_hex(),
            proposed_at: crate::unix_seconds_now(),
            scope: LensScope::default(),
        };
        let writer = crate::WriteActor::new(self.actor(), self.actor_class());
        let trigger = input.trigger;
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
            let placement = placed_in(vault, txn, position, declared.as_ref())?;
            record.scope = LensScope::of(placement);
            LensArtifacts {
                lens_ref,
                prompt_ref,
                slot_ref: format!(
                    "lens:{}@{}/{}",
                    record.pack_name, record.pack_content_hash, record.skill_id
                ),
                prompt: intent.prompt(),
                compiled_json: &compiled_json,
                trigger,
                placement,
                at: record.proposed_at,
            }
            .stage(vault, writer)?
            .apply(txn)?;
            PROPOSALS.put(&vault.store, txn, &lens_ref, &record)?;
            INTENTS.put(&vault.store, txn, &lens_ref, &LensIntentIndex::of(&prompt_ref))?;
            Ok(record.receipt(&lens_ref))
        })
    }

    /// `vault.lenses.list`: one page of the vault's lens proposals, each with
    /// its slot state derived from the owner's current selection and the
    /// live install, never from a second registry.
    ///
    /// A reader narrowed to some worlds or facets (OF-250) pages only the
    /// proposals its own read admits, judged before the page counts them and
    /// in the page's own snapshot: the whole proposal, its tree and its
    /// history once its pack is gone, where its read admits the lens's scope,
    /// else its row alone while it reads the slot's SKILL and live pack
    /// source (FIX 2136).
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
                |_, _, _| Ok(LensAdmission::Whole),
                |_, _| Ok(true),
            )?);
        }
        Ok(read
            .read_projected(&[], None, |txn, _| {
                vault.lens_proposals_page_in(
                    txn,
                    input.pack_name.as_deref(),
                    after,
                    limit,
                    input.with_compiled,
                    |txn, record, skill_id| {
                        proposal_admission_in(vault, &read, txn, record, skill_id)
                    },
                    |txn, tree| tree_admitted_in(vault, &read, txn, tree),
                )
            })?
            .value)
    }
}

/// Whether `key` reads under a credential narrowed to some worlds or facets,
/// or asked for some worlds only: a reader `vault.lenses.list` serves a
/// filtered projection.
pub(super) fn reads_narrowed(key: &ScopedReadActorKey) -> bool {
    key.has_world_ceiling()
        || key.asked_world_ceiling().is_some()
        || key
            .authority_scope()
            .is_some_and(|scope| !matches!(scope.facets, ScopeAxis::All))
}

impl Vault {
    /// One page of proposals in `txn`. `admits` judges each proposal the
    /// pack filter keeps before the page counts it, so a withheld proposal
    /// neither fills a page nor sets its cursor; `with_compiled` carries the
    /// tree of each proposal it admits whole while `tree_admits` admits that
    /// tree.
    fn lens_proposals_page_in(
        &self,
        txn: &heed::RoTxn<'_>,
        pack_name: Option<&str>,
        after: Option<EntityId>,
        limit: usize,
        with_compiled: bool,
        mut admits: impl FnMut(
            &heed::RoTxn<'_>,
            &LensProposalRecord,
            &EntityId,
        ) -> Result<LensAdmission>,
        mut tree_admits: impl FnMut(&heed::RoTxn<'_>, &GeneratedLens) -> Result<bool>,
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
            let admission = admits(txn, &record, &skill_id)?;
            if admission == LensAdmission::Withheld {
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
            let compiled = record.compiled_in(self, txn, &lens_ref)?;
            let stamp = compiled.version_stamp();
            let carried = with_compiled
                && admission == LensAdmission::Whole
                && tree_admits(txn, &compiled)?;
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
                compiled: carried.then_some(compiled),
            });
        }
        Ok(LensListPage { rows, next_after })
    }
}
