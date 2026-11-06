//! The drafter's training traffic (FIX 15128, FIX 15129; DRAFTER-DATA = A):
//! one example per answered chat reply, apart from the chat breakpoint a
//! self agent's reply keeps as its reuse seed (FIX 4465 D), whose rules this
//! leaves as they are.
//!
//! **What it holds.** The request exactly as the reply's answering rung sent
//! it (its messages and tools as admitted, the context board when it rode,
//! the rung's prompt first) and the span the reply generated: its reasoning,
//! tool calls and text, in the provider-neutral parts the request uses, so
//! the trainer renders the span with the target's chat template and its end
//! token. Every agent's reply is one, a turn whose board rode as much as one
//! whose board did not, a queued Continue or Retry as much as a live turn.
//!
//! **Who writes it.** The host hands a reply over once it is saved whole,
//! off the answer's path ([`Vault::keep_drafter_example`]): never one that
//! keeps no durable record, runs off the record, fell back from its captured
//! call or failed, and only one its host's drafter target answered. The
//! engine keeps none while the owner's policy is off, none in a room with an
//! open off-record stretch, and none whose records are not all live, known by
//! world and author, outside a Tier-A withhold and outside the worlds the
//! policy excludes.
//!
//! **Custody.** The record names ids, the wire model, its source family and
//! its dependency set in the clear. The request and the span are one body,
//! sealed under an erasable key of the example's own (purpose
//! `DrafterArtifact`, parent the example), minted in the write that keeps it.
//!
//! **Erase.** The dependency set names every record the call was read from
//! (the turn's sources: the agent's definition, its craft, its log, the
//! context board's rows when the board rode, the requester's MESSAGE), each
//! MESSAGE's TURN, each summary's folded turns and messages, the reply
//! MESSAGE, its TURN and its conversation, the records each quotes, the world
//! and author of each, the agent and the requester. One index row per named
//! id lets the erase of any of them drop the example and stage its key's
//! retirement in the erase's own transaction
//! ([`erase_drafter_examples_for_source_in_txn`]). A version trained on a
//! corpus that held the example names the whole set in its own, so the same
//! erase reaches the version.
//!
//! **Bound.** The newest [`DRAFTER_EXAMPLES_KEPT`] examples are kept; the
//! corpus sweep drops older ones and retires their keys.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{DrafterDependencies, DrafterSealing, invalid, policy_in_txn};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::secret_custody::revoke_side_row_custody_with_context_in_txn;
use crate::secret_record::CustodyWrite;
use crate::side_table::{self, Named, Raw, SideKey, SideTable};
use crate::store::Store;
use crate::store::drafter_custody::{
    drafter_artifact_key_in_txn, mint_drafter_artifact_key_in_txn,
    retire_drafter_artifact_key_in_txn, retire_drafter_artifact_keys_in_txn,
};
use crate::{EdgeKind, FinishReason, LlmMessage, LlmRequest, Vault};

/// How many examples the vault keeps, the newest; the corpus sweep drops
/// the rest. Not an owner ruling: the engine's own bound on one night's
/// corpus and on the sealed traffic the vault holds.
pub const DRAFTER_EXAMPLES_KEPT: usize = 2048;

/// The name an example's sealed body binds.
const BODY_NAME: &str = "drafter-example.json";

/// Examples. Key: id16 (the example, time-ordered).
const EXAMPLES: SideTable<EntityId, DrafterExampleRecord, Named> =
    SideTable::new(&side_table::DRAFTER_EXAMPLE);
/// Sealed example bodies. Key: id16 (the example).
const BODIES: SideTable<EntityId, Vec<u8>, Raw> = SideTable::new(&side_table::DRAFTER_EXAMPLE_BODY);
/// Which examples name a record. Key: id16 (the record) + id16 (the example).
const NAMED_BY: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::DRAFTER_EXAMPLE_SOURCE);

/// The owner's policy is off: no new drafter work.
const SKIP_POLICY_OFF: &str = "drafter.example.policy_off";
/// The reply's room holds an open off-record stretch.
const SKIP_OFF_RECORD: &str = "drafter.example.off_record";
/// The reply MESSAGE belongs to no one conversation.
const SKIP_CONVERSATION_UNKNOWN: &str = "drafter.example.conversation_unknown";
/// The reply MESSAGE lies in no one TURN.
const SKIP_TURN_UNKNOWN: &str = "drafter.example.turn_unknown";
/// The example reaches a world the owner's policy excludes.
const SKIP_EXCLUDED_WORLD: &str = "drafter.example.excluded_world";

/// One answered chat reply, saved whole, as its host hands it to the
/// drafter's traffic (FIX 15128, FIX 15129).
#[derive(Debug, Clone)]
pub struct DrafterTrafficReply {
    /// The reply MESSAGE.
    pub reply: EntityId,
    /// The stream generation the reply was saved under.
    pub generation: EntityId,
    /// The agent definition that answered.
    pub agent: EntityId,
    /// The actor whose call it was.
    pub requester: EntityId,
    /// Every row the call was read from, known whole (FIX 6935): the
    /// agent's definition, its craft, its log, the context board's rows when
    /// the board rode, the requester's witnessed MESSAGE.
    pub sources: Vec<EntityId>,
    /// The model the answering rung's wire named.
    pub wire_model: String,
    /// The weights identity the answering worker reported for the call, the
    /// identity a [`super::DrafterTarget`]'s `model` names.
    pub target_model: String,
    /// The request exactly as the answering rung sent it.
    pub request: LlmRequest,
    /// The span the reply generated: its reasoning, tool calls and text, in
    /// the order the model generated them.
    pub generated: LlmMessage,
    pub finish_reason: FinishReason,
}

/// What [`Vault::keep_drafter_example`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrafterExampleKept {
    /// The example is kept under this id.
    Kept(EntityId),
    /// No example is kept, for this reason code (`drafter.example.*`, or the
    /// corpus's `drafter.corpus.*` for a record it was read from).
    Skipped(&'static str),
}

/// One example's record: what it names, in the clear, and the pin of its
/// sealed body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DrafterExampleRecord {
    pub(super) conversation: EntityId,
    pub(super) reply: EntityId,
    pub(super) generation: EntityId,
    pub(super) turn: EntityId,
    pub(super) agent: EntityId,
    pub(super) requester: EntityId,
    pub(super) wire_model: String,
    /// The weights identity the answering worker reported: the export keeps
    /// only examples of its target's.
    pub(super) target_model: String,
    /// Its source family: the hex BLAKE3 of the request's canonical bytes.
    pub(super) family: String,
    /// Every record it was read from, walked in the write that kept it.
    pub(super) dependencies: DrafterDependencies,
    pub(super) body: DrafterExampleSeal,
    /// The vault's recorded clock when it was kept.
    pub(super) recorded_at: u64,
}

/// The pin of an example's sealed body: its random id, its key's random
/// ref, its plaintext length and BLAKE3. Never the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DrafterExampleSeal {
    pub(super) id: [u8; 16],
    pub(super) key_ref: [u8; 32],
    pub(super) bytes: u64,
    pub(super) blake3: [u8; 32],
}

/// Where the side-row wall places an example's body (FIX 16231): the
/// origin of every custody record it mints from it.
const EXAMPLE_BODY_PLACE: &str = "side:DRAFTER_EXAMPLE_BODY";

/// The origin the wall names an example's custody records by.
fn example_body_origin(id: &EntityId) -> Result<EntityId> {
    crate::batch::secret_scan::side_row_origin(EXAMPLE_BODY_PLACE, id.as_bytes())
}

/// What an example's sealed body holds.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DrafterExampleBody {
    pub(super) request: LlmRequest,
    pub(super) generated: LlmMessage,
    pub(super) finish_reason: FinishReason,
}

/// Every id `dependencies` names, in any list, once each.
fn named_ids(dependencies: &DrafterDependencies) -> BTreeSet<EntityId> {
    [
        &dependencies.sources,
        &dependencies.derived,
        &dependencies.worlds,
        &dependencies.authors,
        &dependencies.erase_subjects,
    ]
    .into_iter()
    .flatten()
    .copied()
    .collect()
}

/// The one conversation MESSAGE `reply` belongs to, in `txn`; `None` for
/// none, several, or a row that does not read.
fn reply_conversation_in(store: &Store, txn: &RoTxn<'_>, reply: &EntityId) -> Option<EntityId> {
    crate::memory::sole_edge_target(store, txn, reply, EdgeKind::BelongsTo, "message")
        .ok()
        .flatten()
}

impl Vault {
    /// Keeps `reply` as one of the drafter's training examples (FIX 15128,
    /// FIX 15129), in one write: its records walked and rechecked live, its
    /// body sealed under a key minted for it, one index row per id its
    /// dependency set names. The host calls it once the reply is saved
    /// whole, off the answer's path. A reply that fails a check is skipped,
    /// with its reason.
    ///
    /// # Errors
    /// The request does not encode, an archived vault, the random source,
    /// and custody and storage faults.
    pub fn keep_drafter_example(&self, reply: DrafterTrafficReply) -> Result<DrafterExampleKept> {
        let DrafterTrafficReply {
            reply: message,
            generation,
            agent,
            requester,
            sources,
            wire_model,
            target_model,
            request,
            generated,
            finish_reason,
        } = reply;
        // The conversation is read first, in a snapshot closed before the
        // off-record check, which opens reads of its own.
        let conversation = {
            let txn = self.store.env.read_txn()?;
            reply_conversation_in(&self.store, &txn, &message)
        };
        let Some(conversation) = conversation else {
            return Ok(DrafterExampleKept::Skipped(SKIP_CONVERSATION_UNKNOWN));
        };
        if self.room_has_unrecorded_stretch(conversation) {
            return Ok(DrafterExampleKept::Skipped(SKIP_OFF_RECORD));
        }
        let family = request
            .canonical_hash_hex()
            .map_err(|_| invalid("a drafter example's request did not encode"))?;
        let mut body = DrafterExampleBody {
            request,
            generated,
            finish_reason,
        };
        let mut seal = [0u8; 16];
        crate::key_material::os_fill(&mut seal)?;
        self.with_write_txn_grouped(|txn| {
            let store = &self.store;
            let policy = policy_in_txn(store, txn)?;
            if !policy.enabled {
                return Ok(DrafterExampleKept::Skipped(SKIP_POLICY_OFF));
            }
            if reply_conversation_in(store, txn, &message) != Some(conversation) {
                return Ok(DrafterExampleKept::Skipped(SKIP_CONVERSATION_UNKNOWN));
            }
            let turns = self.turns_of_in(txn, message)?;
            let [turn] = turns.as_slice() else {
                return Ok(DrafterExampleKept::Skipped(SKIP_TURN_UNKNOWN));
            };
            let turn = *turn;
            let records = [conversation, message, turn]
                .into_iter()
                .chain(sources.iter().copied());
            let walk = match self.walk_example_in(txn, agent, requester, conversation, records)? {
                Ok(walk) => walk,
                Err(code) => return Ok(DrafterExampleKept::Skipped(code)),
            };
            if walk
                .worlds
                .iter()
                .any(|world| policy.excluded_worlds.contains(world))
            {
                return Ok(DrafterExampleKept::Skipped(SKIP_EXCLUDED_WORLD));
            }
            let id = store.clock.entity_id()?;
            // FIX 16231: the side-row wall masks a secret the call carried,
            // as an authored row's write does, before the body is sealed: no
            // drafter trains on a secret's value, only on its custody handle.
            crate::batch::secret_scan::admit_typed(
                self,
                txn,
                (EXAMPLE_BODY_PLACE, id.as_bytes()),
                &mut body,
            )?;
            let plain = Zeroizing::new(
                serde_json::to_vec(&body)
                    .map_err(|_| invalid("a drafter example did not encode"))?,
            );
            let key = mint_drafter_artifact_key_in_txn(store, txn, &id, &seal)?;
            let key_ref = key.key_ref;
            let sealed = DrafterSealing::for_example(id, seal, key)
                .seal_chunk(BODY_NAME, 0, true, &plain)?;
            let record = DrafterExampleRecord {
                conversation,
                reply: message,
                generation,
                turn,
                agent,
                requester,
                wire_model: wire_model.clone(),
                target_model: target_model.clone(),
                family: family.clone(),
                dependencies: walk.into_dependencies(),
                body: DrafterExampleSeal {
                    id: seal,
                    key_ref,
                    bytes: plain.len() as u64,
                    blake3: *blake3::hash(&plain).as_bytes(),
                },
                recorded_at: self.now_recorded_at(),
            };
            for named in named_ids(&record.dependencies) {
                NAMED_BY.put(store, txn, &(named, id), &())?;
            }
            BODIES.put(store, txn, &id, &sealed)?;
            EXAMPLES.put(store, txn, &id, &record)?;
            Ok(DrafterExampleKept::Kept(id))
        })
    }

    /// Drops every example but the newest [`DRAFTER_EXAMPLES_KEPT`], each
    /// with its index rows and its body, and stages the retirement of each
    /// one's key; a body no kept record names goes too. The corpus sweep
    /// runs it. Returns how many examples and bodies it removed.
    ///
    /// # Errors
    /// Storage and custody faults.
    pub(super) fn sweep_drafter_examples(&self) -> Result<u64> {
        let due = {
            let txn = self.store.env.read_txn()?;
            let examples = EXAMPLES.scan_keys(&self.store, &txn, &[])?;
            let bodies = BODIES.scan_keys(&self.store, &txn, &[])?;
            examples.len() > DRAFTER_EXAMPLES_KEPT || bodies.len() > examples.len()
        };
        if !due {
            return Ok(0);
        }
        let write = CustodyWrite::of(self);
        self.with_write_txn_grouped(|txn| {
            let store = &self.store;
            let ids = EXAMPLES.scan_keys(store, txn, &[])?;
            let excess = ids.len().saturating_sub(DRAFTER_EXAMPLES_KEPT);
            let (dropped, kept) = ids.split_at(excess);
            for id in dropped {
                drop_example_in_txn(&write, txn, id)?;
            }
            let kept: BTreeSet<EntityId> = kept.iter().copied().collect();
            let mut removed = excess as u64;
            for id in BODIES.scan_keys(store, txn, &[])? {
                if !kept.contains(&id) {
                    revoke_side_row_custody_with_context_in_txn(
                        &write,
                        txn,
                        &example_body_origin(&id)?,
                    )?;
                    BODIES.delete(store, txn, &id)?;
                    removed += 1;
                }
            }
            Ok(removed)
        })
    }
}

/// Every example in `txn` whose record decodes, by id, oldest first, and
/// how many records did not decode.
///
/// # Errors
/// Storage faults.
pub(super) fn example_records_in(
    store: &Store,
    txn: &RoTxn<'_>,
) -> Result<(Vec<(EntityId, DrafterExampleRecord)>, u64)> {
    let mut rows = Vec::new();
    let mut damaged = 0;
    for row in EXAMPLES.iter_raw_from(store, txn, &[])? {
        let (key, value) = row?;
        match (
            <EntityId as SideKey>::decode_key(&key),
            EXAMPLES.decode_value(&value),
        ) {
            (Some(id), Ok(record)) => rows.push((id, record)),
            _ => damaged += 1,
        }
    }
    Ok((rows, damaged))
}

/// The sealed body of example `id`, opened in `txn` and checked against the
/// pin `record` keeps; `None` when it has no body, or its key is retired or
/// retiring.
///
/// # Errors
/// A damaged body or key, and custody and storage faults.
pub(super) fn open_example_body_in(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    record: &DrafterExampleRecord,
) -> Result<Option<DrafterExampleBody>> {
    let corrupt = || Error::CorruptedIndex("drafter example");
    let Some(sealed) = BODIES.get(store, txn, id)? else {
        return Ok(None);
    };
    let Some(key) = drafter_artifact_key_in_txn(store, txn, id, &record.body.key_ref)? else {
        return Ok(None);
    };
    let plain = DrafterSealing::for_example(*id, record.body.id, key)
        .open_chunk(BODY_NAME, 0, true, &sealed)?;
    if plain.len() as u64 != record.body.bytes
        || *blake3::hash(&plain).as_bytes() != record.body.blake3
    {
        return Err(corrupt());
    }
    serde_json::from_slice(&plain)
        .map(Some)
        .map_err(|_| corrupt())
}

/// Drops example `id` in `wtxn`: its index rows, its body and its record,
/// and stages the retirement of its key. A record that does not decode
/// retires every key minted under the example; an absent one stages none.
fn drop_example_in_txn(
    write: &CustodyWrite<'_>,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let store = write.store;
    // Each secret the wall lifted from its body goes with it (FIX 16231).
    revoke_side_row_custody_with_context_in_txn(write, wtxn, &example_body_origin(id)?)?;
    if let Some(bytes) = EXAMPLES.get_bytes(store, wtxn, id)? {
        match EXAMPLES.decode_value(&bytes) {
            Ok(record) => {
                for named in named_ids(&record.dependencies) {
                    NAMED_BY.delete(store, wtxn, &(named, *id))?;
                }
                retire_drafter_artifact_key_in_txn(store, wtxn, &record.body.key_ref)?;
            }
            Err(_) => retire_drafter_artifact_keys_in_txn(store, wtxn, id)?,
        }
    }
    BODIES.delete(store, wtxn, id)?;
    EXAMPLES.delete(store, wtxn, id)?;
    Ok(())
}

/// The erase of `id` drops every training example whose dependency set
/// names it (FIX 15128), in the erase's own transaction at both delete doors
/// (`deletion::derived_rows`) and at an actor's erase, and stages the
/// retirement of each one's key, so no restored image opens its body again.
/// An id no example names changes nothing.
///
/// # Errors
/// Storage and custody faults.
pub(crate) fn erase_drafter_examples_for_source_in_txn(
    write: &CustodyWrite<'_>,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let store = write.store;
    let examples: BTreeSet<EntityId> = NAMED_BY
        .scan_keys(store, wtxn, id.as_bytes())?
        .into_iter()
        .map(|(_, example)| example)
        .collect();
    for example in &examples {
        drop_example_in_txn(write, wtxn, example)?;
        NAMED_BY.delete(store, wtxn, &(*id, *example))?;
    }
    Ok(())
}
