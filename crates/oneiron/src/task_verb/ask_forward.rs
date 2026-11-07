//! A person's word on a `tasks.ask` this node did not admit (FIX 7494).
//!
//! Only the node that admitted an ask cuts it ([`ask_record::owns_revision`]),
//! and a domain ask's word needs that node's own rows and a live owner proof,
//! neither of which replicates. A replica therefore never makes such a word
//! effective itself. It persists the holder's signed intent as an immutable
//! TASK companion record, and the entity transport carries it to every node,
//! the admitting one among them. Only that node consumes it: it checks the
//! holder's operation signature, authenticates the owner there, and admits
//! the word, or voids the holder's seat, once, in one writer with the
//! intent's result. The result is a second immutable TASK companion, signed
//! with the group's issuer key, which the transport carries back. A pending
//! intent is not an answer: the replica reports it pending until that result
//! reads there. A hard erase of the holder retires their intents and those
//! intents' results, or owes a pair a legal hold keeps its retirement until
//! the hold lifts (`erase`, FIX 20468). An intent or result that lands after
//! that erase retires, or is owed its retirement, at its put (FIX 7494).
//!
//! Entry: [`Memory::tasks_answer_forward`] on the replica;
//! [`drain_ask_forward_intents`] at the admitting node.
//!
//! FIX 20468 serves the three doors as `tasks.answer.forward.challenge`,
//! `tasks.answer.forward` and `tasks.answer.forward.status`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::ask_record::{self, AskGroup};
use super::{TaskAskAnswer, TaskAskHandle, TaskAskWord};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::derived_domains::{TASK_ASK_FORWARD_INTENT, TASK_ASK_FORWARD_RESULT};
use crate::error::{Error, RecordError, Result};
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult,
    verify_actor_binding,
};
use crate::registry::ENTITY_TYPE_TASK;
use crate::{EntityId, Vault};

mod consume;
mod erase;

pub(crate) use erase::{
    retire_holder_ask_forward_rows_in_txn, settle_held_ask_forward_rows_in_txn,
};

/// Subkind of a relayed intent's TASK companion record.
pub(super) const INTENT: &str = "tasks.ask_forward_intent";
/// Subkind of the admitting node's result companion for one intent.
pub(super) const RESULT: &str = "tasks.ask_forward_result";

/// Domain of the challenge a holder signs for one intent.
const CHALLENGE_DOMAIN: &[u8] = b"oneiron/tasks.ask-forward/v1\0";
/// The framing every capability slip token carries.
const TOKEN_PREFIX: &str = "v2.slip.";

/// What a relayed intent asks the ask's admitting node to do (FIX 7494).
/// The SDK rows take it as their input (FIX 20468).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AskForwardAct {
    /// The holder's own word, admitted there as `tasks_answer` admits it.
    Word(TaskAskWord),
    /// The holder voids their own seat on the ask, as an option link's
    /// "Not you?" voids its bearer's.
    Void,
}

impl AskForwardAct {
    /// The act's tag in the challenge.
    fn tag(&self) -> u8 {
        match self {
            Self::Word(_) => 1,
            Self::Void => 2,
        }
    }

    /// The digest of the whole act, which the holder's signature commits.
    fn digest(&self) -> Result<[u8; 32]> {
        let bytes = rmp_serde::to_vec_named(self).map_err(|_| ask_record::invalid())?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }
}

/// The holder's proof for one intent: their slip, and their signature over
/// the slip's binding transcript (`CapabilitySlip::binding_transcript`) of
/// [`ask_forward_challenge`]. It proves this one intent; the request that
/// carries it authenticates apart, as every request does (FIX 20468).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AskForwardHolderProof {
    /// The holder's `v2.slip.` token.
    pub token: String,
    /// The holder's Ed25519 signature, 128 lowercase hex characters.
    pub signature: String,
}

/// Hand-written so the token cannot reach a log through a derive.
impl std::fmt::Debug for AskForwardHolderProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AskForwardHolderProof")
            .finish_non_exhaustive()
    }
}

impl AskForwardHolderProof {
    /// The signature's bytes: exactly 128 lowercase hex characters.
    fn signature_bytes(&self) -> Option<[u8; 64]> {
        let text = self.signature.as_bytes();
        if text.len() != 128 {
            return None;
        }
        let digit = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        };
        let mut bytes = [0_u8; 64];
        for (byte, pair) in bytes.iter_mut().zip(text.chunks_exact(2)) {
            let [high, low] = pair else {
                return None;
            };
            *byte = (digit(*high)? << 4) | digit(*low)?;
        }
        Some(bytes)
    }
}

/// One relayed intent, as the replica that took it persisted it: an
/// immutable TASK companion record, never an answer. Its id derives from its
/// group, its holder and its intent key, so a retry under the same key is the
/// same intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AskForwardIntent {
    pub(super) group: EntityId,
    /// The exact question revision the holder answered.
    pub(super) revision: u64,
    /// The person whose word or void this is: the slip's holder.
    pub(super) holder: EntityId,
    pub(super) intent_key: String,
    pub(super) act: AskForwardAct,
    /// The digest of `act` that the holder's signature commits.
    pub(super) payload_digest: [u8; 32],
    pub(super) proof: AskForwardHolderProof,
    /// When the replica persisted it. The admitting node cuts on its own
    /// clock.
    pub(super) at: u64,
}

impl AskForwardIntent {
    /// The same payload under the same id: everything but the proof and the
    /// time the replica took it.
    fn same_payload(&self, other: &Self) -> bool {
        self.group == other.group
            && self.revision == other.revision
            && self.holder == other.holder
            && self.intent_key == other.intent_key
            && self.act == other.act
            && self.payload_digest == other.payload_digest
    }

    /// The shape every node checks at the put door (`ask_record::guard`):
    /// its id, its payload digest, its time and its proof's form. Its group
    /// and the holder's proof are judged there and at the admitting node.
    pub(super) fn validate_put(
        &self,
        id: EntityId,
        occurred: crate::TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        if self.at == 0
            || occurred.start != self.at
            || occurred.end != self.at
            || learned_at != self.at
            || self.intent_key.is_empty()
            || intent_id(self.group, self.holder, &self.intent_key)? != id
            || self.act.digest()? != self.payload_digest
            || !self.proof.token.starts_with(TOKEN_PREFIX)
            || self.proof.signature_bytes().is_none()
        {
            return Err(ask_record::invalid());
        }
        Ok(())
    }
}

/// What the admitting node did with one intent (FIX 7494): the existing ask
/// outcomes, never a new kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum AskForwardOutcome {
    /// It admitted the word, as `tasks_answer` admits one.
    Answered { answer: Box<TaskAskAnswer> },
    /// It voided the holder's seat; the group's void generation after it.
    Voided { generation: u64 },
    /// It refused the intent with this existing memory error code.
    Refused { code: String },
}

/// The admitting node's committed result for one intent: an immutable TASK
/// companion signed with the group's issuer key, which only that node holds,
/// so a node that reads it knows that node committed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AskForwardResult {
    pub(super) intent: EntityId,
    pub(super) group: EntityId,
    /// The intent's payload digest, so a result answers that payload alone.
    pub(super) payload_digest: [u8; 32],
    pub(super) outcome: AskForwardOutcome,
    /// The admitting node's clock when it committed the result.
    pub(super) at: u64,
    pub(super) signature: Vec<u8>,
}

impl AskForwardResult {
    /// The bytes the group's issuer key signs: every field but the signature.
    fn signed_body(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(&(
            self.intent,
            self.group,
            self.payload_digest,
            &self.outcome,
            self.at,
        ))
        .map_err(|_| ask_record::invalid())
    }

    /// The shape every node checks at the put door: its id and its time.
    pub(super) fn validate_put(
        &self,
        id: EntityId,
        occurred: crate::TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        if self.at == 0
            || occurred.start != self.at
            || occurred.end != self.at
            || learned_at != self.at
            || result_id(self.intent)? != id
        {
            return Err(ask_record::invalid());
        }
        Ok(())
    }

    /// Checks that this result answers `intent`, the stored intent it names
    /// (FIX 7494). Before any signature, it must name the intent's group and
    /// bind its payload digest. Then the issuer signature is checked against
    /// `group`, that intent's stored group, so another group's key never
    /// verifies it.
    pub(super) fn verify_for(&self, intent: &AskForwardIntent, group: &AskGroup) -> Result<()> {
        if self.group != intent.group || self.payload_digest != intent.payload_digest {
            return Err(ask_record::invalid());
        }
        ask_record::verify_forward_result(group, &self.signed_body()?, &self.signature)
    }
}

/// What a relayed intent stands at, as the replica that took it reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AskForwardReceipt {
    /// Persisted and relayed: the ask's admitting node has not committed a
    /// result for it yet. It is no answer.
    Pending { intent_ref: EntityId },
    /// The admitting node admitted the word.
    Answered {
        intent_ref: EntityId,
        answer: Box<TaskAskAnswer>,
    },
    /// The admitting node voided the holder's seat; the group's void
    /// generation after it.
    Voided {
        intent_ref: EntityId,
        generation: u64,
    },
}

/// The intent `holder` relays under `intent_key` on the ask `group`.
fn intent_id(group: EntityId, holder: EntityId, intent_key: &str) -> Result<EntityId> {
    EntityId::derive(
        TASK_ASK_FORWARD_INTENT,
        &[group.as_bytes(), holder.as_bytes(), intent_key.as_bytes()],
    )
}

/// The admitting node's result for the intent `intent`.
fn result_id(intent: EntityId) -> Result<EntityId> {
    EntityId::derive(TASK_ASK_FORWARD_RESULT, &[intent.as_bytes()])
}

/// The challenge a holder signs, through their slip's binding transcript
/// (`CapabilitySlip::binding_transcript`), for one intent (FIX 7494). It
/// commits the vault the authority log names, the ask's group, whose id only
/// its admitting node derives (`ask_record::group_id`) and so names that
/// node, the exact question revision, the intent, its holder and the whole
/// act. It opens with its own domain, and each field carries its length. The
/// node that receives the intent rebuilds it from the intent and its own
/// rows; the intent never supplies it.
///
/// # Errors
/// An act that does not encode, or an id that does not derive.
pub fn ask_forward_challenge(
    vault_id: &[u8; 32],
    handle: TaskAskHandle,
    revision: u64,
    holder: EntityId,
    intent_key: &str,
    act: &AskForwardAct,
) -> Result<Vec<u8>> {
    let intent = intent_id(handle.group_ref, holder, intent_key)?;
    challenge(vault_id, handle.group_ref, revision, intent, holder, act)
}

/// [`ask_forward_challenge`] for an intent whose id is known.
fn challenge(
    vault_id: &[u8; 32],
    group: EntityId,
    revision: u64,
    intent: EntityId,
    holder: EntityId,
    act: &AskForwardAct,
) -> Result<Vec<u8>> {
    let revision = revision.to_be_bytes();
    let tag = [act.tag()];
    let digest = act.digest()?;
    let fields: [&[u8]; 7] = [
        vault_id,
        group.as_bytes(),
        &revision,
        intent.as_bytes(),
        holder.as_bytes(),
        &tag,
        &digest,
    ];
    let mut bytes = CHALLENGE_DOMAIN.to_vec();
    bytes.extend_from_slice(&(fields.len() as u64).to_be_bytes());
    for field in fields {
        bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    Ok(bytes)
}

/// The intent stored under `id`.
fn read_intent(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<AskForwardIntent>> {
    ask_record::read(vault, txn, id, INTENT)
}

/// The result stored for the intent `id`, checked against that intent and
/// signed by its group's issuer key.
fn read_result(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    intent: &AskForwardIntent,
) -> Result<Option<AskForwardResult>> {
    let Some(result) = ask_record::read::<AskForwardResult>(vault, txn, result_id(id)?, RESULT)?
    else {
        return Ok(None);
    };
    if result.intent != id {
        return Err(ask_record::invalid());
    }
    let group =
        ask_record::read_group(vault, txn, intent.group)?.ok_or_else(ask_record::invalid)?;
    result.verify_for(intent, &group)?;
    Ok(Some(result))
}

/// Whether this node admitted the ask `intent` names.
fn admitted_here(vault: &Vault, txn: &heed::RoTxn<'_>, intent: &AskForwardIntent) -> Result<bool> {
    Ok(match ask_record::read_group(vault, txn, intent.group)? {
        Some(group) => ask_record::owns_revision(vault, txn, intent.group, &group)?,
        None => false,
    })
}

/// The relayed-intent subkind a TASK row carries, read without failing: any
/// other row, or one that does not decode, has none.
fn subkind(raw: &[u8]) -> Option<&'static str> {
    if EntityMetadataHeader::parse(raw)?.entity_type != ENTITY_TYPE_TASK {
        return None;
    }
    let value = rmpv::decode::read_value(&mut raw.get(ENTITY_METADATA_HEADER_LEN..)?).ok()?;
    value
        .as_map()?
        .iter()
        .find_map(|(key, value)| match (key.as_str()?, value.as_str()?) {
            ("subkind", INTENT) => Some(INTENT),
            ("subkind", RESULT) => Some(RESULT),
            _ => None,
        })
}

/// The intents that landed at one vault open for asks it admitted, not
/// consumed yet (FIX 7494). The vault holds it
/// ([`Vault::ask_forward_arrivals`]) and drops it when it closes; the next
/// open reads the stored intents again.
#[derive(Default)]
pub(crate) struct AskForwardArrivals {
    /// Whether this open's stored intents were read once, for those that
    /// landed before this open or while the vault was closed.
    recovered: bool,
    intents: BTreeSet<EntityId>,
}

/// Runs `act` on `vault`'s arrivals, under their lock.
fn with_arrivals<T>(vault: &Vault, act: impl FnOnce(&mut AskForwardArrivals) -> T) -> T {
    let mut arrivals = vault
        .ask_forward_arrivals
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    act(&mut arrivals)
}

/// The TASK put hook's part for relayed intents (FIX 7494), in the writing
/// transaction, local or replicated: an intent for an ask this node admitted,
/// with no result yet, is noted for [`drain_ask_forward_intents`]. An intent
/// with a result delivers it to the code runs parked on the intent, whether
/// the result or the park came last. A result is accepted only once its
/// intent is here: without it, the result waits as a pending dependency. An
/// intent or result whose holder this node hard-erased, which the erase never
/// met, retires in this writer instead (`erase`). Every other TASK row passes
/// untouched.
pub(super) fn note_put_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    task: EntityId,
) -> Result<()> {
    let Some(raw) = vault.get_raw_in(txn, &task)? else {
        return Ok(());
    };
    let intent = match subkind(&raw) {
        Some(INTENT) => task,
        Some(RESULT) => match ask_record::read::<AskForwardResult>(vault, txn, task, RESULT)? {
            Some(result) => result.intent,
            None => return Ok(()),
        },
        _ => return Ok(()),
    };
    let Some(stored) = read_intent(vault, txn, intent)? else {
        if task == intent {
            return Ok(());
        }
        return Err(Error::Record(RecordError::AskDependencyPending));
    };
    // FIX 7494: the holder's `dt:` marker, as sync ingest reads it.
    if vault.local_hard_delete_marker_exists_in_txn(txn, &stored.holder)? {
        return erase::retire_erased_holder_pair_in_txn(vault, txn, stored.holder, intent);
    }
    if let Some(result) = read_result(vault, txn, intent, &stored)? {
        return deliver_result_in_txn(vault, txn, intent, &result);
    }
    if task == intent && admitted_here(vault, txn, &stored)? {
        with_arrivals(vault, |arrivals| arrivals.intents.insert(intent));
    }
    Ok(())
}

/// The result for the code runs parked on its intent, in `txn`: the intent
/// ref is their wait id. A run that parks after the result landed takes it
/// at its park, which passes the intent to the same hook.
fn deliver_result_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    intent: EntityId,
    result: &AskForwardResult,
) -> Result<()> {
    if !crate::code_run::has_parked_run_in_txn(vault, txn, intent)? {
        return Ok(());
    }
    let reply = serde_json::json!({
        "intent_ref": intent,
        "outcome": result.outcome,
        "at": result.at,
    });
    let now_ms = vault.store.clock.now_recorded_at().saturating_mul(1000);
    crate::code_run::deliver_wait_in_txn(vault, txn, intent, &reply, now_ms).map(drop)
}

/// Consumes, at this node, every relayed intent that landed for an ask it
/// admitted (FIX 7494). The client sync lane calls it after an import, and
/// the ask sweep every host already runs calls it, so no timer of its own
/// runs. The first call of a vault open also reads the intents stored before
/// that open. An intent whose rows have not all landed stays noted for the
/// next call, and so does one whose consumption failed, which is logged.
///
/// # Errors
/// A storage error reading the stored intents.
pub(crate) fn drain_ask_forward_intents(vault: &Vault) -> Result<()> {
    if !with_arrivals(vault, |arrivals| {
        std::mem::replace(&mut arrivals.recovered, true)
    }) && let Err(error) = recover_stored_intents(vault)
    {
        with_arrivals(vault, |arrivals| arrivals.recovered = false);
        return Err(error);
    }
    let intents = with_arrivals(vault, |arrivals| std::mem::take(&mut arrivals.intents));
    for intent in intents {
        let keep = match consume::consume_intent(vault, intent) {
            Ok(standing) => standing == consume::Standing::Pending,
            Err(error) => {
                tracing::warn!(
                    intent = %intent.to_hex(),
                    %error,
                    "a relayed ask intent was not consumed; it stays pending"
                );
                true
            }
        };
        if keep {
            with_arrivals(vault, |arrivals| arrivals.intents.insert(intent));
        }
    }
    Ok(())
}

/// Notes every stored intent for an ask this node admitted that has no
/// result yet: one read of the TASK rows per vault open.
fn recover_stored_intents(vault: &Vault) -> Result<()> {
    use crate::ports::EntityStoreRead;
    let txn = vault.store.env.read_txn()?;
    let mut found = BTreeSet::new();
    for row in vault
        .store
        .port_entity_ids_by_type(&txn, ENTITY_TYPE_TASK, None)?
    {
        let id = row?;
        let Some(raw) = vault.get_raw_in(&txn, &id)? else {
            continue;
        };
        if subkind(&raw) != Some(INTENT) {
            continue;
        }
        let Some(intent) = read_intent(vault, &txn, id)? else {
            continue;
        };
        if admitted_here(vault, &txn, &intent)? && read_result(vault, &txn, id, &intent)?.is_none()
        {
            found.insert(id);
        }
    }
    drop(txn);
    with_arrivals(vault, |arrivals| arrivals.intents.extend(found));
    Ok(())
}

/// The vault id a challenge commits: the one the authority log derives,
/// which every replica of the vault shares. A vault with none relays nothing.
fn forward_vault_id(vault: &Vault, txn: &heed::RoTxn<'_>) -> MemoryResult<[u8; 32]> {
    vault
        .authority_view_readonly_in_txn(txn)?
        .vault_id
        .ok_or_else(|| {
            MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "this vault has no authority log to bind a relayed ask word to",
                &["Root the vault before relaying an ask word."],
            )
        })
}

/// A relayed word whose proof is not this person's own slip.
fn holder_refused() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        "the relayed ask word's holder proof is not this person's own slip",
        &["Sign the intent's challenge with your own slip's binding key."],
    )
}

impl Memory<'_> {
    /// The challenge this surface's person signs for a relayed intent
    /// ([`ask_forward_challenge`]), read on this node: its vault, and the
    /// ask's revision as this surface reads the ask `handle` names.
    pub fn tasks_answer_forward_challenge(
        &self,
        handle: &TaskAskHandle,
        intent_key: &str,
        act: &AskForwardAct,
    ) -> MemoryResult<Vec<u8>> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let group = self
            .ask_group_named_in(&txn, handle.group_ref)?
            .ok_or_else(|| MemoryError::bad_request("unknown ask handle"))?;
        let vault_id = forward_vault_id(self.vault(), &txn)?;
        Ok(ask_forward_challenge(
            &vault_id,
            *handle,
            group.effective.what.revision,
            self.actor(),
            intent_key,
            act,
        )?)
    }

    /// Relays this surface's person's word, or the void of their own seat, on
    /// the ask `handle` names to the node that admitted it (FIX 7494). The
    /// intent is persisted before this returns, and the entity transport
    /// carries it there; nothing here makes it effective. On the admitting
    /// node itself it is consumed at once. The same intent key with the same
    /// act is the same intent, and returns where it stands; another act under
    /// it is refused and reuses nothing. `proof` is the person's own slip and
    /// their signature over its binding transcript of
    /// [`Self::tasks_answer_forward_challenge`].
    pub fn tasks_answer_forward(
        &self,
        handle: &TaskAskHandle,
        intent_key: &str,
        act: &AskForwardAct,
        proof: &AskForwardHolderProof,
    ) -> MemoryResult<AskForwardReceipt> {
        if !self.has_task_work_turn() {
            return self
                .task_work_memory()
                .tasks_answer_forward(handle, intent_key, act, proof);
        }
        // A person's word is theirs to give, on their own surface.
        if self.writes_generated()
            || self.room_turn().is_some()
            || self.actor_class() != crate::EdgeActorClass::Human
        {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "a relayed ask word is a person's own, given on their own client",
                &["Ask the person to answer through their own client."],
            ));
        }
        if intent_key.is_empty() {
            return Err(MemoryError::bad_request(
                "a relayed ask word needs an intent key",
            ));
        }
        let holder = self.actor();
        let slip = crate::authority::CapabilitySlip::from_token(&proof.token)
            .map_err(|_| holder_refused())?;
        if slip.claims.holder_ref != holder.to_hex() || proof.signature_bytes().is_none() {
            return Err(holder_refused());
        }
        let intent_ref = intent_id(handle.group_ref, holder, intent_key)?;
        let admitted_here = self.with_verified_actor_write_txn(|txn| {
            let group = self
                .ask_group_named_in(txn, handle.group_ref)?
                .ok_or_else(|| MemoryError::bad_request("unknown ask handle"))?;
            let now = self.vault().store.clock.now_recorded_at();
            let intent = AskForwardIntent {
                group: handle.group_ref,
                revision: group.effective.what.revision,
                holder,
                intent_key: intent_key.to_owned(),
                act: act.clone(),
                payload_digest: act.digest()?,
                proof: proof.clone(),
                at: now,
            };
            match read_intent(self.vault(), txn, intent_ref)? {
                Some(stored) if stored.same_payload(&intent) => {}
                Some(_) => {
                    return Err(MemoryError::new(
                        MEMORY_CODE_INVALID_STATE,
                        "this intent key already carries another relayed ask word",
                        &["Relay a new word under a new intent key."],
                    ));
                }
                None => ask_record::put(self.vault(), txn, intent_ref, INTENT, &intent, now)?,
            }
            Ok(ask_record::owns_revision(
                self.vault(),
                txn,
                handle.group_ref,
                &group,
            )?)
        })?;
        // On the admitting node the intent needs no transport.
        if admitted_here {
            consume::consume_intent(self.vault(), intent_ref)?;
        }
        self.tasks_answer_forward_status(intent_ref)
    }

    /// Where the relayed intent `intent_ref` stands, for its own holder:
    /// pending until the admitting node's signed result reads here, then that
    /// result. A refusal comes back as the refusal it was there.
    pub fn tasks_answer_forward_status(
        &self,
        intent_ref: EntityId,
    ) -> MemoryResult<AskForwardReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let intent = read_intent(self.vault(), &txn, intent_ref)?
            .filter(|intent| intent.holder == self.actor())
            .ok_or_else(|| MemoryError::bad_request("unknown relayed ask intent"))?;
        let Some(result) = read_result(self.vault(), &txn, intent_ref, &intent)? else {
            return Ok(AskForwardReceipt::Pending { intent_ref });
        };
        match result.outcome {
            AskForwardOutcome::Answered { answer } => {
                Ok(AskForwardReceipt::Answered { intent_ref, answer })
            }
            AskForwardOutcome::Voided { generation } => Ok(AskForwardReceipt::Voided {
                intent_ref,
                generation,
            }),
            AskForwardOutcome::Refused { code } => Err(MemoryError::new(
                &code,
                "the ask's admitting node refused this relayed ask word",
                &[
                    "Read the ask's status, then relay a new word under a new intent key if it still waits.",
                ],
            )),
        }
    }
}
