//! The Coach's born-with reach to ask the vault owner about its own
//! training offers (OF-577, FIX 856; Engine ruling 10-18).
//!
//! The Coach is a System MACHINE seeded with no actor ceiling, so both doors
//! a training offer ask passes would refuse it: the witness door's
//! System-author floor wants an Auto row bound to the writer, and ask
//! admission wants an Auto actor ceiling. The shipped manifest carries one
//! actor-bound `scoped_grants` row instead, naming the Coach and the effector
//! `tasks.ask.training_offer_owner`, with Auto as its selector ceiling. It
//! reaches two acts and nothing wider: witnessing the one reserved question
//! about a pending offer into its owner's conversation, and asking that one
//! owner on that question's TURN. Every other act of the Coach keeps its
//! default ceiling, read and permits.
//!
//! The owner revokes it like any policy row, through the owner manifest
//! door: delete the row, or set its selector ceiling to "proposed". Matching
//! rows fold restrictively: one actor-bound Auto row is needed, and any
//! Proposed, malformed or unsupported row closes it, as does a fail-closed
//! policy, which yields no rows. A revoked reach refuses both acts; a
//! training offer ask never falls back to the Coach's generic ceiling.
//!
//! The same row reaches the result of a training run an offer led to
//! (FIX 857): the one reserved question about a Scored run's result, while
//! the run still waits at the expectation it froze, and the ask on its TURN.
//! Revoking the row closes both questions.

use rmpv::Value;

use super::ceiling::PolicyApprovalCeiling;
use super::constants::{
    ACTOR_CEILING_KEY, ACTOR_CLASS_KEY, ACTOR_REF_KEY, GRANT_EFFECTOR_KEY,
    GRANT_RECEIPT_REQUIRED_KEY, GRANT_SCOPE_KEY, GRANT_SELECTORS_KEY, POLICY_SCOPED_GRANTS_KEY,
};
use super::grants::PolicyScopedGrant;
use super::resolution::PolicyManifestResolution;
use super::witness_message::{WITNESS_AUTHOR_SYSTEM, WitnessMessageEnvelope};
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::skill_optimize::TrainingOffer;
use crate::task_verb::{ConsultPayloadRef, TaskAskSpec, TaskAskTarget, TaskAssignee};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

/// The effector of the Coach's reach: asking the vault owner about the
/// Coach's own pending training offers.
const COACH_OFFER_ASK_EFFECTOR: &str = "tasks.ask.training_offer_owner";
const COACH_ACTOR_CLASS: &str = "system";

fn invalid(reason: &'static str) -> Error {
    Error::InvariantViolation(reason)
}

/// The Coach's reach row: bound to its derived id, the effect preset, no
/// receipt, and an Auto selector ceiling.
fn reach_row(actor_ref: &str) -> Result<Value> {
    Ok(Value::Map(vec![
        (Value::from(ACTOR_REF_KEY), Value::from(actor_ref)),
        (Value::from(ACTOR_CLASS_KEY), Value::from(COACH_ACTOR_CLASS)),
        (
            Value::from(GRANT_EFFECTOR_KEY),
            Value::from(COACH_OFFER_ASK_EFFECTOR),
        ),
        (
            Value::from(GRANT_SCOPE_KEY),
            crate::federation::scope_codec::encode_scope_value(
                &crate::federation::scope_codec::effect_preset(),
            )?,
        ),
        (
            Value::from(GRANT_RECEIPT_REQUIRED_KEY),
            Value::Boolean(false),
        ),
        (
            Value::from(GRANT_SELECTORS_KEY),
            Value::Map(vec![(Value::from(ACTOR_CEILING_KEY), Value::from("auto"))]),
        ),
    ]))
}

/// The shipped manifest with the Coach's reach row joined to its one
/// scoped-grant table: what a fresh vault seeds.
pub(super) fn with_shipped_coach_offer_reach(manifest: Vec<u8>) -> Result<Vec<u8>> {
    let actor_ref = crate::dreamer_runner::authority::coach_actor_id()?.to_hex();
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut manifest.as_slice())
        .map_err(|_| invalid("decode shipped policy"))?
    else {
        return Err(invalid("shipped policy is not a map"));
    };
    let row = reach_row(&actor_ref)?;
    match entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some(POLICY_SCOPED_GRANTS_KEY))
    {
        Some((_, Value::Array(rows))) => rows.push(row),
        Some(_) => return Err(invalid("shipped scoped grants are not a list")),
        None => entries.push((
            Value::from(POLICY_SCOPED_GRANTS_KEY),
            Value::Array(vec![row]),
        )),
    }
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &Value::Map(entries))
        .map_err(|_| invalid("encode shipped policy"))?;
    Ok(data)
}

/// One reach row's selector ceiling: `{ceiling: auto|proposed}` and nothing
/// else, on the effect preset, with no budget and no receipt. `None` is a
/// form the reach does not support.
fn row_ceiling(grant: &PolicyScopedGrant) -> Option<PolicyApprovalCeiling> {
    if grant.budget.is_some()
        || grant.receipt_required
        || grant.authority_scope != crate::federation::scope_codec::effect_preset()
    {
        return None;
    }
    let Some(Value::Map(selectors)) = &grant.scope else {
        return None;
    };
    match selectors.as_slice() {
        [(key, ceiling)] if key.as_str() == Some(ACTOR_CEILING_KEY) => {
            PolicyApprovalCeiling::parse(ceiling)
        }
        _ => None,
    }
}

/// Whether the live policy grants the Coach its reach: a restrictive fold
/// over this effector's rows that can name the Coach. One row bound to the
/// Coach must read Auto; any row that reads Proposed or is unsupported
/// closes it, and absence closes it.
fn offer_reach_granted(policy: &PolicyManifestResolution) -> bool {
    let Ok(coach) = crate::dreamer_runner::authority::coach_actor_id() else {
        return false;
    };
    let coach = coach.to_hex();
    let mut granted = false;
    for grant in policy.scoped_grants() {
        if grant.effector.trim() != COACH_OFFER_ASK_EFFECTOR
            || grant
                .actor_class
                .as_deref()
                .is_some_and(|class| class != COACH_ACTOR_CLASS)
            || grant
                .actor_ref
                .as_deref()
                .is_some_and(|actor| actor != coach)
        {
            continue;
        }
        match row_ceiling(grant) {
            Some(PolicyApprovalCeiling::Auto) => {
                granted |= grant.actor_class.is_some() && grant.actor_ref.is_some();
            }
            Some(PolicyApprovalCeiling::Proposed) | None => return false,
        }
    }
    granted
}

/// Whether `actor` is the Coach, in its System class.
fn is_coach(actor: EntityId, class: EdgeActorClass) -> Result<bool> {
    Ok(class == EdgeActorClass::System
        && actor == crate::dreamer_runner::authority::coach_actor_id()?)
}

/// The offer a tuple names while it still waits at `digest`, asked of a
/// live vault owner.
fn pending_for_owner_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    offer: &EntityId,
    digest: &str,
    owner: &EntityId,
) -> Result<Option<TrainingOffer>> {
    if !crate::policy_model::is_live_vault_owner_in_txn(vault, txn, owner)? {
        return Ok(None);
    }
    Ok(
        crate::skill_optimize::pending_training_offer_in_txn(vault, txn, offer)?
            .filter(|row| row.digest == digest),
    )
}

/// The ask door's ceiling for a training offer intent: whether the Coach,
/// under its reach, asks exactly the one owner its intent key names about
/// its own pending offer, on that tuple's reserved question TURN, with no
/// context refs, task or class. A training swap intent reads the same over
/// its pending result question. Any other asker or shape is refused.
/// # Errors
/// Storage errors, or a policy that does not resolve.
pub(crate) fn coach_offer_ask_ceiling_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    class: EdgeActorClass,
    input: &TaskAskSpec,
) -> Result<bool> {
    if !is_coach(actor, class)? {
        return Ok(false);
    }
    if crate::task_verb::is_training_swap_ask_intent(&input.intent_key) {
        return coach_swap_ask_ceiling_in(vault, txn, input);
    }
    let Some(key) = crate::task_verb::training_offer_ask_key(&input.intent_key) else {
        return Ok(false);
    };
    let (offer, owner, digest) = &key;
    let asks_owner = matches!(
        &input.who,
        Some(TaskAskTarget::Responder(TaskAssignee::Human { actor_ref })) if actor_ref == owner
    );
    if !asks_owner
        || input.task_ref.is_some()
        || input.class.is_some()
        || !input.what.context_refs.is_empty()
    {
        return Ok(false);
    }
    let Some(question) = crate::task_verb::reserved_offer_question_in(vault, txn, &key)? else {
        return Ok(false);
    };
    if input.what.reference != ConsultPayloadRef::Turn(question.turn)
        || pending_for_owner_in(vault, txn, offer, digest, owner)?.is_none()
    {
        return Ok(false);
    }
    Ok(offer_reach_granted(&super::resolve_policy_manifest(
        &vault.store,
        txn,
    )?))
}

/// [`coach_offer_ask_ceiling_in_txn`] for a training swap intent: the Coach
/// asks exactly the one owner its intent key names about a Scored run's
/// result that still waits at the frozen expectation, on that tuple's
/// reserved question TURN, with no context refs, task or class.
fn coach_swap_ask_ceiling_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    input: &TaskAskSpec,
) -> Result<bool> {
    let Some(key) = crate::task_verb::training_swap_ask_key(&input.intent_key) else {
        return Ok(false);
    };
    let asks_owner = matches!(
        &input.who,
        Some(TaskAskTarget::Responder(TaskAssignee::Human { actor_ref })) if *actor_ref == key.1
    );
    if !asks_owner
        || input.task_ref.is_some()
        || input.class.is_some()
        || !input.what.context_refs.is_empty()
    {
        return Ok(false);
    }
    let Some(question) = crate::task_verb::pending_swap_question_in(vault, txn, &key)? else {
        return Ok(false);
    };
    if input.what.reference != ConsultPayloadRef::Turn(question.turn) {
        return Ok(false);
    }
    Ok(offer_reach_granted(&super::resolve_policy_manifest(
        &vault.store,
        txn,
    )?))
}

/// The Coach's leave to write one `system` question row about a pending
/// offer, bound to the writer and the row's exact canonical bytes. Only the
/// witness door's System-author floor reads it.
pub(crate) struct OfferQuestionPermit {
    actor: WriteActor,
    body: Vec<u8>,
}

/// The permit the Coach's reserved question about a pending offer carries to
/// the witness door, or `None` for every other message. It is given only
/// when the writer is the Coach in its System class; the message is the
/// canonical question envelope; its metadata names an offer tuple whose
/// reservation holds exactly this conversation, TURN and MESSAGE; the offer
/// still waits at that digest for a live owner; the text is that offer's
/// question; and the live policy grants the reach. The metadata locates the
/// tuple and proves nothing by itself. A training swap question carries its
/// permit on the same terms over its result (`coach_swap_question_permit_in`).
/// # Errors
/// Storage errors, or a body that does not encode.
#[expect(
    clippy::too_many_arguments,
    reason = "one witness message's ids, its envelope and the policy it lands under"
)]
pub(crate) fn coach_offer_question_permit_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
    conversation: EntityId,
    turn: EntityId,
    message: EntityId,
    envelope: &WitnessMessageEnvelope<'_>,
    policy: &PolicyManifestResolution,
) -> Result<Option<OfferQuestionPermit>> {
    if envelope.message_type == crate::task_verb::SWAP_QUESTION_TYPE {
        let ids = (conversation, turn, message);
        return coach_swap_question_permit_in(vault, txn, actor, ids, envelope, policy);
    }
    if envelope.author != WITNESS_AUTHOR_SYSTEM
        || envelope.message_type != crate::task_verb::OFFER_QUESTION_TYPE
        || !envelope.is_visible
        || envelope.order != 0
        || !is_coach(actor.entity_ref(), actor.actor_class())?
    {
        return Ok(None);
    }
    let Some(key) = envelope
        .metadata
        .as_ref()
        .and_then(crate::task_verb::offer_question_key)
    else {
        return Ok(None);
    };
    let Some(question) = crate::task_verb::reserved_offer_question_in(vault, txn, &key)? else {
        return Ok(None);
    };
    if question.conversation != conversation || question.turn != turn || question.message != message
    {
        return Ok(None);
    }
    let (offer, owner, digest) = &key;
    let Some(row) = pending_for_owner_in(vault, txn, offer, digest, owner)? else {
        return Ok(None);
    };
    if envelope.content != crate::task_verb::offer_question_text(&row)
        || !offer_reach_granted(policy)
    {
        return Ok(None);
    }
    Ok(Some(OfferQuestionPermit {
        actor,
        body: envelope.encode_body()?,
    }))
}

/// The permit the Coach's reserved question about a Scored run's result
/// carries to the witness door: the writer is the Coach in its System class;
/// the message is the canonical question envelope; its metadata names a swap
/// tuple whose reservation holds exactly these `(conversation, TURN,
/// MESSAGE)` ids; the run still waits at the expectation the question froze,
/// for a live owner; the text is that result's question; and the live policy
/// grants the reach.
fn coach_swap_question_permit_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
    ids: (EntityId, EntityId, EntityId),
    envelope: &WitnessMessageEnvelope<'_>,
    policy: &PolicyManifestResolution,
) -> Result<Option<OfferQuestionPermit>> {
    if envelope.author != WITNESS_AUTHOR_SYSTEM
        || !envelope.is_visible
        || envelope.order != 0
        || !is_coach(actor.entity_ref(), actor.actor_class())?
    {
        return Ok(None);
    }
    let Some(key) = envelope
        .metadata
        .as_ref()
        .and_then(crate::task_verb::swap_question_key)
    else {
        return Ok(None);
    };
    let Some(question) = crate::task_verb::pending_swap_question_in(vault, txn, &key)? else {
        return Ok(None);
    };
    if (question.conversation, question.turn, question.message) != ids
        || envelope.content != question.text
        || !offer_reach_granted(policy)
    {
        return Ok(None);
    }
    Ok(Some(OfferQuestionPermit {
        actor,
        body: envelope.encode_body()?,
    }))
}

/// Whether `permit` lets `actor` write the `system` row `body` past the
/// floor: it binds both, the reach still holds under `policy`, and neither an
/// AGENT_DEF self-limit nor a row bound to this writer clamps it to Proposed.
pub(super) fn offer_question_authorized(
    permit: &OfferQuestionPermit,
    actor: WriteActor,
    body: &[u8],
    policy: &PolicyManifestResolution,
    agent_definition_ceiling: Option<PolicyApprovalCeiling>,
) -> bool {
    permit.actor == actor
        && permit.body == body
        && agent_definition_ceiling != Some(PolicyApprovalCeiling::Proposed)
        && policy.actor_bound_ceiling(COACH_ACTOR_CLASS, &actor.entity_ref().to_hex())
            != Some(PolicyApprovalCeiling::Proposed)
        && offer_reach_granted(policy)
}

/// Whether `row` binds the Coach to its offer-ask effector, whatever its
/// ceiling.
fn binds_coach_reach(row: &Value, actor_ref: &str) -> bool {
    row.as_map().is_some_and(|fields| {
        let field = |key: &str| {
            fields
                .iter()
                .find(|(name, _)| name.as_str() == Some(key))
                .and_then(|(_, value)| value.as_str())
        };
        field(ACTOR_REF_KEY) == Some(actor_ref)
            && field(GRANT_EFFECTOR_KEY).map(str::trim) == Some(COACH_OFFER_ASK_EFFECTOR)
    })
}

/// The live manifest with the Coach's reach row joined to its scoped-grant
/// table, or `None` when a row already binds the Coach to this effector: an
/// owner's revocation stands.
fn with_coach_reach_row(live: &[u8], actor_ref: &str) -> Result<Option<Vec<u8>>> {
    let Value::Map(mut entries) =
        rmpv::decode::read_value(&mut &live[..]).map_err(|_| invalid("decode live policy"))?
    else {
        return Err(invalid("live policy is not a map"));
    };
    let at = entries
        .iter()
        .position(|(key, _)| key.as_str() == Some(POLICY_SCOPED_GRANTS_KEY));
    let mut rows = match at.map(|at| std::mem::replace(&mut entries[at].1, Value::Nil)) {
        None | Some(Value::Nil) => Vec::new(),
        Some(Value::Array(rows)) => rows,
        Some(single @ Value::Map(_)) => vec![single],
        Some(_) => return Err(invalid("policy scoped grants are not a list")),
    };
    if rows.iter().any(|row| binds_coach_reach(row, actor_ref)) {
        return Ok(None);
    }
    rows.push(reach_row(actor_ref)?);
    match at {
        Some(at) => entries[at].1 = Value::Array(rows),
        None => entries.push((Value::from(POLICY_SCOPED_GRANTS_KEY), Value::Array(rows))),
    }
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &Value::Map(entries))
        .map_err(|_| invalid("encode live policy"))?;
    Ok(Some(data))
}

impl Vault {
    /// Whether the live policy grants the Coach its offer-ask reach.
    pub fn coach_offer_reach(&self) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        Ok(offer_reach_granted(&super::resolve_policy_manifest(
            &self.store,
            &txn,
        )?))
    }

    /// Owner act (OF-577): adds the Coach's reach row to the trusted policy
    /// pack the Dreamer grant edits, for a vault whose pack was seeded before
    /// the row shipped or that the owner edited since. Returns whether the
    /// policy changed. A row already binding the Coach to this effector stands
    /// as the owner left it, revoked or not. Refuses, changing nothing, when
    /// the edit would not open the reach or would move other policy.
    pub fn grant_coach_offer_reach(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        now: u64,
    ) -> Result<bool> {
        let actor_ref = crate::dreamer_runner::authority::coach_actor_id()?.to_hex();
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let (id, body) = super::dreamer_grant::grant_target(&self.store, &txn)?;
        let Some(data) = with_coach_reach_row(&body, &actor_ref)? else {
            return Ok(false);
        };
        let before = super::resolve_policy_manifest(&self.store, &txn)?;
        let retention = super::resolve_gate_decision_retention(&self.store, &txn)?;
        self.write_owner_policy_manifest_in_txn(owner, &mut txn, id, data, now)?;
        let after = super::resolve_policy_manifest(&self.store, &txn)?;
        if after.is_fail_closed()
            || after.diagnostics().loaded_manifest_forces_fail_closed()
            || after.carry_forward_confidence != before.carry_forward_confidence
            || super::resolve_gate_decision_retention(&self.store, &txn)? != retention
            || !offer_reach_granted(&after)
        {
            // Dropping the transaction leaves the policy as it was.
            return Err(Error::InvalidConfig(
                "the Coach's offer-ask grant would not take without changing other policy; \
                 the owner's policy rows keep the Coach out or conflict"
                    .into(),
            ));
        }
        txn.commit()?;
        // A floor this commit moved is judged again at once (FIX 5505).
        self.apply_pending_rebinds_after_commit();
        Ok(true)
    }
}
