//! Unified dreamer.trap record lifecycle: open/wait/signal/consume and supersession-chain transitions.

use super::codec::{
    decode_attempt_id_value, decode_hash_hex, expect_key, expect_map, expect_string, expect_u64,
    invalid_trap, pinned_key_index,
};
use super::peer_wait::{peer_wait_binding_delete_in_txn, peer_wait_task_for_trap};
use super::step_claim::dreamer_runtime_envelope;
use super::trap_binding::{
    TrapBindingRow, trap_binding_delete_in_txn, trap_binding_put_in_txn, trap_binding_read,
};
use super::types::{
    DREAMER_TRAP_PREDICATE, DREAMER_TRAP_VALUE_KEYS, DREAMER_TRAP_VALUE_SCHEMA_VERSION,
    DreamerTrapKind, DreamerTrapState, DurableStepContext, KEY_AT, KEY_ATTEMPT_ID, KEY_NOTE,
    KEY_SCHEMA_VERSION, KEY_STATE, KEY_STEP_HASH, KEY_TRAP_KIND, TRAP_CHAIN_WALK_CAP, TrapRef,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
use crate::temporal::TimeRange;
use crate::write_envelope::{
    ClaimCandidate, WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY,
    WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY, WriteActor, WriteEnvelope, WriteProvenance,
};
use rmpv::Value;

// ---------------------------------------------------------------------------
// Trap record: ONE claim kind, supersession-based state machine (design D4)
// ---------------------------------------------------------------------------
/// Park-owner token derived from a trap's `created` anchor claim id. The
/// step layer parks trapped attempts under THIS token, records it in the trap's
/// private binding row, and the consume path resumes with it — a parked row
/// held by any other owner is refused fail-closed.
#[must_use]
pub fn trap_park_owner(trap_claim_id: &EntityId) -> String {
    format!(
        "dreamer.trap:{}",
        bytes_to_hex_lower(trap_claim_id.as_bytes())
    )
}

/// Opens a trap for a suspended step: writes the `created` anchor claim AND
/// the private trap-binding row (attempt id + step hash + park owner) in ONE
/// wtxn. The binding row is the device-local ground truth the consume path
/// validates against — it never syncs and cannot be forged through claims.
/// The budget path in [`call_as_step`] parks the attempt right after; consent
/// waits arrive via [`trap_for_durable_wait`].
pub fn open_trap(
    vault: &Vault,
    ctx: &DurableStepContext<'_>,
    kind: DreamerTrapKind,
    step_hash: [u8; 32],
    note: &str,
) -> Result<TrapRef> {
    let claim_id = EntityId::now();
    let value = encode_trap_claim_value(&EncodedTrapClaim {
        kind,
        attempt_id: ctx.attempt_id,
        step_hash,
        state: DreamerTrapState::Created,
        at: ctx.now_ms,
        note: note.to_owned(),
    });
    let candidate = ClaimCandidate::new(
        DREAMER_TRAP_PREDICATE,
        ClaimSubject::Entity(ctx.subject),
        value,
        1.0,
    );
    let envelope = dreamer_runtime_envelope(ctx)?;
    let occurred = TimeRange {
        start: ctx.now_ms,
        end: ctx.now_ms,
    };
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .claim_candidate(&claim_id, candidate, &envelope, occurred, ctx.now_ms)
            .apply(wtxn)?;
        trap_binding_put_in_txn(
            vault,
            wtxn,
            &claim_id,
            &TrapBindingRow {
                attempt_id: ctx.attempt_id,
                step_hash,
                park_owner: trap_park_owner(&claim_id),
            },
        )
    })?;
    Ok(TrapRef {
        trap_claim_id: claim_id,
        kind,
        step_hash,
    })
}

/// Maps a guest-facing durable wait raised inside a Dreamer attempt onto the
/// unified trap record kind: the destructive/outbound consent flavors park as a
/// Consent trap, and each WORK wait parks as its own kind — a peer delegation
/// (ONE-1700) and a human answer (ONE-1708). Waiting for someone to do the work
/// is not waiting for permission to do it, and the two resume on different
/// evidence: a terminal TASK versus an identity-stamped response.
#[must_use]
pub fn trap_for_durable_wait(
    wait: &crate::code_run::SelfDurableWait,
    _step_hash: [u8; 32],
) -> DreamerTrapKind {
    match wait.reason {
        crate::code_run::SelfDurableWaitReason::HumanInput => DreamerTrapKind::HumanResponse,
        crate::code_run::SelfDurableWaitReason::DestructiveEffect
        | crate::code_run::SelfDurableWaitReason::OutboundEffect => DreamerTrapKind::Consent,
        crate::code_run::SelfDurableWaitReason::PeerResult => DreamerTrapKind::PeerResult,
    }
}

/// Registers the runner's wait on an open trap (`created→waiting`).
/// Signal-before-wait: if the signal already landed, returns `Sent` without
/// writing; the caller proceeds straight to consume.
pub fn register_wait(vault: &Vault, trap: &TrapRef, now: u64) -> Result<DreamerTrapState> {
    vault.with_write_txn(|wtxn| register_wait_in_txn(vault, wtxn, trap, now))
}

/// Transaction-composable body of [`register_wait`], so a delegation can
/// co-commit the `Waiting` transition with its local TASK→trap binding.
pub(super) fn register_wait_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    trap: &TrapRef,
    now: u64,
) -> Result<DreamerTrapState> {
    let (head_id, head) = trap_head(vault, &trap.trap_claim_id)?;
    match head.state {
        DreamerTrapState::Created => {
            append_trap_transition_in_txn(
                vault,
                wtxn,
                &head_id,
                &head,
                DreamerTrapState::Waiting,
                now,
                None,
            )?;
            Ok(DreamerTrapState::Waiting)
        }
        DreamerTrapState::Waiting => Ok(DreamerTrapState::Waiting),
        DreamerTrapState::Sent => Ok(DreamerTrapState::Sent),
        DreamerTrapState::Consumed => Err(invalid_trap("dreamer trap already consumed")),
    }
}

/// Writes the resume SIGNAL (`→sent`). The body MUST carry the suspended
/// step's hash; a mismatched hash is rejected here (defense in depth) and
/// again independently at consume (the security boundary, ruling L8).
pub fn send_trap_signal(
    vault: &Vault,
    trap_claim_id: &EntityId,
    step_hash: [u8; 32],
    now: u64,
) -> Result<EntityId> {
    let (head_id, head) = trap_head(vault, trap_claim_id)?;
    if head.step_hash != step_hash {
        return Err(invalid_trap("dreamer trap signal hash mismatch"));
    }
    if !head.state.may_transition_to(DreamerTrapState::Sent) {
        return Err(invalid_trap("dreamer trap signal on non-waiting trap"));
    }
    append_trap_transition(vault, &head_id, &head, DreamerTrapState::Sent, now, None)
}

/// Validates and absorbs the resume signal (`→consumed`).
///
/// Fail-closed validation (ruling L8, uniform including the durable path):
/// the head must be `sent`; the anchor must be THIS trap's `created` record
/// (a record in any other state cannot anchor a consume); the binding —
/// attempt id, step hash, and park owner — is re-derived from the PRIVATE row
/// written when the trap opened on this device, never from caller-supplied
/// fields or synced claims (forged → typed reject); the head's supersession
/// lineage must chain back to the anchor through legal transitions (stale →
/// typed reject). On success the `consumed` transition and the
/// `resume_parked` un-park (owner-checked) commit in ONE wtxn (atomic
/// consume+resume, design D4); the resumed attempt id is returned.
pub fn consume_trap_signal(
    vault: &Vault,
    store: &crate::dreamer_runner::DreamerRunnerStore<'_>,
    trap: &TrapRef,
    now: u64,
) -> Result<AttemptId> {
    let (head_id, head) = trap_head(vault, &trap.trap_claim_id)?;
    if head.state != DreamerTrapState::Sent {
        return Err(invalid_trap("dreamer trap consume requires a sent signal"));
    }
    let anchor = vault
        .get_claim(&trap.trap_claim_id)?
        .ok_or(invalid_trap("dreamer trap created record missing"))?;
    let anchor_decoded = decode_trap_claim_value(&anchor.value)?;
    if anchor_decoded.state != DreamerTrapState::Created {
        return Err(invalid_trap("dreamer trap anchor must be a created record"));
    }
    let binding = trap_binding_read(vault, &trap.trap_claim_id)?
        .ok_or(invalid_trap("dreamer trap binding missing"))?;
    if head.step_hash != binding.step_hash
        || anchor_decoded.step_hash != binding.step_hash
        || trap.step_hash != binding.step_hash
    {
        return Err(invalid_trap("dreamer trap signal hash mismatch"));
    }
    if head.attempt_id != binding.attempt_id || anchor_decoded.attempt_id != binding.attempt_id {
        return Err(invalid_trap(
            "dreamer trap signal names a different attempt",
        ));
    }
    require_lineage_chains_to_anchor(vault, &head_id, &trap.trap_claim_id)?;
    let delegated_task = peer_wait_task_for_trap(vault, &trap.trap_claim_id)?;

    vault.with_write_txn(|wtxn| {
        append_trap_transition_in_txn(
            vault,
            wtxn,
            &head_id,
            &head,
            DreamerTrapState::Consumed,
            now,
            None,
        )?;
        // Idempotent when no parked row exists (a consent trap raised before
        // any park, or a resume raced by the runner); a row parked by any
        // OTHER owner is refused inside resume_parked_in_txn.
        store.resume_parked_in_txn(wtxn, binding.attempt_id, &binding.park_owner, now)?;
        // Consumed is terminal — retire the private binding with the trap.
        trap_binding_delete_in_txn(vault, wtxn, &trap.trap_claim_id)?;
        // A delegation's TASK→trap binding retires in the SAME transaction, so
        // reconciliation never re-walks a settled wait and a duplicate result
        // finds nothing to signal.
        if let Some(task_ref) = delegated_task {
            peer_wait_binding_delete_in_txn(vault, wtxn, &task_ref, &trap.trap_claim_id)?;
        }
        Ok(())
    })?;
    Ok(binding.attempt_id)
}

#[derive(Debug, Clone)]
pub(super) struct EncodedTrapClaim {
    pub(super) kind: DreamerTrapKind,
    pub(super) attempt_id: AttemptId,
    pub(super) step_hash: [u8; 32],
    pub(super) state: DreamerTrapState,
    pub(super) at: u64,
    pub(super) note: String,
}

pub(super) fn encode_trap_claim_value(claim: &EncodedTrapClaim) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_TRAP_VALUE_SCHEMA_VERSION),
        ),
        (Value::from(KEY_TRAP_KIND), Value::from(claim.kind.as_str())),
        (
            Value::from(KEY_ATTEMPT_ID),
            Value::Binary(claim.attempt_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_STEP_HASH),
            Value::from(bytes_to_hex_lower(&claim.step_hash)),
        ),
        (Value::from(KEY_STATE), Value::from(claim.state.as_str())),
        (Value::from(KEY_AT), Value::from(claim.at)),
        (Value::from(KEY_NOTE), Value::from(claim.note.as_str())),
    ])
}

pub(crate) struct DecodedTrapClaim {
    pub(crate) kind: DreamerTrapKind,
    pub(crate) attempt_id: AttemptId,
    pub(crate) step_hash: [u8; 32],
    pub(crate) state: DreamerTrapState,
    pub(crate) note: String,
}

/// Fail-closed `dreamer.trap` claim value decode: pinned keys only, no
/// duplicates, schema-version checked, every field mandatory.
pub(crate) fn decode_trap_claim_value(value: &Value) -> Result<DecodedTrapClaim> {
    let entries = expect_map(value, "dreamer trap value must be a MessagePack map")?;
    let mut schema_version = None;
    let mut trap_kind = None;
    let mut attempt_id = None;
    let mut step_hash = None;
    let mut state = None;
    let mut at = None;
    let mut note = None;
    let mut seen = [false; DREAMER_TRAP_VALUE_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer trap value keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_TRAP_VALUE_KEYS)
            .ok_or(invalid_trap("dreamer trap value key is not pinned"))?;
        if seen[index] {
            return Err(invalid_trap("duplicate dreamer trap value key"));
        }
        seen[index] = true;

        match DREAMER_TRAP_VALUE_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer trap value schema_version must be an integer",
                )?);
            }
            KEY_TRAP_KIND => {
                let parsed = expect_string(value, "dreamer trap value trap_kind must be a string")?;
                trap_kind = Some(
                    DreamerTrapKind::parse(&parsed)
                        .ok_or(invalid_trap("unknown dreamer trap value trap_kind"))?,
                );
            }
            KEY_ATTEMPT_ID => attempt_id = Some(decode_attempt_id_value(value)?),
            KEY_STEP_HASH => {
                let hex = expect_string(value, "dreamer trap value step_hash must be a string")?;
                step_hash = Some(decode_hash_hex(&hex)?);
            }
            KEY_STATE => {
                let parsed = expect_string(value, "dreamer trap value state must be a string")?;
                state = Some(
                    DreamerTrapState::parse(&parsed)
                        .ok_or(invalid_trap("unknown dreamer trap value state"))?,
                );
            }
            KEY_AT => {
                at = Some(expect_u64(
                    value,
                    "dreamer trap value at must be an integer",
                )?);
            }
            KEY_NOTE => {
                note = Some(expect_string(
                    value,
                    "dreamer trap value note must be a string",
                )?);
            }
            _ => unreachable!("index resolved from DREAMER_TRAP_VALUE_KEYS"),
        }
    }

    let schema_version =
        schema_version.ok_or(invalid_trap("missing dreamer trap value schema_version"))?;
    if schema_version != DREAMER_TRAP_VALUE_SCHEMA_VERSION {
        return Err(invalid_trap(
            "unsupported dreamer trap value schema_version",
        ));
    }

    at.ok_or(invalid_trap("missing dreamer trap value at"))?;

    Ok(DecodedTrapClaim {
        kind: trap_kind.ok_or(invalid_trap("missing dreamer trap value trap_kind"))?,
        attempt_id: attempt_id.ok_or(invalid_trap("missing dreamer trap value job_id"))?,
        step_hash: step_hash.ok_or(invalid_trap("missing dreamer trap value step_hash"))?,
        state: state.ok_or(invalid_trap("missing dreamer trap value state"))?,
        note: note.ok_or(invalid_trap("missing dreamer trap value note"))?,
    })
}

/// Walks forward from any claim in a trap chain to the current head by
/// following inbound `Supersedes` edges (superseder → superseded).
pub(super) fn trap_head(vault: &Vault, anchor: &EntityId) -> Result<(EntityId, DecodedTrapClaim)> {
    let mut current = *anchor;
    for _ in 0..TRAP_CHAIN_WALK_CAP {
        let superseder = vault
            .edges_in(&current)?
            .into_iter()
            .find(|edge| edge.kind == EdgeKind::Supersedes)
            .map(|edge| edge.target);
        match superseder {
            Some(next) => current = next,
            None => {
                let body = vault
                    .get_claim(&current)?
                    .ok_or(invalid_trap("dreamer trap record missing"))?;
                if body.predicate != DREAMER_TRAP_PREDICATE {
                    return Err(invalid_trap("dreamer trap head is not a trap record"));
                }
                return Ok((current, decode_trap_claim_value(&body.value)?));
            }
        }
    }
    Err(invalid_trap("dreamer trap supersession chain too deep"))
}

/// Walks backward from `head` via outbound `Supersedes` edges and requires
/// reaching `anchor` (the run's `created` record). A sent record that does
/// not chain to this run's anchor is stale.
fn require_lineage_chains_to_anchor(
    vault: &Vault,
    head: &EntityId,
    anchor: &EntityId,
) -> Result<()> {
    let mut current = *head;
    for _ in 0..TRAP_CHAIN_WALK_CAP {
        if current == *anchor {
            return Ok(());
        }
        let superseded = vault
            .edges_out(&current)?
            .into_iter()
            .find(|edge| edge.kind == EdgeKind::Supersedes)
            .map(|edge| edge.target);
        match superseded {
            Some(next) => current = next,
            None => return Err(invalid_trap("dreamer trap signal not chained to this trap")),
        }
    }
    Err(invalid_trap("dreamer trap supersession chain too deep"))
}

/// Appends one trap state transition: writes the next-state claim and
/// supersedes the current head in ONE wtxn. Illegal transitions are typed
/// rejects and write nothing.
fn append_trap_transition(
    vault: &Vault,
    head_id: &EntityId,
    head: &DecodedTrapClaim,
    next: DreamerTrapState,
    now: u64,
    note_override: Option<&str>,
) -> Result<EntityId> {
    vault.with_write_txn(|wtxn| {
        append_trap_transition_in_txn(vault, wtxn, head_id, head, next, now, note_override)
    })
}

/// Transaction-composable body of [`append_trap_transition`], so the consume
/// path can co-commit the transition with the `resume_parked` un-park.
fn append_trap_transition_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    head_id: &EntityId,
    head: &DecodedTrapClaim,
    next: DreamerTrapState,
    now: u64,
    note_override: Option<&str>,
) -> Result<EntityId> {
    if !head.state.may_transition_to(next) {
        return Err(invalid_trap("illegal dreamer trap state transition"));
    }
    let head_body = vault
        .get_claim(head_id)?
        .ok_or(invalid_trap("dreamer trap record missing"))?;
    let envelope = envelope_from_claim_body(&head_body)?;
    let subject = match head_body.subject {
        ClaimSubject::Entity(entity) => entity,
        ClaimSubject::Edge { .. } => {
            return Err(invalid_trap("dreamer trap subject must be an entity"));
        }
    };

    let claim_id = EntityId::now();
    let value = encode_trap_claim_value(&EncodedTrapClaim {
        kind: head.kind,
        attempt_id: head.attempt_id,
        step_hash: head.step_hash,
        state: next,
        at: now,
        note: note_override.map_or_else(|| head.note.clone(), str::to_owned),
    });
    let candidate = ClaimCandidate::new(
        DREAMER_TRAP_PREDICATE,
        ClaimSubject::Entity(subject),
        value,
        1.0,
    );
    let occurred = TimeRange {
        start: now,
        end: now,
    };
    vault
        .batch_in()
        .claim_candidate(&claim_id, candidate, &envelope, occurred, now)
        .apply(wtxn)?;
    vault.supersede_claim_in_txn(wtxn, &claim_id, head_id, now)?;
    Ok(claim_id)
}

/// Rebuilds the runtime write envelope from a trap claim's envelope-stamped
/// evidence map (actor ref + class + provenance), so transitions carry the
/// same actor identity as the record they supersede.
pub(super) fn envelope_from_claim_body(body: &ClaimBody) -> Result<WriteEnvelope> {
    let Some(Value::Map(entries)) = &body.evidence else {
        return Err(invalid_trap(
            "dreamer trap record missing envelope evidence",
        ));
    };
    let mut actor_ref = None;
    let mut actor_class = None;
    let mut provenance = None;
    for (key, value) in entries {
        match key.as_str() {
            Some(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY) => {
                if let Value::Binary(bytes) = value
                    && let Ok(raw) = <[u8; 16]>::try_from(bytes.as_slice())
                {
                    actor_ref = EntityId::from_bytes(raw).ok();
                }
            }
            Some(WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY) => {
                actor_class = value
                    .as_u64()
                    .and_then(|raw| u8::try_from(raw).ok())
                    .and_then(EdgeActorClass::try_from_u8);
            }
            Some(WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY) => provenance = Some(value.clone()),
            _ => {}
        }
    }
    let actor_ref = actor_ref.ok_or(invalid_trap("dreamer trap evidence missing actor"))?;
    let actor_class =
        actor_class.ok_or(invalid_trap("dreamer trap evidence missing actor class"))?;
    let provenance = provenance.ok_or(invalid_trap("dreamer trap evidence missing provenance"))?;
    Ok(WriteEnvelope::new(
        WriteActor::new(actor_ref, actor_class),
        ClaimSource::Generated,
        WriteProvenance::new(provenance)?,
        ClaimApprovalStatus::Proposed,
    ))
}
