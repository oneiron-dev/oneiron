//! Typing-only rungs read per TURN (FIX 14711). A span that owes only its
//! typing rung no longer queues a job of its own: its TURN's one carrier
//! asks every such span of that TURN in packs, as many spans to a call as
//! the questions-per-call row takes, and each span's reading lands on its
//! own, exactly as a single rung's does. Every span in one call is the same
//! TURN's, so the call's subject owns all the words it read and an erase of
//! that TURN takes its step state as before. Audits, both-rung spans and the
//! follower's novelty keep their own paths.

use std::collections::BTreeSet;

use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::{
    DreamerAttemptPayload, DreamerAttemptStatus, DreamerConsolidationScope, DreamerRunnerStore,
};
use crate::{EntityId, Error, Result, Vault};
use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::super::{SieveRung, SieveSpan};
use super::{
    QUEUE, RungEvidence, RungInput, SPANS, WakeRecipePolicy, chunks, rung_evidence_in_txn,
};

/// The carrier's attempt type: a Micro job, one queued per TURN.
pub(crate) const TYPING_BATCH_ATTEMPT: &str = "dreamer.sieve.typing_batch";

const MEMBER_DOMAIN: &[u8] = b"oneiron:dreamer-sieve:typing-member:v1";

/// The carrier's input: the TURN whose typing-only spans it reads.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TypingBatchInput {
    turn: String,
}

fn invalid() -> Error {
    Error::InvalidConfig("invalid sieve typing batch payload".into())
}

/// Whether `span` owes its typing rung and nothing else.
pub(crate) fn typing_only(span: &SieveSpan) -> bool {
    span.owed == [SieveRung::Typing]
}

/// Queues `span`'s TURN carrier under `parent`, deduped: one waits per
/// TURN, and the carrier reads the span from the queue when it runs.
pub(crate) fn route_typing_in_txn(
    store: &DreamerRunnerStore<'_>,
    txn: &mut heed::RwTxn<'_>,
    parent: &DreamerAttemptStatus,
    span: &SieveSpan,
    now: u64,
) -> Result<()> {
    let turn = span.turn.to_hex();
    let input =
        serde_json::to_string(&TypingBatchInput { turn: turn.clone() }).map_err(|_| invalid())?;
    store.enqueue_kind_in_txn(
        txn,
        DreamerConsolidationScope::Micro.attempt_kind(),
        DreamerAttemptPayload {
            attempt_type: TYPING_BATCH_ATTEMPT.into(),
            input: Value::from(input),
            parent_attempt: Some(parent.attempt.id),
        },
        Some(format!("sieve:typing:{turn}")),
        parent.attempt.run_id.clone(),
        now,
    )?;
    Ok(())
}

/// The TURN a carrier's `input` names.
pub(crate) fn typing_batch_turn(input: &Value) -> Result<EntityId> {
    let input: TypingBatchInput =
        serde_json::from_str(input.as_str().ok_or_else(invalid)?).map_err(|_| invalid())?;
    EntityId::from_hex(&input.turn).map_err(|_| invalid())
}

/// One typing-only span the carrier reads: its rung input, as its own job
/// would have carried it, and the evidence its read pins.
pub(crate) struct TypingMember {
    pub(crate) input: RungInput,
    pub(crate) evidence: RungEvidence,
}

/// What a carrier finds of its TURN's typing-only spans in one snapshot.
pub(crate) struct TypingMembers {
    /// The spans whose evidence pins, in queue order: highest score first.
    pub(crate) ready: Vec<TypingMember>,
    /// The spans whose source is withheld or changed under them: each waits
    /// out its retry delay, as a single rung's withheld source does.
    pub(crate) withheld: Vec<[u8; 32]>,
}

/// `turn`'s queued typing-only spans, in queue order, but those in `held`
/// (the spans this carrier run already set aside). A span its TURN or
/// source no longer admits stays queued and is not served, as the
/// continuous selection leaves it.
pub(crate) fn typing_members(
    vault: &Vault,
    turn: &EntityId,
    held: &BTreeSet<[u8; 32]>,
    policy: &WakeRecipePolicy,
) -> Result<TypingMembers> {
    vault.store.authorization_now()?;
    let txn = vault.store.env.read_txn()?;
    let mut spans = Vec::new();
    for (_, key) in SPANS.scan_keys(&vault.store, &txn, turn.as_bytes())? {
        let Some(span) = QUEUE.get(&vault.store, &txn, &key)? else {
            continue;
        };
        if span.turn == *turn && typing_only(&span) && !held.contains(&span.id) {
            spans.push(span);
        }
    }
    let pairs = spans
        .iter()
        .map(|span| (span.turn, span.source))
        .collect::<Vec<_>>();
    let admission = chunks::admissions_in_txn(vault, &txn, &pairs)?;
    let mut members = TypingMembers {
        ready: Vec::new(),
        withheld: Vec::new(),
    };
    for (span, admission) in spans.into_iter().zip(admission) {
        if admission != chunks::Admission::Readable {
            continue;
        }
        let input = RungInput {
            span,
            audit: false,
            policy: policy.clone(),
        };
        match rung_evidence_in_txn(vault, &txn, &input)? {
            Some(evidence) => members.ready.push(TypingMember { input, evidence }),
            None => members.withheld.push(input.span.id),
        }
    }
    Ok(members)
}

/// The key a member's reading is kept under in the audit table: its
/// carrier and its span, never a queued attempt of its own. The carrier
/// reads many spans, so each keeps its own receipt.
pub(crate) fn typing_member_key(carrier: AttemptId, span: &SieveSpan) -> Result<AttemptId> {
    let hash = blake3::Hasher::new()
        .update(MEMBER_DOMAIN)
        .update(carrier.as_bytes())
        .update(&span.id)
        .finalize();
    Ok(AttemptId::from_bytes(&hash.as_bytes()[..16])?)
}
