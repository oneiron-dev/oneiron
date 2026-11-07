//! The memo index of terminal `dreamer.step` claims: its keys, its admission
//! gate, its lookup and its deindex, moved out of `step_claim` for FIX 4816.
//! `step_claim` re-exports the names it held.
//!
//! FIX 4816: the index admits two producers, each by its stamped surface and
//! the exact job its value names. The Dreamer runner's durable step is one.
//! A self-written compaction's paid call, filed with its run's job and run
//! stamped, is the other, so a job and step hash find it. Only the runner's
//! own record replays as a memo, settles an owed call or backs a
//! step-derived effect (`step_claim_is_runner_execution`).

use super::super::ModelId;
use super::step_claim::{DecodedStepClaim, decode_step_claim_value};
use super::types::{
    COMPACTION_STEP_SURFACE, DREAMER_STEP_PREDICATE, ENVELOPE_PROVENANCE_ATTEMPT_KEY,
    ENVELOPE_PROVENANCE_RUN_KEY, ENVELOPE_PROVENANCE_SURFACE_KEY, KEY_PROGRESSION,
    STEP_HEX_DIGEST_LEN,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::claim::ClaimBody;
use crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
use crate::side_table::{self, Raw, SideKey, SideTable};
use crate::store::Store;
use crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY;
use rmpv::Value;

/// Key of one forward step-index row: id16(attempt) + hash32(step) -> claim id16.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct StepIndexKey {
    pub(super) attempt_id: AttemptId,
    pub(super) step_hash: [u8; 32],
}

impl SideKey for StepIndexKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.attempt_id.as_bytes());
        out.extend_from_slice(&self.step_hash);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (attempt, hash) = bytes.split_at_checked(16)?;
        Some(Self {
            attempt_id: AttemptId::from_bytes(attempt).ok()?,
            step_hash: hash.try_into().ok()?,
        })
    }
}

/// Key of the reverse "i:" sub-index row: claim id16 -> the forward row's full stored key
/// bytes. Both shapes share the `DREAMER_STEP_INDEX` declaration; they cannot collide because
/// a forward row's key is always 48 bytes (id16 + hash32) and a reverse row's is always 18
/// (`i:` + id16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct StepIndexClaimKey(pub(super) EntityId);

impl SideKey for StepIndexClaimKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(b"i:");
        out.extend_from_slice(self.0.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let rest = bytes.strip_prefix(b"i:")?;
        Some(Self(EntityId::from_bytes(rest.try_into().ok()?).ok()?))
    }
}

/// The forward memo-index row: (attempt, step hash) -> the claim id that answered it.
pub(super) const STEP_INDEX_FORWARD: SideTable<StepIndexKey, EntityId, Raw> =
    SideTable::new(&side_table::DREAMER_STEP_INDEX);
/// The reverse "i:" sub-index: claim id -> the forward row's full stored key bytes, so a
/// deindex can find (and verify) the forward row it must retire without knowing its key.
pub(super) const STEP_INDEX_CLAIM: SideTable<StepIndexClaimKey, Vec<u8>, Raw> =
    SideTable::new(&side_table::DREAMER_STEP_INDEX);

// ---------------------------------------------------------------------------
// Memo index maintenance (device-local; wired at the milestone hook points)
// ---------------------------------------------------------------------------
/// Indexes a `dreamer.step` claim into the private memo index inside the
/// caller's write txn. Twin of `index_dreamer_milestone_claim_for_put`;
/// non-Active/stale bodies deindex.
///
/// Active is NOT sufficient (ONE-1344): the memo index decides which stored
/// response a later `call_as_step` may return without spending, so only a
/// claim carrying a well-formed model binding AND a producer's provenance
/// that binds it to the job its own value names is admitted: the runner's,
/// or a compaction step's (FIX 4816). Anything else
/// (a forged body, a replicated peer row, a hand-written claim) stays an
/// ordinary claim and is deindexed here — a tolerant skip, never a write
/// error, so replay of a peer's write can never fail on local index policy.
pub(crate) fn index_dreamer_step_claim_for_put(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: &EntityId,
    body: &ClaimBody,
    _learned_at: u64,
) -> Result<()> {
    deindex_dreamer_step_claim(store, wtxn, claim_id)?;

    if body.predicate != DREAMER_STEP_PREDICATE
        || body.lifecycle != crate::claim::ClaimLifecycleStatus::Active
        || body.stale
    {
        return Ok(());
    }
    let Ok(decoded) = decode_step_claim_value(&body.value) else {
        return Ok(());
    };
    if step_claim_producer(&decoded, body).is_none() {
        return Ok(());
    }

    let forward_key = StepIndexKey {
        attempt_id: decoded.attempt_id,
        step_hash: decoded.step_hash,
    };
    STEP_INDEX_FORWARD.put(store, wtxn, &forward_key, claim_id)?;
    STEP_INDEX_CLAIM.put(
        store,
        wtxn,
        &StepIndexClaimKey(*claim_id),
        &STEP_INDEX_FORWARD.key_bytes(&forward_key),
    )?;
    Ok(())
}

/// Read-only consistency check for an ALREADY producer-attested terminal
/// step: the runner's or a compaction step's (FIX 4816). This does not
/// create execution authority; ordinary and replayed claims may pass this
/// shape check but cannot mint the vault-local witness.
pub(crate) fn terminal_step_identity(body: &ClaimBody) -> Option<(AttemptId, [u8; 32], ModelId)> {
    if body.predicate != DREAMER_STEP_PREDICATE
        || body.lifecycle != crate::claim::ClaimLifecycleStatus::Active
        || body.stale
    {
        return None;
    }
    let decoded = decode_step_claim_value(&body.value).ok()?;
    let finished = matches!(&body.value, Value::Map(entries) if entries.iter().any(|(key, value)|
        key.as_str() == Some(KEY_PROGRESSION) && value.as_str() == Some("finished")));
    if !finished || step_claim_producer(&decoded, body).is_none() {
        return None;
    }
    Some((
        decoded.attempt_id,
        decoded.step_hash,
        ModelId::new(decoded.model_id).ok()?,
    ))
}

/// The producer a terminal step claim's stamped provenance attests (FIX 4816).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StepClaimProducer {
    /// The Dreamer runner's durable step: the one producer a memo replays.
    Runner,
    /// A self-written compaction's paid call, filed under its run's job.
    Compaction,
}

/// Memo-index admission gate (ONE-1344, FIX 4816): the producer a claim
/// attests, or `None`. A claim is admitted to the index only when BOTH
/// bindings hold:
///
/// * WITH-WHAT identity present and well formed — a fully revisioned
///   `provider/name@revision` model id, a non-empty purpose, and a lowercase
///   hex params digest. This is exactly what the memo-hit branch compares the
///   live request against, so an unusable identity must never be indexed;
/// * producer binding — the stamped write-envelope provenance names a
///   producer's surface AND the SAME attempt id the claim value carries, so
///   a body cannot buy a memo row for a job it does not belong to. A
///   compaction step also carries the run its host stamped.
pub(super) fn step_claim_producer(
    decoded: &DecodedStepClaim,
    body: &ClaimBody,
) -> Option<StepClaimProducer> {
    if ModelId::new(decoded.model_id.clone()).is_err()
        || decoded.purpose.is_empty()
        || !is_lowercase_hex_digest(&decoded.params_hash)
    {
        return None;
    }
    step_claim_provenance_producer(body, decoded.attempt_id)
}

/// The execution gate (FIX 4816): true only for the Dreamer runner's own
/// record of its attempt's step. A memo replay, an owed call's settlement
/// and a step-derived effect read only such a claim. An indexed compaction
/// step is a miss there, never a refusal.
pub(super) fn step_claim_is_runner_execution(decoded: &DecodedStepClaim, body: &ClaimBody) -> bool {
    step_claim_producer(decoded, body) == Some(StepClaimProducer::Runner)
}

/// The producer the claim's stamped write-envelope provenance attests: a map
/// whose attempt id equals `attempt_id` and whose surface is the runner's,
/// or the compaction step's with a non-empty run.
fn step_claim_provenance_producer(
    body: &ClaimBody,
    attempt_id: AttemptId,
) -> Option<StepClaimProducer> {
    let Some(Value::Map(evidence)) = body.evidence.as_ref() else {
        return None;
    };
    let provenance = evidence.iter().find_map(|(key, value)| {
        (key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY)).then_some(value)
    });
    let Some(Value::Map(entries)) = provenance else {
        return None;
    };
    let field = |name: &str| {
        entries
            .iter()
            .find_map(|(key, value)| (key.as_str() == Some(name)).then_some(value))
            .and_then(Value::as_str)
    };
    let expected_attempt = bytes_to_hex_lower(attempt_id.as_bytes());
    if field(ENVELOPE_PROVENANCE_ATTEMPT_KEY) != Some(expected_attempt.as_str()) {
        return None;
    }
    let surface = field(ENVELOPE_PROVENANCE_SURFACE_KEY)?;
    if surface == DREAMER_RUNNER_ATTEMPT_KIND {
        Some(StepClaimProducer::Runner)
    } else if surface == COMPACTION_STEP_SURFACE
        && field(ENVELOPE_PROVENANCE_RUN_KEY).is_some_and(|run| !run.is_empty())
    {
        Some(StepClaimProducer::Compaction)
    } else {
        None
    }
}

/// True for a BLAKE3 digest rendered as 64 lowercase hex characters.
fn is_lowercase_hex_digest(value: &str) -> bool {
    value.len() == STEP_HEX_DIGEST_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Removes a claim's memo-index rows inside the caller's write txn.
pub(crate) fn deindex_dreamer_step_claim(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: &EntityId,
) -> Result<()> {
    let claim_key = StepIndexClaimKey(*claim_id);
    let Some(forward_key_bytes) = STEP_INDEX_CLAIM.get(store, wtxn, &claim_key)? else {
        return Ok(());
    };
    // Only delete the forward row if it still points at THIS claim.
    if let Some(forward_key) = forward_key_bytes
        .strip_prefix(STEP_INDEX_FORWARD.decl().prefix)
        .and_then(StepIndexKey::decode_key)
        && STEP_INDEX_FORWARD.get(store, wtxn, &forward_key)?.as_ref() == Some(claim_id)
    {
        STEP_INDEX_FORWARD.delete(store, wtxn, &forward_key)?;
    }
    STEP_INDEX_CLAIM.delete(store, wtxn, &claim_key)?;
    Ok(())
}

pub(super) fn step_index_lookup(
    vault: &Vault,
    attempt_id: AttemptId,
    step_hash: &[u8; 32],
) -> Result<Option<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    step_index_lookup_in_txn(vault, &rtxn, attempt_id, step_hash)
}

/// Forgets the memo in the caller's writer, so a charge-mark forget commits
/// beside it (FIX 7489). The terminal claim stays.
pub(crate) fn forget_step_memo_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt_id: AttemptId,
    step_hash: &[u8; 32],
) -> Result<()> {
    let Some(claim_id) = step_index_lookup_in_txn(vault, txn, attempt_id, step_hash)? else {
        return Ok(());
    };
    deindex_dreamer_step_claim(&vault.store, txn, &claim_id)
}

/// Forgets `attempt_id`'s memo of the step `step_hash`, so the attempt's next
/// call of that step asks its model again. The terminal claim stays; only the
/// index row that would replay it goes.
pub(crate) fn forget_step_memo(
    vault: &Vault,
    attempt_id: AttemptId,
    step_hash: &[u8; 32],
) -> Result<()> {
    vault.with_write_txn(|wtxn| forget_step_memo_in_txn(vault, wtxn, attempt_id, step_hash))
}

pub(super) fn step_index_lookup_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt_id: AttemptId,
    step_hash: &[u8; 32],
) -> Result<Option<EntityId>> {
    STEP_INDEX_FORWARD.get(
        &vault.store,
        txn,
        &StepIndexKey {
            attempt_id,
            step_hash: *step_hash,
        },
    )
}
