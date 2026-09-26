//! Durable Dreamer milestone claims: the index doors, the F4 binding check,
//! and the pinned claim-value shape.

use crate::ports::EntityStoreRead;
use rmpv::Value;

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptRecord};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::claim::{ClaimBody, ClaimSubject};
use crate::entity_id::EntityId;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MACHINE};
use crate::side_table::{self, Raw, SideKey, SideTable};
use crate::store::Store;
use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::{WriteEnvelope, WriteProvenance};

use super::codec::{
    decode_attempt_id, decode_dreamer_attempt_payload, encode_attempt_id, expect_key, expect_map,
    expect_string, expect_u64, invalid_dreamer_runner, pinned_key_index,
};
use super::constants::{
    DREAMER_MILESTONE_PREDICATE, DREAMER_MILESTONE_VALUE_KEYS,
    DREAMER_MILESTONE_VALUE_SCHEMA_VERSION, DREAMER_RUNNER_ATTEMPT_KIND, KEY_AT, KEY_ATTEMPT_ID,
    KEY_MILESTONE, KEY_SCHEMA_VERSION,
};
use super::store::DreamerRunnerStore;
use super::types::{DreamerDurableMilestone, DreamerMilestoneClaim, DreamerMilestoneKind};

/// Marker that the one-time durable-milestone-index backfill pass has run.
pub(super) const MILESTONE_INDEX_BACKFILLED: SideTable<(), Vec<u8>, Raw> =
    SideTable::new(&side_table::DREAMER_MILESTONE_INDEX_BACKFILLED);
/// Durable milestone-index candidate row (empty-value marker) for an
/// attempt, ordered by (at, learned_at, claim_id); only indexed once the
/// milestone claim is bound to its attempt.
pub(super) const MILESTONE_INDEX_CANDIDATE: SideTable<MilestoneCandidateKey, (), Raw> =
    SideTable::new(&side_table::DREAMER_MILESTONE_INDEX_CANDIDATE);
/// Pointer from a milestone claim id back to its
/// [`MILESTONE_INDEX_CANDIDATE`] row key (the full stored key bytes).
pub(super) const MILESTONE_INDEX_CLAIM: SideTable<EntityId, Vec<u8>, Raw> =
    SideTable::new(&side_table::DREAMER_MILESTONE_INDEX_CLAIM);

/// `dreamer.milestone_index.v1.c:` row key: attempt id, then `(at,
/// learned_at, claim id)` — not a [`crate::side_table::FixedSideKey`] tuple
/// because four fixed-width parts need one more slot than the built-in
/// tuples spell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MilestoneCandidateKey {
    pub(super) attempt_id: AttemptId,
    pub(super) at: u64,
    pub(super) learned_at: u64,
    pub(super) claim_id: EntityId,
}

impl SideKey for MilestoneCandidateKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.attempt_id.encode_into(out);
        out.extend_from_slice(&self.at.to_be_bytes());
        out.extend_from_slice(&self.learned_at.to_be_bytes());
        self.claim_id.encode_into(out);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (attempt_bytes, rest) = bytes.split_at_checked(16)?;
        let (at_bytes, rest) = rest.split_at_checked(8)?;
        let (learned_bytes, claim_bytes) = rest.split_at_checked(8)?;
        Some(Self {
            attempt_id: AttemptId::decode_key(attempt_bytes)?,
            at: u64::from_be_bytes(at_bytes.try_into().ok()?),
            learned_at: u64::from_be_bytes(learned_bytes.try_into().ok()?),
            claim_id: EntityId::decode_key(claim_bytes)?,
        })
    }
}

impl From<&DreamerDurableMilestone> for MilestoneCandidateKey {
    fn from(milestone: &DreamerDurableMilestone) -> Self {
        Self {
            attempt_id: milestone.attempt_id,
            at: milestone.at,
            learned_at: milestone.learned_at,
            claim_id: milestone.claim_id,
        }
    }
}

impl DreamerRunnerStore<'_> {
    /// Returns the latest active/approved durable milestone for `attempt_id`.
    ///
    /// This is the coarse fallback surface for consumers that cannot reach the
    /// executing device's live ephemeral row.
    pub fn latest_durable_milestone(
        &self,
        attempt_id: AttemptId,
    ) -> Result<Option<DreamerDurableMilestone>> {
        let rtxn = self.vault.store.env.read_txn()?;
        if MILESTONE_INDEX_BACKFILLED.contains(&self.vault.store, &rtxn, &())? {
            return latest_indexed_dreamer_milestone(&self.vault.store, &rtxn, attempt_id);
        }
        drop(rtxn);

        let mut wtxn = self.vault.store.env.write_txn()?;
        if MILESTONE_INDEX_BACKFILLED.contains(&self.vault.store, &wtxn, &())? {
            drop(wtxn);
            let rtxn = self.vault.store.env.read_txn()?;
            return latest_indexed_dreamer_milestone(&self.vault.store, &rtxn, attempt_id);
        }
        let latest = backfill_dreamer_milestone_index(&self.vault.store, &mut wtxn, attempt_id)?;
        wtxn.commit()?;
        Ok(latest)
    }
}

pub(super) fn apply_milestone_claim_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt: &AttemptRecord,
    milestone: DreamerMilestoneClaim,
) -> Result<()> {
    let milestone = stamp_agent_dispatch_milestone(attempt, milestone)?;
    let value = dreamer_milestone_value(attempt.id, milestone.kind, milestone.occurred.start);
    let candidate = ClaimCandidate::new(
        DREAMER_MILESTONE_PREDICATE,
        ClaimSubject::Entity(milestone.subject),
        value,
        1.0,
    );
    vault
        .batch_in()
        .claim_candidate(
            &milestone.claim_id,
            candidate,
            &milestone.envelope,
            milestone.occurred,
            milestone.learned_at,
        )
        .apply(wtxn)
}

/// Milestones co-committed for an agent-dispatch attempt carry AUTHORITATIVE
/// attribution: the subject is stamped to the attempt id and the envelope
/// provenance's agent key is stamped from the dispatched payload's own
/// `agent_id`, never trusted from the caller — an admission milestone can
/// therefore not attribute another agent. Non-agent attempts pass through
/// unchanged.
fn stamp_agent_dispatch_milestone(
    attempt: &AttemptRecord,
    milestone: DreamerMilestoneClaim,
) -> Result<DreamerMilestoneClaim> {
    if attempt.kind != DREAMER_RUNNER_ATTEMPT_KIND {
        return Ok(milestone);
    }
    let Ok(payload) = decode_dreamer_attempt_payload(&attempt.payload) else {
        // A payload that fails the dreamer envelope decode errors moments
        // later in status decoding; the milestone stamp is not the door.
        return Ok(milestone);
    };
    if payload.attempt_type != crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE {
        return Ok(milestone);
    }
    let Some(agent_id) = crate::agent_dispatch::agent_dispatch_payload_agent_id(&payload) else {
        return Err(invalid_dreamer_runner(
            "agent dispatch payload is unattributable; refusing milestone claim",
        ));
    };
    let subject = EntityId::from_bytes(*attempt.id.as_bytes()).map_err(|_| {
        invalid_dreamer_runner("agent dispatch attempt id is not usable as a milestone subject")
    })?;
    let mut entries = match milestone.envelope.provenance().value() {
        Value::Map(entries) => entries
            .iter()
            .filter(|(key, _)| {
                key.as_str() != Some(crate::agent_dispatch::AGENT_DISPATCH_MILESTONE_AGENT_KEY)
            })
            .cloned()
            .collect::<Vec<_>>(),
        other => vec![(Value::from("caller"), other.clone())],
    };
    entries.push((
        Value::from(crate::agent_dispatch::AGENT_DISPATCH_MILESTONE_AGENT_KEY),
        Value::from(agent_id),
    ));
    let envelope = WriteEnvelope::new(
        milestone.envelope.actor(),
        milestone.envelope.source(),
        WriteProvenance::new(Value::Map(entries))?,
        milestone.envelope.approval(),
    );
    Ok(DreamerMilestoneClaim {
        subject,
        envelope,
        ..milestone
    })
}

pub(crate) fn index_dreamer_milestone_claim_for_put(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: &EntityId,
    body: &ClaimBody,
    learned_at: u64,
) -> Result<()> {
    deindex_dreamer_milestone_claim(store, wtxn, claim_id)?;

    let Some(milestone) = dreamer_milestone_from_claim_body(claim_id, body, learned_at) else {
        return Ok(());
    };

    // A milestone becomes durable-index visible only when it is BOUND to the
    // attempt it names — for EVERY milestone kind. A forged claim stays an
    // ordinary claim but never enters `latest_durable_milestone` (tolerant
    // skip, never a write error: replicated replay must not fail a peer's
    // write on local queue state).
    if !dreamer_milestone_attribution_is_bound(store, wtxn, milestone.attempt_id, body) {
        return Ok(());
    }

    let candidate_key = MilestoneCandidateKey::from(&milestone);
    MILESTONE_INDEX_CANDIDATE.put(store, wtxn, &candidate_key, &())?;
    MILESTONE_INDEX_CLAIM.put(
        store,
        wtxn,
        claim_id,
        &MILESTONE_INDEX_CANDIDATE.key_bytes(&candidate_key),
    )?;
    Ok(())
}

/// F4 binding check for the durable milestone index, applied to EVERY
/// milestone kind on every door that indexes (the `apply_put` hook and the
/// one-time backfill). Resolution ladder:
///
/// * no local queue row → NOT bound (fail closed). Queue rows are private
///   per-device runner state and are never sync-materialized, so a milestone
///   claim replicated from a peer has nothing local to bind against —
///   indexing it would let a peer's (or a forger's) claim decide this
///   device's resume point. `latest_durable_milestone` is only meaningful on
///   the device holding the row, so nothing legitimate is lost;
/// * unreadable/undecodable local row or payload → NOT bound (fail closed);
/// * non-dreamer or non-agent-dispatch attempt → bound (today's semantics for
///   milestones that carry no agent attribution);
/// * agent-dispatch attempt → bound only when ALL THREE bindings hold:
///   the claim's subject is the attempt id, its write envelope is a SYSTEM
///   (Dreamer bookkeeping) envelope, and its stamped attribution equals the
///   dispatched payload's `agent_id`.
fn dreamer_milestone_attribution_is_bound(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    attempt_id: AttemptId,
    body: &ClaimBody,
) -> bool {
    let attempt_hex = bytes_to_hex_lower(attempt_id.as_bytes());
    let record =
        match crate::attempt_queue::AttemptQueue::from_store(store).get_in_txn(txn, attempt_id) {
            Ok(Some(record)) => record,
            Ok(None) => {
                tracing::warn!(
                    attempt_id = %attempt_hex,
                    "milestone names an attempt with no local queue row; \
                     refusing durable index entry",
                );
                return false;
            }
            Err(error) => {
                tracing::warn!(
                    attempt_id = %attempt_hex,
                    %error,
                    "milestone attempt row read failed; refusing durable index entry",
                );
                return false;
            }
        };
    if record.kind != DREAMER_RUNNER_ATTEMPT_KIND {
        return true;
    }
    let Ok(payload) = decode_dreamer_attempt_payload(&record.payload) else {
        tracing::warn!(
            attempt_id = %attempt_hex,
            "milestone attempt payload failed to decode; refusing durable index entry",
        );
        return false;
    };
    if payload.attempt_type != crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE {
        return true;
    }
    let Some(expected) = crate::agent_dispatch::agent_dispatch_payload_agent_id(&payload) else {
        tracing::warn!(
            attempt_id = %attempt_hex,
            "agent dispatch payload is unattributable; refusing durable index entry",
        );
        return false;
    };

    // (1) Subject binding: the milestone must be about THIS attempt.
    let Ok(expected_subject) = EntityId::from_bytes(*attempt_id.as_bytes()) else {
        return false;
    };
    if body.subject != ClaimSubject::Entity(expected_subject) {
        tracing::warn!(
            attempt_id = %attempt_hex,
            "milestone subject is not the dispatched attempt id; \
             refusing durable index entry",
        );
        return false;
    }

    // (2) Envelope-actor binding: agent-dispatch milestones are runner
    // bookkeeping and ride the SYSTEM/Dreamer envelope (B1 (a)). This is
    // RESOLVED from the writer's stored entity, not trusted from the class
    // byte on the record: the milestone's stamped `actor_entity_ref` must
    // name a currently-stored MACHINE (the only System-capable kind), so an
    // agent-envelope milestone, a class-byte lie, or a writer whose entity
    // was deleted after the write all fail closed. (The residual — a genuine
    // MACHINE actor the manifest grants Auto — is the manifest boundary; see
    // the report. oneiron has no per-actor write authentication, so WHICH
    // system actor is Auto-granted is deployment policy.)
    match milestone_claim_envelope_writer_kind(store, txn, body) {
        Ok(Some(kind)) if kind == ENTITY_TYPE_MACHINE => {}
        other => {
            tracing::warn!(
                attempt_id = %attempt_hex,
                ?other,
                "milestone writer does not resolve to a stored MACHINE (system) \
                 actor; refusing durable index entry",
            );
            return false;
        }
    }

    // (3) Attribution binding: the stamped agent is the dispatched agent.
    match milestone_claim_agent_attribution(body) {
        Some(claimed) if claimed == expected => true,
        claimed => {
            tracing::warn!(
                attempt_id = %attempt_hex,
                expected,
                ?claimed,
                "milestone attribution does not match the dispatched agent; \
                 refusing durable index entry",
            );
            false
        }
    }
}

/// Reads the write-envelope evidence map a claim carries (`evid`).
fn milestone_claim_envelope_evidence(body: &ClaimBody) -> Option<&Vec<(Value, Value)>> {
    match body.evidence.as_ref() {
        Some(Value::Map(evidence)) => Some(evidence),
        _ => None,
    }
}

/// Resolves the STORED entity type of a milestone claim's write actor from
/// its stamped `actor_entity_ref` evidence — the resolved writer, not the
/// self-asserted class byte. `Ok(None)` when the evidence carries no actor
/// ref, the ref is malformed, or no entity is stored there (a deleted or
/// never-existent writer); the stored type byte otherwise. Read errors
/// propagate so the caller fails closed.
fn milestone_claim_envelope_writer_kind(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    body: &ClaimBody,
) -> Result<Option<u8>> {
    let Some(actor_ref) = milestone_claim_envelope_actor_ref(body) else {
        return Ok(None);
    };
    let Some(raw) = store
        .port_entity_record(txn, &actor_ref)?
        .map(|row| row.encode())
    else {
        return Ok(None);
    };
    Ok(EntityMetadataHeader::parse(&raw).map(|header| header.entity_type))
}

/// Reads the actor entity id stamped into a claim's write-envelope evidence.
fn milestone_claim_envelope_actor_ref(body: &ClaimBody) -> Option<EntityId> {
    milestone_claim_envelope_evidence(body)?
        .iter()
        .find_map(|(key, value)| {
            if key.as_str() != Some(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY) {
                return None;
            }
            let Value::Binary(bytes) = value else {
                return None;
            };
            let arr: [u8; 16] = bytes.as_slice().try_into().ok()?;
            EntityId::from_bytes(arr).ok()
        })
}

/// Reads the agent attribution a milestone claim carries in its stamped
/// write-envelope evidence (`evid.provenance.agent`).
fn milestone_claim_agent_attribution(body: &ClaimBody) -> Option<String> {
    let provenance = milestone_claim_envelope_evidence(body)?
        .iter()
        .find_map(|(key, value)| {
            (key.as_str() == Some(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY))
                .then_some(value)
        })?;
    let Value::Map(entries) = provenance else {
        return None;
    };
    entries.iter().find_map(|(key, value)| {
        (key.as_str() == Some(crate::agent_dispatch::AGENT_DISPATCH_MILESTONE_AGENT_KEY))
            .then(|| value.as_str().map(str::to_owned))
            .flatten()
    })
}

pub(crate) fn deindex_dreamer_milestone_claim(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: &EntityId,
) -> Result<()> {
    let Some(candidate_key) = MILESTONE_INDEX_CLAIM.get(store, &*wtxn, claim_id)? else {
        return Ok(());
    };
    // The stored pointer is always this door's own `key_bytes` output
    // (never sync-materialized, never peer-supplied), so the strip+decode
    // below only fails on in-process corruption; a failure there leaves the
    // candidate row behind rather than deleting the wrong one.
    if let Some(candidate) = candidate_key
        .strip_prefix(MILESTONE_INDEX_CANDIDATE.decl().prefix)
        .and_then(MilestoneCandidateKey::decode_key)
    {
        MILESTONE_INDEX_CANDIDATE.delete(store, wtxn, &candidate)?;
    }
    MILESTONE_INDEX_CLAIM.delete(store, wtxn, claim_id)?;
    Ok(())
}

fn latest_indexed_dreamer_milestone(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    attempt_id: AttemptId,
) -> Result<Option<DreamerDurableMilestone>> {
    let mut latest: Option<DreamerDurableMilestone> = None;
    // A lazy, per-row-tolerant iterator rather than `scan_from`: a malformed
    // candidate key (ONE-1288's corrupt-row fixture) must be skipped like
    // any other non-matching row, never abort the whole lookup.
    for row in MILESTONE_INDEX_CANDIDATE.iter_from(store, rtxn, attempt_id.as_bytes())? {
        let Ok((key, ())) = row else { continue };
        let Some(milestone) = indexed_dreamer_milestone_if_current(store, rtxn, &key, attempt_id)?
        else {
            continue;
        };
        latest = Some(milestone);
    }
    Ok(latest)
}

fn indexed_dreamer_milestone_if_current(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    key: &MilestoneCandidateKey,
    expected_attempt_id: AttemptId,
) -> Result<Option<DreamerDurableMilestone>> {
    if key.attempt_id != expected_attempt_id {
        return Ok(None);
    }
    let Some(raw) = store.port_entity_record(rtxn, &key.claim_id)? else {
        return Ok(None);
    };

    if raw.entity_type != ENTITY_TYPE_CLAIM
        || (raw.body.len() + crate::batch::ENTITY_METADATA_HEADER_LEN) == ENTITY_METADATA_HEADER_LEN
    {
        return Ok(None);
    }
    let Ok(body) = crate::claim::decode_claim_body(&raw.body, true) else {
        return Ok(None);
    };
    let Some(milestone) = dreamer_milestone_from_claim_body(&key.claim_id, &body, raw.learned_at)
    else {
        return Ok(None);
    };
    if milestone.attempt_id == key.attempt_id
        && milestone.at == key.at
        && milestone.learned_at == key.learned_at
        && milestone.claim_id == key.claim_id
    {
        Ok(Some(milestone))
    } else {
        Ok(None)
    }
}

fn backfill_dreamer_milestone_index(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    attempt_id: AttemptId,
) -> Result<Option<DreamerDurableMilestone>> {
    let mut milestones = Vec::new();
    for row in store.port_entity_records(&*wtxn)? {
        let (claim_id, row) = row?;
        if row.entity_type != ENTITY_TYPE_CLAIM || row.body.is_empty() {
            continue;
        }
        let body = crate::claim::decode_claim_body(&row.body, true)?;
        let Some(milestone) = dreamer_milestone_from_claim_body(&claim_id, &body, row.learned_at)
        else {
            continue;
        };
        // The one-time backfill is an indexing door like the `apply_put`
        // hook, so it runs the SAME binding check — otherwise a forged
        // milestone written before the index existed would be admitted by
        // the rebuild.
        if !dreamer_milestone_attribution_is_bound(store, &*wtxn, milestone.attempt_id, &body) {
            continue;
        }
        milestones.push(milestone);
    }

    let mut latest: Option<DreamerDurableMilestone> = None;
    for milestone in milestones {
        let candidate_key = MilestoneCandidateKey::from(&milestone);
        MILESTONE_INDEX_CANDIDATE.put(store, wtxn, &candidate_key, &())?;
        MILESTONE_INDEX_CLAIM.put(
            store,
            wtxn,
            &milestone.claim_id,
            &MILESTONE_INDEX_CANDIDATE.key_bytes(&candidate_key),
        )?;
        if milestone.attempt_id == attempt_id
            && latest.as_ref().is_none_or(|current| {
                (milestone.at, milestone.learned_at, milestone.claim_id)
                    > (current.at, current.learned_at, current.claim_id)
            })
        {
            latest = Some(milestone);
        }
    }
    MILESTONE_INDEX_BACKFILLED.put(store, wtxn, &(), &b"1".to_vec())?;
    Ok(latest)
}

fn dreamer_milestone_from_claim_body(
    claim_id: &EntityId,
    body: &ClaimBody,
    learned_at: u64,
) -> Option<DreamerDurableMilestone> {
    if body.predicate != DREAMER_MILESTONE_PREDICATE
        || body.approval != ClaimApprovalStatus::Approved
        || body.lifecycle != ClaimLifecycleStatus::Active
        || body.stale
    {
        return None;
    }
    let Ok((attempt_id, kind, at)) = decode_milestone_value(&body.value) else {
        return None;
    };
    Some(DreamerDurableMilestone {
        claim_id: *claim_id,
        attempt_id,
        kind,
        at,
        learned_at,
    })
}

/// The ONE home of the pinned `dreamer.job_milestone` claim-value shape
/// (`["schema_version","job_id","milestone","at"]`). Public so the agent
/// dispatch layer (and the DREAM execution loop) build milestone values here
/// instead of re-encoding the shape.
pub fn dreamer_milestone_value(
    attempt_id: AttemptId,
    kind: DreamerMilestoneKind,
    at: u64,
) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_MILESTONE_VALUE_SCHEMA_VERSION),
        ),
        (Value::from(KEY_ATTEMPT_ID), encode_attempt_id(attempt_id)),
        (Value::from(KEY_MILESTONE), Value::from(kind.as_str())),
        (Value::from(KEY_AT), Value::from(at)),
    ])
}

fn decode_milestone_value(value: &Value) -> Result<(AttemptId, DreamerMilestoneKind, u64)> {
    let entries = expect_map(value, "dreamer milestone value must be a MessagePack map")?;
    let mut schema_version = None;
    let mut attempt_id = None;
    let mut milestone = None;
    let mut at = None;
    let mut seen = [false; DREAMER_MILESTONE_VALUE_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer milestone value keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_MILESTONE_VALUE_KEYS).ok_or(
            invalid_dreamer_runner("dreamer milestone value key is not pinned"),
        )?;
        if seen[index] {
            return Err(invalid_dreamer_runner(
                "duplicate dreamer milestone value key",
            ));
        }
        seen[index] = true;

        match DREAMER_MILESTONE_VALUE_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer milestone value schema_version must be an integer",
                )?);
            }
            KEY_ATTEMPT_ID => attempt_id = Some(decode_attempt_id(value)?),
            KEY_MILESTONE => {
                let parsed =
                    expect_string(value, "dreamer milestone value milestone must be a string")?;
                milestone = Some(DreamerMilestoneKind::parse(&parsed).ok_or(
                    invalid_dreamer_runner("unknown dreamer milestone value milestone"),
                )?);
            }
            KEY_AT => {
                at = Some(expect_u64(
                    value,
                    "dreamer milestone value at must be an integer",
                )?);
            }
            _ => unreachable!("index resolved from DREAMER_MILESTONE_VALUE_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_dreamer_runner(
        "missing dreamer milestone value schema_version",
    ))?;
    if schema_version != DREAMER_MILESTONE_VALUE_SCHEMA_VERSION {
        return Err(invalid_dreamer_runner(
            "unsupported dreamer milestone value schema_version",
        ));
    }

    Ok((
        attempt_id.ok_or(invalid_dreamer_runner(
            "missing dreamer milestone value job_id",
        ))?,
        milestone.ok_or(invalid_dreamer_runner(
            "missing dreamer milestone value milestone",
        ))?,
        at.ok_or(invalid_dreamer_runner("missing dreamer milestone value at"))?,
    ))
}
