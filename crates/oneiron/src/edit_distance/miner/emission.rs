//! ED-04 preference-claim and skill-edit emission.

use rmpv::Value;

use super::config::{
    GATE_OUTCOME_REJECTED, MARK_KIND_PREFERENCE, MARK_KIND_SKILL_EDIT, MINED_EVIDENCE_RECEIPTS_KEY,
    MINED_EVIDENCE_ROW_LABEL, MINER_CLUSTER_HASH_DOMAIN, MINER_EVIDENCE_RECORD_ID_DOMAIN,
    MINER_PREFERENCE_CONFIDENCE, MINER_REJECTION_COOLDOWN_SECS, MINT_MARK_KEY_PREFIX,
    MINT_MARK_ROW_LABEL, PREDICATE_PREFERENCE_PHRASING, PREFERENCE_VALUE_KEY_CLASS,
    PREFERENCE_VALUE_KEY_FROM, PREFERENCE_VALUE_KEY_RATIONALE, PREFERENCE_VALUE_KEY_TO,
    PROVENANCE_KEY_CLUSTER, PROVENANCE_KEY_RUN, PROVENANCE_KEY_SESSION, PROVENANCE_KEY_SURFACE,
    ROW_VERSION, SKILL_EDIT_KEY_PREFIX, SKILL_EDIT_ROW_LABEL,
};
use super::mining::classify_substitution;
use super::model::{
    MinedOutcome, MinedSkillEditVerdict, MinerRun, StoredMinedEvidence, StoredMintMark,
    StoredSkillEdit, SubstitutionClass, SubstitutionCluster,
};
use super::store::{decode_row, encode_row, meta_key, mined_skill_edit_in_txn};
use crate::Vault;
use crate::actor_claims::edit_cost_scope;
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::dreamer_consolidation::{ConsolidationEvidenceEnvelope, encode_consolidation_evidence};
use crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_ASSET;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteEnvelope, WriteProvenance};

// ---------------------------------------------------------------------------
// The chooser
// ---------------------------------------------------------------------------

/// Rules on one at-threshold cluster, or declines.
pub(super) fn emit_cluster(
    vault: &Vault,
    run: &MinerRun,
    cluster: &SubstitutionCluster,
    now: u64,
) -> Result<Option<MinedOutcome>> {
    let handle = cluster_handle(cluster);
    match classify_substitution(&cluster.from, &cluster.to) {
        SubstitutionClass::Lexical => Ok(emit_preference_claim(vault, run, cluster, &handle, now)?
            .map(MinedOutcome::PreferenceClaim)),
        // A content correction with no skill to edit has no proposal to make.
        // No mint-mark is written, so the cluster is still eligible in a pass
        // where its amendments do name a skill.
        SubstitutionClass::Content => match cluster.skill {
            None => Ok(None),
            Some(skill) => Ok(emit_skill_edit(vault, cluster, skill, &handle, now)?
                .map(MinedOutcome::SkillEditProposal)),
        },
    }
}

/// Whether a cluster may propose: no mark, a mark whose proposal no longer
/// stands, or a rejection past its cooldown.
///
/// Takes the CALLER's transaction, and the caller is the emission's own write
/// transaction. Reading the marks in a transaction of its own would leave a
/// window between the answer and the write in which a second pass could get the
/// same answer, and two live proposals for one cluster is the exact state the
/// mint-marks exist to make impossible.
pub(super) fn cluster_is_eligible(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    handle: &[u8; 32],
    now: u64,
) -> Result<bool> {
    let Some(mark) = mint_mark_in_txn(vault, txn, handle)? else {
        return Ok(true);
    };
    let reference = EntityId::from_hex(&mark.reference)
        .map_err(|_| Error::CorruptedIndex(MINT_MARK_ROW_LABEL))?;
    match mark.kind.as_str() {
        MARK_KIND_SKILL_EDIT => skill_edit_is_stale(vault, txn, &reference, now),
        MARK_KIND_PREFERENCE => preference_is_stale(vault, txn, &reference, now),
        _ => Err(Error::CorruptedIndex(MINT_MARK_ROW_LABEL)),
    }
}

// ---------------------------------------------------------------------------
// Emission
// ---------------------------------------------------------------------------

/// Whether the skill-edit proposal a mark points at has stopped standing for
/// its cluster — the content arm's half of the hysteresis.
///
/// Deliberately the same three-way shape as [`preference_is_stale`], because it
/// is the same question. What differs is where the answer lives: a preference
/// claim is answered at the inbox door, which writes a tray row and a gate
/// decision, while a mined skill edit is answered at [`resolve_mined_skill_edit`],
/// which writes the verdict onto the proposal. A proposal that was ERASED
/// rather than answered frees its cluster: nothing stands, so there is nothing
/// left for the mark to speak for.
fn skill_edit_is_stale(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    proposal_id: &EntityId,
    now: u64,
) -> Result<bool> {
    let Some(proposal) = mined_skill_edit_in_txn(vault, txn, proposal_id)? else {
        return Ok(true);
    };
    let Some(decision) = proposal.decision else {
        // Open in front of the decider: the cluster has already spoken.
        return Ok(false);
    };
    match decision.verdict {
        // Applied. Re-proposing an edit the skill already carries is nagging.
        MinedSkillEditVerdict::Accepted => Ok(false),
        MinedSkillEditVerdict::Rejected => {
            Ok(now >= decision.at.saturating_add(MINER_REJECTION_COOLDOWN_SECS))
        }
    }
}

/// Whether the preference claim a mark points at has stopped standing for its
/// cluster.
///
/// The state does NOT live in the claim's `approval` field, and reading it there
/// would make the cooldown dead code: the inbox reject door closes the tray row
/// and appends a `rejected` gate decision, leaving the body exactly as Proposed
/// as it was. So the answer is assembled from the three places it actually is:
///
/// * gone — the claim was erased; nothing stands and the cluster is free;
/// * a PENDING gate consent — the question is still open in front of the
///   decider, and asking again is the nagging this exists to stop;
/// * `Approved`/`Auto` — the preference landed and is standing truth;
/// * otherwise the row was CLOSED without accepting, so the newest `rejected`
///   decision's own clock runs the cooldown.
///
/// A claim with no tray row, no acceptance and no rejection stays quiet. Its row
/// was consumed by something this module cannot read as an answer, and "no
/// answer I understand" is not a licence to re-propose.
fn preference_is_stale(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim_id: &EntityId,
    now: u64,
) -> Result<bool> {
    let Some(body) = vault.get_claim_in_txn(txn, claim_id)? else {
        return Ok(true);
    };
    if vault
        .store
        .pending_gate_consent_in_txn(txn, claim_id)?
        .is_some()
        || matches!(
            body.approval,
            ClaimApprovalStatus::Approved | ClaimApprovalStatus::Auto
        )
    {
        return Ok(false);
    }
    let rejected_at = vault
        .store
        .gate_decisions_for_claim_in_txn(txn, claim_id.as_bytes())?
        .iter()
        .filter(|decision| decision.outcome == GATE_OUTCOME_REJECTED)
        .map(|decision| decision.created_at)
        .max();
    Ok(rejected_at.is_some_and(|at| now >= at.saturating_add(MINER_REJECTION_COOLDOWN_SECS)))
}

/// Lands a mined preference claim through the write gate, with its mint-mark,
/// in ONE transaction — or declines, when that transaction finds the cluster
/// has already spoken.
///
/// `Proposed`, never `Auto`: a phrasing preference inferred from three
/// corrections is a reading of the decider's habit, and the decider is the one
/// who confirms it. The gate can only narrow a Proposed request, so the lane is
/// structural rather than a convention.
///
/// # The cluster is the evidence, so the cluster is persisted
///
/// A mined claim is Dreamer-authored, so the write door asks it to cite at
/// least one ref that RESOLVES. The miner's truthful evidence is the
/// at-threshold cluster itself — and its receipt ids are side-ledger strings
/// (`gate:<hex>`), never entities, so no resolver can ever follow one. The
/// cluster is therefore written as a typed record entity, in the SAME
/// transaction and BEFORE the candidate is gated, and the claim cites THAT.
/// The receipt ids stay in the record and beside the envelope for readers;
/// they are simply not what the floor resolves.
fn emit_preference_claim(
    vault: &Vault,
    run: &MinerRun,
    cluster: &SubstitutionCluster,
    handle: &[u8; 32],
    now: u64,
) -> Result<Option<EntityId>> {
    let claim_id = EntityId::now();
    let class = SubstitutionClass::Lexical;
    let envelope = miner_envelope(run, handle)?;
    let evidence_id = mined_evidence_record_id(handle)?;
    let evidence_record = encode_row(
        &StoredMinedEvidence::new(cluster, class),
        MINED_EVIDENCE_ROW_LABEL,
    )?;
    let candidate = ClaimCandidate::new(
        PREDICATE_PREFERENCE_PHRASING,
        ClaimSubject::Entity(cluster.actor),
        preference_value(cluster, class),
        MINER_PREFERENCE_CONFIDENCE,
    )
    .with_evidence(mined_evidence_candidate(cluster, evidence_id))
    .with_scope(edit_cost_scope(&cluster.scope))
    .with_validity(Some(cluster.at), None);
    let mark = encode_row(
        &StoredMintMark::new(MARK_KIND_PREFERENCE, &claim_id),
        MINT_MARK_ROW_LABEL,
    )?;
    let mark_key = mint_mark_key(handle);
    let occurred = TimeRange {
        start: cluster.at,
        end: cluster.at,
    };
    vault.with_write_txn(|wtxn| {
        if !cluster_is_eligible(vault, wtxn, handle, now)? {
            return Ok(None);
        }
        // FIRST, and in this transaction: the door validates the candidate
        // below against this very `wtxn`, so a record written after it — or in
        // a transaction of its own — is a ref the resolver cannot see.
        vault
            .batch_in()
            .put(
                &evidence_id,
                ENTITY_TYPE_ASSET,
                occurred,
                cluster.at,
                &evidence_record,
            )
            .apply(wtxn)?;
        vault
            .batch_in()
            .claim_candidate(&claim_id, candidate, &envelope, occurred, cluster.at)
            .apply_recording_gate_decisions(wtxn)?;
        vault.store.vault_meta.put(wtxn, &mark_key, &mark)?;
        Ok(Some(claim_id))
    })
}

/// The mined-evidence record's entity id, derived from the cluster's own
/// already domain-separated handle.
///
/// Deterministic, so one cluster has one record however many passes read it —
/// the mint-mark still decides whether a proposal is minted at all. A digest
/// landing on a reserved sentinel is re-salted rather than forced.
pub(super) fn mined_evidence_record_id(handle: &[u8; 32]) -> Result<EntityId> {
    for salt in 0..=u8::MAX {
        let mut hasher = blake3::Hasher::new();
        hasher.update(MINER_EVIDENCE_RECORD_ID_DOMAIN);
        hasher.update(&[salt]);
        hasher.update(handle);
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        if let Ok(id) = EntityId::from_bytes(bytes) {
            return Ok(id);
        }
    }
    Err(Error::InvariantViolation(
        "mined evidence record id derivation failed",
    ))
}

/// A mined claim's candidate evidence: the persisted cluster record in the ONE
/// envelope the GATE-12 floor decodes, with the citation array riding beside it
/// for readers.
///
/// `Inferred` is the lattice-truthful meet — a mined preference is derived from
/// repeated corrections, never stated. The floor reads `refs`/`chain`/
/// `source_meet` and ignores every other key, so the citations add no second
/// schema to it.
pub(super) fn mined_evidence_candidate(
    cluster: &SubstitutionCluster,
    record_id: EntityId,
) -> Value {
    let mut entries = match encode_consolidation_evidence(&ConsolidationEvidenceEnvelope {
        refs: vec![record_id],
        chain: Vec::new(),
        source_meet: ClaimSource::Inferred,
    }) {
        Value::Map(entries) => entries,
        // The encoder's contract is a map; anything else would carry no
        // admissible evidence, and the door would refuse the write.
        other => return other,
    };
    entries.push((
        Value::from(MINED_EVIDENCE_RECEIPTS_KEY),
        receipt_citations(cluster),
    ));
    Value::Map(entries)
}

/// Mints a gated skill-edit proposal with its mint-mark in ONE transaction — or
/// declines, on the same in-transaction dedup check the preference arm makes.
///
/// The proposal is a ROW, not an edit: the skill's content and every prior
/// version are untouched, exactly as `skill_attribution`'s discovery proposals
/// leave them. ONE-1448 consumes this class, and the apply door it goes through
/// is the gate.
fn emit_skill_edit(
    vault: &Vault,
    cluster: &SubstitutionCluster,
    skill: EntityId,
    handle: &[u8; 32],
    now: u64,
) -> Result<Option<EntityId>> {
    let proposal_id = EntityId::now();
    let class = SubstitutionClass::Content;
    let row = encode_row(
        &StoredSkillEdit {
            v: ROW_VERSION,
            skill: skill.to_hex(),
            scope: cluster.scope.clone(),
            from: cluster.from.clone(),
            to: cluster.to.clone(),
            evidence_receipts: cluster.receipt_refs.clone(),
            rationale: class.rationale().to_owned(),
            at: cluster.at,
            decision: None,
        },
        SKILL_EDIT_ROW_LABEL,
    )?;
    let mark = encode_row(
        &StoredMintMark::new(MARK_KIND_SKILL_EDIT, &proposal_id),
        MINT_MARK_ROW_LABEL,
    )?;
    let row_key = meta_key(SKILL_EDIT_KEY_PREFIX, proposal_id.as_bytes());
    let mark_key = mint_mark_key(handle);
    vault.with_write_txn(|wtxn| {
        if !cluster_is_eligible(vault, wtxn, handle, now)? {
            return Ok(None);
        }
        // Inside the transaction with the row it proposes to edit: a proposal
        // naming a skill that is not there is one ONE-1448 could only fail on.
        vault.read_skill_record_in_txn(&*wtxn, &skill)?;
        vault.store.vault_meta.put(wtxn, &row_key, &row)?;
        vault.store.vault_meta.put(wtxn, &mark_key, &mark)?;
        Ok(Some(proposal_id))
    })
}

/// The miner's write envelope: the caller's Agent actor, `Generated` source,
/// `Proposed` ceiling.
///
/// `Generated` because a mined preference is derived, never stated — which is
/// also what makes GATE-007 refuse to let it supersede anything the owner said.
/// The provenance is the shape `gate.rs::dreamer_run_id_from_provenance` parses
/// (`dreamer_promotion`'s precedent, verbatim on the two keys that matter), so
/// the pending row lands in the run's INBOX GROUP and the decider can answer it.
/// The extra `session` and `cluster` keys are this module's trace: a landed
/// claim resolves back to the exact bucket that earned it.
///
/// **No `session_tag`.** It looks like free review bundling and is in fact a
/// trap: a `sess`-carrying body may only be written by the envelope actor that
/// PRODUCED the session (`batch.rs`'s bound-producer rule), and the inbox accept
/// door re-puts the reviewed body RAW — so the tag would make the mined claim
/// impossible to accept. The run group already bundles the pass's proposals,
/// which is the job the tag would have done.
pub(super) fn miner_envelope(run: &MinerRun, handle: &[u8; 32]) -> Result<WriteEnvelope> {
    let provenance = WriteProvenance::new(Value::Map(vec![
        (
            Value::from(PROVENANCE_KEY_SURFACE),
            Value::from(DREAMER_RUNNER_ATTEMPT_KIND),
        ),
        (
            Value::from(PROVENANCE_KEY_RUN),
            Value::from(run.run_id.as_str()),
        ),
        (
            Value::from(PROVENANCE_KEY_SESSION),
            Value::from(run.session.to_hex()),
        ),
        (
            Value::from(PROVENANCE_KEY_CLUSTER),
            Value::from(bytes_to_hex_lower(handle)),
        ),
    ]))?;
    Ok(WriteEnvelope::new(
        run.agent,
        ClaimSource::Generated,
        provenance,
        ClaimApprovalStatus::Proposed,
    ))
}

/// The claim value: the pair, the class, and the chooser's receipted rationale.
///
/// The rationale rides the BODY rather than a receipt of its own: the miner
/// mints no receipt kind (a projector, not a door), and a claim a reader can
/// quote is a better record than a receipt nothing projects.
pub(super) fn preference_value(cluster: &SubstitutionCluster, class: SubstitutionClass) -> Value {
    Value::Map(vec![
        (
            Value::from(PREFERENCE_VALUE_KEY_FROM),
            Value::from(cluster.from.as_str()),
        ),
        (
            Value::from(PREFERENCE_VALUE_KEY_TO),
            Value::from(cluster.to.as_str()),
        ),
        (
            Value::from(PREFERENCE_VALUE_KEY_CLASS),
            Value::from(class.as_str()),
        ),
        (
            Value::from(PREFERENCE_VALUE_KEY_RATIONALE),
            Value::from(class.rationale()),
        ),
    ])
}

/// The citation array — trace-or-derivation, in the `skill.edit_cost` shape.
pub(super) fn receipt_citations(cluster: &SubstitutionCluster) -> Value {
    Value::Array(
        cluster
            .receipt_refs
            .iter()
            .map(|receipt| Value::from(receipt.as_str()))
            .collect(),
    )
}

/// The cluster's durable handle: a domain-separated hash of its whole identity.
///
/// Hashed rather than concatenated because the scope and both substitution
/// sides are text of unbounded length, and an LMDB key is not. The domain keeps
/// the digest from ever being read as another unit's.
pub(super) fn cluster_handle(cluster: &SubstitutionCluster) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MINER_CLUSTER_HASH_DOMAIN);
    for part in [
        cluster.scope.as_bytes(),
        cluster.actor.as_bytes(),
        cluster.from.as_bytes(),
        cluster.to.as_bytes(),
    ] {
        hasher.update(&[0]);
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn mint_mark_key(handle: &[u8; 32]) -> Vec<u8> {
    meta_key(MINT_MARK_KEY_PREFIX, handle)
}

pub(super) fn mint_mark_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    handle: &[u8; 32],
) -> Result<Option<StoredMintMark>> {
    let Some(raw) = vault.store.vault_meta.get(txn, &mint_mark_key(handle))? else {
        return Ok(None);
    };
    let row: StoredMintMark = decode_row(&raw, MINT_MARK_ROW_LABEL)?;
    if row.v != ROW_VERSION {
        return Err(Error::CorruptedIndex(MINT_MARK_ROW_LABEL));
    }
    Ok(Some(row))
}
