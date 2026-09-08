//! Projecting the `skill.reliability` claim from the outcome ledger, including the imported base.

use std::collections::HashMap;

use rmpv::Value;

use crate::Vault;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::skill_attribution::{AttributionJudgment, AttributionVerdict, attribution_judgments};
use crate::temporal::TimeRange;

use super::codec::{
    ENTITY_ID_LEN, KEY_SCHEMA_VERSION, decode_value, encode_value, invalid, map_u64,
};
use super::floor::floor_check_in_txn;
use super::ledger::{
    outcome_key, receipt_manifest_names_skill, record_outcome_in_txn, tally_outcomes,
};
use super::posterior::{
    KEY_ALPHA, KEY_BETA, SKILL_RELIABILITY_SCHEMA_VERSION, SkillReliabilityPosterior,
};
use super::provenance::skill_reliability_prior;
use super::read::active_reliability_heads_in_txn;

/// The §G.1 predicate this module projects. Reserved `skill.*` namespace:
/// public claim writes are rejected, and the rows land through the
/// engine-owned reserved door.
pub const PREDICATE_SKILL_RELIABILITY: &str = "skill.reliability";

/// `skill_reliability:imported_base:v1:` + skill id (16 B).
///
/// The α, β a synced claim carried that this vault's outcome ledger cannot
/// reproduce. Node-local like the ledger it completes — this row is a record of
/// what arrived, not a fact about the skill, so it never travels.
const IMPORTED_BASE_PREFIX: &[u8] = b"skill_reliability:imported_base:v1:";

// ---------------------------------------------------------------------------
// Projector
// ---------------------------------------------------------------------------

/// Projects `skill.reliability` over one SK-04 attribution pass.
///
/// Records the defect losses those judgments carry and re-projects every skill
/// they touched, returning those skills in first-seen order. Lapse and
/// discovery judgments are read and deliberately contribute nothing.
///
/// Each skill is recorded and projected in ONE write transaction, so a skill's
/// outcome rows and its claim never disagree. Across skills the pass is
/// resumable rather than atomic: the posterior is RECOMPUTED from the outcome
/// ledger every time, so an interrupted pass leaves stale claims that the next
/// pass corrects — never double-counted ones.
///
/// **Every judgment is re-grounded here, not trusted.** [`AttributionJudgment`]
/// is a public type with public fields, so the argument is caller-owned data —
/// and this function authors reserved `skill.*` truth through the engine-owned
/// door. So a row counts only if it IS the row ONE-1737's projector persisted
/// at that sequence (`attribution_judgments` is the stack seam, and the seam is
/// over PERSISTED judgments) and its citation resolves to a real pack receipt
/// whose manifest loaded this skill — the same grounding
/// [`record_skill_contributing_win`] runs on the α side. Ungrounded rows are
/// SKIPPED rather than fatal: one forged row must not deny a whole pass.
pub fn project_skill_reliability(
    vault: &Vault,
    judgments: &[AttributionJudgment],
) -> Result<Vec<EntityId>> {
    let persisted = persisted_judgments_by_sequence(vault)?;
    let mut batches: Vec<(EntityId, Vec<&AttributionJudgment>)> = Vec::new();
    for judgment in judgments {
        if judgment.verdict != AttributionVerdict::SkillDefect {
            continue;
        }
        // The subject of a defect verdict is a SKILL by SK-04's routing, but a
        // projector that trusts that without checking would mint a reliability
        // claim on whatever entity a malformed row named.
        let Some(record) = vault.get_skill_record(&judgment.subject)? else {
            continue;
        };
        // A judgment with nothing to cite cannot be counted: the row it would
        // write has no key, and a loss with no trace is the thing the doctrine
        // header exists to refuse.
        let Some(receipt_ref) = judgment.evidence_receipts.first() else {
            continue;
        };
        // …and a citation that names no stamped receipt, or a receipt whose
        // pack never loaded this skill, is a trace only in shape.
        let Some(receipt) = crate::receipt::attempt_pack_receipt(vault, receipt_ref)? else {
            continue;
        };
        if !receipt_manifest_names_skill(&receipt, &record) {
            continue;
        }
        // Grounded — but grounding is not authorization. This row must also BE
        // the row ONE-1737's projector routed at this sequence.
        if persisted.get(&judgment.sequence) != Some(judgment) {
            continue;
        }
        match batches.iter_mut().find(|(id, _)| *id == judgment.subject) {
            Some((_, rows)) => rows.push(judgment),
            None => batches.push((judgment.subject, vec![judgment])),
        }
    }

    let mut projected = Vec::with_capacity(batches.len());
    for (skill, rows) in batches {
        let at = rows.iter().map(|row| row.at).max().unwrap_or_default();
        let prior = skill_reliability_prior(vault, &skill)?;
        vault.with_write_txn(|wtxn| {
            for row in &rows {
                // ONE judgment is ONE attributed outcome, so it writes ONE row.
                // `evidence_receipts` is a list because the type is general —
                // SK-04 emits a single receipt per routed outcome — and keying
                // on each element would turn one multi-cited outcome into
                // several losses.
                let receipt = row
                    .evidence_receipts
                    .first()
                    .ok_or(invalid("a reliability loss must cite a receipt"))?;
                record_outcome_in_txn(vault, wtxn, &skill, receipt, false, row.at)?;
            }
            project_in_txn(vault, wtxn, &skill, prior, at)
        })?;
        projected.push(skill);
    }
    Ok(projected)
}

/// Re-projects ONE skill's reliability claim from the outcome ledger.
///
/// The entry point for skills whose evidence is wins only — a skill that has
/// never been blamed still has a posterior, and it is not the attribution
/// projector's job to say so.
pub fn project_skill_reliability_for(
    vault: &Vault,
    skill: &EntityId,
    at: u64,
) -> Result<SkillReliabilityPosterior> {
    let prior = skill_reliability_prior(vault, skill)?;
    vault.with_write_txn(|wtxn| project_in_txn(vault, wtxn, skill, prior, at))
}

fn project_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    skill: &EntityId,
    prior: SkillReliabilityPosterior,
    at: u64,
) -> Result<SkillReliabilityPosterior> {
    let heads = active_reliability_heads_in_txn(vault, wtxn, skill)?;
    let base = projection_base_in_txn(vault, wtxn, skill, prior, &heads)?;
    let tally = tally_outcomes(vault, wtxn, skill)?;
    let posterior = tally.posterior(base);
    let evidence = Value::Array(
        tally
            .cited
            .iter()
            .map(|receipt| Value::from(receipt.as_str()))
            .collect(),
    );

    // Convergence, not just currency: ONE head that already says exactly this
    // is the no-op case, but TWO heads is a fork that must collapse even when
    // the winning value is unchanged.
    let unchanged = match heads.as_slice() {
        [(_, body, _)] => {
            body.value == posterior.to_value() && body.evidence.as_ref() == Some(&evidence)
        }
        _ => false,
    };
    if !unchanged {
        let claim_id = EntityId::now();
        let mut body = ClaimBody::new(
            PREDICATE_SKILL_RELIABILITY,
            ClaimSubject::Entity(*skill),
            posterior.to_value(),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.evidence = Some(evidence);
        body.source = Some(ClaimSource::Observed);
        vault.put_reserved_claim_in_txn(
            wtxn,
            &claim_id,
            &body,
            TimeRange { start: at, end: at },
            at,
        )?;
        // EVERY active head is superseded, not just the first one found.
        // `EntityId::now()` is per-replica unique, so two replicas that both
        // projected this skill hold two distinct claim entities; after a sync
        // both are Active, and superseding one of them leaves the other active
        // forever. Same shape as the scan-verdict precedent in `skill_hub`,
        // including its `superseded_at` clamp: `supersede_reserved_claim_in_txn`
        // re-Puts the old row over `{start: old_start, end: now}`, and an
        // out-of-order event time would make that range invalid and roll the
        // whole transaction back — permanently, since the retry re-derives the
        // same `at`.
        for (head_id, _, head_start) in &heads {
            vault.supersede_reserved_claim_in_txn(wtxn, &claim_id, head_id, at.max(*head_start))?;
        }
    }

    // Cache follows truth, in the same transaction that moved truth.
    vault.refresh_skill_confidence_cache_in_txn(
        wtxn,
        skill,
        posterior.mean(),
        TimeRange { start: at, end: at },
        at,
    )?;
    floor_check_in_txn(
        vault,
        wtxn,
        skill,
        posterior,
        attributed_outcomes(prior, posterior),
        at,
    )?;
    Ok(posterior)
}

/// The α, β the local outcome ledger is folded ON TOP of.
///
/// Sync carries entities, edges and tombstones — `vault_meta` outcome rows
/// stay node-local, so a replica that receives another's reliability CLAIM
/// receives the posterior but none of the outcomes underneath it. Recomputing
/// `prior + local tally` and superseding that claim would DESTROY the other
/// replica's history with one local loss.
///
/// So a head citing receipts this vault holds no outcome rows for is history
/// this ledger cannot reproduce: its α, β becomes the base, and the local tally
/// folds onto it. The base is persisted (node-local, like the ledger it
/// completes) because the head that carried it is superseded moments later —
/// and because the claim body is pinned to `{alpha, beta}`, so it has nowhere
/// else to live. Claims THIS replica writes cite only local receipts, so they
/// never re-enter as a base and the fold cannot double-count itself.
///
/// The honest bound: this converges history INTO a replica, not between two
/// replicas that each attribute outcomes the other never sees. Cross-replica
/// exactness needs per-outcome identity on the wire (the outcome rows
/// themselves), which is a sync-scope change, not a projector one.
fn projection_base_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    skill: &EntityId,
    prior: SkillReliabilityPosterior,
    heads: &[(EntityId, ClaimBody, u64)],
) -> Result<SkillReliabilityPosterior> {
    let mut base = read_imported_base_in_txn(vault, wtxn, skill)?;
    let mut imported = None;
    for (_, body, _) in heads {
        if !cites_receipts_absent_locally(vault, wtxn, skill, body)? {
            continue;
        }
        let candidate = SkillReliabilityPosterior::from_value(&body.value)?;
        // The richest head wins: more pseudo-observations is strictly more
        // history, and picking by weight is order-independent where picking
        // by arrival is not.
        if base.is_none_or(|held| candidate.observations() > held.observations()) {
            base = Some(candidate);
            imported = Some(candidate);
        }
    }
    if let Some(imported) = imported {
        write_imported_base_in_txn(vault, wtxn, skill, imported)?;
    }
    Ok(base.unwrap_or(prior))
}

/// True when the claim rests on at least one receipt the local outcome ledger
/// has no row for — the mark of a posterior projected somewhere else.
fn cites_receipts_absent_locally(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
    body: &ClaimBody,
) -> Result<bool> {
    let Some(Value::Array(cited)) = body.evidence.as_ref() else {
        return Ok(false);
    };
    for receipt in cited {
        let Some(receipt) = receipt.as_str() else {
            continue;
        };
        if vault
            .store
            .vault_meta
            .get(rtxn, &outcome_key(skill, receipt))?
            .is_none()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn read_imported_base_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<Option<SkillReliabilityPosterior>> {
    let Some(raw) = vault
        .store
        .vault_meta
        .get(rtxn, &imported_base_key(skill))?
    else {
        return Ok(None);
    };
    let value = decode_value(&raw)?;
    if map_u64(&value, KEY_SCHEMA_VERSION) != Some(SKILL_RELIABILITY_SCHEMA_VERSION) {
        return Err(invalid(
            "unsupported skill reliability imported-base schema",
        ));
    }
    SkillReliabilityPosterior::from_value(&value).map(Some)
}

fn write_imported_base_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    skill: &EntityId,
    base: SkillReliabilityPosterior,
) -> Result<()> {
    let row = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(SKILL_RELIABILITY_SCHEMA_VERSION),
        ),
        (Value::from(KEY_ALPHA), Value::F32(base.alpha)),
        (Value::from(KEY_BETA), Value::F32(base.beta)),
    ]);
    let encoded = encode_value(&row)?;
    vault
        .store
        .vault_meta
        .put(wtxn, &imported_base_key(skill), &encoded)?;
    Ok(())
}

fn imported_base_key(skill: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(IMPORTED_BASE_PREFIX.len() + ENTITY_ID_LEN);
    key.extend_from_slice(IMPORTED_BASE_PREFIX);
    key.extend_from_slice(skill.as_bytes());
    key
}

/// Attributed outcomes carried by a posterior: the pseudo-observation weight it
/// holds ABOVE its prior.
///
/// Derived rather than counted, because the local outcome ledger is not the
/// whole story on a replica — a synced posterior carries outcomes whose rows
/// never travelled. Equals the local tally exactly whenever it is the whole
/// story, so the pure-local reading is unchanged.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "float-to-int saturates in Rust; the weight is clamped non-negative first"
)]
pub(super) fn attributed_outcomes(
    prior: SkillReliabilityPosterior,
    posterior: SkillReliabilityPosterior,
) -> u32 {
    (posterior.observations() - prior.observations())
        .round()
        .max(0.0) as u32
}

/// The ROUTED judgments ONE-1737 persisted, keyed by sequence.
///
/// Read once per pass rather than once per judgment: the seam is a prefix scan,
/// and a batch of N judgments must not cost N scans.
fn persisted_judgments_by_sequence(vault: &Vault) -> Result<HashMap<u64, AttributionJudgment>> {
    Ok(attribution_judgments(vault)?
        .into_iter()
        .map(|judgment| (judgment.sequence, judgment))
        .collect())
}
