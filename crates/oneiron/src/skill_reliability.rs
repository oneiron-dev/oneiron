//! ARCH-0053 §5 skill reliability (SK-05, ONE-1738): the Beta(α, β) posterior
//! that decides which skills load, and the demotion of the record's
//! `confidence` field to a rebuildable cache over it.
//!
//! ```text
//! SK-04 judgments ─┐
//!                  ├─▶ outcome ledger ─▶ Beta(α,β) ─▶ skill.reliability CLAIM (truth)
//! contributing ────┘   (per skill,                       │
//!  wins                 keyed by receipt)                ├─▶ SkillRecord.confidence (CACHE)
//!                                                        ├─▶ selection score (mean + UCB)
//!                                                        └─▶ floor crossing → quarantine PROPOSAL
//! ```
//!
//! **Residence, not shape (doc-13 r7).** Reliability is EPISTEMIC, so it lives
//! where epistemic things live: a projector-written superseding CLAIM on the
//! SKILL entity citing the receipts it rests on. The record field that used to
//! hold it is now a materialization — CID-7's demotion pattern, the same
//! "claims are truth, the record is cache" law the contact record follows.
//!
//! **What counts (§5).** Only two classes of outcome move the posterior:
//! - β: an SK-04-routed [`AttributionVerdict::SkillDefect`] judgment — the
//!   skill's content was wrong.
//! - α: a CONTRIBUTING WIN — a terminal pack receipt whose manifest loaded the
//!   skill, whose attempt COMPLETED, and which SK-04 routed to no judgment.
//!
//! Everything else contributes NOTHING, by construction rather than by
//! special-case: an [`AttributionVerdict::ExecutionLapse`] blames the actor and
//! its attempt failed, so it is neither a defect on this skill nor a win; a
//! [`AttributionVerdict::Discovery`] became an edit proposal, not a verdict on
//! reliability. ONE-1737's projector states the seam from its side: "Crediting
//! a win is the reliability posterior's job (ONE-1738), which reads the same
//! receipts."
//!
//! **Companion-surface skills are out** (ARCH-0053 §12 surrogate-verifier
//! residue). A companion skill produces no objective win signal — no attempt,
//! no terminal pack receipt, no attributed outcome — so it simply never enters
//! this ledger. That is why there is no companion special-case here: the input
//! set is attributed outcomes, and companion surfaces produce none.
//!
//! **No shared Beta module exists yet, deliberately.** The OF-184 registry
//! entry lists ONE-1248/1249/1250, but those tickets are PsychProfile storage,
//! SKILL provenance fields and CompactionPacket validation — none of them mints
//! shared posterior machinery. The only landed Beta/UCB code is
//! [`crate::critic::CriticReliability`], which is lens-scoped and carries its
//! own outcome-source policy. [`SkillReliabilityPosterior`] therefore MIRRORS
//! that shape (α, β, apply, mean, UCB) in ~40 lines without importing it;
//! extracting one shared trait is a job for whichever ticket actually owns
//! OF-184, and should be done with both call sites in hand rather than by
//! guessing a seam from one.

use rmpv::Value;

use crate::Vault;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::skill::SkillRecord;
use crate::skill_attribution::{AttributionJudgment, AttributionVerdict};
use crate::temporal::TimeRange;

/// The §G.1 predicate this module projects. Reserved `skill.*` namespace:
/// public claim writes are rejected, and the rows land through the
/// engine-owned reserved door.
pub const PREDICATE_SKILL_RELIABILITY: &str = "skill.reliability";

/// The floor-crossing PROPOSAL predicate. A proposal to quarantine is a ROW,
/// never a lifecycle state (`skill.rs` lifecycle machine): the record stays
/// `active` until a human rules on this claim.
pub const PREDICATE_SKILL_QUARANTINE_PROPOSAL: &str = "skill.quarantine_proposal";

/// `vault_meta` key of the reliability floor dial. Per-feature key const in the
/// owning module (the `INBOX_REVIEW_DIAL_KEY` house pattern) — `settings.rs` is
/// UI customization and owns nothing here.
pub const SKILL_RELIABILITY_FLOOR_KEY: &[u8] = b"settings:skill:v1:reliability_floor";

/// Default reliability floor: the posterior LOWER BOUND a skill must hold to
/// stay out of the quarantine-proposal path.
///
/// 0.25 is deliberately far below every seeded prior mean
/// ([`ProvenanceTrustClass`]), so crossing it takes real attributed losses
/// rather than an unlucky provenance class.
pub const DEFAULT_SKILL_RELIABILITY_FLOOR: f32 = 0.25;

/// Attributed outcomes a skill must carry before the floor can fire.
///
/// A lower bound computed on a pure prior measures IGNORANCE, not
/// unreliability — every prior in the table sits under the floor on its lower
/// bound, so without this guard the first projection pass would propose
/// quarantining every newborn skill. The floor answers "the evidence says this
/// is bad", which needs evidence.
pub const SKILL_RELIABILITY_FLOOR_MIN_OUTCOMES: u32 = 5;

/// Upper bound on the receipts one reliability claim cites.
///
/// α and β count EVERY attributed outcome; the citation list is the trace, and
/// a trace that grows without bound turns a hot claim body into a ledger. The
/// most recent [`SKILL_RELIABILITY_MAX_CITED_RECEIPTS`] are kept — the outcome
/// keyspace remains the complete record.
pub const SKILL_RELIABILITY_MAX_CITED_RECEIPTS: usize = 64;

/// One-sided 95% normal quantile, for the posterior lower bound.
const LOWER_BOUND_Z: f64 = 1.645;

/// Exploration weight of the selection bonus.
///
/// Derived, not tuned by feel: the bonus is `c · σ · sqrt(2 ln N)`, so a 2-pull
/// arm outranks a 100-pull arm exactly when `c · (σ_new − σ_old) · sqrt(2 ln N)`
/// exceeds the mean gap. For the pinned anchor pair (Beta(3,1) vs Beta(91,11))
/// that threshold is `c ≈ 0.285`; 0.25 sits under it, so two lucky pulls never
/// outrank a hundred observed ones, while an arm with an EQUAL mean and wider
/// posterior still ranks above the well-pulled one (anti-shadowing).
const SELECTION_EXPLORATION: f64 = 0.25;

/// `skill_reliability:outcome:v1:` + skill id (16 B) + receipt id (UTF-8).
///
/// The receipt id in the KEY is what makes the projector idempotent: an outcome
/// already recorded re-writes its own row instead of incrementing a counter, so
/// re-running a pass over the same judgments cannot double-count.
const OUTCOME_PREFIX: &[u8] = b"skill_reliability:outcome:v1:";

/// Terminal attempt state that credits a contributing win
/// (`AttemptState::Completed`'s wire string, as stamped on the pack receipt).
const ATTEMPT_OUTCOME_COMPLETED: &str = "completed";

/// `skill.scan_verdict` body key + the value that marks canonical bytes vetted.
/// Duplicated rather than imported: `ScanVerdict::as_str` is private to
/// `skill_hub`, and the wire spelling is the pinned ABI either way.
const SCAN_VERDICT_KEY: &str = "verdict";
const SCAN_VERDICT_CLEAN: &str = "clean";

const KEY_ALPHA: &str = "alpha";
const KEY_BETA: &str = "beta";
const KEY_SCHEMA_VERSION: &str = "schema_version";
const KEY_WIN: &str = "win";
const KEY_AT: &str = "at";
const KEY_LOWER_BOUND: &str = "lowerBound";
const KEY_FLOOR: &str = "floor";

/// Schema version of the outcome rows this module persists.
pub const SKILL_RELIABILITY_SCHEMA_VERSION: u64 = 1;

const ENTITY_ID_LEN: usize = 16;

const fn invalid(reason: &'static str) -> Error {
    Error::InvalidSkillBody(reason)
}

// ---------------------------------------------------------------------------
// Posterior
// ---------------------------------------------------------------------------

/// A Beta(α, β) posterior over one skill's success rate.
///
/// Mirrors [`crate::critic::CriticReliability`]'s shape without importing it
/// (see the module header). Both `alpha` and `beta` stay strictly positive: the
/// seeded prior is positive and outcomes only add.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SkillReliabilityPosterior {
    pub alpha: f32,
    pub beta: f32,
}

impl SkillReliabilityPosterior {
    /// The prior a skill starts from, keyed by provenance class.
    ///
    /// | class | prior | mean |
    /// |---|---|---|
    /// | [`ProvenanceTrustClass::VettedImport`] | Beta(3, 1) | 0.75 |
    /// | [`ProvenanceTrustClass::HumanAuthored`] | Beta(2, 1) | 0.667 |
    /// | [`ProvenanceTrustClass::UnvettedImport`] | Beta(1, 1) | 0.50 |
    /// | [`ProvenanceTrustClass::Generated`] | Beta(1, 2) | 0.333 |
    ///
    /// The ordering is the point: bytes a scanner cleared start optimistic, a
    /// human's own skill starts trusted-but-unproven, an unvetted import starts
    /// uniform, and machine-distilled or conversation-converted content starts
    /// WEAK — it has to earn its place against skills someone vouched for.
    #[must_use]
    pub const fn seeded_from_provenance(class: ProvenanceTrustClass) -> Self {
        let (alpha, beta) = match class {
            ProvenanceTrustClass::VettedImport => (3.0, 1.0),
            ProvenanceTrustClass::HumanAuthored => (2.0, 1.0),
            ProvenanceTrustClass::UnvettedImport => (1.0, 1.0),
            ProvenanceTrustClass::Generated => (1.0, 2.0),
        };
        Self { alpha, beta }
    }

    /// Folds one attributed outcome in.
    pub const fn apply(&mut self, win: bool) {
        if win {
            self.alpha += 1.0;
        } else {
            self.beta += 1.0;
        }
    }

    /// Total pseudo-observations: prior weight plus attributed outcomes.
    #[must_use]
    pub fn observations(&self) -> f32 {
        self.alpha + self.beta
    }

    /// Posterior mean — the value the record's `confidence` cache holds.
    #[must_use]
    pub fn mean(&self) -> f32 {
        self.alpha / self.observations()
    }

    /// One-sided 95% lower confidence bound: `mean − Z·σ`, clamped to `[0, 1]`,
    /// with `σ` the Beta standard deviation
    /// `sqrt(αβ / ((α+β)² (α+β+1)))` and `Z` = [`LOWER_BOUND_Z`].
    ///
    /// The normal approximation is deliberate: it is the same σ the selection
    /// bonus rides, so the pessimistic and optimistic ends of this module can
    /// never disagree about how uncertain a posterior is.
    ///
    /// Sanity anchors: Beta(3, 1) (two wins on a uniform prior) → ≈ 0.43;
    /// Beta(91, 11) (90/100) → ≈ 0.84. Two lucky pulls never outrank a hundred
    /// observed ones on this ranking.
    #[must_use]
    pub fn lower_bound(&self) -> f32 {
        let mean = f64::from(self.mean());
        let bound = mean - LOWER_BOUND_Z * self.std_dev();
        clamp_unit(bound)
    }

    /// Selection score: posterior mean plus the exploration bonus
    /// `c · σ · sqrt(2 ln(N + 1))` over `total_pulls` observations across the
    /// candidate set (`c` = [`SELECTION_EXPLORATION`]).
    ///
    /// Deliberately NOT clamped to `[0, 1]`: the score is a ranking key, and
    /// capping it at 1.0 would flatten exactly the arms exploration is meant to
    /// separate. There is no hard active-cap anywhere in this path (OF-184) —
    /// shadowing is prevented by the bonus, not by a quota.
    #[must_use]
    pub fn ucb(&self, total_pulls: u32) -> f32 {
        let horizon = (2.0 * f64::from(total_pulls.max(1).saturating_add(1)).ln()).sqrt();
        let bonus = SELECTION_EXPLORATION * self.std_dev() * horizon;
        // A ranking key, so no unit clamp — see the doc comment above.
        narrow(f64::from(self.mean()) + bonus)
    }

    /// Beta standard deviation, in f64 so the square roots keep their digits.
    fn std_dev(&self) -> f64 {
        let alpha = f64::from(self.alpha);
        let beta = f64::from(self.beta);
        let total = alpha + beta;
        (alpha * beta / (total * total * (total + 1.0))).sqrt()
    }

    fn to_value(self) -> Value {
        Value::Map(vec![
            (Value::from(KEY_ALPHA), Value::F32(self.alpha)),
            (Value::from(KEY_BETA), Value::F32(self.beta)),
        ])
    }

    fn from_value(value: &Value) -> Result<Self> {
        let alpha =
            map_f32(value, KEY_ALPHA).ok_or(invalid("skill.reliability body is missing alpha"))?;
        let beta =
            map_f32(value, KEY_BETA).ok_or(invalid("skill.reliability body is missing beta"))?;
        if !alpha.is_finite() || !beta.is_finite() || alpha <= 0.0 || beta <= 0.0 {
            return Err(invalid(
                "skill.reliability alpha/beta must be finite and positive",
            ));
        }
        Ok(Self { alpha, beta })
    }
}

/// Provenance classes the prior table is keyed by (ARCH-0053 §5).
///
/// Total over lawful [`SkillRecord`] shapes: the record invariant is that
/// exactly one of `generated` / `human_authored` holds and `generated` matches
/// [`ClaimSource::Generated`], so every record lands in exactly one arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProvenanceTrustClass {
    /// Imported, and a scanner cleared the record's canonical content hash
    /// (SK-02/SK-03 `skill.scan_verdict` rows on the content anchor).
    VettedImport,
    /// Imported with no clean verdict on its bytes — including an import that
    /// carries no canonical content hash to check.
    UnvettedImport,
    /// Human-authored locally (conversion, fork, hand-written).
    HumanAuthored,
    /// Machine-generated: Dreamer distill, conversation convert.
    Generated,
}

// ---------------------------------------------------------------------------
// Priors
// ---------------------------------------------------------------------------

/// Classifies a stored skill for the prior table.
pub fn skill_provenance_trust_class(
    vault: &Vault,
    skill: &EntityId,
) -> Result<ProvenanceTrustClass> {
    let record = read_skill(vault, skill)?;
    provenance_trust_class(vault, &record)
}

fn provenance_trust_class(vault: &Vault, record: &SkillRecord) -> Result<ProvenanceTrustClass> {
    if record.generated {
        return Ok(ProvenanceTrustClass::Generated);
    }
    if record.source != ClaimSource::Imported {
        return Ok(ProvenanceTrustClass::HumanAuthored);
    }
    let Some(content_hash) = record.content_hash else {
        return Ok(ProvenanceTrustClass::UnvettedImport);
    };
    let vetted = vault
        .skill_scan_verdicts_for_content_hash(content_hash)?
        .iter()
        .any(|body| map_str(&body.value, SCAN_VERDICT_KEY) == Some(SCAN_VERDICT_CLEAN));
    Ok(if vetted {
        ProvenanceTrustClass::VettedImport
    } else {
        ProvenanceTrustClass::UnvettedImport
    })
}

/// The prior a skill's posterior starts from, before any attributed outcome.
pub fn skill_reliability_prior(
    vault: &Vault,
    skill: &EntityId,
) -> Result<SkillReliabilityPosterior> {
    skill_provenance_trust_class(vault, skill)
        .map(SkillReliabilityPosterior::seeded_from_provenance)
}

// ---------------------------------------------------------------------------
// Outcome ledger
// ---------------------------------------------------------------------------

/// Credits one CONTRIBUTING WIN against a skill.
///
/// Grounded at the door, exactly as SK-04 grounds blame evidence: the receipt
/// must be a stamped terminal pack receipt, its attempt must have COMPLETED,
/// and the skill must appear in the manifest that receipt recorded. A win the
/// pack never loaded is attribution by assertion.
///
/// Recording is idempotent — the key carries the receipt id — so replaying a
/// close, or crediting the same receipt from two call sites, moves α once.
pub fn record_skill_contributing_win(
    vault: &Vault,
    skill: &EntityId,
    receipt_ref: &str,
    at: u64,
) -> Result<()> {
    let record = read_skill(vault, skill)?;
    let Some(receipt) = crate::receipt::attempt_pack_receipt(vault, receipt_ref)? else {
        return Err(invalid("contributing win cites an unstamped receipt"));
    };
    if receipt.outcome != ATTEMPT_OUTCOME_COMPLETED {
        return Err(invalid(
            "a contributing win requires a completed attempt receipt",
        ));
    }
    // A receipt stamped before the manifest field-set carries no manifest and
    // cannot answer which skills the pack loaded — an absent fact, not a failed
    // check (the ONE-1737 evidence door draws the same line).
    if let Some(manifest) = receipt.pack_manifest_skills()
        && !manifest
            .iter()
            .any(|entry| manifest_entry_names_skill(entry, &record.skill_id))
    {
        return Err(invalid(
            "contributing win names a skill absent from the receipt manifest",
        ));
    }
    vault.with_write_txn(|wtxn| record_outcome_in_txn(vault, wtxn, skill, receipt_ref, true, at))
}

/// A manifest wire form is `reference@version`; a SKILL row's reference is its
/// `skill_id`. Split from the RIGHT so an id containing `@` still resolves.
fn manifest_entry_names_skill(wire_form: &str, skill_id: &str) -> bool {
    wire_form
        .rsplit_once('@')
        .is_some_and(|(reference, _)| reference == skill_id)
}

fn record_outcome_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    skill: &EntityId,
    receipt_ref: &str,
    win: bool,
    at: u64,
) -> Result<()> {
    if receipt_ref.is_empty() {
        return Err(invalid("a reliability outcome must cite a receipt"));
    }
    let row = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(SKILL_RELIABILITY_SCHEMA_VERSION),
        ),
        (Value::from(KEY_WIN), Value::Boolean(win)),
        (Value::from(KEY_AT), Value::from(at)),
    ]);
    let encoded = encode_value(&row)?;
    vault
        .store
        .vault_meta
        .put(wtxn, &outcome_key(skill, receipt_ref), &encoded)?;
    Ok(())
}

fn outcome_prefix(skill: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(OUTCOME_PREFIX.len() + ENTITY_ID_LEN);
    key.extend_from_slice(OUTCOME_PREFIX);
    key.extend_from_slice(skill.as_bytes());
    key
}

fn outcome_key(skill: &EntityId, receipt_ref: &str) -> Vec<u8> {
    let mut key = outcome_prefix(skill);
    key.extend_from_slice(receipt_ref.as_bytes());
    key
}

/// Attributed-outcome counts for one skill, plus the citation trace.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct OutcomeTally {
    wins: u32,
    losses: u32,
    /// The most recent [`SKILL_RELIABILITY_MAX_CITED_RECEIPTS`] receipt ids, in
    /// ledger order. Pack receipt ids embed the UUIDv7 attempt id, so key order
    /// IS mint order.
    cited: Vec<String>,
}

impl OutcomeTally {
    fn total(&self) -> u32 {
        self.wins.saturating_add(self.losses)
    }

    fn posterior(&self, prior: SkillReliabilityPosterior) -> SkillReliabilityPosterior {
        SkillReliabilityPosterior {
            alpha: prior.alpha + count_weight(self.wins),
            beta: prior.beta + count_weight(self.losses),
        }
    }
}

fn tally_outcomes(vault: &Vault, rtxn: &heed::RoTxn<'_>, skill: &EntityId) -> Result<OutcomeTally> {
    let prefix = outcome_prefix(skill);
    let mut tally = OutcomeTally::default();
    for row in vault.store.vault_meta.prefix_iter(rtxn, &prefix)? {
        let (key, raw) = row?;
        let receipt = key
            .get(prefix.len()..)
            .and_then(|suffix| std::str::from_utf8(suffix).ok())
            .ok_or(Error::CorruptedIndex("skill reliability outcome key"))?;
        if decode_outcome_win(&raw)? {
            tally.wins = tally.wins.saturating_add(1);
        } else {
            tally.losses = tally.losses.saturating_add(1);
        }
        tally.cited.push(receipt.to_owned());
        if tally.cited.len() > SKILL_RELIABILITY_MAX_CITED_RECEIPTS {
            tally.cited.remove(0);
        }
    }
    Ok(tally)
}

fn decode_outcome_win(raw: &[u8]) -> Result<bool> {
    let value = decode_value(raw)?;
    if map_u64(&value, KEY_SCHEMA_VERSION) != Some(SKILL_RELIABILITY_SCHEMA_VERSION) {
        return Err(invalid("unsupported skill reliability outcome schema"));
    }
    value
        .as_map()
        .and_then(|entries| {
            entries
                .iter()
                .find(|(k, _)| k.as_str() == Some(KEY_WIN))
                .and_then(|(_, v)| v.as_bool())
        })
        .ok_or(invalid("skill reliability outcome is missing win"))
}

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
pub fn project_skill_reliability(
    vault: &Vault,
    judgments: &[AttributionJudgment],
) -> Result<Vec<EntityId>> {
    let mut batches: Vec<(EntityId, Vec<&AttributionJudgment>)> = Vec::new();
    for judgment in judgments {
        if judgment.verdict != AttributionVerdict::SkillDefect {
            continue;
        }
        // The subject of a defect verdict is a SKILL by SK-04's routing, but a
        // projector that trusts that without checking would mint a reliability
        // claim on whatever entity a malformed row named.
        if vault.get_skill_record(&judgment.subject)?.is_none() {
            continue;
        }
        // A judgment with nothing to cite cannot be counted: the row it would
        // write has no key, and a loss with no trace is the thing the doctrine
        // header exists to refuse.
        if judgment.evidence_receipts.is_empty() {
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
    let tally = tally_outcomes(vault, wtxn, skill)?;
    let posterior = tally.posterior(prior);
    let evidence = Value::Array(
        tally
            .cited
            .iter()
            .map(|receipt| Value::from(receipt.as_str()))
            .collect(),
    );

    let active = active_reliability_claim_in_txn(vault, wtxn, skill)?;
    let unchanged = active.as_ref().is_some_and(|(_, body)| {
        body.value == posterior.to_value() && body.evidence.as_ref() == Some(&evidence)
    });
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
        if let Some((prior_id, _)) = active {
            vault.supersede_reserved_claim_in_txn(wtxn, &claim_id, &prior_id, at)?;
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
    floor_check_in_txn(vault, wtxn, skill, posterior, tally.total(), at)?;
    Ok(posterior)
}

/// Reads the active `skill.reliability` posterior, or `None` when the skill has
/// never been projected.
pub fn skill_reliability_posterior(
    vault: &Vault,
    skill: &EntityId,
) -> Result<Option<SkillReliabilityPosterior>> {
    let rtxn = vault.store.env.read_txn()?;
    active_reliability_claim_in_txn(vault, &rtxn, skill)?
        .map(|(_, body)| SkillReliabilityPosterior::from_value(&body.value))
        .transpose()
}

fn active_claim_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
    predicate: &str,
) -> Result<Option<(EntityId, ClaimBody)>> {
    for id in vault.claims_for_subject_in_txn(rtxn, skill)? {
        let Some(body) = vault.get_claim_in_txn(rtxn, &id)? else {
            continue;
        };
        if body.predicate == predicate && body.lifecycle == ClaimLifecycleStatus::Active {
            return Ok(Some((id, body)));
        }
    }
    Ok(None)
}

fn active_reliability_claim_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<Option<(EntityId, ClaimBody)>> {
    active_claim_in_txn(vault, rtxn, skill, PREDICATE_SKILL_RELIABILITY)
}

// ---------------------------------------------------------------------------
// Cache rebuild (CID-7 demotion door)
// ---------------------------------------------------------------------------

/// Rebuilds the record's `confidence` CACHE from the reliability claim and
/// returns the value written.
///
/// The REPAIR law in one call (doc 13 §3, CID-7's shape): clobber or drop the
/// record field, run this, get the claim's posterior mean back. Claims are
/// truth — this reads them and never writes them, which is the direction proof.
/// A skill with no reliability claim rebuilds to its provenance prior's mean,
/// so the cache is defined before the first attributed outcome too.
pub fn rebuild_skill_confidence_cache(vault: &Vault, skill: &EntityId, at: u64) -> Result<f32> {
    let prior = skill_reliability_prior(vault, skill)?;
    vault.with_write_txn(|wtxn| {
        let posterior = match active_reliability_claim_in_txn(vault, wtxn, skill)? {
            Some((_, body)) => SkillReliabilityPosterior::from_value(&body.value)?,
            None => prior,
        };
        let mean = posterior.mean();
        vault.refresh_skill_confidence_cache_in_txn(
            wtxn,
            skill,
            mean,
            TimeRange { start: at, end: at },
            at,
        )?;
        Ok(mean)
    })
}

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

/// The skill's selection score: posterior mean plus the exploration bonus
/// ([`SkillReliabilityPosterior::ucb`]).
///
/// Reads the CLAIM, never the record's cache field — a stale or clobbered cache
/// must never be able to change which skills load. A skill with no claim scores
/// off its provenance prior.
///
/// `total_pulls` is the observation total across the candidate set the caller is
/// ranking (sum of [`SkillReliabilityPosterior::observations`]); it is an
/// argument rather than a hidden scan so ranking N skills costs N reads, not N².
pub fn skill_selection_score(vault: &Vault, skill: &EntityId, total_pulls: u32) -> Result<f32> {
    let posterior = match skill_reliability_posterior(vault, skill)? {
        Some(posterior) => posterior,
        None => skill_reliability_prior(vault, skill)?,
    };
    Ok(posterior.ucb(total_pulls))
}

// ---------------------------------------------------------------------------
// Floor crossing
// ---------------------------------------------------------------------------

/// Reads the reliability floor dial (default [`DEFAULT_SKILL_RELIABILITY_FLOOR`]).
pub fn skill_reliability_floor(vault: &Vault) -> Result<f32> {
    let rtxn = vault.store.env.read_txn()?;
    floor_in_txn(vault, &rtxn)
}

fn floor_in_txn(vault: &Vault, rtxn: &heed::RoTxn<'_>) -> Result<f32> {
    let Some(raw) = vault
        .store
        .vault_meta
        .get(rtxn, SKILL_RELIABILITY_FLOOR_KEY)?
    else {
        return Ok(DEFAULT_SKILL_RELIABILITY_FLOOR);
    };
    let bytes: [u8; 4] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex("skill reliability floor"))?;
    let floor = f32::from_be_bytes(bytes);
    if !floor.is_finite() || !(0.0..=1.0).contains(&floor) {
        return Err(Error::CorruptedIndex("skill reliability floor"));
    }
    Ok(floor)
}

/// Sets the reliability floor dial.
pub fn set_skill_reliability_floor(vault: &Vault, floor: f32) -> Result<()> {
    if !floor.is_finite() || !(0.0..=1.0).contains(&floor) {
        return Err(invalid("reliability floor must be finite in [0, 1]"));
    }
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .vault_meta
            .put(wtxn, SKILL_RELIABILITY_FLOOR_KEY, &floor.to_be_bytes())?;
        Ok(())
    })
}

/// Mints a quarantine PROPOSAL when the skill's posterior lower bound has
/// fallen under the floor, and returns the proposal's claim id.
///
/// NEVER automatic (ARCH-0053 §5/§6): the lifecycle stays wherever it was and
/// the proposal lands as a row with `approval = proposed`. The record-shape
/// invariant in `skill.rs` enforces the other half — a `quarantined` record
/// stamped anything but `approved` is rejected at every door — so there is no
/// path from this function to a retired skill without a human ruling.
///
/// Returns the EXISTING proposal while one is open: a second crossing is the
/// same unanswered question, not a second question.
pub fn check_reliability_floor(
    vault: &Vault,
    skill: &EntityId,
    at: u64,
) -> Result<Option<EntityId>> {
    let prior = skill_reliability_prior(vault, skill)?;
    vault.with_write_txn(|wtxn| {
        let tally = tally_outcomes(vault, wtxn, skill)?;
        let posterior = tally.posterior(prior);
        floor_check_in_txn(vault, wtxn, skill, posterior, tally.total(), at)
    })
}

fn floor_check_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    skill: &EntityId,
    posterior: SkillReliabilityPosterior,
    outcomes: u32,
    at: u64,
) -> Result<Option<EntityId>> {
    if outcomes < SKILL_RELIABILITY_FLOOR_MIN_OUTCOMES {
        return Ok(None);
    }
    let floor = floor_in_txn(vault, wtxn)?;
    let lower_bound = posterior.lower_bound();
    if lower_bound >= floor {
        return Ok(None);
    }
    if let Some((existing, _)) =
        active_claim_in_txn(vault, wtxn, skill, PREDICATE_SKILL_QUARANTINE_PROPOSAL)?
    {
        return Ok(Some(existing));
    }
    let proposal_id = EntityId::now();
    let mut body = ClaimBody::new(
        PREDICATE_SKILL_QUARANTINE_PROPOSAL,
        ClaimSubject::Entity(*skill),
        Value::Map(vec![
            (Value::from(KEY_ALPHA), Value::F32(posterior.alpha)),
            (Value::from(KEY_BETA), Value::F32(posterior.beta)),
            (Value::from(KEY_LOWER_BOUND), Value::F32(lower_bound)),
            (Value::from(KEY_FLOOR), Value::F32(floor)),
        ]),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(ClaimSource::Observed);
    vault.put_reserved_claim_in_txn(
        wtxn,
        &proposal_id,
        &body,
        TimeRange { start: at, end: at },
        at,
    )?;
    Ok(Some(proposal_id))
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn read_skill(vault: &Vault, skill: &EntityId) -> Result<SkillRecord> {
    vault
        .get_skill_record(skill)?
        .ok_or(invalid("skill reliability names an unknown skill"))
}

fn clamp_unit(value: f64) -> f32 {
    narrow(value.clamp(0.0, 1.0))
}

/// f64 math down to the f32 the posterior stores. The intermediate width exists
/// so the square roots keep their digits; the stored value never needed it.
#[expect(
    clippy::cast_possible_truncation,
    reason = "f64 intermediate narrowed to the f32 the posterior stores"
)]
fn narrow(value: f64) -> f32 {
    value as f32
}

/// An attributed-outcome count as posterior weight.
///
/// Past 2^24 an f32 stops representing consecutive integers, so a skill with
/// ~16.7M attributed outcomes accumulates rounding. That is the honest failure:
/// the RATIO is unaffected at that scale, whereas saturating the count would
/// silently freeze the posterior against all further evidence.
#[expect(
    clippy::cast_precision_loss,
    reason = "outcome counts weight an f32 posterior; the ratio is what is read"
)]
fn count_weight(count: u32) -> f32 {
    count as f32
}

fn map_entry<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value
        .as_map()?
        .iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .map(|(_, v)| v)
}

fn map_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    map_entry(value, key)?.as_str()
}

fn map_u64(value: &Value, key: &str) -> Option<u64> {
    map_entry(value, key)?.as_u64()
}

fn map_f32(value: &Value, key: &str) -> Option<f32> {
    match map_entry(value, key)? {
        Value::F32(v) => Some(*v),
        Value::F64(v) => Some(*v as f32),
        _ => None,
    }
}

fn encode_value(value: &Value) -> Result<Vec<u8>> {
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, value)
        .map_err(|_| invalid("skill reliability MessagePack encode failed"))?;
    Ok(encoded)
}

fn decode_value(raw: &[u8]) -> Result<Value> {
    rmpv::decode::read_value(&mut std::io::Cursor::new(raw))
        .map_err(|_| invalid("skill reliability MessagePack decode failed"))
}

#[cfg(test)]
mod tests;
