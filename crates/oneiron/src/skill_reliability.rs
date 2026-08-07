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

use std::collections::HashMap;

use rmpv::Value;

use crate::Vault;
use crate::attempt_queue::ManifestEntry;
use crate::batch::EntityMetadataHeader;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::ReceiptRecord;
use crate::skill::{SkillContentHash, SkillRecord};
use crate::skill_attribution::{AttributionJudgment, AttributionVerdict, attribution_judgments};
use crate::skill_hub::PREDICATE_SKILL_HUB_PROVENANCE;
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

/// `skill_reliability:imported_base:v1:` + skill id (16 B).
///
/// The α, β a synced claim carried that this vault's outcome ledger cannot
/// reproduce. Node-local like the ledger it completes — this row is a record of
/// what arrived, not a fact about the skill, so it never travels.
const IMPORTED_BASE_PREFIX: &[u8] = b"skill_reliability:imported_base:v1:";

/// Terminal attempt state that credits a contributing win
/// (`AttemptState::Completed`'s wire string, as stamped on the pack receipt).
const ATTEMPT_OUTCOME_COMPLETED: &str = "completed";

/// `skill.scan_verdict` body keys + the values that decide whether canonical
/// bytes were actually CLEARED. Duplicated rather than imported:
/// `ScanVerdict::as_str` / `SkillGovernance::as_str` are private to
/// `skill_hub`, and the wire spelling is the pinned ABI either way.
const SCAN_VERDICT_KEY: &str = "verdict";
const SCAN_VERDICT_CLEAN: &str = "clean";
const SCAN_GOVERNANCE_KEY: &str = "governance";
const SCAN_GOVERNANCE_PROHIBITED: &str = "prohibited";

/// `skill.hub_provenance` body key naming the bytes a hub alias vouches for.
const HUB_PROVENANCE_CONTENT_HASH_KEY: &str = "contentHash";

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
        narrow((mean - LOWER_BOUND_Z * self.std_dev()).clamp(0.0, 1.0))
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
    provenance_trust_class(vault, skill, &record)
}

fn provenance_trust_class(
    vault: &Vault,
    skill: &EntityId,
    record: &SkillRecord,
) -> Result<ProvenanceTrustClass> {
    if record.generated {
        return Ok(ProvenanceTrustClass::Generated);
    }
    if record.source != ClaimSource::Imported {
        return Ok(ProvenanceTrustClass::HumanAuthored);
    }
    let Some(content_hash) = record.content_hash else {
        return Ok(ProvenanceTrustClass::UnvettedImport);
    };
    // The top prior is the VETTED-HUB import (ARCH-0053 §5): a hub carries
    // these bytes AND a scanner cleared them. Both halves are read, because
    // either half alone is a different claim. A clean verdict on bytes no hub
    // vouches for says only "a scanner looked at some bytes" — there is no
    // trust relationship behind it to be optimistic about — and a hub alias
    // over bytes nobody scanned is what `UnvettedImport` NAMES.
    let vetted = hub_vouches_for_content(vault, skill, content_hash)?
        && vault
            .skill_scan_verdicts_for_content_hash(content_hash)?
            .iter()
            .any(scan_verdict_cleared_the_bytes);
    Ok(if vetted {
        ProvenanceTrustClass::VettedImport
    } else {
        ProvenanceTrustClass::UnvettedImport
    })
}

/// True when a scanner receipt actually CLEARED the bytes it names.
///
/// `verdict == clean` alone is not a clearance. `governance` is a separate
/// POLICY axis carried on the same receipt (`skill_hub::SkillGovernance`), and
/// the scan-ingest door validates only the provider text — nothing stops a
/// receipt that pairs a clean scan with `prohibited` governance. Seeding the
/// MOST optimistic prior off bytes the governance axis forbids inverts the
/// table it is keyed by, so a prohibited row clears nothing however clean the
/// scanner found it.
///
/// `riskLevel` and `completeness` are deliberately NOT read here: both are
/// scanner-signal axes the scanner already summarized into `verdict`, so
/// re-judging them would be this module second-guessing the provider.
/// `governance` is the one axis on the row that is NOT the scanner's opinion.
fn scan_verdict_cleared_the_bytes(body: &ClaimBody) -> bool {
    map_str(&body.value, SCAN_VERDICT_KEY) == Some(SCAN_VERDICT_CLEAN)
        && map_str(&body.value, SCAN_GOVERNANCE_KEY) != Some(SCAN_GOVERNANCE_PROHIBITED)
}

/// True when an active `skill.hub_provenance` alias on this skill names exactly
/// these canonical bytes.
///
/// Scan verdicts hang off the content ANCHOR, which is content-global — every
/// holder of the same bytes sees the same verdicts. The provenance row is the
/// per-skill half: it is what says a HUB carried these bytes to this vault.
fn hub_vouches_for_content(
    vault: &Vault,
    skill: &EntityId,
    content_hash: SkillContentHash,
) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    let hash_hex = content_hash.to_hex();
    for (_, body, _) in active_claims_in_txn(vault, &rtxn, skill, PREDICATE_SKILL_HUB_PROVENANCE)? {
        if map_str(&body.value, HUB_PROVENANCE_CONTENT_HASH_KEY) == Some(hash_hex.as_str()) {
            return Ok(true);
        }
    }
    Ok(false)
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
    if !receipt_manifest_names_skill(&receipt, &record) {
        return Err(invalid(
            "contributing win names a skill absent from the receipt manifest",
        ));
    }
    vault.with_write_txn(|wtxn| record_outcome_in_txn(vault, wtxn, skill, receipt_ref, true, at))
}

/// The manifest chokepoint BOTH outcome doors run: did the pack that stamped
/// this receipt actually load this skill revision?
///
/// A receipt stamped before the manifest field-set carries no manifest and
/// cannot answer which skills the pack loaded — an absent fact, not a failed
/// check (the ONE-1737 evidence door draws the same line).
fn receipt_manifest_names_skill(receipt: &ReceiptRecord, record: &SkillRecord) -> bool {
    let Some(manifest) = receipt.pack_manifest_skills() else {
        return true;
    };
    manifest
        .iter()
        .any(|entry| manifest_entry_names_skill(entry, &record.skill_id, &record.version))
}

/// A manifest wire form is `reference@version`; a SKILL row's reference is its
/// `skill_id` and its version is the REVISION the pack loaded.
/// [`ManifestEntry::parse_wire_form`] owns the split.
///
/// The version is compared exactly whenever the entry carries one. A revision
/// is its own SKILL entity with its own posterior (`supersede_skill_record`
/// freezes the old one), so a `skill@1` receipt crediting the `skill@2` entity
/// would move a claim about bytes that attempt never ran. An entry with an
/// empty version is an absent fact — it names no revision to disagree with —
/// and still resolves, exactly as an absent manifest does above.
fn manifest_entry_names_skill(wire_form: &str, skill_id: &str, version: &str) -> bool {
    ManifestEntry::parse_wire_form(wire_form).is_some_and(|(reference, entry_version)| {
        reference == skill_id && (entry_version.is_empty() || entry_version == version)
    })
}

/// Writes one outcome row, keyed `(skill, receipt)`.
///
/// **A routed verdict outranks the default credit, whichever arrives first.** A
/// blamed attempt still reaches its terminal door COMPLETED, so the same receipt
/// can plausibly be offered as a contributing win and routed to a skill defect —
/// and a host that does both would otherwise get a posterior that depends on
/// call order. A loss overwrites a win (SK-04 corrected the default); a win never
/// overwrites a loss.
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
    let key = outcome_key(skill, receipt_ref);
    if win
        && let Some(existing) = vault.store.vault_meta.get(wtxn, &key)?
        && !decode_outcome_win(&existing)?
    {
        return Ok(());
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
    vault.store.vault_meta.put(wtxn, &key, &encoded)?;
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
    map_entry(&value, KEY_WIN)
        .and_then(Value::as_bool)
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
fn attributed_outcomes(
    prior: SkillReliabilityPosterior,
    posterior: SkillReliabilityPosterior,
) -> u32 {
    (posterior.observations() - prior.observations())
        .round()
        .max(0.0) as u32
}

/// Reads the active `skill.reliability` posterior, or `None` when the skill has
/// never been projected.
pub fn skill_reliability_posterior(
    vault: &Vault,
    skill: &EntityId,
) -> Result<Option<SkillReliabilityPosterior>> {
    let rtxn = vault.store.env.read_txn()?;
    resolved_reliability_posterior_in_txn(vault, &rtxn, skill)
}

/// The posterior the active heads settle on: the richest one.
///
/// A fork is transient — the next projection supersedes every head — but a read
/// that lands mid-fork must not answer with whichever row the edge index
/// happened to yield first.
fn resolved_reliability_posterior_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<Option<SkillReliabilityPosterior>> {
    let mut resolved: Option<SkillReliabilityPosterior> = None;
    for (_, body, _) in active_reliability_heads_in_txn(vault, rtxn, skill)? {
        let candidate = SkillReliabilityPosterior::from_value(&body.value)?;
        if resolved.is_none_or(|held| candidate.observations() > held.observations()) {
            resolved = Some(candidate);
        }
    }
    Ok(resolved)
}

/// EVERY active claim for `predicate` on `skill`, with the `occurred_start` a
/// supersession has to clamp against.
fn active_claims_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
    predicate: &str,
) -> Result<Vec<(EntityId, ClaimBody, u64)>> {
    let mut rows = Vec::new();
    for id in vault.claims_for_subject_in_txn(rtxn, skill)? {
        let Some(body) = vault.get_claim_in_txn(rtxn, &id)? else {
            continue;
        };
        if body.predicate != predicate || body.lifecycle != ClaimLifecycleStatus::Active {
            continue;
        }
        let raw = vault
            .store
            .entities
            .get(rtxn, id.as_bytes())?
            .ok_or(Error::CorruptedIndex("claim_of edge"))?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        rows.push((id, body, header.occurred_start));
    }
    Ok(rows)
}

fn active_reliability_heads_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<Vec<(EntityId, ClaimBody, u64)>> {
    active_claims_in_txn(vault, rtxn, skill, PREDICATE_SKILL_RELIABILITY)
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
///
/// A SUPERSEDED revision is frozen history and keeps the cache it was frozen
/// with (see `Vault::refresh_skill_confidence_cache_in_txn`); the value returned
/// is still the claim's, so a caller reading it reads truth either way.
pub fn rebuild_skill_confidence_cache(vault: &Vault, skill: &EntityId, at: u64) -> Result<f32> {
    let prior = skill_reliability_prior(vault, skill)?;
    vault.with_write_txn(|wtxn| {
        let posterior = resolved_reliability_posterior_in_txn(vault, wtxn, skill)?.unwrap_or(prior);
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
///
/// Reads the CLAIM, exactly as selection does. The local outcome ledger is not
/// the whole posterior on a replica — a vault that synced a below-floor claim
/// holds no outcome rows behind it, so recomputing from the tally would exit at
/// `outcomes < MIN_OUTCOMES` and skip the quarantine proposal the evidence
/// already demands. The ledger answers only for a skill nobody has projected.
pub fn check_reliability_floor(
    vault: &Vault,
    skill: &EntityId,
    at: u64,
) -> Result<Option<EntityId>> {
    let prior = skill_reliability_prior(vault, skill)?;
    vault.with_write_txn(|wtxn| {
        let posterior = match resolved_reliability_posterior_in_txn(vault, wtxn, skill)? {
            Some(posterior) => posterior,
            None => tally_outcomes(vault, wtxn, skill)?.posterior(prior),
        };
        floor_check_in_txn(
            vault,
            wtxn,
            skill,
            posterior,
            attributed_outcomes(prior, posterior),
            at,
        )
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
    if let Some((existing, _, _)) =
        active_claims_in_txn(vault, wtxn, skill, PREDICATE_SKILL_QUARANTINE_PROPOSAL)?
            .into_iter()
            .next()
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
