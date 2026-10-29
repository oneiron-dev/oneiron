//! What the attribution judge settled on a finding's exact attempt (OF-568
//! L10, agent-mind §3.5: "An `environment` label from the attribution judge
//! blames nobody"). The labels are those retained on the attempt's sealed
//! terminal pack receipt, joined on that receipt alone: never on the actor and
//! a time, and never on a served or request receipt. A finding with no exact
//! attempt, an actor-only or taskless one, gets none. The amendment judge's
//! labels on that attempt's amended proposals join beside them, on the same
//! receipt (FIX 8264).
//!
//! Scope (CALLS "Label scope"): a finding takes its attempt's labels only when
//! one of them is the judge's current `environment`. It then takes every label
//! on that receipt, with its share and judge revision, `skill_defect`,
//! `execution_lapse` and `unclear` included: a mixed explanation, with no
//! latest-wins rule and no vote (CALLS "Conflicting labels"). An environment
//! label on one loaded skill explains that skill's outcome; it never clears
//! the attempt's other skills, its calls or its TASK.
//!
//! The labels are counter-evidence and another possible cause, never a
//! verdict: they add [`AgentHealthCounter::EnvironmentCause`], their source ids
//! join the finding's DIAGNOSTIC (never the card's evidence count), and the
//! Coach gets a copy as one more recipient (ROUTE ruling A). The leader, the
//! spawner, the owner copy and the tone stay as they were. No score, hold or
//! grant moves, nothing asks the Coach, and nothing here re-judges: a label
//! that lands after the review reaches the open card at the nightly pass. A
//! read that fails, or a Coach that does not resolve, lands the card as it
//! would have landed, with a warning, and the nightly pass tries again.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    AgentHealthCard, AgentHealthConfidence, AgentHealthCounter, AgentHealthOutcome, CARDS, Finding,
    add_recipients,
};
use crate::attempt_queue::AttemptId;
use crate::edit_distance::attribution::{AmendmentCauseRecord, amendment_causes_in_txn};
use crate::receipt::attempt_pack_receipt_id;
use crate::skill_attribution::{
    AttributionCauseRecord, AttributionVerdict, attempt_attribution_causes,
};
use crate::{EntityId, Result, Vault};

/// Domain of an amendment label's source id: one id per settled cause row
/// and label.
const AMENDMENT_SOURCE_DOMAIN: &[u8] = b"oneiron:agent-health-amendment-cause:v1";

/// One attribution label a card carries (OF-568 L10): a typed reference to
/// the judge's retained label, never prose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCauseSource {
    /// The retained label's immutable source id: the DIAGNOSTIC cites it.
    pub source: EntityId,
    /// The sealed terminal pack receipt of the attempt it was judged on.
    pub receipt: String,
    /// The loaded skill its evidence named, if any.
    pub skill: Option<EntityId>,
    /// The judge's label, as its stable wire token: `environment`,
    /// `skill_defect`, `execution_lapse`, `discovery`, `unclear`, or for an
    /// amendment `preference_shift`.
    pub label: String,
    /// The label's share of the outcome, in `0..=1`.
    pub share: f32,
    /// The judge revision that settled it; `None` for the rule tier.
    pub judge_revision: Option<String>,
    /// The revision that displaced that judge, when one has: the label is
    /// history then, not current support.
    pub displaced_by: Option<String>,
}

impl HealthCauseSource {
    fn of(record: AttributionCauseRecord) -> Self {
        Self {
            source: record.source,
            receipt: record.receipt,
            skill: record.skill,
            label: record.label.as_str().to_owned(),
            share: record.share,
            judge_revision: record.judge_revision,
            displaced_by: record.displaced_by,
        }
    }

    /// One per label the amendment judge gave `record`, an amendment of the
    /// attempt that sealed `receipt` (FIX 8264). The label's source id is
    /// spelled from the cause row's stored source and the label, so the
    /// same settled labels fold onto the same card row; the displacement of
    /// that row's judge rides with the record (FIX 11638).
    fn of_amendment(record: &AmendmentCauseRecord, receipt: &str) -> Result<Vec<Self>> {
        let source = record.source.to_hex();
        record
            .shares
            .iter()
            .filter(|share| share.share > 0.0)
            .map(|share| {
                let label = share.class.as_str();
                Ok(Self {
                    source: EntityId::derive(
                        AMENDMENT_SOURCE_DOMAIN,
                        &[source.as_bytes(), label.as_bytes()],
                    )?,
                    receipt: receipt.to_owned(),
                    skill: record.skill,
                    label: label.to_owned(),
                    share: share.share,
                    judge_revision: record.judge.clone(),
                    displaced_by: record.displaced_by.clone(),
                })
            })
            .collect()
    }

    /// The judge's `environment` label, by a judge not displaced.
    fn environment(&self) -> bool {
        self.label == AttributionVerdict::Environment.as_str() && self.displaced_by.is_none()
    }
}

/// A card's key in the card table.
type CardKey = ([u8; 16], [u8; 1], [u8; 16]);

/// Each open card's labels as they stand now, by card key.
pub(super) type Late = BTreeMap<CardKey, Vec<HealthCauseSource>>;

/// Each finding's labels, aligned with `findings`, and
/// [`AgentHealthCounter::EnvironmentCause`] on each finding whose labels hold
/// a current environment label. A read that fails leaves every finding as it
/// was.
pub(super) fn attach(vault: &Vault, findings: &mut [Finding]) -> Vec<Vec<HealthCauseSource>> {
    let sources = match finding_sources(vault, findings) {
        Ok(sources) => sources,
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "agent-health attribution labels not read; the nightly review reads them again"
            );
            return vec![Vec::new(); findings.len()];
        }
    };
    for (finding, sources) in findings.iter_mut().zip(&sources) {
        if sources.iter().any(HealthCauseSource::environment)
            && !finding
                .counter
                .contains(&AgentHealthCounter::EnvironmentCause)
        {
            finding.counter.push(AgentHealthCounter::EnvironmentCause);
        }
    }
    sources
}

/// Each open card's labels as they stand now: those on every receipt it
/// already cites, re-read, and those of every exact attempt it witnessed
/// (FIX 8258), in scope, one copy per source id. A card with none is absent.
/// A read that fails is logged and the pass goes on without late labels.
pub(super) fn late(vault: &Vault) -> Late {
    read_late(vault).unwrap_or_else(|error| {
        tracing::warn!(
            kind = ?error.kind(),
            "agent-health late attribution labels not read"
        );
        Late::new()
    })
}

/// The Coach, only when some finding or open card holds a current
/// environment label. Resolved before the review's read snapshot and outside
/// any writer, since resolving it opens a writer of its own. A Coach that does
/// not resolve is no copy this pass: logged, and the nightly pass tries again.
pub(super) fn coach(
    vault: &Vault,
    sources: &[Vec<HealthCauseSource>],
    late: &Late,
) -> Option<EntityId> {
    let wanted = sources
        .iter()
        .chain(late.values())
        .flatten()
        .any(HealthCauseSource::environment);
    if !wanted {
        return None;
    }
    match vault.coach_authority() {
        Ok(coach) => Some(coach.entity_ref()),
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "agent-health environment copy: the Coach did not resolve"
            );
            None
        }
    }
}

/// Folds a finding's labels into its merged card in the landing write, then
/// re-reads every receipt the card cites so a judge displaced since reaches
/// it. A re-read that fails keeps the card's held labels as they were.
pub(super) fn fold_finding(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    card: &mut AgentHealthCard,
    sources: &[HealthCauseSource],
    coach: Option<EntityId>,
) {
    fold(card, sources, None);
    let fresh = held_sources(vault, txn, &card.causes).unwrap_or_else(|error| {
        tracing::warn!(
            kind = ?error.kind(),
            "agent-health attribution labels not re-read"
        );
        Vec::new()
    });
    fold(card, &fresh, coach);
}

/// Folds an open card's late labels into it at the nightly pass. Returns
/// whether the card changed; a changed card is touched at `now`.
pub(super) fn fold_late(
    card: &mut AgentHealthCard,
    late: &Late,
    key: &CardKey,
    coach: Option<EntityId>,
    now: u64,
) -> bool {
    let Some(sources) = late.get(key) else {
        return false;
    };
    if card.outcome != AgentHealthOutcome::Open || !fold(card, sources, coach) {
        return false;
    }
    card.updated_at = now;
    true
}

/// Folds `fresh` into the card's labels. A held label takes its fresh
/// displacement, a new one is appended, and none is ever dropped: a later
/// repeat with no labels never erases an explanation, and a displaced label
/// stays as history. The counter follows the current labels, and a card with
/// a current environment label copies to the Coach, never taken away again.
/// Returns whether the card changed.
fn fold(card: &mut AgentHealthCard, fresh: &[HealthCauseSource], coach: Option<EntityId>) -> bool {
    let mut changed = false;
    for source in fresh {
        if let Some(held) = card
            .causes
            .iter_mut()
            .find(|held| held.source == source.source)
        {
            if *held != *source {
                held.clone_from(source);
                changed = true;
            }
        } else {
            card.causes.push(source.clone());
            changed = true;
        }
    }
    let current = card.causes.iter().any(HealthCauseSource::environment);
    if current
        != card
            .counter_evidence
            .contains(&AgentHealthCounter::EnvironmentCause)
    {
        if current {
            card.counter_evidence
                .push(AgentHealthCounter::EnvironmentCause);
        } else {
            card.counter_evidence
                .retain(|counter| *counter != AgentHealthCounter::EnvironmentCause);
        }
        card.confidence = if card.counter_evidence.is_empty() {
            AgentHealthConfidence::High
        } else {
            AgentHealthConfidence::Low
        };
        changed = true;
    }
    if current && let Some(coach) = coach {
        let before = card.recipients.len();
        add_recipients(&mut card.recipients, card.subject, &[coach]);
        changed |= card.recipients.len() != before;
    }
    changed
}

fn finding_sources(vault: &Vault, findings: &[Finding]) -> Result<Vec<Vec<HealthCauseSource>>> {
    let rtxn = vault.store.env.read_txn()?;
    findings
        .iter()
        .map(|finding| match finding.attempt.as_ref() {
            Some(attempt) => attempt_sources(vault, &rtxn, attempt),
            None => Ok(Vec::new()),
        })
        .collect()
}

fn read_late(vault: &Vault) -> Result<Late> {
    let rtxn = vault.store.env.read_txn()?;
    let mut late = Late::new();
    for (key, card) in CARDS.scan(&vault.store, &rtxn)? {
        if card.outcome != AgentHealthOutcome::Open {
            continue;
        }
        let mut sources = held_sources(vault, &rtxn, &card.causes)?;
        let mut read = BTreeSet::new();
        for attempt in card.witnessed_attempts.iter().chain(&card.attempt) {
            if read.insert(*attempt)
                && let Ok(attempt) = AttemptId::from_bytes(attempt.as_bytes())
            {
                sources.extend(attempt_sources(vault, &rtxn, &attempt)?);
            }
        }
        let mut seen = BTreeSet::new();
        sources.retain(|source| seen.insert(source.source));
        if !sources.is_empty() {
            late.insert(key, sources);
        }
    }
    Ok(late)
}

/// The labels on `attempt`'s sealed terminal pack receipt when one is a
/// current environment label; none for an attempt that sealed no receipt, or
/// whose labels hold no current environment label.
fn attempt_sources(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: &AttemptId,
) -> Result<Vec<HealthCauseSource>> {
    let receipt = attempt_pack_receipt_id(attempt);
    if crate::receipt::attempt_pack_receipt_in_txn(&vault.store, txn, &receipt)?.is_none() {
        return Ok(Vec::new());
    }
    let sources = receipt_sources(vault, txn, &receipt)?;
    if sources.iter().any(HealthCauseSource::environment) {
        Ok(sources)
    } else {
        Ok(Vec::new())
    }
}

/// The labels on every receipt `held` was read from, as they stand now.
fn held_sources(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    held: &[HealthCauseSource],
) -> Result<Vec<HealthCauseSource>> {
    let receipts: BTreeSet<&str> = held.iter().map(|source| source.receipt.as_str()).collect();
    let mut sources = Vec::new();
    for receipt in receipts {
        sources.extend(receipt_sources(vault, txn, receipt)?);
    }
    Ok(sources)
}

fn receipt_sources(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    receipt: &str,
) -> Result<Vec<HealthCauseSource>> {
    let mut sources: Vec<HealthCauseSource> = attempt_attribution_causes(vault, txn, receipt)?
        .into_iter()
        .map(HealthCauseSource::of)
        .collect();
    sources.extend(amendment_sources(vault, txn, receipt)?);
    Ok(sources)
}

/// The labels the amendment judge gave the amended proposals of the attempt
/// that sealed `receipt` (FIX 8264): read for the actor that receipt is bound
/// to, and kept only where the amendment names that very receipt.
fn amendment_sources(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    receipt: &str,
) -> Result<Vec<HealthCauseSource>> {
    let Some(actor) = crate::skill::resident::receipt_resident_in_txn(&vault.store, txn, receipt)?
    else {
        return Ok(Vec::new());
    };
    let mut sources = Vec::new();
    for record in amendment_causes_in_txn(vault, txn, &actor, None, 0..=u64::MAX)? {
        if record.attempt_receipt.as_deref() == Some(receipt) {
            sources.extend(HealthCauseSource::of_amendment(&record, receipt)?);
        }
    }
    Ok(sources)
}
