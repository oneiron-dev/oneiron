//! OF-544: immutable attempt confessions, directed rechecks and random audit draws.
//! Checks are host-executed against the pinned result, under the host's ordinary
//! Grant and budget. Drawing a check grants no authority and runs no model.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptState};
use crate::learning::TypeRef;
use crate::learning_setting::{AUDIT_RATE, setting_value_in_txn};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};

const SEALS: SideTable<[u8; 16], SealedAttemptReceipt, Named> =
    SideTable::new(&side_table::SELF_HEAL_ATTEMPT_SEAL);

/// The agent's report, not an outcome label. Uncertainty requests examination
/// just as an explicit flaw does, but is not a claim that a flaw exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveConfession {
    pub objective: String,
    pub met: bool,
    pub flaw: Option<String>,
    pub uncertainty: Option<String>,
}

impl ObjectiveConfession {
    #[must_use]
    pub fn confesses_flaw(&self) -> bool {
        !self.met || self.flaw.is_some()
    }

    #[must_use]
    pub fn needs_recheck(&self) -> bool {
        self.confesses_flaw() || self.uncertainty.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptConfession {
    pub attempt: AttemptId,
    /// The skill or actor this attempt measured.
    pub subject: EntityId,
    pub type_ref: TypeRef,
    /// Every objective the attempt was given, including ones it met.
    pub objectives: Vec<ObjectiveConfession>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealCheckKind {
    ConfessionRecheck,
    RandomAudit,
}

/// The draw and the rate are saved together, including unselected draws.
/// Changing an owner's seed or pin never redraws an attempt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditDraw {
    pub rate: f64,
    pub sample: f64,
    pub at: u64,
}

impl AuditDraw {
    #[must_use]
    pub fn selected(&self) -> bool {
        self.sample < self.rate
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealCheckRequest {
    pub reference: String,
    pub attempt: AttemptId,
    pub kind: SealCheckKind,
    pub result_ref: String,
    /// Directed checks name the confessed or uncertain objectives; a random
    /// audit examines every objective, not merely what the agent disclosed.
    pub objectives: Vec<ObjectiveConfession>,
    pub rate: f64,
    pub created_at: u64,
}

/// An independently checked finding, including an evidence ref when clear.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveFinding {
    pub objective: String,
    pub flaw_present: bool,
    pub evidence_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealCheckOutcome {
    pub judge_revision: String,
    pub checked_at: u64,
    /// Exactly one independently checked answer per requested objective.
    pub findings: Vec<ObjectiveFinding>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealCheckReceipt {
    pub request: SealCheckRequest,
    pub outcome: Option<SealCheckOutcome>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedAttemptReceipt {
    pub confession: AttemptConfession,
    pub executor: String,
    pub result_ref: String,
    pub sealed_at: u64,
    pub passing: bool,
    pub draw: Option<AuditDraw>,
    pub checks: Vec<SealCheckReceipt>,
}

fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

fn reference(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(invalid(
            "a seal reference is 1..=256 bytes without controls",
        ));
    }
    Ok(())
}

fn validate_confession(confession: &AttemptConfession) -> Result<()> {
    confession.type_ref.validate()?;
    if confession.objectives.is_empty() || confession.objectives.len() > 256 {
        return Err(invalid("a confession covers 1..=256 objectives"));
    }
    let mut seen = BTreeSet::new();
    for objective in &confession.objectives {
        reference(&objective.objective)?;
        if !seen.insert(&objective.objective) {
            return Err(invalid("a confession repeats an objective"));
        }
        for text in [&objective.flaw, &objective.uncertainty]
            .into_iter()
            .flatten()
        {
            if text.trim().is_empty() || text.len() > 4096 {
                return Err(invalid("a confession detail is nonempty and at most 4 KiB"));
            }
        }
    }
    Ok(())
}

fn request(
    receipt: &SealedAttemptReceipt,
    kind: SealCheckKind,
    rate: f64,
    now: u64,
) -> SealCheckReceipt {
    let objectives = receipt
        .confession
        .objectives
        .iter()
        .filter(|objective| kind == SealCheckKind::RandomAudit || objective.needs_recheck())
        .cloned()
        .collect();
    let tag = match kind {
        SealCheckKind::ConfessionRecheck => "recheck",
        SealCheckKind::RandomAudit => "audit",
    };
    SealCheckReceipt {
        request: SealCheckRequest {
            reference: format!(
                "seal:{tag}:{}",
                crate::entity_id::bytes_to_hex_lower(receipt.confession.attempt.as_bytes())
            ),
            attempt: receipt.confession.attempt,
            kind,
            result_ref: receipt.result_ref.clone(),
            objectives,
            rate,
            created_at: now,
        },
        outcome: None,
    }
}

impl Vault {
    /// Attach one immutable confession to a terminal attempt's pinned output.
    /// Named flaws and uncertainty immediately create durable directed checks.
    /// This writes no learning evidence and changes no task score.
    pub fn record_attempt_confession(
        &self,
        confession: &AttemptConfession,
        now: u64,
    ) -> Result<SealedAttemptReceipt> {
        validate_confession(confession)?;
        self.with_write_txn_grouped(|txn| {
            let key = *confession.attempt.as_bytes();
            if let Some(receipt) = SEALS.get(&self.store, txn, &key)? {
                return if receipt.confession == *confession {
                    Ok(receipt)
                } else {
                    Err(invalid("an attempt's confession is immutable"))
                };
            }
            let attempt = AttemptQueue::new(self)
                .get_in_txn(txn, confession.attempt)?
                .ok_or(Error::EntityNotFound)?;
            if !attempt.state.is_terminal() {
                return Err(invalid("a confession requires a terminal attempt"));
            }
            if !crate::vault::live_entity_row_in_txn(&self.store, txn, &confession.subject)?
                .is_live()
            {
                return Err(Error::EntityNotFound);
            }
            let result_ref = attempt
                .result_ref
                .as_ref()
                .ok_or(invalid(
                    "a confession requires the attempt's durable result",
                ))?
                .as_str()
                .to_owned();
            let executor = attempt.executor_model.ok_or(invalid(
                "a confession requires the attempt's executor revision",
            ))?;
            reference(&executor)?;
            let mut receipt = SealedAttemptReceipt {
                confession: confession.clone(),
                executor,
                result_ref,
                sealed_at: now,
                // Eligibility comes from the durable attempt, never its
                // self-report: confessing cannot opt out of a random audit.
                passing: attempt.state == AttemptState::Completed,
                draw: None,
                checks: Vec::new(),
            };
            if confession
                .objectives
                .iter()
                .any(ObjectiveConfession::needs_recheck)
            {
                receipt.checks.push(request(
                    &receipt,
                    SealCheckKind::ConfessionRecheck,
                    1.0,
                    now,
                ));
            }
            SEALS.put(&self.store, txn, &key, &receipt)?;
            Ok(receipt)
        })
    }

    pub fn sealed_attempt_receipt(
        &self,
        attempt: AttemptId,
    ) -> Result<Option<SealedAttemptReceipt>> {
        let txn = self.store.env.read_txn()?;
        SEALS.get(&self.store, &txn, attempt.as_bytes())
    }

    /// [`Self::sealed_attempt_receipt`] in the caller's snapshot.
    pub(crate) fn sealed_attempt_receipt_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        attempt: AttemptId,
    ) -> Result<Option<SealedAttemptReceipt>> {
        SEALS.get(&self.store, txn, attempt.as_bytes())
    }

    /// Durable work for the host's auditor. Reading a request does not lease
    /// extra budget, widen a Grant, or execute a model.
    pub fn pending_seal_checks(&self) -> Result<Vec<SealCheckRequest>> {
        let txn = self.store.env.read_txn()?;
        Ok(SEALS
            .scan(&self.store, &txn)?
            .into_iter()
            .flat_map(|(_, receipt)| receipt.checks)
            .filter(|check| check.outcome.is_none())
            .map(|check| check.request)
            .collect())
    }

    /// Admit an independently executed check. Raw confession never enters
    /// the projector. Duplicate delivery is idempotent, including after a
    /// setting change; a conflicting finding is refused rather than counted twice.
    pub fn record_seal_check_outcome(
        &self,
        attempt: AttemptId,
        kind: SealCheckKind,
        outcome: &SealCheckOutcome,
        now: u64,
    ) -> Result<SealedAttemptReceipt> {
        reference(&outcome.judge_revision)?;
        self.with_write_txn_grouped(|txn| {
            let mut receipt = SEALS
                .get(&self.store, txn, attempt.as_bytes())?
                .ok_or(Error::EntityNotFound)?;
            let index = receipt
                .checks
                .iter()
                .position(|check| check.request.kind == kind)
                .ok_or(invalid("this attempt has no such seal check"))?;
            let check = &receipt.checks[index];
            if let Some(existing) = &check.outcome {
                return if existing == outcome {
                    Ok(receipt)
                } else {
                    Err(invalid("a completed seal check is immutable"))
                };
            }
            if outcome.checked_at < check.request.created_at || outcome.checked_at > now {
                return Err(invalid(
                    "a seal check's time lies between its request and admission",
                ));
            }
            let expected: BTreeSet<_> = check
                .request
                .objectives
                .iter()
                .map(|objective| objective.objective.as_str())
                .collect();
            let mut seen = BTreeSet::new();
            for finding in &outcome.findings {
                reference(&finding.evidence_ref)?;
                if !expected.contains(finding.objective.as_str())
                    || !seen.insert(finding.objective.as_str())
                {
                    return Err(invalid(
                        "a seal finding is outside the requested objectives",
                    ));
                }
                for prior in receipt
                    .checks
                    .iter()
                    .filter_map(|check| check.outcome.as_ref())
                {
                    if prior.findings.iter().any(|old| {
                        old.objective == finding.objective
                            && old.flaw_present != finding.flaw_present
                    }) {
                        return Err(invalid("seal checks disagree on an objective's finding"));
                    }
                }
            }
            if seen != expected {
                return Err(invalid(
                    "a seal check must examine every requested objective",
                ));
            }
            receipt.checks[index].outcome = Some(outcome.clone());
            crate::learning::honesty::project_seal_check_in_txn(self, txn, &receipt, index, now)?;
            crate::skill_optimize::audit_rate::fit_audit_rate_in_txn(
                self, txn, &receipt, index, now,
            )?;
            SEALS.put(&self.store, txn, attempt.as_bytes(), &receipt)?;
            Ok(receipt)
        })
    }
}

/// The Coach's draw recipe. Each passing attempt gets exactly one draw at
/// the setting in force in this transaction. Directed rechecks do not suppress
/// random audits: uncertainty must not become an escape from a deep check.
pub(crate) fn draw_audits_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    now: u64,
) -> Result<u64> {
    let rate = setting_value_in_txn(&vault.store, txn, &AUDIT_RATE)?;
    if !rate.is_finite() || !(AUDIT_RATE.min..=AUDIT_RATE.max).contains(&rate) {
        return Err(invalid(
            "the seal audit rate is bounded and strictly positive",
        ));
    }
    let mut selected = 0;
    for (key, mut receipt) in SEALS.scan(&vault.store, txn)? {
        if !receipt.passing || receipt.draw.is_some() {
            continue;
        }
        let draw = AuditDraw {
            rate,
            sample: rand::random::<f64>(),
            at: now,
        };
        if draw.selected() {
            receipt
                .checks
                .push(request(&receipt, SealCheckKind::RandomAudit, rate, now));
            selected += 1;
        }
        receipt.draw = Some(draw);
        SEALS.put(&vault.store, txn, &key, &receipt)?;
    }
    Ok(selected)
}
