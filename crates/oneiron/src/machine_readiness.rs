//! The issuer's half of a machine's readiness (pass 34,
//! `34-compute-general/DESIGN.md` sections 7.3 and 16, practice 6; row Q4,
//! Engine ANSWER Q4-ESCALATION-SIDE = B).
//!
//! An execution node checks itself while idle and reports the run of failed
//! checks in its `Node` answer: how many in a row, and when the first of
//! the run failed. The node drains itself on a failed check and clears
//! itself once one passes, with no person (CG-2 row 9). Only a check that
//! keeps failing reaches the owner: once the run reaches
//! `machines.readiness.escalate_after` failed checks (item: the machine;
//! default 3, 45 minutes at the 900 s period), the issuer that read the
//! fact queues ONE decision ask for the run on its own vault, through the
//! built queue as it is ([`Vault::queue_decision_ask`]'s writer): "clear the
//! drain", "keep it drained", or "take the machine out", with "keep it
//! drained" recommended. A later read of the same run finds that ask and
//! queues nothing, also after it was answered; a new run is a new ask.
//!
//! The ask's text is fixed by the run, so its question id (seeded by the
//! family, the machine, the run's start and the text) names the run. The
//! latest check, why and results ride in the ask's state.
//!
//! The caller is the issuer's scheduled read of a node's facts: the job
//! worker's work-order pass reads the `Node` answer (`oneiron-server`'s
//! `gpu_execution_node::issuer::guard::ReadinessReads`).

pub(crate) mod setting_keys;

use serde_json::json;

use crate::error::Result;
use crate::llm::decision::catalogue::MACHINE_READINESS;
use crate::llm::decision::{
    AnswerContract, AskTo, DecisionRung, HumanAskReason, HumanDecisionRequest, ProviderPin,
};
use crate::{EntityId, Vault};

use setting_keys::MACHINE_READINESS_ESCALATE_AFTER;

/// The queue pin of a machine-readiness ask.
pub const MACHINE_READINESS_QUEUE: &str = "machines.readiness";

/// The queue pin's version.
pub const MACHINE_READINESS_QUEUE_VERSION: &str = "v1";

/// The owner's choice that clears the machine's drain: the issuer's half
/// through `vault.machines.execution.clear_drain`. The node's own drain
/// clears at its next passed check, or at the box.
pub const CLEAR_THE_DRAIN: &str = "clear the drain";

/// The owner's choice that changes nothing: the machine stays drained until
/// a check passes. The recommended answer.
pub const KEEP_IT_DRAINED: &str = "keep it drained";

/// The owner's choice that takes the machine out of job service: the built
/// revoke of its job grant.
pub const TAKE_THE_MACHINE_OUT: &str = "take the machine out";

/// A run of failed readiness checks, as a machine reported it in its
/// `Node` answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessStreak {
    /// The machine that reported it.
    pub machine: EntityId,
    /// Its failed checks in a row.
    pub failed_in_a_row: u32,
    /// When the run's first failed check ran, on the machine's wall clock:
    /// the run's identity.
    pub failing_since_ms: u64,
    /// The newest failed check, as the machine names it (`devices`,
    /// `disk`, ...), and why it failed.
    pub check: String,
    pub why: String,
    /// The machine's newest check results, oldest first, one line each.
    pub results: Vec<String>,
}

/// What the issuer did with a run of failed checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessEscalation {
    /// Fewer failed checks in a row than the machine's
    /// `machines.readiness.escalate_after`: nothing reaches the owner.
    BelowThreshold { escalate_after: u32 },
    /// The run's one ask, by its arrival number: queued by this call, or by
    /// an earlier read of the same run.
    Asked { seq: u64, queued_now: bool },
}

impl Vault {
    /// Raises the owner's one decision ask for `streak` once it reaches the
    /// machine's `machines.readiness.escalate_after` failed checks in a row
    /// (a value under one reads as one). The run's ask is found again on
    /// every later read, open or answered, and nothing more is queued.
    ///
    /// # Errors
    ///
    /// Storage errors, and a question the decision catalogue refuses.
    pub fn raise_machine_readiness_ask(
        &self,
        streak: &ReadinessStreak,
    ) -> Result<ReadinessEscalation> {
        self.with_write_txn_grouped(|txn| {
            let escalate_after = MACHINE_READINESS_ESCALATE_AFTER
                .read_in_txn(self, txn, &[], Some(&streak.machine.to_hex()))?
                .value;
            if streak.failed_in_a_row < escalate_after.max(1) {
                return Ok(ReadinessEscalation::BelowThreshold { escalate_after });
            }
            let request = readiness_request(streak)?;
            if let Some(ask) = self.decision_ask_for_in_txn(
                txn,
                &request.question,
                request.principal,
                &request.evidence,
                &request.to,
                request.correlation,
            )? {
                return Ok(ReadinessEscalation::Asked {
                    seq: ask.seq,
                    queued_now: false,
                });
            }
            let state = json!({
                "machine": streak.machine.to_hex(),
                "failed_in_a_row": streak.failed_in_a_row,
                "failing_since_ms": streak.failing_since_ms,
                "check": streak.check,
                "why": streak.why,
                "results": streak.results,
                "recommendation": KEEP_IT_DRAINED,
            });
            let seq = self.queue_decision_ask_in_txn(txn, &request, Some(&state))?;
            Ok(ReadinessEscalation::Asked {
                seq,
                queued_now: true,
            })
        })
    }
}

/// The run's ask, put to the owner: one choice of three, keyed by the
/// machine and the run's start. Its text holds only what the run fixes.
fn readiness_request(streak: &ReadinessStreak) -> Result<HumanDecisionRequest> {
    let machine = streak.machine.to_hex();
    let text = format!(
        "Machine {machine} keeps failing its readiness check, every check since {since} \
         (its own clock). It takes no new work until a check passes, and then clears itself. \
         The latest check, why it failed and the recent results are in this ask's details. \
         Clear the drain, keep it drained, or take the machine out? Recommended: keep it \
         drained.",
        since = utc_millis(streak.failing_since_ms),
    );
    let question = MACHINE_READINESS.question(
        &[
            streak.machine.as_bytes().as_slice(),
            &streak.failing_since_ms.to_be_bytes(),
        ],
        text,
        AnswerContract::Choice {
            options: [CLEAR_THE_DRAIN, KEEP_IT_DRAINED, TAKE_THE_MACHINE_OUT]
                .map(str::to_owned)
                .to_vec(),
        },
    )?;
    Ok(HumanDecisionRequest {
        question,
        principal: streak.machine,
        evidence: vec![streak.machine],
        reason: HumanAskReason::OwnerSelected,
        prior: None,
        prior_provider: None,
        queue_pin: ProviderPin {
            rung: DecisionRung::Human,
            model: MACHINE_READINESS_QUEUE.to_owned(),
            version: MACHINE_READINESS_QUEUE_VERSION.to_owned(),
        },
        to: AskTo::owner(),
        correlation: None,
    })
}

/// RFC 3339 in UTC with milliseconds for a time in Unix milliseconds.
fn utc_millis(unix_ms: u64) -> String {
    i64::try_from(unix_ms)
        .ok()
        .and_then(chrono::DateTime::from_timestamp_millis)
        .map_or_else(
            || format!("{unix_ms} ms after 1970"),
            |stamp| stamp.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        )
}
