//! The typed brief one agent-health review observed (OF-568 L7, agent-mind
//! §3.5: "the evidence: the brief revision, receipt ids, the time window and
//! the numbers against the dial"). A pin is a TASK's brief revision and
//! digest as the review read them: a witness alone. It holds no brief text;
//! an older revision's text is read back from the TASK's settled
//! `tasks.brief` history (FIX 8077). The reviewed agent's dispatch captures
//! no brief stamp, so a pin is never a launch snapshot: it is what the review
//! saw when it read the TASK.

use serde::{Deserialize, Serialize};

use super::Finding;
use crate::self_heal::AgentHealthSignal;
use crate::task_verb::StoredBrief;
use crate::{EntityId, Error, Result, Vault};

/// The typed brief THIS REVIEW OBSERVED on a finding's TASK: its revision
/// and digest when the review read it. It is not a launch snapshot, since the
/// reviewed agent's dispatch captures no brief stamp, and it holds no text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthBriefPin {
    /// The TASK whose brief the review read.
    pub task: EntityId,
    /// The brief's revision, as its `BriefStamp` carries it.
    pub rev: u32,
    /// The brief's digest (`BriefStamp::digest`), as 64 hex.
    pub digest: String,
    /// When the review read it.
    pub observed_at: u64,
}

impl HealthBriefPin {
    fn of(task: EntityId, stored: &StoredBrief, observed_at: u64) -> Self {
        Self {
            task,
            rev: stored.rev,
            digest: crate::entity_id::bytes_to_hex_lower(&stored.digest),
            observed_at,
        }
    }

    /// Whether `stored` is the revision this pin observed.
    fn observes(&self, stored: &StoredBrief) -> bool {
        self.rev == stored.rev
            && self.digest == crate::entity_id::bytes_to_hex_lower(&stored.digest)
    }
}

/// The brief an ask froze, as the Coach's model reads it: the pin and the
/// text of the revision it names. It is built for one ask and never stored.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HealthObservedBrief {
    /// The pin the ask froze.
    pub pin: HealthBriefPin,
    /// The observed brief as JSON: the TASK's brief today when it carries
    /// the pin's revision and digest, else the settled `tasks.brief`
    /// revision that landed exactly that revision and digest. `None`: no
    /// such revision reads, as for a posted TASK's first brief once it has
    /// moved on, which no `tasks.brief` CLAIM landed.
    pub text: Option<String>,
}

/// The pin of `task`'s typed brief in `txn`, observed at `now`; `None` when
/// the TASK holds no typed brief.
pub(super) fn pin_task_brief_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
    now: u64,
) -> Result<Option<HealthBriefPin>> {
    Ok(crate::task_verb::task_stored_brief_in(vault, txn, task)?
        .map(|stored| HealthBriefPin::of(task, &stored, now)))
}

/// Pins each finding's TASK brief in `txn`, one snapshot for the landing.
/// `unsupported_done` pinned its own under the read it diagnosed in, so it
/// is left as it is. A finding with no TASK has no pin, and a TASK whose
/// brief does not read lands its card unpinned with a warning: the pin is
/// evidence, never a reason the card fails to land.
pub(super) fn pin_findings_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    findings: &mut [Finding],
    now: u64,
) {
    for finding in findings {
        if finding.signal == AgentHealthSignal::UnsupportedDone {
            continue;
        }
        if let Some(task) = finding.task {
            finding.observed_brief = match pin_task_brief_in(vault, txn, task, now) {
                Ok(pin) => pin,
                Err(error) => {
                    tracing::warn!(
                        task = %task.to_hex(),
                        kind = ?error.kind(),
                        "agent-health brief pin not read"
                    );
                    None
                }
            };
        }
    }
}

/// What an ask hands the Coach from its frozen `pin`, read in `txn`: the
/// pin, with the brief's text when today's brief is the pinned revision, or
/// else when the TASK's settled `tasks.brief` history holds it (FIX 8077).
/// `None` with no pin.
pub(super) fn observed_brief_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pin: Option<&HealthBriefPin>,
) -> Result<Option<HealthObservedBrief>> {
    let Some(pin) = pin else {
        return Ok(None);
    };
    let text = match crate::task_verb::task_stored_brief_in(vault, txn, pin.task)? {
        Some(stored) if pin.observes(&stored) => Some(
            serde_json::to_string(&stored.brief)
                .map_err(|_| Error::InvalidConfig("a typed brief did not encode".into()))?,
        ),
        _ => settled_text_in(vault, txn, pin),
    };
    Ok(Some(HealthObservedBrief {
        pin: pin.clone(),
        text,
    }))
}

/// The pinned revision's text from the TASK's settled `tasks.brief`
/// history, once its brief has moved on. A history that does not read
/// leaves the text unknown, with a warning: it never fails the ask.
fn settled_text_in(vault: &Vault, txn: &heed::RoTxn<'_>, pin: &HealthBriefPin) -> Option<String> {
    match crate::task_verb::settled_brief_in(vault, txn, pin.task, pin.rev, &pin.digest) {
        Ok(brief) => brief.and_then(|brief| serde_json::to_string(&brief).ok()),
        Err(error) => {
            tracing::warn!(
                task = %pin.task.to_hex(),
                kind = ?error.kind(),
                "agent-health brief history not read"
            );
            None
        }
    }
}
