//! The Coach's in-vault replay of an instruction candidate (OF-380, FIX
//! 1662): the failing agent's call as the vault kept it, or rebuilt from the
//! real failure, replayed with no tool run before and after the instruction
//! is added, each reply judged on the host's decision ladder; and the
//! in-vault scrubber the invented example's door asks.

use std::cell::RefCell;
use std::rc::Rc;

use serde_json::json;

use super::{CodeFixDecisions, CodeFixHost, CodeFixJob, PublisherCandidateKind, class_name};
use crate::failure_signals::{
    CodeFixReplay, CodeFixSourceSnapshot, ExactReplay, ExactReplayRequest, ExportScrubber,
    FailureSource, InventedExampleDraft, InventedMessage, InventedRole, ReplayFidelity, ReplayRun,
    ScrubRun, ShadowRun, exact_replay,
};
use crate::limit_ask::EngineLimit;
use crate::{ContentPart, EntityId, LlmMessage, LlmMessageRole, LlmRequest, Result, Vault};

const REPRODUCED_WORDING: &str = "Does the reply fail the way the failure describes?";
const FIXED_WORDING: &str = "The reply before failed the way the failure describes. Does the \
    reply after no longer fail that way?";
const SAFE_WORDING: &str = "Is this text plainly made up, with no real person's name, contact \
    detail, account, address, private fact or secret in it?";

/// The Coach's in-vault replay of one job: the failing agent's call as the
/// vault kept it, or rebuilt from the real failure, run with no tool run,
/// judged on the ladder.
pub(super) struct CoachReplay<'a> {
    /// Where the texts its questions read whole are measured.
    pub(super) vault: &'a Vault,
    pub(super) job: &'a CodeFixJob,
    pub(super) host: &'a dyn CodeFixHost,
    pub(super) decisions: &'a CodeFixDecisions<'a>,
    pub(super) evidence: &'a [EntityId],
    /// The real failure as this run read it once (OF-380 L1): the failing
    /// call its replay starts from and its engine pairs run from, and the
    /// texts its invented example may copy nothing of.
    pub(super) snapshot: &'a CodeFixSourceSnapshot,
    /// The id of the Coach's own candidate, drafted from the job: a reply
    /// under it reads the draft (FIX 6997).
    pub(super) drafted: Option<String>,
    /// Each candidate's id and what it is: the instruction it adds, or the
    /// engine its matched pair runs (`engine`), never a prompt string.
    pub(super) candidates: Vec<(String, PublisherCandidateKind)>,
    /// What the vault kept of the request the failing call sent (FIX 1662),
    /// read again before each replay send: a copy since gone or changed is
    /// dropped and never sent again (FIX 6659), and once its capsule reads
    /// erased no replay of the call runs, rebuilt or not (FIX 6251).
    pub(super) exact: RefCell<ExactReplay>,
    /// The real failing call and the agent's reply to it, once a replay
    /// reproduced the failure; `None` when it did not, or could not run.
    /// One the kept request ran is dropped with it (FIX 6659).
    pub(super) baseline: RefCell<Option<Option<Rc<Baseline>>>>,
}

/// The real failing call replayed: the conversation its questions read, the
/// agent's reply, and how the call was sent.
pub(super) struct Baseline {
    conversation: Vec<InventedMessage>,
    before: String,
    fidelity: ReplayFidelity,
}

impl CoachReplay<'_> {
    /// Measures the longest text a question's state carries whole: each
    /// message of `conversation` and a reply of `reply` bytes.
    fn measure(&self, conversation: &[InventedMessage], reply: usize) {
        let longest = conversation
            .iter()
            .map(|message| message.text.len())
            .fold(reply, usize::max);
        let _ = self
            .vault
            .measure_limit(EngineLimit::MaintenanceTextBytes, longest as u64);
    }

    fn failure_state(&self, note: Option<&str>) -> serde_json::Value {
        json!({
            "failure_class": class_name(self.job.failure_class),
            "reports": self.job.reports,
            "note": note,
        })
    }

    /// Does `reply` to `conversation` fail the way the case did?
    pub(super) fn fails(
        &self,
        note: Option<&str>,
        conversation: &[InventedMessage],
        reply: &str,
    ) -> Option<bool> {
        self.measure(conversation, reply.len());
        let state = json!({
            "failure": self.failure_state(note),
            "conversation": conversation_state(conversation),
            "reply": reply,
        });
        self.decisions
            .yes("reproduced", REPRODUCED_WORDING, self.evidence, &state)
    }

    /// The real failing call: what the agent was briefed on and asked.
    fn real_conversation(&self) -> Option<Vec<InventedMessage>> {
        let source = &self.job.source;
        let text = [source.briefing.as_deref(), source.task.as_deref()]
            .into_iter()
            .flatten()
            .filter(|text| !text.trim().is_empty())
            .collect::<Vec<_>>()
            .join("\n\n");
        (!text.is_empty()).then(|| {
            vec![InventedMessage {
                role: InventedRole::User,
                text,
            }]
        })
    }

    /// The kept request's state, read again from the vault just before a
    /// replay sends the call (FIX 6659, 6251). Once its capsule reads erased
    /// it stays erased, read no more, and the baseline is dropped, a rebuilt
    /// one included: the call is replayed no more. Otherwise a copy an erase
    /// took since the job read it, or one that no longer reads as it did, is
    /// dropped and never sent again, and the call may be rebuilt; a copy the
    /// job did not read is not taken up now.
    fn live_exact(&self) -> Result<ExactReplay> {
        if matches!(*self.exact.borrow(), ExactReplay::Erased) {
            return Ok(ExactReplay::Erased);
        }
        let live = exact_replay(self.vault, &self.job.origin)?;
        if matches!(live, ExactReplay::Erased) {
            *self.exact.borrow_mut() = ExactReplay::Erased;
            *self.baseline.borrow_mut() = Some(None);
            return Ok(ExactReplay::Erased);
        }
        let mut kept = self.exact.borrow_mut();
        if kept.request().is_some() && kept.request() == live.request() {
            return Ok(live);
        }
        *kept = ExactReplay::NotKept;
        Ok(ExactReplay::NotKept)
    }

    /// The real failing call replayed once for every candidate: the request
    /// it sent, when the vault kept it and the host sends it as kept, else
    /// the call rebuilt from the failure's text (FIX 1662). A failure the
    /// replay does not reproduce cannot say whether a candidate fixed it.
    /// The kept request is read again last, just before the send this
    /// precedes: beside a baseline the kept request ran, that request as
    /// read now; one whose copy is gone is dropped with it, and the call is
    /// rebuilt (FIX 6659). Once the call's capsule reads erased, no baseline
    /// stands, a rebuilt one included (FIX 6251).
    fn baseline(&self) -> Result<Option<(Rc<Baseline>, Option<ExactReplayRequest>)>> {
        let ran = self.baseline.borrow().clone();
        let ran = match ran {
            Some(ran) => ran,
            None => {
                let ran = match self.exact_baseline()? {
                    Some(ran) => Some(ran),
                    None => self.rebuilt_baseline()?,
                }
                .map(Rc::new);
                *self.baseline.borrow_mut() = Some(ran.clone());
                ran
            }
        };
        let Some(baseline) = ran else {
            return Ok(None);
        };
        let live = self.live_exact()?;
        if matches!(live, ExactReplay::Erased) {
            return Ok(None);
        }
        if baseline.fidelity == ReplayFidelity::Rebuilt {
            return Ok(Some((baseline, None)));
        }
        if let Some(exact) = live.request() {
            return Ok(Some((baseline, Some(exact.clone()))));
        }
        *self.baseline.borrow_mut() = None;
        drop(baseline);
        self.baseline()
    }

    /// The kept request sent again, when it reproduces the failure: read
    /// again just before it is sent (FIX 6659, 6251).
    fn exact_baseline(&self) -> Result<Option<Baseline>> {
        let live = self.live_exact()?;
        let Some(exact) = live.request() else {
            return Ok(None);
        };
        let Some(before) = self.host.reply_exact(exact)? else {
            return Ok(None);
        };
        let conversation = request_conversation(&exact.request);
        if self.fails(None, &conversation, &before) != Some(true) {
            return Ok(None);
        }
        Ok(Some(Baseline {
            conversation,
            before,
            fidelity: exact.fidelity(),
        }))
    }

    /// The call rebuilt from the failure's text, when it reproduces the
    /// failure; none once the call's capsule reads erased, read again just
    /// before the call is sent (FIX 6251).
    fn rebuilt_baseline(&self) -> Result<Option<Baseline>> {
        let Some(conversation) = self.real_conversation() else {
            return Ok(None);
        };
        if matches!(self.live_exact()?, ExactReplay::Erased) {
            return Ok(None);
        }
        // The rebuilt call sends the failure's own texts alone.
        let rows = self.job.source.source_rows.clone();
        Ok(self
            .host
            .reply(&self.job.source.instructions, &conversation, rows)?
            .filter(|before| self.fails(None, &conversation, before) == Some(true))
            .map(|before| Baseline {
                conversation,
                before,
                fidelity: ReplayFidelity::Rebuilt,
            }))
    }

    /// How the baseline ran, once one reproduced the failure.
    pub(super) fn fidelity(&self) -> Option<ReplayFidelity> {
        self.baseline
            .borrow()
            .as_ref()
            .and_then(Option::as_ref)
            .map(|baseline| baseline.fidelity)
    }

    /// Did the candidate fix the failure: `before`, the reply that failed the
    /// way the failure did, and `after`, the reply under the candidate, each
    /// to `conversation`, read whole and measured. `Unavailable` when the
    /// ladder failed, abstained or answered off the contract.
    pub(super) fn fixed(
        &self,
        conversation: &[InventedMessage],
        before: &str,
        after: &str,
    ) -> ShadowRun {
        self.measure(conversation, before.len().max(after.len()));
        let state = json!({
            "failure": self.failure_state(None),
            "conversation": conversation_state(conversation),
            "before": before,
            "after": after,
        });
        match self
            .decisions
            .yes("fixed", FIXED_WORDING, self.evidence, &state)
        {
            Some(true) => ShadowRun::Fixed,
            Some(false) => ShadowRun::NotFixed,
            None => ShadowRun::Unavailable,
        }
    }
}

impl CodeFixReplay for CoachReplay<'_> {
    fn reproduces(
        &self,
        _failure: &FailureSource,
        example: &InventedExampleDraft,
    ) -> Result<ReplayRun> {
        // The live agent answers in place of the invented failing turn.
        let Some(last) = example
            .conversation
            .iter()
            .rposition(|message| message.role == InventedRole::User)
        else {
            return Ok(ReplayRun::Unavailable);
        };
        let conversation = &example.conversation[..=last];
        // The invented example is the draft's: the reply reads the job's rows.
        let rows = self.job.source_rows.clone();
        let Some(reply) = self
            .host
            .reply(&self.job.source.instructions, conversation, rows)?
        else {
            return Ok(ReplayRun::Unavailable);
        };
        Ok(
            match self.fails(Some(&example.note), conversation, &reply) {
                Some(true) => ReplayRun::Reproduced,
                Some(false) => ReplayRun::NotReproduced,
                None => ReplayRun::Unavailable,
            },
        )
    }

    fn shadow_replay(&self, _failure: &FailureSource, candidate_id: &str) -> Result<ShadowRun> {
        // Only an instruction is added to the agent's: an engine candidate
        // runs as a matched pair of its own (`engine`).
        let Some((_, PublisherCandidateKind::Instruction { instruction: fix })) =
            self.candidates.iter().find(|(id, _)| id == candidate_id)
        else {
            return Ok(ShadowRun::Unavailable);
        };
        // The kept request was read again last in `baseline`, just before
        // this send: once the call's capsule reads erased there is none, and
        // no after runs (FIX 6251).
        let Some((baseline, exact)) = self.baseline()? else {
            return Ok(ShadowRun::Unavailable);
        };
        let (conversation, before) = (&baseline.conversation, &baseline.before);
        // The fix runs the way the failure was replayed: on the kept request
        // when that reproduced it (FIX 1662) and its copy is still kept
        // (FIX 6659), else on the rebuilt call.
        let after = match exact {
            Some(exact) => self.host.reply_exact(&with_fix(&exact, fix))?,
            None => {
                let instructions = &self.job.source.instructions;
                let system = [instructions.as_str(), fix.as_str()]
                    .into_iter()
                    .filter(|text| !text.trim().is_empty())
                    .collect::<Vec<_>>()
                    .join("\n\n");
                // The Coach's own fix is the draft's; a publisher's is the
                // host's configuration, which adds no rows.
                let rows = if self.drafted.as_deref() == Some(candidate_id) {
                    self.job.source_rows.clone()
                } else {
                    self.job.source.source_rows.clone()
                };
                self.host.reply(&system, conversation, rows)?
            }
        };
        let Some(after) = after else {
            return Ok(ShadowRun::Unavailable);
        };
        Ok(self.fixed(conversation, before, &after))
    }
}

/// The in-vault scrubber: one typed question over the whole text, measured.
pub(super) struct CoachScrubber<'a> {
    pub(super) vault: &'a Vault,
    pub(super) decisions: &'a CodeFixDecisions<'a>,
    pub(super) evidence: &'a [EntityId],
}

impl ExportScrubber for CoachScrubber<'_> {
    fn scrub(&self, text: &str) -> Result<ScrubRun> {
        let _ = self
            .vault
            .measure_limit(EngineLimit::MaintenanceTextBytes, text.len() as u64);
        let state = json!({ "text": text });
        Ok(
            match self
                .decisions
                .yes("export_safe", SAFE_WORDING, self.evidence, &state)
            {
                Some(true) => ScrubRun::Clean,
                Some(false) => ScrubRun::Flagged,
                None => ScrubRun::Unavailable,
            },
        )
    }
}

/// A shadow replay already run, handed to the export door so the candidate
/// runs once.
pub(super) struct Ran(pub(super) ShadowRun);

impl CodeFixReplay for Ran {
    fn reproduces(
        &self,
        _failure: &FailureSource,
        _example: &InventedExampleDraft,
    ) -> Result<ReplayRun> {
        Ok(ReplayRun::Unavailable)
    }

    fn shadow_replay(&self, _failure: &FailureSource, _candidate_id: &str) -> Result<ShadowRun> {
        Ok(self.0)
    }
}

/// The kept request's messages as its questions read them, every part whole:
/// text as written, any other part as its JSON.
pub(super) fn request_conversation(request: &LlmRequest) -> Vec<InventedMessage> {
    request
        .messages
        .iter()
        .map(|message| InventedMessage {
            role: match message.role {
                LlmMessageRole::System => InventedRole::System,
                LlmMessageRole::User => InventedRole::User,
                LlmMessageRole::Assistant => InventedRole::Assistant,
                LlmMessageRole::Tool => InventedRole::Tool,
            },
            text: message
                .content
                .iter()
                .map(|part| match part {
                    ContentPart::Text { text } => text.clone(),
                    other => serde_json::to_string(other).unwrap_or_default(),
                })
                .collect::<Vec<_>>()
                .join("\n\n"),
        })
        .collect()
}

/// `exact` with a candidate's `fix` added to the agent's instructions: one
/// system message after those the request leads with. A blank fix adds
/// nothing.
fn with_fix(exact: &ExactReplayRequest, fix: &str) -> ExactReplayRequest {
    let mut exact = exact.clone();
    if !fix.trim().is_empty() {
        let at = exact
            .request
            .messages
            .iter()
            .take_while(|message| message.role == LlmMessageRole::System)
            .count();
        exact.request.messages.insert(
            at,
            LlmMessage {
                role: LlmMessageRole::System,
                content: vec![ContentPart::Text {
                    text: fix.to_owned(),
                }],
            },
        );
    }
    exact
}

fn conversation_state(conversation: &[InventedMessage]) -> Vec<serde_json::Value> {
    conversation
        .iter()
        .map(|message| json!({ "role": message.role, "text": message.text }))
        .collect()
}
