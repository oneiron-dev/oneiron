//! The calls a resumed pinned entry answers instead of issuing them
//! (DOOR-141 PR3b): each one an earlier entry settled, matched in the order
//! the pinned source makes them, and why the entry holds once one does not
//! line up.

use std::collections::VecDeque;

use serde_json::json;

use crate::code_run::{
    AgentVerbAnswer, CodeRunBridgeCall, ProgramResumeCall, ProgramResumeKind, ProgramRowAnswer,
    SelfCall, SelfDispatchOutcome,
};

const DIVERGED: &str = "the pinned source made another call where an earlier entry settled one";
const NESTED_CALLABLE: &str = "a callable the pinned entry calls returned past its wait, halted or stored outputs: it cannot resume inside it";
const CALLABLE_PARKED: &str = "a callable the pinned entry calls parked before its body ran";
const REOPEN_REDIRECTED: &str = "a hook redirected a callable the pinned entry runs again: its earlier calls belong to another body";
const FRAME_UNCONSUMED: &str =
    "a callable the pinned entry resumed returned before every call it settled earlier";
const UNREADABLE: &str = "a settled call's row does not decode";
const HOOK_VIEW: &str =
    "a settled call's guest read a verb hook's view, which its row does not keep";
const UNCONSUMED: &str = "the pinned source ended before every call an earlier entry settled";

/// The calls one pinned entry answers instead of issuing them, in the order
/// the pinned source makes them.
pub(in crate::engine_executor) struct ProgramInjection {
    /// Whether the entry's own pinned call went by: it is always issued.
    pub(super) entered: bool,
    pub(super) calls: VecDeque<SettledCall>,
    /// Every call of the entry so far, in the order the pinned source made
    /// them: answered from an earlier row, or issued at a row of its own
    /// (FIX 5878).
    pub(super) log: Vec<ProgramLogEntry>,
    /// Why the entry holds, once a call did not line up.
    pub(super) held: Option<&'static str>,
    /// Whether the call answered last is an open callable its body runs
    /// again for: the row it is issued at is its own (FIX 5878).
    pub(super) reopening: bool,
    /// The rows of the open callables running again, innermost last.
    pub(super) reopened: Vec<u64>,
}

impl ProgramInjection {
    /// An injection that answers `calls` in their order.
    pub(super) fn new(calls: VecDeque<SettledCall>) -> Self {
        Self {
            entered: false,
            calls,
            log: Vec::new(),
            held: None,
            reopening: false,
            reopened: Vec::new(),
        }
    }
}

/// One call of a pinned entry, in the order its source made it (FIX 5878).
#[derive(Debug, Clone, Copy)]
pub(in crate::engine_executor) enum ProgramLogEntry {
    /// Answered from an earlier entry's row, as listed.
    Answered(ProgramResumeCall),
    /// Issued at this row of the entry's own.
    Issued(u64),
}

/// One call an earlier entry settled: its row, as listed, and the delivered
/// reply that answers it when it parked on a wait.
pub(super) struct SettledCall {
    pub(super) row: CodeRunBridgeCall,
    pub(super) listed: ProgramResumeCall,
    pub(super) reply: Option<serde_json::Value>,
}

/// One callable a pinned entry's calls ran inside its pinned call (FIX
/// 5878): its row, where its own calls end in the entry's log (exclusive),
/// and how a later entry answers it: whole from its row, by running its
/// body again (it unwound on the entry's wait), or not at all (it returned
/// past that wait, the bridge halted inside it, or its own calls stored
/// outputs).
#[derive(Debug, Clone, Copy)]
pub(in crate::engine_executor) struct ProgramCallableSpan {
    pub(in crate::engine_executor) seq: u64,
    pub(in crate::engine_executor) log_end: usize,
    pub(in crate::engine_executor) kind: ProgramResumeKind,
}

/// What the bridge does with one call of a pinned entry.
pub(in crate::engine_executor) enum InjectedAnswer {
    /// Issue it.
    Live,
    /// Answer it so: an earlier entry settled it, in the row at `seq`.
    Settled {
        seq: u64,
        outcome: Box<SelfDispatchOutcome>,
        view: Option<serde_json::Value>,
    },
    /// Refuse it, as every call after it: the entry holds.
    Hold,
}

impl ProgramInjection {
    /// The answer for `call`, the next call the pinned source makes. A call
    /// that is not the settled one in its place, or a settled row that does
    /// not decode, holds the entry, as does a settled call whose guest read
    /// a post hook's view. A callable whose body ended answers from its row,
    /// whole, and its own calls are not replayed (FIX 5878). One whose body
    /// unwound on the entry's wait runs its body again, at a row of its own,
    /// and its own calls meet the rows listed after it. One that returned
    /// past the wait, halted or stored outputs, or that parked before its
    /// body ran, holds. A spawn that misses its row (FIX 7447) runs live, as
    /// every call after it.
    pub(in crate::engine_executor) fn answer(&mut self, call: &SelfCall) -> InjectedAnswer {
        if !self.entered {
            self.entered = true;
            return InjectedAnswer::Live;
        }
        if self.held.is_some() {
            return InjectedAnswer::Hold;
        }
        let Some(settled) = self.calls.pop_front() else {
            return InjectedAnswer::Live;
        };
        if matches!(call, SelfCall::SkillsCall(_)) && settled.reply.is_some() {
            return self.hold(CALLABLE_PARKED);
        }
        match settled.listed.kind {
            ProgramResumeKind::Settled => {}
            ProgramResumeKind::HeldCallable => return self.hold(NESTED_CALLABLE),
            // The same call runs its body again: its row's answer is the
            // body's unwinding, never its result.
            ProgramResumeKind::OpenCallable => {
                // A body a hook redirected before ran another callable: its
                // calls are not this one's to answer.
                if settled.row.rewritten_request.is_some() {
                    return self.hold(REOPEN_REDIRECTED);
                }
                return match settled.row.program_answer_for(call) {
                    Ok(ProgramRowAnswer::Settled(_)) if matches!(call, SelfCall::SkillsCall(_)) => {
                        self.reopening = true;
                        InjectedAnswer::Live
                    }
                    Ok(_) => self.hold(DIVERGED),
                    Err(_) => self.hold(UNREADABLE),
                };
            }
        }
        let outcome = match settled.row.program_answer_for(call) {
            // Its guest read a post hook's view in place of the result the
            // row keeps (a callable's included): the row cannot answer it as
            // the guest read it, so the entry holds, as a resumed pending
            // step does.
            Ok(ProgramRowAnswer::Settled(_)) if settled.row.hook_view_served => {
                return self.hold(HOOK_VIEW);
            }
            Ok(ProgramRowAnswer::Settled(outcome)) => outcome,
            // The same spawn asked for another project or other objectives
            // (FIX 7447): no row answers it, so it runs live through its
            // ordinary gates, and so does every call after it, which may read
            // what it answers now. The rows they settled stay in the record;
            // the entry lists the calls it made in their place.
            Ok(ProgramRowAnswer::Missed) => {
                self.calls.clear();
                return InjectedAnswer::Live;
            }
            Ok(ProgramRowAnswer::Drifted) => return self.hold(DIVERGED),
            Err(_) => return self.hold(UNREADABLE),
        };
        self.log.push(ProgramLogEntry::Answered(settled.listed));
        let seq = settled.row.seq;
        let Some(reply) = settled.reply else {
            return InjectedAnswer::Settled {
                seq,
                outcome,
                view: None,
            };
        };
        // The call parked on a wait whose reply is delivered: the reply is
        // its answer, as a verb's output reads.
        InjectedAnswer::Settled {
            seq,
            view: Some(json!({ "output": reply.clone() })),
            outcome: Box::new(SelfDispatchOutcome::AgentVerb(AgentVerbAnswer::new(
                reply, None,
            ))),
        }
    }

    fn hold(&mut self, why: &'static str) -> InjectedAnswer {
        self.held = Some(why);
        InjectedAnswer::Hold
    }

    /// Notes the call the bridge issues at `seq`, after the injection let it
    /// run live: an open callable running its body again owns it (FIX 5878).
    pub(in crate::engine_executor) fn issued(&mut self, seq: u64) {
        self.log.push(ProgramLogEntry::Issued(seq));
        if std::mem::take(&mut self.reopening) {
            self.reopened.push(seq);
        }
    }

    /// How many calls the entry made so far.
    pub(in crate::engine_executor) fn log_len(&self) -> usize {
        self.log.len()
    }

    /// The callable at `seq` returned. One that ran its body again must have
    /// met every call listed after it: those it settled before lie inside
    /// it, up to the wait the entry parked on (FIX 5878).
    pub(in crate::engine_executor) fn returned(&mut self, seq: u64) {
        if self.reopened.last() != Some(&seq) {
            return;
        }
        self.reopened.pop();
        if self.held.is_none() && !self.calls.is_empty() {
            self.held = Some(FRAME_UNCONSUMED);
        }
    }

    /// A hook rewrote the call at `seq`: one that runs a callable's body
    /// again holds the entry, as the body it runs is not the one its earlier
    /// calls came from (FIX 5878). Its calls are refused from here on, so
    /// none takes effect.
    pub(in crate::engine_executor) fn redirected(&mut self, seq: u64) {
        if self.reopened.last() == Some(&seq) && self.held.is_none() {
            self.held = Some(REOPEN_REDIRECTED);
        }
    }

    /// Every call of the entry, in its source's order, once it ended: a
    /// held entry, one whose source ended before every settled call, or
    /// one a callable it ran again did not return from, holds instead.
    pub(super) fn settle(self) -> Result<Vec<ProgramLogEntry>, &'static str> {
        if let Some(held) = self.held {
            return Err(held);
        }
        if !self.calls.is_empty() {
            return Err(UNCONSUMED);
        }
        if !self.reopened.is_empty() {
            return Err(FRAME_UNCONSUMED);
        }
        Ok(self.log)
    }
}
