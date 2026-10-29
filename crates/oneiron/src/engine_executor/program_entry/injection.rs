//! The calls a resumed pinned entry answers instead of issuing them
//! (DOOR-141 PR3b): each one an earlier entry settled, matched in the order
//! the pinned source makes them, and why the entry holds once one does not
//! line up.

use std::collections::VecDeque;

use serde_json::json;

use crate::code_run::{
    AgentVerbAnswer, CodeRunBridgeCall, ProgramResumeCall, ProgramRowAnswer, SelfCall,
    SelfDispatchOutcome,
};

const DIVERGED: &str = "the pinned source made another call where an earlier entry settled one";
const NESTED_CALLABLE: &str = "a callable the pinned entry calls cannot resume inside it";
const UNREADABLE: &str = "a settled call's row does not decode";
const UNCONSUMED: &str = "the pinned source ended before every call an earlier entry settled";

/// The calls one pinned entry answers instead of issuing them, in the order
/// the pinned source makes them.
pub(in crate::engine_executor) struct ProgramInjection {
    /// Whether the entry's own pinned call went by: it is always issued.
    pub(super) entered: bool,
    pub(super) calls: VecDeque<SettledCall>,
    /// The calls answered so far, as the entry's checkpoint lists them.
    pub(super) answered: Vec<ProgramResumeCall>,
    /// Why the entry holds, once a call did not line up.
    pub(super) held: Option<&'static str>,
}

/// One call an earlier entry settled: its row, as listed, and the delivered
/// reply that answers it when it parked on a wait.
pub(super) struct SettledCall {
    pub(super) row: CodeRunBridgeCall,
    pub(super) listed: ProgramResumeCall,
    pub(super) reply: Option<serde_json::Value>,
}

/// What the bridge does with one call of a pinned entry.
pub(in crate::engine_executor) enum InjectedAnswer {
    /// Issue it.
    Live,
    /// Answer it so: an earlier entry settled it.
    Settled {
        outcome: Box<SelfDispatchOutcome>,
        view: Option<serde_json::Value>,
    },
    /// Refuse it, as every call after it: the entry holds.
    Hold,
}

impl ProgramInjection {
    /// The answer for `call`, the next call the pinned source makes. A call
    /// that is not the settled one in its place, a settled row that does not
    /// decode, or a callable called inside the entry holds the entry. A spawn
    /// that misses its row (FIX 7447) runs live, as every call after it.
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
        if matches!(call, SelfCall::SkillsCall(_)) {
            return self.hold(NESTED_CALLABLE);
        }
        let outcome = match settled.row.program_answer_for(call) {
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
        self.answered.push(settled.listed);
        let Some(reply) = settled.reply else {
            return InjectedAnswer::Settled {
                outcome,
                view: None,
            };
        };
        // The call parked on a wait whose reply is delivered: the reply is
        // its answer, as a verb's output reads.
        InjectedAnswer::Settled {
            view: Some(json!({ "output": reply.clone() })),
            outcome: Box::new(SelfDispatchOutcome::AgentVerb(AgentVerbAnswer {
                output: reply,
                rows: None,
                observations: Vec::new(),
            })),
        }
    }

    fn hold(&mut self, why: &'static str) -> InjectedAnswer {
        self.held = Some(why);
        InjectedAnswer::Hold
    }

    /// The calls the entry answered, once it ended: a held entry, or one
    /// whose source ended before every settled call, holds instead.
    pub(super) fn settle(self) -> Result<Vec<ProgramResumeCall>, &'static str> {
        if let Some(held) = self.held {
            return Err(held);
        }
        if !self.calls.is_empty() {
            return Err(UNCONSUMED);
        }
        Ok(self.answered)
    }
}
