//! The skill bodies a call's native producer witnessed (FIX 3608,
//! `crate::skill`): asked for on a skill-library call a durable run makes,
//! made by the leader's pattern load, and taken once by the executor's host
//! with the call's answer. A call of any other kind witnesses none.

use super::{ExecutorCallSite, HostSelfDispatcher};
use crate::memory::HostWriteOrigin;
use crate::skill::{SkillBodyCapture, SkillBodyWitness, WitnessedAnswer, answer_digest};
use crate::task_verb::sdk::AgentVerb;

impl HostSelfDispatcher<'_> {
    /// `origin`, for a call of `verb` at `site`, with where its producer
    /// witnesses the skill bodies its answer carries: for a skill-library
    /// call a durable run makes (`vault.skills.get`, `list`, `archive` and
    /// `restore`, whose answers the library's view makes); else `origin` as
    /// it is.
    pub(super) fn with_skill_body_capture(
        &self,
        origin: HostWriteOrigin,
        verb: AgentVerb,
        site: Option<ExecutorCallSite<'_>>,
    ) -> HostWriteOrigin {
        let library = matches!(
            verb,
            AgentVerb::VaultSkillsGet
                | AgentVerb::VaultSkillsList
                | AgentVerb::VaultSkillsArchive
                | AgentVerb::VaultSkillsRestore
        );
        if !library || site.is_none() {
            return origin;
        }
        let capture = SkillBodyCapture::default();
        *self.skill_bodies.borrow_mut() = Some(capture.clone());
        origin.with_skill_bodies(capture)
    }

    /// Keeps `body`, the skill body the leader's pattern load carries in
    /// `answer`, the JSON it answers with, when the answer carries a file of
    /// it exactly.
    pub(super) fn witness_skill_body(
        &self,
        answer: &serde_json::Value,
        body: Option<SkillBodyWitness>,
    ) {
        let capture = SkillBodyCapture::default();
        if let Some(body) = body {
            capture.witness(WitnessedAnswer {
                answer: answer_digest(answer.to_string().as_bytes()),
                bodies: vec![body],
            });
        }
        *self.skill_bodies.borrow_mut() = Some(capture);
    }

    /// What the last call's producer witnessed of its answer, taken once:
    /// the capture closes, so nothing its producer witnesses later joins it.
    pub(crate) fn take_skill_bodies(&self) -> Option<WitnessedAnswer> {
        self.skill_bodies.take()?.finish()
    }
}
