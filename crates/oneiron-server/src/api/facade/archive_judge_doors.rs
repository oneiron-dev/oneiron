//! `vault.research.archive.judge` (ARM05 P3; ARCH-0053 #output-archive,
//! ARCH-0076): one output revision's placement and quality score for its
//! campaign's controller, asked of this host's decision ladder on the
//! caller's own line. The engine checks the controller gate, reads the
//! output, the task and the pinned judge rubric, takes only answers made at
//! the band's high mark with no person asked, and records the placement and
//! score producer records the caller passes to
//! `vault.research.archive.record`. This door lends it the ladder and the
//! admitted embedder.
use std::sync::Arc;
use std::time::Duration;

use oneiron::autoreason_campaign::archive::{
    ArchiveJudgeAsk, ArchiveJudgeHost, ArchiveJudgeQuestion, CampaignArchiveJudge,
    CampaignArchiveJudged,
};
use oneiron::embed::Embedder;
use oneiron::llm::decision::catalogue::{ARCHIVE_PLACEMENT, SKILL_OPTIMIZE_JUDGMENT};
use oneiron::llm::decision::{DecisionRung, Reversibility, TypedDecision};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::AI_VERDICT_DEADLINE_MS;
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{Listed, credential_listing};
use crate::auth::CoreAuth;
use crate::decision_graph::{LadderCall, ladder_decide};
use crate::replay_judge::JUDGE_REVISION;
use crate::server::SyncServer;

const VERB: &str = "vault.research.archive.judge";
/// One axis's placement question: this host's wording. The call's state
/// carries the task, the response, the axis and its bins.
const PLACEMENT_WORDING: &str = "Which of this axis's bins does the response fall in? Judge the \
kind of response it is along the state's axis, never how good it is, and answer the one bin that \
names that kind.";
/// The score question's kind beside the replay judge's revision.
const SCORE_KIND: &str = "archive_score";

/// The host's ladder on one caller's line, and its embedder.
struct CallerLadder<'a> {
    server: &'a SyncServer,
    caller: (EntityId, EdgeActorClass),
}

impl ArchiveJudgeHost for CallerLadder<'_> {
    fn decide(&self, ask: &ArchiveJudgeAsk) -> oneiron::Result<TypedDecision> {
        let key: Vec<&[u8]> = ask.key.iter().map(String::as_bytes).collect();
        let question = match &ask.question {
            ArchiveJudgeQuestion::Placement { .. } => {
                ARCHIVE_PLACEMENT.question(&key, PLACEMENT_WORDING.to_owned(), ask.contract())?
            }
            // The replay judge's own response_score wording, as the ruler
            // ruling names it (ARCHIVE-QUALITY-RULER = A).
            ArchiveJudgeQuestion::Score => {
                let wording = &self.server.config.skills.replay_judge;
                let revision = format!("{JUDGE_REVISION}+{}", wording.digest());
                let mut parts = vec![revision.as_bytes(), SCORE_KIND.as_bytes()];
                parts.extend(key);
                SKILL_OPTIMIZE_JUDGMENT.question(
                    &parts,
                    wording.response_score.clone(),
                    ask.contract(),
                )?
            }
        };
        let host = self.server.decision_host();
        let deadline = RetrievalDeadline::after(Duration::from_millis(AI_VERDICT_DEADLINE_MS));
        ladder_decide(
            self.server,
            LadderCall {
                principal: self.caller.0,
                class: self.caller.1,
                question: &question,
                evidence: &ask.evidence,
                images: &[],
                audio: &[],
                state: &ask.state,
                // Never an owner ask: an unanswered question is refused.
                dial: host.dial(DecisionRung::Big),
                policy: &host.bands(),
                reversibility: Reversibility::ReversibleRead,
                deadline: &deadline,
                label: VERB,
                ask_to: None,
                correlation: None,
                posture: None,
            },
        )
    }

    fn embedder(&self) -> Option<Arc<dyn Embedder>> {
        self.server
            .embedder_slot()?
            .admitted_provider()
            .map(|embedder| embedder as Arc<dyn Embedder>)
    }
}

/// `vault.research.archive.judge` (`host_door_lists`, `host_door_caller`):
/// the row's `facade_actor` proof admits a caller bound to a principal; the
/// engine checks the controller gate on the request's root before any
/// question and again in its writer. The answer names the producer records
/// the engine wrote and the output the caller named; it serves no row
/// content, so the list holds only what the caller's reads derived it from.
pub(crate) async fn vault_research_archive_judge(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: CampaignArchiveJudge,
) -> Listed<CampaignArchiveJudged> {
    credential_listing(server, auth, caller, VERB, move |server, auth, memory| {
        let ladder = CallerLadder { server, caller };
        crate::decision_verdict::on_caller_line(
            server.vault(),
            caller,
            VERB,
            auth.off_record_session(),
            || oneiron::verbs::research_archive_judge(&memory, input, &ladder),
        )
    })
    .await
}
