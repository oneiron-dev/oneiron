//! Named producers of a queued attempt's recorded input rows.

/// One host producer that reads some of an attempt's inputs and reports
/// their rows (FIX 7073), kept on the record as its key. Each producer is
/// one constant here, so no two share a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadSetProducer(&'static str);

impl ReadSetProducer {
    /// The Coach's training-offer draft: its brief, the offer skill's body
    /// and the pilots its draft grounds on.
    pub const COACH_OFFER_DRAFT: Self = Self("coach.offer_draft");

    /// The skill pack load door: the SKILL whose instructions loaded and the
    /// replicated carrier its package was recovered from (FIX 7017).
    pub const SKILL_PACK: Self = Self("skill.pack_load");

    /// The actor claim load door: each actor CLAIM a run loaded (FIX 7017).
    pub const ACTOR_CLAIM: Self = Self("actor.claim_load");

    /// A resident run's tool answers: the rows each verb answer listed as
    /// served (FIX 7017).
    pub const TOOL_ANSWERS: Self = Self("resident.tool_answers");

    /// The skill bodies a resident run's host exposed in its task (FIX 7020).
    pub const CODE_RUN_TASK_EXPOSURE: Self = Self("resident.task_exposure");

    /// A resident run's model-step inputs (FIX 7020); unknown until FIX 7104
    /// keeps their complete row set.
    pub const CODE_RUN_STEP_INPUT: Self = Self("resident.step_input");

    /// The host-built resident task itself (FIX 7020): not source-free, so
    /// its producer reports None without a witnessed row source (Engine
    /// 03:58, CALLS `FIX 7020 host-built task source`).
    pub const CODE_RUN_HOST_TASK: Self = Self("resident.host_task");

    /// A Dreamer weave recipe's evidence: the one row its draft reads
    /// (FIX 7019).
    pub const DREAMER_RECIPE_EVIDENCE: Self = Self("dreamer.recipe_evidence");

    /// A Dreamer weave lens render's period: the rows its stored report's
    /// items were read from (FIX 7019).
    pub const DREAMER_WEAVE_REPORT: Self = Self("dreamer.weave_report");

    /// A Dreamer consolidation branch's extraction: each slice's TURNs,
    /// conversations, projected MESSAGEs and the listed rows its page
    /// shows, and every row its branch pinned (FIX 7019).
    pub const DREAMER_EXTRACTION: Self = Self("dreamer.extraction");

    /// The Coach's eval-authoring pass: the inventory it read and the
    /// authoring skill's body (FIX 7019).
    pub const COACH_EVAL_AUTHORING: Self = Self("coach.eval_authoring");

    /// A workflow model step's input: its agent definition row, the memory
    /// and chat rows its context render read and its planner craft (FIX 6934).
    pub const WORKFLOW_STEP_INPUT: Self = Self("workflow.step_input");

    /// A Coach attribution pass's complete trace inputs (FIX 7020).
    pub const ATTRIBUTION_TRACE: Self = Self("coach.attribution_trace");

    /// A review explainer's proposal, fork and live-entity inputs (FIX 7020).
    pub const REVIEW_BUNDLE: Self = Self("entity_doc.review_bundle");

    /// The key the record keeps.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}
