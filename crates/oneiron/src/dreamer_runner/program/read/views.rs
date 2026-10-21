//! The wire shapes of a turn program's reads (DOOR-141 PR3a). Ids are
//! lowercase hex: 32 characters for an entity, attempt or step, 64 for a
//! digest. Times are the vault's recording clock, in seconds. A field the
//! caller's own lane does not read is absent and named in `withheld`.

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::llm::model_step::SettledStepView;

use super::super::types::ProgramRecipePin;

/// The admissions the wakes of one landed turn decided, one page at a time.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TurnProgramAdmissionRequest {
    /// 32-hex id of the TURN whose landing woke the programs.
    pub turn_ref: String,
    /// 32-hex registration: only the admission of this armed program.
    #[serde(default)]
    pub registration: Option<String>,
    /// The previous page's `next_cursor`: the scan goes on after it.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Admissions in this page: 64 when absent, at most 64. Must be positive.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// One page of a turn's admissions the caller reads, in admission-id order.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TurnProgramAdmissionView {
    pub turn_ref: String,
    pub admissions: Vec<TurnProgramAdmissionItem>,
    /// Where the next page's scan goes on; none once every admission was
    /// examined. A page may hold none and still name one.
    pub next_cursor: Option<String>,
    /// Admission rows this page's scan examined that do not decode
    /// (FIX 5839): skipped, each counted on one page alone. A diagnostic of
    /// the scan, not a count of this turn's admissions.
    pub undecodable_admission_rows_examined: u64,
}

/// What admitting one wake decided.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TurnProgramAdmissionItem {
    /// 64-hex admission id: actor, registration, definition revision and
    /// turn.
    pub admission: String,
    pub registration: EntityId,
    /// The waking actor the program runs as, and its class.
    pub actor: EntityId,
    pub actor_class: String,
    /// The turn's conversation; withheld unless the turn and the
    /// conversation read on the caller's lane.
    pub conversation: Option<EntityId>,
    /// When the turn landed; withheld unless the turn reads on the caller's
    /// lane.
    pub landed_at: Option<u64>,
    /// 64-hex definition revision the wake woke.
    pub revision: String,
    /// The pinned executable the admission bound; none for a refusal, and
    /// withheld unless its SKILL reads on the caller's lane.
    pub definition: Option<ProgramRecipePin>,
    /// 64-hex digest of the credential scope the waking turn was admitted
    /// under, when a credential admitted it.
    pub sealed_scope: Option<String>,
    /// 32-hex Gate decision that recorded the admission.
    pub gate_receipt: String,
    pub outcome: ProgramAdmissionOutcomeView,
    pub decided_at: u64,
    /// The fields withheld from this caller, by name.
    pub withheld: Vec<String>,
}

/// Whether an admission queued the program or refused it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProgramAdmissionOutcomeView {
    /// Queued as the root attempt of its run tree, in the code run the
    /// admission fixed (also the attempt's queue run id).
    Queued { root: String, code_run: String },
    /// Refused in the admission's writer; nothing was queued.
    Refused { reason: String },
}

/// Where one program's run stands, with one page of its steps.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProgramRunRequest {
    /// 32-hex id of the program's root attempt, or of any try of it (`job:`
    /// prefix allowed).
    pub root: String,
    /// The previous page's `next_cursor`: the step list goes on after it.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Steps in this page: 64 when absent, at most 64. Must be positive.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// One program's run: its admission's binding, its queue tries, the program
/// runtime's own record of its code run, and a page of its steps. The run
/// tree, the run-tree row and the rest are each read in a snapshot of their
/// own: nothing here claims they agree at one instant.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProgramRunView {
    /// 32-hex root attempt its admission queued.
    pub root: String,
    /// 64-hex admission.
    pub admission: String,
    /// The waking actor the program runs as, and its class.
    pub actor: EntityId,
    pub actor_class: String,
    /// 32-hex code run the program runs as, also its queue run id.
    pub code_run: String,
    /// The pinned executable; withheld unless its SKILL reads on the
    /// caller's lane.
    pub definition: Option<ProgramRecipePin>,
    /// When the root entered its run tree, from its run-tree row.
    pub root_created_at: Option<u64>,
    /// Every try of the run, in the order the queue made them.
    pub tries: Vec<ProgramTryView>,
    /// The newest try's queue row.
    pub queue: Option<ProgramQueueView>,
    /// The newest try parked and not terminal (FIX 5712): work the program
    /// still owes, held, not runnable. Nothing arms a deadline for it.
    pub held: Option<ProgramHeldView>,
    /// Every try of `tries` parked and not terminal, the newest among them,
    /// in the same order (FIX 5840).
    pub held_by_try: Vec<ProgramHeldView>,
    /// The program runtime's record of its code run; none before a try
    /// entered it.
    pub run: Option<ProgramRunStateView>,
    /// One page of the run's steps, in step-ref order.
    pub steps: Vec<ProgramStepView>,
    /// Step rows of this page that do not decode (FIX 5736), skipped.
    pub undecodable_steps: u64,
    /// Where the next page starts; none past the last step.
    pub next_cursor: Option<String>,
    /// The fields withheld from this caller, by name.
    pub withheld: Vec<String>,
}

/// One try of a program's run, as its run tree renders it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProgramTryView {
    pub attempt: String,
    /// The run tree's status: queued, running, paused, completed, failed,
    /// cancelled or abandoned.
    pub status: String,
    pub result_ref: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// One try's queue row.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProgramQueueView {
    pub attempt: String,
    /// The queue state, as the attempt queue names it.
    pub state: String,
    /// The lease generation within this try.
    pub lease_generation: u32,
    pub result_ref: Option<String>,
    pub updated_at: u64,
}

/// A held program's park: who holds it, why, and since when.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProgramHeldView {
    pub attempt: String,
    pub cause: String,
    pub owner: String,
    pub reason: String,
    pub parked_at: u64,
}

/// The program runtime's record of one code run.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProgramRunStateView {
    /// 32-hex try that entered the code run.
    pub entered_by: String,
    pub entered_at: u64,
    pub lifecycle: ProgramRunLifecycle,
    /// The settled run's result (`code-run:<hex>`): its code run's final
    /// committed state.
    pub result_ref: Option<String>,
    pub settled_at: Option<u64>,
    /// The checkpoint frontier its code run last committed.
    pub frontier: Option<ProgramFrontierView>,
}

/// Whether a program's code run is entered or settled.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProgramRunLifecycle {
    /// Entered and not settled.
    Entered,
    /// Finished, its result attached.
    Settled,
}

/// A code run's committed position: its counts and its last state hash.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProgramFrontierView {
    pub bridge_calls: u64,
    pub steps: u64,
    pub outputs: u64,
    /// 64-hex chained state hash.
    pub state_hash: String,
}

/// One step of a program's run: what issued it and how it stands.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProgramStepView {
    /// 32-hex step ref, as `settled_program_step` takes it.
    pub step_ref: String,
    /// 32-hex try that issued it.
    pub attempt: String,
    pub issue: ProgramStepIssueView,
    pub state: ProgramStepState,
    /// 64-hex digest of the exact result, once settled.
    pub result_digest: Option<String>,
    /// Why its end is unknown, when it is.
    pub uncertain: Option<String>,
    pub at: u64,
}

/// The binding a step was issued under, committed before its effect ran.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProgramStepIssueView {
    /// A model step: its logical occurrence in the run and its 64-hex
    /// canonical request hash.
    Model {
        occurrence: u64,
        request_hash: String,
    },
    /// A verb write: its place in its step, its 32-hex receipt and the
    /// 64-hex digest of its call.
    Write {
        step_start: u64,
        ordinal: u64,
        receipt: String,
        call_digest: String,
    },
    /// An outbound send: its 64-hex frozen intent and its call sequence.
    Outbound { intent: String, call_seq: u64 },
}

/// How a step stands.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProgramStepState {
    /// Bound and not ended.
    Issued,
    /// Ended, with its exact result's digest.
    Settled,
    /// Its end is unknown: never taken for settled, never sent again.
    Uncertain,
}

/// One settled step of a program's run.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SettledProgramStepRequest {
    /// 32-hex id of the program's root attempt, or of any try of it (`job:`
    /// prefix allowed).
    pub root: String,
    /// 32-hex step ref, as the program's run read lists it.
    pub step_ref: String,
}

/// One settled step and its exact result, as far as the caller reads it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SettledProgramStepView {
    /// 32-hex root attempt.
    pub root: String,
    /// 32-hex try that issued the step.
    pub attempt: String,
    pub actor: EntityId,
    pub code_run: String,
    pub step_ref: String,
    pub issue: ProgramStepIssueView,
    pub settled_at: u64,
    /// 64-hex digest of the exact result the step settled with: for a write,
    /// of the outcome its receipt stores, not of `body_base64`'s bytes.
    pub result_digest: String,
    /// The record that holds the exact result: the model step's terminal
    /// claim (32 hex), the write's receipt (32 hex) or the send's intent (64
    /// hex). None when a model step's terminal claim is gone, or its body is
    /// withheld for its actor's deletion.
    pub result_ref: Option<String>,
    pub availability: ProgramResultAvailability,
    /// A model step's terminal record and stored response, when readable.
    pub model_step: Option<SettledStepView>,
    /// A send's body as the side-row wall admitted it, or a write's answer
    /// (the verb's JSON output as its receipt keeps it, FIX 5837), base64,
    /// when it was kept and is readable.
    pub body_base64: Option<String>,
}

/// Whether a settled step's exact result reads for this caller.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProgramResultAvailability {
    /// Every record it derives from reads on the caller's lane.
    Readable,
    /// A record it derives from does not read on the caller's lane, or the
    /// program's actor is soft-deleted, hard-deleted or erased (an archive
    /// withholds nothing): withheld, never refused.
    Withheld,
    /// Nothing holds it: the terminal claim or the receipt's answer is gone,
    /// or the send's body was never kept.
    Absent,
}

/// Where one program's restarter resumes, one page of its settled calls at a
/// time (DOOR-141 PR3b).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProgramCheckpointRequest {
    /// 32-hex id of the program's root attempt, or of any try of it (`job:`
    /// prefix allowed).
    pub root: String,
    /// The previous page's `next_cursor`: the call list goes on there.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Calls in this page: 64 when absent, at most 64. Must be positive.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// The resume checkpoint of one program's run, as its restarter reads it:
/// its head, the frontier its run record joined, and a page of the calls it
/// answers instead of issuing them. Refs and digests only, never a body.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProgramCheckpointView {
    /// 32-hex root attempt its admission queued.
    pub root: String,
    /// The waking actor the program runs as.
    pub actor: EntityId,
    /// 32-hex code run the program runs as.
    pub code_run: String,
    /// The pinned executable; withheld unless its SKILL reads on the
    /// caller's lane.
    pub definition: Option<ProgramRecipePin>,
    /// The checkpoint's head; none before an entry committed one.
    pub checkpoint: Option<ProgramCheckpointHeadView>,
    /// The checkpoint frontier the program's run record last joined.
    pub frontier: Option<ProgramFrontierView>,
    /// One page of the settled calls, in the order the pinned source makes
    /// them.
    pub calls: Vec<ProgramCheckpointCallView>,
    /// Where the next page starts; none past the last settled call.
    pub next_cursor: Option<String>,
    /// The fields withheld from this caller, by name.
    pub withheld: Vec<String>,
}

/// A resume checkpoint's head.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProgramCheckpointHeadView {
    /// 32-hex try whose entry committed it.
    pub committed_by: String,
    /// The pinned revision's content hash and 64-hex call-contract digest
    /// the run replays.
    pub content_hash: String,
    pub contract_digest: String,
    /// How many entries committed.
    pub entries: u64,
    /// The record row the last entry's own pinned call took.
    pub entry_start: u64,
    /// The record's rows and its 64-hex last checkpoint state hash, as the
    /// last entry committed them.
    pub bridge_calls: u64,
    pub state_hash: String,
    /// How many of the pinned source's calls are settled: the applied
    /// position.
    pub applied: u64,
    /// How many of them the last entry answered from an earlier row instead
    /// of issuing them: the committed injection position.
    pub injected: u64,
    /// The wait the last entry parked on, when it did.
    pub wait: Option<ProgramCheckpointWaitView>,
    pub at: u64,
}

/// The wait a program's last entry parked on.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProgramCheckpointWaitView {
    /// The record row of the call that parked.
    pub row: u64,
    /// 32-hex wait and its generation in the run.
    pub wait_id: String,
    pub generation: u64,
    /// Whether a reply is delivered to it, or it settled with one: the
    /// program resumes only then.
    pub delivered: bool,
    /// The consent evidence of the code consent wait it is, when one binds
    /// it (FIX 5883); none for any other wait, and withheld by name
    /// (`checkpoint.wait.consent`) when it does not read on the caller's
    /// lane.
    pub consent: Option<ProgramCheckpointConsentView>,
}

/// What a program's parked code consent wait holds as consent evidence
/// (FIX 5883): refs and digests only, never the reply, the held input, a
/// credential or model text. A receipt is `gate:<hex>`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProgramCheckpointConsentView {
    /// 64-hex digest of the wait's immutable binding to its held effect.
    pub binding_digest: String,
    /// 64-hex code-bound approval digest an answer names.
    pub effect_digest: String,
    /// Where the wait stands: provisional, waiting, settling, settled or
    /// consumed.
    pub state: String,
    /// 32-hex ask the owner's word stands on, once it is open.
    pub ask: Option<String>,
    /// The first answer's choice, and its 32-hex word on the ask.
    pub choice: Option<String>,
    pub word: Option<String>,
    /// The consent act's receipt.
    pub answer_receipt: Option<String>,
    /// What the settlement came to, and its receipt.
    pub outcome: Option<String>,
    pub settlement_receipt: Option<String>,
    /// The parked run's consumption of the settled reply, its receipt.
    pub consumption_receipt: Option<String>,
    /// 64-hex facts digests of the settlement and consumption receipts as
    /// the consent Gate ledger holds them: none before the fact, or once an
    /// opted-in retention sweep dropped its record.
    pub settlement_facts_digest: Option<String>,
    pub consumption_facts_digest: Option<String>,
}

/// One settled call of a program's pinned source.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProgramCheckpointCallView {
    /// Its place in the pinned source's order.
    pub index: u64,
    /// Where its result is: `code-run:<32 hex>#<row>`, the row of the run's
    /// record that settled it.
    pub result_ref: String,
    pub row: u64,
    /// 64-hex digest of that row's canonical request.
    pub request_digest: String,
    /// 32-hex wait whose delivered reply answers it, when one does.
    pub answered_by_wait: Option<String>,
    /// Whether the last entry answered it from an earlier row instead of
    /// issuing it.
    pub injected: bool,
}
