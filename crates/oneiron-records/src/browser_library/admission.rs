//! Moved from `crates/oneiron/src/browser_library/admission.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_browser::SubgoalStatus;
use oneiron_browser::SupersedeOutcome;
use oneiron_browser::WorkflowCheck;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The job a filing in an admission run files for (CUA E8b): the filing's
/// own write keeps the program it filed against the job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramAdmissionFiling {
    pub job: EntityId,
    pub finding: EntityId,
    pub fingerprint: [u8; 32],
}

/// What an admission job came to (CUA E8b).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramAdmissionOutcome {
    /// The library's own door filed the program as `workflow`.
    Admitted {
        workflow: EntityId,
        superseded: Option<SupersedeOutcome>,
    },
    /// The library's door refused it: its check, and the postcondition
    /// checks the page missed, by index.
    Refused {
        check: Option<WorkflowCheck>,
        unmet: Vec<usize>,
    },
    /// The page the proposal's steps reached is not its pre-press page:
    /// the no-model batch ended so, and nothing was proposed.
    ReconstructionStopped { status: SubgoalStatus },
    /// The no-model batch ended Done but the filled postcondition is unmet
    /// on its page: the checks it missed, by index; nothing was proposed
    /// (FIX 10721).
    PostconditionUnmet { unmet: Vec<usize> },
    /// The proposal names parameters it gives no value.
    ArgsMissing { params: Vec<String> },
    /// The proposal's secret slots take secrets this run does not hold.
    SecretsUnbound { slots: Vec<String> },
    /// The source caller could not be established at use.
    CredentialUnavailable { cause: CallerUnavailable },
    /// The sources no longer stand as the job named them.
    SourceUnavailable { cause: SourceUnavailable },
    /// The browser's door refused a call, by its code.
    BrowserRefused { code: String },
    /// The job was cut off when its process stopped and was not run again:
    /// the program a filing in its run filed, if one did.
    Interrupted { filed: Option<EntityId> },
    /// An engine error stopped the job, by its kind alone.
    Failed { kind: String },
    /// The job's payload did not decode: its receipt keeps empty refs,
    /// and its sources' kept bindings are dropped, as every ended job's
    /// are.
    Undecodable,
}

/// Why the source caller could not be established (CUA E8b).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallerUnavailable {
    /// The slip's mint, or the kept binding, is gone.
    CredentialMissing,
    /// The slip or an ancestor was revoked.
    CredentialRevoked,
    /// The slip's lifetime ended.
    CredentialExpired,
    /// The binding no longer verifies as the instrument the source used.
    CredentialChanged,
    /// The host could not establish it: a registration it does not hold.
    CredentialUnavailable,
    /// No binding is kept for the source: an earlier job used and dropped
    /// it, or the capture kept none.
    InstrumentNotHeld,
    /// The credential's scope, its connector's or the agent's grant no
    /// longer admits the call.
    ScopeRefused,
    /// No door rebuilds this caller: a person with no credential.
    ContextUnavailable,
    /// The managed vault's attested owner the source acted as is no longer
    /// its live owner (FIX 11690): his lapse, not the door's.
    OwnerNotLive,
}

/// Why a job's sources no longer stand (CUA E8b).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceUnavailable {
    /// The job names no source.
    NoSources,
    /// A source's claim or its source authority was erased.
    Erased { evidence: EntityId },
    /// A source's claim no longer reads as its caller.
    Withheld { evidence: EntityId },
    /// A source no longer stands in the job's scope, group or runs.
    Changed { evidence: EntityId },
    /// The Coach's finding is gone.
    FindingGone,
    /// The candidate's seen marker names another finding or job: a newer
    /// proposal took this one's place.
    ProposalMoved,
}

/// An admission job's receipt (CUA E8b): references and its typed outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramAdmissionReceipt {
    pub job: EntityId,
    pub finding: EntityId,
    pub fingerprint: [u8; 32],
    pub source_evidence: Vec<EntityId>,
    /// The admission run the job's calls were made in.
    pub run_id: Option<EntityId>,
    /// The program a filing in the job's run filed, written in that
    /// filing's own write.
    pub filed: Option<EntityId>,
    /// None while only the filing is written.
    pub outcome: Option<ProgramAdmissionOutcome>,
    pub settled_at: Option<u64>,
}
