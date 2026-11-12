//! Moved from `crates/oneiron/src/batch/secret_scan/lift_history/mod.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::batch::secret_scan::SecretScanMode;
use crate::secret_snapshot::SnapshotSecretLiftProposal;
use serde::Deserialize;
use serde::Serialize;

/// A family of carriers the sweep walks, in walk order.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum LiftFamily {
    /// The entity table: a record's body, the text it was indexed with and
    /// the text it staged for idle publication, a NOTE's live text, title and
    /// pin quotes, a file's bytes.
    Records,
    /// The attempt records (`job_records`), with the intake events their rows
    /// carry: an inbound surface event is queued inside its attempt's row.
    Attempts,
    /// The rows of each side table the catalog classes as authored.
    SideRows,
    /// Carriers no door rewrites: receipt ledgers, op logs, snapshots,
    /// stream seeds and documents' stored history.
    Carriers,
}

impl LiftFamily {
    pub const ALL: [Self; 4] = [
        Self::Records,
        Self::Attempts,
        Self::SideRows,
        Self::Carriers,
    ];

    /// The family's stable code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Records => "records",
            Self::Attempts => "attempts",
            Self::SideRows => "side_rows",
            Self::Carriers => "carriers",
        }
    }

    fn next(self) -> Option<Self> {
        Self::ALL
            .into_iter()
            .skip_while(|family| *family != self)
            .nth(1)
    }
}

/// What queued a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LiftTrigger {
    /// The owner switched the scan from off to on.
    Switch,
    /// The owner asked for a run.
    Owner,
    /// Custody came to know a value (FIX 2781): a pass marks it in the files
    /// stored before, and reads nothing else.
    KnownValue,
}

/// Why the sweep filed a proposal instead of placing a hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LiftCause {
    /// No rule the door has places it: a recovery phrase, a key split over
    /// fields, a masked copy the row's own reading refuses.
    Unplaceable,
    /// The row's own writer refuses a rewrite: an immutable record.
    Immutable,
    /// A legal hold keeps the record as it stands.
    Held,
    /// A file, whose bytes stay as they are; its keys are marked.
    File,
    /// A carrier no door rewrites.
    NoDoor,
    /// The record's retained history still holds the value.
    History,
}

impl LiftCause {
    /// The cause's stable code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unplaceable => "unplaceable",
            Self::Immutable => "immutable",
            Self::Held => "held",
            Self::File => "file",
            Self::NoDoor => "no_door",
            Self::History => "history",
        }
    }
}

/// Why a proposal closed. The owner closes one as `not_a_secret`, `rotated`
/// or `accepted`; the others close it on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LiftCloseReason {
    /// The owner: what the sweep found is no secret.
    NotASecret,
    /// The owner rotated or revoked the value where it is issued.
    Rotated,
    /// The owner keeps the row as it stands.
    Accepted,
    /// A later run read the row again and found no hit there.
    ReadClean,
    /// The owner answered each key the sweep lifted out of the record
    /// through a found-key door: rotate, delete or not a secret.
    Answered,
    /// The row was deleted.
    Deleted,
}

impl LiftCloseReason {
    /// The reason's stable code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotASecret => "not_a_secret",
            Self::Rotated => "rotated",
            Self::Accepted => "accepted",
            Self::ReadClean => "read_clean",
            Self::Answered => "answered",
            Self::Deleted => "deleted",
        }
    }
}

/// How many open proposals one cause holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LiftCauseCount {
    pub cause: LiftCause,
    pub open: u64,
}

/// One family's counts in a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LiftCounts {
    pub family: LiftFamily,
    /// Rows the census read.
    pub read: u64,
    /// Rows the sweep rewrote with their handles.
    pub masked: u64,
    /// Proposals it filed.
    pub proposals: u64,
    /// Rows that failed again when retried.
    pub failed: u64,
}

impl LiftCounts {
    const fn new(family: LiftFamily) -> Self {
        Self {
            family,
            read: 0,
            masked: 0,
            proposals: 0,
            failed: 0,
        }
    }
}

/// The owner's receipt for one finished run. Holds no value and no digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SecretLiftReceipt {
    pub receipt_id: String,
    pub trigger: LiftTrigger,
    /// The owner who asked, as hex; none for a switch's run.
    pub requested_by: Option<String>,
    pub requested_at: u64,
    pub finished_at: u64,
    pub families: Vec<LiftCounts>,
    pub masked: u64,
    pub proposals: u64,
    pub failed: u64,
}

/// A hit the sweep left for the owner, with why. A closed one keeps its
/// cause and says when, by whom and why it closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SecretLiftHistoryProposal {
    /// The proposal's id, as hex: what the owner's close names.
    #[serde(default)]
    pub id: String,
    pub family: LiftFamily,
    pub cause: LiftCause,
    /// The record or row (`record:<id>`, `side:<table>:<key>`,
    /// `carrier:<table>:<key>`), the detector's reason and a suggested
    /// custody name. No value.
    pub proposal: SnapshotSecretLiftProposal,
    pub run_id: String,
    pub filed_at: u64,
    /// When it closed; none while it is open.
    pub closed_at: Option<u64>,
    /// Who closed it: the owner, as hex, or `sweep` when it closed on its
    /// own.
    pub closed_by: Option<String>,
    pub close_reason: Option<LiftCloseReason>,
    /// The owner's close's Gate receipt, `gate:<hex>`; none for one that
    /// closed on its own.
    pub close_receipt: Option<String>,
}

impl SecretLiftHistoryProposal {
    /// Whether the proposal is still open.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        self.closed_at.is_none()
    }
}

/// Where a run stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SecretLiftProgress {
    pub run_id: String,
    pub trigger: LiftTrigger,
    pub requested_at: u64,
    /// The family the walk is in.
    pub family: LiftFamily,
    /// Rows waiting to be tried again.
    pub retrying: u64,
    pub counts: Vec<LiftCounts>,
}

/// The sweep's state for the owner: the run in progress, the last receipt
/// and the proposals still open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SecretLiftStatus {
    pub mode: SecretScanMode,
    /// A run waits while the switch is off.
    pub paused: bool,
    pub running: Option<SecretLiftProgress>,
    pub last: Option<SecretLiftReceipt>,
    pub open_proposals: u64,
    /// The open proposals, counted by why the sweep left each.
    pub open_by_cause: Vec<LiftCauseCount>,
    /// The proposals closed, by the owner or on their own.
    pub closed_proposals: u64,
    /// The first open proposals, in key order.
    pub proposals: Vec<SecretLiftHistoryProposal>,
}

/// `vault.secrets.lift_history`'s input: the status, after closing one
/// proposal or queueing a run when asked.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretLiftRequest {
    /// Queue a run now. A run already queued walks again from the start.
    #[serde(default)]
    pub start: bool,
    /// Close one open proposal first, with the owner's reason.
    #[serde(default)]
    pub close: Option<SecretLiftClose>,
}

/// The owner's close of one lift proposal.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretLiftClose {
    /// The proposal's `id`.
    pub proposal: String,
    /// `not_a_secret`, `rotated` or `accepted`.
    pub reason: LiftCloseReason,
}
