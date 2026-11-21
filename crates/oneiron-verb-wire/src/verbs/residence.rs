//! Moved from `crates/oneiron/src/verbs/residence.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::authority::RESIDENCE_PREDICTED_DOCUMENTS_DEFAULT;
use oneiron_authority::authority::RESIDENCE_PREDICTED_WINDOWS_DEFAULT;
use oneiron_authority::authority::ResidenceAct;
use oneiron_authority::authority::ResidenceResult;
use oneiron_authority::authority::ResidenceResultStatus;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::bytes_to_hex_lower;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use serde::Deserialize;
use serde::Serialize;

/// `opened` (items fetched on demand), `predicted` (opened, plus the
/// windows and entity documents its home predicts it will open; ARCH-0023b
/// #predicted-residence) or `all` (full window replication).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResidenceModeName {
    Opened,
    Predicted,
    All,
}

/// `vault.residence.index`'s input: the machine whose thin index to read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResidenceMachineRequest {
    /// The owner's machine, by its machine id (32 hex).
    pub machine: EntityId,
}

/// `vault.residence.mode`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResidenceModeRequest {
    /// The owner's machine, by its machine id (32 hex).
    pub machine: EntityId,
    pub mode: ResidenceModeName,
    /// With mode `predicted` only: the most the home's prediction names
    /// for this machine. Unset, 32 windows and 128 entity documents.
    #[serde(default)]
    pub budget: Option<ResidencePredictedBudget>,
}

/// The owner's budget for a machine at the predicted level: the most
/// windows and entity documents one prediction names (Engine ruling
/// L7-46-BUDGET B). No ceiling: a prediction names its set by digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResidencePredictedBudget {
    pub windows: u32,
    pub documents: u32,
}

impl ResidenceModeRequest {
    /// The owner's residence directive this row asks for.
    ///
    /// # Errors
    ///
    /// A budget beside a mode other than `predicted`.
    pub fn act(&self) -> MemoryResult<ResidenceAct> {
        match (self.mode, self.budget) {
            (ResidenceModeName::Opened, None) => Ok(ResidenceAct::SyncOpened),
            (ResidenceModeName::All, None) => Ok(ResidenceAct::SyncAll),
            (ResidenceModeName::Predicted, budget) => Ok(ResidenceAct::SyncPredicted {
                window_budget: budget
                    .map_or(RESIDENCE_PREDICTED_WINDOWS_DEFAULT, |budget| budget.windows),
                document_budget: budget.map_or(RESIDENCE_PREDICTED_DOCUMENTS_DEFAULT, |budget| {
                    budget.documents
                }),
            }),
            (ResidenceModeName::Opened | ResidenceModeName::All, Some(_)) => {
                Err(MemoryError::bad_request(
                    "vault.residence.mode takes a budget only with mode predicted",
                ))
            }
        }
    }
}

/// `vault.residence.open`'s input: one item of one window, opened on the
/// named machine.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResidenceOpenRequest {
    /// The owner's machine, by its machine id (32 hex).
    pub machine: EntityId,
    /// The item's month window, `YYYY-MM`.
    pub window: String,
    /// The item, 32 hex.
    pub item: EntityId,
    /// The reason for reading a private NOTE body.
    #[serde(default)]
    pub reason: Option<String>,
    /// Stable anchors to acquire in the opened NOTE's selected text.
    #[serde(default)]
    pub spans: Vec<crate::note::reads::NoteReadSpan>,
}

/// `vault.residence.prune`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResidencePruneRequest {
    /// The owner's machine, by its machine id (32 hex).
    pub machine: EntityId,
    /// Opened-item caches last touched before this (recorded-clock unix
    /// seconds) are dropped.
    pub before: u64,
}

/// `vault.residence.directives`'s input: exactly one of `machine` (every
/// directive this replica holds for that machine, oldest first) or
/// `directive` (that one directive). Both, or neither, is invalid input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResidenceDirectivesRequest {
    /// The owner's machine, by its machine id (32 hex).
    #[serde(default)]
    pub machine: Option<EntityId>,
    /// One residence directive, by its id (32 hex).
    #[serde(default)]
    pub directive: Option<EntityId>,
}

impl ResidenceDirectivesRequest {
    /// The one selector the read takes: a machine, or a directive.
    ///
    /// # Errors
    ///
    /// Neither or both of `machine` and `directive`.
    pub fn validate(&self) -> MemoryResult<()> {
        if self.machine.is_some() == self.directive.is_some() {
            return Err(MemoryError::bad_request(
                "vault.residence.directives names exactly one of machine or directive",
            ));
        }
        Ok(())
    }
}

/// What a residence directive asks its machine to do. `kind` says which; an
/// open names its window and item, a prune its cutoff, a follow its worlds,
/// a sync-predicted its budget, and the home's prediction the owner's
/// sync-predicted directive it executes and its set's digest and counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResidenceActView {
    /// Sync every window the machine may read.
    SyncAll,
    /// Sync what the machine opened.
    SyncOpened,
    /// Sync what the machine opened plus what its home predicts, within
    /// this budget.
    SyncPredicted {
        window_budget: u32,
        document_budget: u32,
    },
    /// The home's prediction for the machine: the set it should hold,
    /// named by digest; only that machine fetches the set itself.
    Predicted {
        /// The owner's sync-predicted directive it executes, 32 hex.
        parent: EntityId,
        /// The set's digest, 64 hex.
        set_digest: String,
        window_count: u32,
        document_count: u32,
    },
    /// Follow these worlds, the owner's pick.
    Follow {
        /// The picked worlds, ascending, 32 hex each.
        worlds: Vec<EntityId>,
    },
    /// Open one item of one window on the machine.
    Open {
        /// The item's month window, `YYYY-MM`.
        window: String,
        /// The item, 32 hex.
        item: EntityId,
    },
    /// Read the machine's thin index.
    Index,
    /// Drop the opened-item caches last touched before `before`
    /// (recorded-clock unix seconds).
    Prune { before: u64 },
}

impl From<&ResidenceAct> for ResidenceActView {
    fn from(act: &ResidenceAct) -> Self {
        match act {
            ResidenceAct::SyncAll => Self::SyncAll,
            ResidenceAct::SyncOpened => Self::SyncOpened,
            ResidenceAct::SyncPredicted {
                window_budget,
                document_budget,
            } => Self::SyncPredicted {
                window_budget: *window_budget,
                document_budget: *document_budget,
            },
            ResidenceAct::Predicted {
                parent,
                set_digest,
                window_count,
                document_count,
            } => Self::Predicted {
                parent: *parent,
                set_digest: bytes_to_hex_lower(set_digest),
                window_count: *window_count,
                document_count: *document_count,
            },
            ResidenceAct::Follow { worlds } => Self::Follow {
                worlds: worlds.iter().copied().collect(),
            },
            ResidenceAct::Open { window, item } => Self::Open {
                window: window.clone(),
                item: *item,
            },
            ResidenceAct::Index => Self::Index,
            ResidenceAct::Prune { before } => Self::Prune { before: *before },
        }
    }
}

/// What the machine did with a directive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResidenceResultStatusName {
    /// The machine applied it.
    Applied,
    /// It does not apply on the machine; `reason` says why. It is never
    /// retried.
    Refused,
}

impl From<ResidenceResultStatus> for ResidenceResultStatusName {
    fn from(status: ResidenceResultStatus) -> Self {
        match status {
            ResidenceResultStatus::Applied => Self::Applied,
            ResidenceResultStatus::Refused => Self::Refused,
        }
    }
}

/// The machine's result for one directive, as this replica received it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResidenceResultView {
    /// Vault-clock seconds on the machine when it finished.
    pub finished_at: u64,
    pub status: ResidenceResultStatusName,
    /// What the act touched: windows the home granted again (sync opened),
    /// read caches dropped (sync all, prune), windows in the thin index
    /// (index), the one item opened (open).
    pub count: u64,
    /// Why a refused directive does not apply; absent once applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl From<&ResidenceResult> for ResidenceResultView {
    fn from(result: &ResidenceResult) -> Self {
        Self {
            finished_at: result.finished_at,
            status: result.status.into(),
            count: result.count,
            reason: result.reason.clone(),
        }
    }
}

/// One residence directive this replica holds, and its machine's result as
/// received here. Control metadata only: no item, index or window body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResidenceDirectiveView {
    /// The directive, 32 hex.
    pub directive: EntityId,
    /// The machine it names, 32 hex.
    pub machine: EntityId,
    /// Vault-clock seconds when the owner issued it.
    pub issued_at: u64,
    pub act: ResidenceActView,
    /// The directive's signed authority entry hash, 64 hex.
    pub entry: String,
    /// The machine's result, once it reached this replica. `null` means it
    /// has not been received here, not that the machine is idle or never ran
    /// it.
    pub result: Option<ResidenceResultView>,
}
