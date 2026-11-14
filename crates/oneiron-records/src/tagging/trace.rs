//! Moved from `crates/oneiron/src/tagging/trace.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::tagging::output::OutputRefusal;
use serde::Deserialize;
use serde::Serialize;
use std::panic::AssertUnwindSafe;
use std::time::Instant;

/// How an attempt settled.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum TaggingOutcome {
    /// The answer passed every check, the marker completed, and the turn's
    /// tags were saved in the same write.
    Saved {
        spans: usize,
        links: usize,
        mood: bool,
        /// Spans linked to at least one entity, real or provisional.
        linked: usize,
        /// Provisional entities the save minted.
        minted: usize,
        #[serde(default)]
        context_links: usize,
        #[serde(default)]
        speaker_links: usize,
        /// Context links whose earlier span the vault holds no save of (not
        /// tagged yet, tagged under another tagger, or erased): each keeps
        /// no antecedent.
        #[serde(default)]
        unresolved_context_links: usize,
        /// Speaker links that name no one person: each is kept unresolved.
        #[serde(default)]
        unresolved_speaker_links: usize,
        /// The saved set's surprise beside the set it replaced, by the
        /// model families' gate; absent for a turn's first set.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        surprise: Option<f32>,
    },
    /// The answer passed every check and the marker completed. In shadow
    /// nothing else is written.
    Shadowed {
        spans: usize,
        links: usize,
        mood: bool,
        /// Spans whose label the label table maps to an entity kind.
        mapped_spans: usize,
        #[serde(default)]
        context_links: usize,
        #[serde(default)]
        speaker_links: usize,
    },
    /// An importer completed the marker with tags it already held.
    Imported {
        spans: usize,
        links: usize,
        mood: bool,
    },
    /// Nothing was owed; the marker completed with no tagger call.
    Skipped { reason: SkipReason },
    /// The turn changed while the tagger read it; the marker is retried at
    /// once on the new text.
    Superseded { retry_at: u64 },
    /// A MESSAGE the turn's saved tags were read from is away from this
    /// replica (a window demoted back to thin, OF-534): no tagger call, the
    /// saved set untouched, and the marker retried at `retry_at`
    /// (store-clock seconds), on the whole text once a promotion brings the
    /// row back.
    Deferred { retry_at: u64 },
    /// The call failed or its answer was refused; retried at `retry_at`
    /// (store-clock seconds).
    Failed {
        failure: TaggingFailure,
        retry_at: u64,
    },
    /// A marker moved onto a new one that owes the turn its pass: committed
    /// for another checkpoint, or by an earlier build below the id range
    /// markers now take.
    Rekeyed,
    /// A try this worker held but never settled, handed back as an immediate
    /// retry at `retry_at`: a stopped worker left it leased, or its settling
    /// write failed. Any answer its call got was never settled.
    HandedBack {
        reason: HandBackReason,
        retry_at: u64,
    },
    /// A payload this build cannot read; the marker is failed for good.
    Unreadable,
}

/// Why a held try was handed back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandBackReason {
    /// A stopped worker left the try leased under this worker's name.
    WorkerRestarted,
    /// The write that would have settled the try failed.
    SettlementFailed,
}

impl HandBackReason {
    /// The retry reason the try's row records.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WorkerRestarted => "worker_restarted",
            Self::SettlementFailed => "settlement_failed",
        }
    }
}

/// Why a marker owed nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// The turn is absent, deleted or archived.
    TurnGone,
    /// The turn holds no visible text.
    NoText,
}

/// Why an attempt failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "class", rename_all = "snake_case")]
pub enum TaggingFailure {
    /// The tagger call returned an error. `code` is the host's failure class
    /// (the tagger client puts no vault text in it) or the engine error kind.
    Call { code: String },
    /// The answer broke a contract rule.
    Refused { refusal: OutputRefusal },
    /// The tagger panicked.
    Panicked,
}
