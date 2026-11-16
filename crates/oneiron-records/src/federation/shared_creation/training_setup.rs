//! Moved from `crates/oneiron/src/federation/shared_creation/training_setup.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::authority::AuthorityEntryHash;
use oneiron_authority::authority::PolicyRevision;
use oneiron_contracts::entity_id::EntityId;

/// Where a shared vault's setup training question stands, kept on its
/// creation record.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedTrainingSetup {
    /// Asked and not yet answered. Every read returns this same question.
    Pending {
        /// The question's identity, derived from the vault id and its
        /// creator: never a fresh draw per read.
        question_ref: [u8; 32],
        /// When it was asked, in seconds on the vault's clock; zero when that
        /// clock could not be read at creation. A record of the asking only:
        /// which choice answers it is the fold's to say.
        created_at: u64,
    },
    /// Answered, through this question or by a counted admin choice of the
    /// setting.
    Answered {
        /// Whether the answer turned the setting on.
        on: bool,
        /// The admin who answered; `None` when the answering choice's row is
        /// not stored here.
        answered_by: Option<EntityId>,
        /// The authority entry of the setting choice that answered it.
        setting_act: AuthorityEntryHash,
        /// The setting revision that choice left.
        setting_revision: PolicyRevision,
        /// When it was answered, in seconds on the vault's clock.
        answered_at: u64,
    },
}
