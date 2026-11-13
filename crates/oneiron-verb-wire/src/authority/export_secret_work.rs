//! Moved from `crates/oneiron/src/authority/export_secret_work.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::authority::AuthorityEntryHash;
use oneiron_contracts::entity_id::EntityId;
pub(crate) use oneiron_store::batch::export::secret_supplement_record::HolderExportNeed;
pub use oneiron_store::batch::export::secret_supplement_record::OpenedSecretSupplement;
pub use oneiron_store::batch::export::secret_supplement_record::SecretSupplementImport;
use serde::Deserialize;
use serde::Serialize;

/// Where one holder export request stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum HolderExportState {
    /// Recorded for its holder: the request's signed authority-log entry,
    /// as hex, the install that holds the secret, and its status as the
    /// fold read it. Enacted means its holder committed the sealed copy,
    /// never that the owner fetched it.
    Recorded {
        request: String,
        holder: EntityId,
        status: OwnerWorkStatus,
    },
    /// No request was recorded, for the reason given; the archive's handle
    /// stands.
    Unassigned { reason: HolderExportUnassigned },
    /// Not recorded for a holder: the export's audit write failed (logged),
    /// or its door writes no audit. Nothing waits for a holder.
    Unrecorded,
}

/// Why an export recorded no request for a secret's holder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HolderExportUnassigned {
    /// The export's door records no owner act (an embedded or raw door):
    /// no act exists to carry to a holder.
    NoOwnerAct,
    /// The exporting owner is no live owner of the vault any more.
    OwnerNotLive,
    /// The owner named no machine to receive the sealed copy.
    NoRecipient,
    /// The machine the owner named is no live linked install with an
    /// encryption key that imports.
    RecipientNotLinked,
    /// No linked install is known to hold the secret at this generation.
    NoHolder,
    /// This install has no live machine profile to carry the owner's act.
    NoCarrier,
}

impl HolderExportUnassigned {
    /// The words a surface shows.
    #[must_use]
    pub fn text(self) -> &'static str {
        match self {
            Self::NoOwnerAct => "this export recorded no owner act to carry to a holder",
            Self::OwnerNotLive => "the exporting owner is no live owner of the vault",
            Self::NoRecipient => "no machine was named to receive the sealed copy",
            Self::RecipientNotLinked => "the named recipient is not a linked install",
            Self::NoHolder => "no linked install is known to hold this secret",
            Self::NoCarrier => "this install cannot carry the owner's act",
        }
    }
}

/// The entry hash a receipt's lowercase hex names.
pub fn entry_of_hex(hex: &str) -> Option<AuthorityEntryHash> {
    blake3::Hash::from_hex(hex)
        .ok()
        .map(|hash| *hash.as_bytes())
}
