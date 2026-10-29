//! Whether an export a server keeps for its caller still stands for him
//! (FIX 11596, ruling 4624(a)). The kept archive carries the owner's act
//! its render carried out; each read checks that act's exact owner again,
//! beside the fresh owner proof the read already admits. An owner the vault
//! no longer records as live, or a caller who now acts as another owner,
//! is a positive lapse: the export is not read again. A snapshot that does
//! not read decides nothing, and the read goes on as before.

use crate::Vault;
use crate::authority::OwnerAct;
use crate::entity_id::EntityId;

/// Why a kept export no longer stands for its caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeptExportLapse {
    /// The owner whose act made the export is no longer one of the vault's
    /// live owners.
    OwnerNotLive,
    /// The caller's fresh owner proof now resolves to another owner than the
    /// one whose act made the export.
    OwnerChanged,
}

impl KeptExportLapse {
    /// What the lapse says to the caller.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::OwnerNotLive => {
                "the owner whose act made this export is no longer this vault's live owner"
            }
            Self::OwnerChanged => "this caller now acts as another owner than the export's",
        }
    }
}

impl Vault {
    /// Whether the export `act` made still stands for a caller whose fresh
    /// owner proof resolves to `reader` (FIX 11596): `None` while `act`'s
    /// owner is `reader` and one of the vault's live owners now. A
    /// snapshot that does not read is logged and decides nothing (`None`):
    /// only a positive lapse ends the export.
    #[must_use]
    pub fn kept_export_lapse(&self, act: &OwnerAct, reader: EntityId) -> Option<KeptExportLapse> {
        if act.owner != reader {
            return Some(KeptExportLapse::OwnerChanged);
        }
        let live = self
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)
            .and_then(|txn| {
                crate::policy_model::is_live_vault_owner_in_txn(self, &txn, &act.owner)
            });
        match live {
            Ok(true) => None,
            Ok(false) => Some(KeptExportLapse::OwnerNotLive),
            Err(error) => {
                tracing::warn!(%error, "kept export owner unread; the read goes on");
                None
            }
        }
    }
}
