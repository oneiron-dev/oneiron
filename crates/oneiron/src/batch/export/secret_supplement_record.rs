//! Snapshot needs and opened secret-supplement import values.

use serde::{Deserialize, Serialize};

use crate::batch::export::ArchiveSecretCustody;
use crate::entity_id::EntityId;
use oneiron_authority::authority::AuthorityEntryHash;

/// One custody secret an export's snapshot met that this install could not
/// open: value-free, for the export's audit write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct HolderExportNeed {
    pub(crate) secret: EntityId,
    /// The custody generation the snapshot read.
    pub(crate) generation: u32,
}

/// One export secret supplement the recipient opened: the archive row of
/// its secret, its value in it, for the owner's import. Wiped when dropped.
pub struct OpenedSecretSupplement {
    /// The export secret request it answers, which the import marks
    /// imported once it commits (FIX 12062).
    pub(crate) request: AuthorityEntryHash,
    pub(crate) row: ArchiveSecretCustody,
}

impl std::fmt::Debug for OpenedSecretSupplement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedSecretSupplement")
            .field("row", &self.row)
            .finish()
    }
}

impl Drop for OpenedSecretSupplement {
    fn drop(&mut self) {
        if let Some(body) = self.row.body.as_mut() {
            zeroize::Zeroize::zeroize(body);
        }
    }
}

/// What the owner's import of one opened supplement did with its secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecretSupplementImport {
    /// Restored under its own id.
    Restored,
    /// The same record is already here: unchanged.
    Unchanged,
    /// Left as it is: an admitted revoke ended it, or the record here under
    /// its id could not be compared.
    Skipped,
}
