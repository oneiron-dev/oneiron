//! `vault.receipts` read in a room (FIX 7355): the same request, page and
//! cursor as the canonical verb, read under the key the run's host admitted
//! for its caller, through this call's one view of the room.
//!
//! The family's served forms are read from the key's content target: the
//! room's overlay ∪ base, so a form a hydrate in the room kept there joins
//! the vault's before the family is ordered, screened, refilled and cut. Each
//! row a served form names is placed as the room holds it, under the vault's
//! world settings, toward the key's destination. Every other family, the gate
//! ledger, the credential trigger-row screen and the owner-notice screen read
//! as on base, with the key in place of a handle. The room sees the vault and
//! itself; the vault never sees the room.

use std::collections::BTreeSet;

use super::SessionReadContext;
use crate::Vault;
use crate::claim::{ClaimReadStatus, PointRead};
use crate::entity_id::EntityId;
use crate::memory::reads::{ReceiptReader, receipts_page_for};
use crate::memory::{MemoryResult, VaultReceiptsPage};
use crate::receipt::ReceiptContent;
use crate::settings::ReadDestination;
use crate::task_verb::sdk::{VAULT_RECEIPTS_LIMIT_DEFAULT, VaultReceiptsRequest};

impl ReceiptReader for SessionReadContext<'_> {
    fn receipt_vault(&self) -> &Vault {
        self.vault
    }

    /// Where the key's rows go, as its host's judges bound it: never this
    /// device's default for a fresh handle.
    fn receipt_destination(&self) -> &ReadDestination {
        self.key.destination()
    }

    /// The key's lane's content: the room's overlay ∪ base, or base alone
    /// where the key reads only some worlds and the room has not placed every
    /// row it holds. Its scan checks wait with the room.
    fn receipt_content(&self) -> ReceiptContent<'_> {
        ReceiptContent::of_room(
            self.lane(ClaimReadStatus::Recorded).store_read(),
            self.session.pending_scan_checks(),
        )
    }

    /// The room's served forms name rows of the room's other participants:
    /// each takes a page place only when the key reads its ASSET and
    /// ASSET_TEXT (FIX 7355).
    fn screens_served_form_rows(&self) -> bool {
        true
    }

    /// The rows of `ids` the key reads in the room, each by its lane's point
    /// read in one snapshot, as `vault.get` reads it here. The key is the
    /// read's credential, so every receipt is judged by it.
    fn readable_trigger_rows(&self, ids: &[EntityId]) -> MemoryResult<Option<BTreeSet<EntityId>>> {
        let reads: Vec<_> = ids.iter().map(|id| PointRead::id(*id)).collect();
        let rows = self
            .lane(ClaimReadStatus::Recorded)
            .read(&reads, None)?
            .value;
        Ok(Some(
            rows.into_iter()
                .flatten()
                .filter(|row| row.body.is_some())
                .map(|row| row.id)
                .collect(),
        ))
    }

    fn reads_owner_notices(&self) -> bool {
        self.key.secret_sight() == crate::secret_custody::SecretSight::Owner
    }
}

impl SessionReadContext<'_> {
    /// `vault.receipts` in the room: `input` decoded as the canonical verb
    /// decodes it, its limit defaulted and checked as there, and one page
    /// read under the key ([`receipts_page_for`]).
    ///
    /// # Errors
    ///
    /// A zero limit, an unknown kind, an `after` no page of these kinds
    /// returned, or the read's failure.
    pub(super) fn receipts_page(
        &self,
        input: &VaultReceiptsRequest,
    ) -> MemoryResult<VaultReceiptsPage> {
        let limit = input.limit.unwrap_or(VAULT_RECEIPTS_LIMIT_DEFAULT);
        crate::memory::caps::check_limit_nonzero(limit)?;
        receipts_page_for(
            self,
            limit,
            input.kinds.as_deref().unwrap_or_default(),
            input.after.as_deref(),
        )
    }
}

/// The rows `page` served, for the run's release rule: each receipt's claim,
/// as the canonical verb's door lists them.
pub(super) fn page_rows(page: &VaultReceiptsPage) -> Vec<EntityId> {
    page.receipts
        .iter()
        .filter_map(|receipt| receipt.claim_ref.as_deref())
        .filter_map(|id| EntityId::from_hex(id).ok())
        .collect()
}
