//! The mail importer (FIX 12559 row 1; MAIL-GOOGLE = A, 2026-10-19): one
//! bounded step of one source at a time, run by the host. Each step:
//!
//! 1. takes the provider's change anchor the first time, before any listing,
//!    so no change made while the mailbox copies is missed;
//! 2. reads the change feed since the anchor: new mail lands, a provider
//!    delete applies the source's own setting, a move to trash or spam
//!    counts as a delete; an anchor the provider no longer keeps starts the
//!    listing over from a new one, and nothing is read as deleted for it;
//! 3. copies the mailbox newest first, headers first, under "Keep a copy of
//!    my mail": all mail, the recent months only, or none for search only;
//! 4. fills in the bodies of messages that landed with their headers only,
//!    newest first.
//!
//! Trash, spam and drafts never land. Every provider call runs outside any
//! vault transaction; each message lands in its own commit with its source
//! audience binding ([`super::landing`]). Imported mail wakes no agent: it is
//! evidence, not a message to anyone.

use serde::{Deserialize, Serialize};

use super::pack::require_pack_active_in;
use super::source::{MailCopySetting, MailSourceKind, MailSourceRow, MailSourceStatus, SOURCES};
use super::state::MailSyncState;
use super::state::OCCURRENCES;
use super::state::SYNC;
use crate::consent::AuthenticatedOwner;
use crate::memory::{MemoryError, MemoryResult};
use crate::{EntityId, Result, Vault};

impl crate::memory::Memory<'_> {
    /// Where one source's import stands: whether new mail arrives live, how
    /// far the copy has come, how many bodies wait, and the last failure. Its
    /// readers see it, and an Owner or an Admin a group address's.
    pub fn mail_sources_sync_status(
        &self,
        input: &super::doors::MailSourceRef,
    ) -> MemoryResult<super::state::MailSyncStatusView> {
        let id = EntityId::from_hex(&input.source_ref)?;
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        let unknown = || MemoryError::not_found("no mail source by that ref");
        let row = SOURCES.get(&vault.store, &txn, &id)?.ok_or_else(unknown)?;
        let reads =
            crate::source_audience::actor_reads_in(vault, &txn, &row.audience, self.actor())?;
        let manages = row.kind == MailSourceKind::GroupAddress
            && super::compliance::manages_in(vault, &txn, self.actor())?;
        if !reads && !manages {
            return Err(unknown());
        }
        Ok(super::state::status_view_in(vault, &txn, id)?)
    }
}
