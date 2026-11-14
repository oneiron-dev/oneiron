//! The owner's typed grant/revoke acts on connector witness-read access grants (FIX 10980).
//!
//! Each changed owner write records one local row in the same transaction.
//! The sequence is its audit identity and order; the vault-clock second is
//! informational. These are writer-trusted records, not signed or
//! mesh-verified authority. The caller validates the owner and the admitted
//! grant binding in the same writer; a local put failure aborts both writes.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::authority::{ActBy, ActSurface, OwnerAct, OwnerActKind};
use crate::batch::export::archive_side_install::{
    ArchivedSideRowOutcome, decode_archived_row, install_archived_row,
};
use crate::batch::export::{
    ArchiveRetainedSideRow, OwnerArchiveRestorePermit, RetainedSideHeldBackReason,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};

/// The owner's change to an access grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AccessGrantActChange {
    Grant,
    Revoke,
}

impl AccessGrantActChange {
    /// The stable receipt word for this change, used as the outcome and the
    /// receipt-id event word.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Grant => "granted",
            Self::Revoke => "revoked",
        }
    }
}

/// One owner act on an access grant, as this install recorded it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccessGrantOwnerActReceipt {
    pub(crate) act: OwnerAct,
    pub(crate) change: AccessGrantActChange,
    /// Vault clock seconds, informational only.
    pub(crate) at: u64,
}

const OWNER_ACTS: SideTable<u64, AccessGrantOwnerActReceipt, Named> =
    SideTable::new(&side_table::ACCESS_GRANT_OWNER_ACT);

/// Records, in the caller's write transaction, the act of the owner `owner`
/// (already validated by the caller in this transaction) making `change` to
/// the access grant `grant` (opaque id, never re-read here) via `surface`.
///
/// The act's `seen` is zero: a vault-local receipt counter is never `seen`,
/// and this index has no signed-op handoff, so no revision reads and no
/// optional fallback. A sequence wrap fails the whole write with
/// [`Error::IndexOverflow`], aborting the grant with it.
///
/// # Errors
/// A sequence wrap, a clock read that fails, or a store write that fails.
pub(crate) fn record_access_grant_owner_act_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owner: EntityId,
    grant: EntityId,
    surface: ActSurface,
    change: AccessGrantActChange,
) -> Result<()> {
    let act = OwnerAct::by_owner(owner, OwnerActKind::AccessGrant, grant, surface, [0; 32]);
    let sequence = match OWNER_ACTS.iter_rev_from(&vault.store, txn, &[])?.next() {
        None => 0,
        Some(row) => row?
            .0
            .checked_add(1)
            .ok_or(Error::IndexOverflow("access grant owner act sequence"))?,
    };
    let at = vault.instant_in_txn(txn)?.secs();
    OWNER_ACTS.put(
        &vault.store,
        txn,
        &sequence,
        &AccessGrantOwnerActReceipt { act, change, at },
    )?;
    Ok(())
}

/// Every owner act on access grants this install recorded, oldest first with
/// each row's actual sequence, read in the caller's transaction for the
/// receipt projector (no second snapshot).
///
/// # Errors
/// A store read that fails.
pub(crate) fn access_grant_owner_acts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(u64, AccessGrantOwnerActReceipt)>> {
    Ok(OWNER_ACTS.scan(&vault.store, txn)?)
}

/// Lands one archived `ACCESS_GRANT_OWNER_ACT` envelope in `txn`: canonical decode and the
/// credential predicate, then the writer's own receipt shape (kind `access_grant`, zero
/// `seen`, the owner's own act). The named grant is never installed or revoked here; past
/// history stays valid when the grant is gone.
///
/// # Errors
/// Storage faults; validation stays in the returned outcome.
fn land_archived_access_grant_owner_act_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    row: &ArchiveRetainedSideRow,
) -> Result<ArchivedSideRowOutcome> {
    let (key, value) = match decode_archived_row(&OWNER_ACTS, row) {
        Ok(decoded) => decoded,
        Err(reason) => return Ok(ArchivedSideRowOutcome::HeldBack(reason)),
    };
    if value.act.act != OwnerActKind::AccessGrant
        || value.act.seen != [0; 32]
        || value.act.by != ActBy::Owner
        || value.act.answer.is_some()
    {
        return Ok(ArchivedSideRowOutcome::HeldBack(
            RetainedSideHeldBackReason::InvalidValue,
        ));
    }
    install_archived_row(&OWNER_ACTS, vault, txn, permit, &key, row)
}

impl Vault {
    /// Lands the owner's archived `ACCESS_GRANT_OWNER_ACT` envelopes in input order, one
    /// outcome per row: an absent act installs, an identical act is unchanged, and a different
    /// act stays live. Never installs or revokes the named grant.
    ///
    /// # Errors
    /// Storage faults; validation stays in the returned outcomes.
    pub(crate) fn land_archived_access_grant_rows_in_txn(
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        permit: &OwnerArchiveRestorePermit,
        rows: &[ArchiveRetainedSideRow],
    ) -> Result<Vec<ArchivedSideRowOutcome>> {
        let mut outcomes = Vec::with_capacity(rows.len());
        for row in rows {
            outcomes.push(land_archived_access_grant_owner_act_row_in_txn(
                vault, txn, permit, row,
            )?);
        }
        Ok(outcomes)
    }
}
