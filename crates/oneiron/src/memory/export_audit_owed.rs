//! The export audit an Owner's copy still owes (L5-17; the lead's ruling on
//! ASK L5-17-DESIGN, 13 Nov 14:03, A with no refusal; DEC-0005:99 "His own
//! export is his will").
//!
//! A copy that someone is owed the audit of, because it carries a TURN of a
//! thread or because the vault has a live Owner beside its exporter, writes
//! its owed row before it leaves: the audit row to write, and each carried
//! thread's root with the binding the copy's own read resolved (FIX 6681).
//! The audit's own write then writes the row and the threads' notices and
//! drops the owed row in one commit. When that write does not commit, the
//! row stays, and a housekeeping pass writes what it owes
//! ([`deliver_owed_export_audits`]), so the audit row and every member's
//! notice land whenever the store can write anything. When even the owed
//! row cannot be written, the copy is still served, and the host log names
//! its export id. The export is never refused.
//!
//! A copy no one is owed the audit of, a solo owner's that carries no
//! thread, writes no owed row: its audit stays best effort.
//!
//! The owed row keeps the members each lost thread's binding names, so an
//! erase drops the erased person from each binding
//! ([`erase_export_audit_owed_actor_in_txn`]).

use serde::{Deserialize, Serialize};

use super::export_audit::{ExportReceipt, append_in_txn};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::side_table::{self, Named, SideTable};
use crate::workspace_roster::{ExportThreadRoots, NoticeDelivery, notify_exported_threads_in_txn};

/// One copy's owed audit: the row to write, and each thread it carries.
#[derive(Serialize, Deserialize)]
pub(super) struct ExportAuditOwed {
    /// The audit row, its time the owed row's own: each holder request it
    /// lists stands as not recorded, as the copy's door answered it when
    /// its audit's write did not commit.
    pub(super) receipt: ExportReceipt,
    /// The root of each thread a TURN the copy carries is of, with its
    /// binding as the copy's read resolved it.
    pub(super) threads: ExportThreadRoots,
}

const OWED: SideTable<EntityId, ExportAuditOwed, Named> =
    SideTable::new(&side_table::EXPORT_AUDIT_OWED);

/// Test-only faults for the integration tests' door
/// (`crate::test_doors::export_audit_owed`): each fails the next write of
/// its kind on the calling thread, once, so tests that run in parallel do
/// not share them.
#[cfg(oneiron_test_support)]
pub(crate) mod test_faults {
    use std::cell::Cell;

    thread_local! {
        static AUDIT_WRITE: Cell<bool> = const { Cell::new(false) };
        static OWED_ROW_WRITE: Cell<bool> = const { Cell::new(false) };
    }

    /// Fails the next export audit write on this thread.
    pub(crate) fn fail_next_audit_write() {
        AUDIT_WRITE.set(true);
    }

    /// Fails the next owed-row write on this thread.
    pub(crate) fn fail_next_owed_row_write() {
        OWED_ROW_WRITE.set(true);
    }

    /// Whether this export audit write fails, clearing the fault.
    pub(crate) fn audit_write_fails() -> bool {
        AUDIT_WRITE.replace(false)
    }

    /// Whether this owed-row write fails, clearing the fault.
    pub(super) fn owed_row_write_fails() -> bool {
        OWED_ROW_WRITE.replace(false)
    }

    /// The error a failed write answers.
    pub(crate) const FAULT: crate::Error =
        crate::Error::InvariantViolation("export audit: the test door failed this write");
}

/// Writes `owed`'s row before its copy leaves, when anyone is owed the
/// copy's audit: the copy carries a TURN of a thread, or the vault has a
/// live Owner beside its exporter. The row's time is the vault clock's,
/// kept with the row (the export id's allocation floor). Answers whether
/// the row stands. A row that is not written is logged with the export id,
/// and the copy is still served: its audit is then best effort.
pub(super) fn owe(vault: &Vault, owed: &mut ExportAuditOwed) -> bool {
    let export = owed.receipt.export;
    match owed_to_anyone(vault, owed) {
        Ok(true) => {}
        Ok(false) => return false,
        Err(error) => tracing::warn!(
            export = %export.to_hex(),
            %error,
            "export audit: who is owed it not read; it is owed"
        ),
    }
    let written = vault.with_write_txn(|txn| {
        #[cfg(oneiron_test_support)]
        if test_faults::owed_row_write_fails() {
            return Err(test_faults::FAULT);
        }
        owed.receipt.at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        OWED.put(&vault.store, txn, &export, owed)
    });
    match written {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(
                export = %export.to_hex(),
                %error,
                "export served, its audit not owed: the owed row was not written"
            );
            false
        }
    }
}

/// Whether anyone is owed `owed`'s audit: the copy carries a TURN of a
/// thread, whose members may be told, or the vault has a live Owner beside
/// its exporter, who reads the audit.
fn owed_to_anyone(vault: &Vault, owed: &ExportAuditOwed) -> crate::Result<bool> {
    if !owed.threads.is_empty() {
        return Ok(true);
    }
    let txn = vault.store.env.read_txn()?;
    Ok(crate::policy_model::owners_in_txn(vault, &txn)?
        .iter()
        .any(|owner| *owner != owed.receipt.exporter))
}

/// Whether `export`'s owed row still stands in `txn`.
pub(super) fn owed_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    export: EntityId,
) -> crate::Result<bool> {
    OWED.contains(&vault.store, txn, &export)
}

/// Drops `export`'s owed row in `txn`, the write that writes its audit row
/// and its threads' notices.
pub(super) fn settle_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    export: EntityId,
) -> crate::Result<()> {
    OWED.delete(&vault.store, txn, &export).map(drop)
}

/// Writes what each owed export audit owes, one row at a time, each in a
/// write of its own, until none is left or `stop` says so: its audit row
/// and each carried private thread's members' notices
/// ([`NoticeDelivery::Owed`]), and the owed row goes in that same write. A
/// row whose write does not commit stays owed for a later pass, logged.
/// Answers how many rows were written, how many failed and how many this
/// run did not reach.
///
/// # Errors
///
/// The owed rows could not be listed.
pub(crate) fn deliver_owed_export_audits(
    vault: &Vault,
    stop: impl Fn() -> bool,
) -> crate::Result<(u64, u64, u64)> {
    let owed = {
        let txn = vault.store.env.read_txn()?;
        OWED.scan_keys(&vault.store, &txn, &[])?
    };
    let (mut delivered, mut failed) = (0_u64, 0_u64);
    for (done, export) in owed.iter().enumerate() {
        if stop() {
            let left = u64::try_from(owed.len().saturating_sub(done)).unwrap_or(u64::MAX);
            return Ok((delivered, failed, left));
        }
        match deliver(vault, *export) {
            Ok(true) => delivered = delivered.saturating_add(1),
            Ok(false) => {}
            Err(error) => {
                failed = failed.saturating_add(1);
                tracing::warn!(
                    export = %export.to_hex(),
                    %error,
                    "owed export audit not written; it stays owed for a later pass"
                );
            }
        }
    }
    Ok((delivered, failed, 0))
}

/// Writes `export`'s owed audit row and its threads' notices, and drops the
/// owed row, in one write. Answers false for a row gone since it was
/// listed, which its copy's own audit write or another pass wrote.
fn deliver(vault: &Vault, export: EntityId) -> crate::Result<bool> {
    vault.with_write_txn(|txn| {
        #[cfg(oneiron_test_support)]
        if test_faults::audit_write_fails() {
            return Err(test_faults::FAULT);
        }
        let Some(owed) = OWED.get(&vault.store, txn, &export)? else {
            return Ok(false);
        };
        append_in_txn(vault, txn, &owed.receipt)?;
        notify_exported_threads_in_txn(
            vault,
            txn,
            &owed.threads,
            owed.receipt.exporter,
            export,
            NoticeDelivery::Owed,
        )?;
        OWED.delete(&vault.store, txn, &export)?;
        Ok(true)
    })
}

/// Drops `actor` from the audience each owed row's thread bindings name,
/// for `actor`'s erase (L5-17): no owed row keeps an erased person's id. The
/// audit row an owed row will write names its exporter, as every audit row
/// does (FIX 6427), and no member.
pub(crate) fn erase_export_audit_owed_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> crate::Result<()> {
    for (export, mut owed) in OWED.scan(&vault.store, wtxn)? {
        if owed.threads.forget_actor(actor) {
            OWED.put(&vault.store, wtxn, &export, &owed)?;
        }
    }
    Ok(())
}

/// Every owed export audit row: each export id, with every person its
/// thread bindings name, for the integration tests' door.
#[cfg(oneiron_test_support)]
pub(crate) fn owed_export_audits(
    vault: &Vault,
) -> crate::Result<std::collections::BTreeMap<EntityId, std::collections::BTreeSet<EntityId>>> {
    let txn = vault.store.env.read_txn()?;
    Ok(OWED
        .scan(&vault.store, &txn)?
        .into_iter()
        .map(|(export, owed)| (export, owed.threads.named_members()))
        .collect())
}
