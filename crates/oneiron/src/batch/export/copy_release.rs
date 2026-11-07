//! An Owner's own whole-vault copy, archive or OKF, released only once it is
//! recorded (fix list row 15416; owner rulings EXPORT-MAILBOXES, 2026-11-07
//! 01:43 and 01:45). Each pass writes the copy into an anonymous spool file
//! only this engine reads, never the caller's sink. When the copy carries
//! another member's personal mailbox, or uses an approval of the Owner's
//! request for one, its audit row, each mailbox's person's notice and each
//! approval's use are written in one write first ([`record_member_mail_export`]);
//! only that write's durable commit lets the copy go. A write that does not
//! commit leaves no trace: its candidate is dropped, and one pass more, in a
//! snapshot of its own that admits the Owner again, makes the copy without
//! those mailboxes, each named, and records it as every other copy is
//! recorded. Only then does the copy go to the caller's sink, its vector or
//! its kept transfer.
//!
//! Which rows go is the vault's one rule ([`crate::mail_pack`]), read once
//! per pass in the pass's own snapshot and judged before a row is read whole:
//! a removal's records archive and an export a code run calls are not
//! judged by it.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use super::{ExportCut, ExportReceiptSource, ReceiptSourceOmission, WholeVaultExportReceipt};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::mail_pack::{CarriedMemberMailboxes, MailboxExportNotice, MemberMailboxPlan};
use crate::memory::{ExportCopy, record_export, record_member_mail_export};
use crate::settings::ReadDestination;
use crate::source_audience::{ExportJudge, ExportVerdicts};
use crate::store::receipt_row::ReceiptRecord;
use crate::write_envelope::WriteActor;

/// Why a saved run's output stays home from an Owner's copy: it was made
/// from another member's personal mailbox the copy leaves out.
const RESULT_MEMBER_MAILBOX: &str = "member_mailbox";
/// Why a saved run's output stays home from an Owner's copy: the rows it
/// was made from are not all known.
const RESULT_SOURCE_UNIDENTIFIED: &str = "source_unidentified";

/// How one whole-vault export pass treats other members' personal
/// mailboxes (fix list row 15416).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MemberMailPass {
    /// A copy the rule does not judge: a removal's records archive, or an
    /// export a code run calls.
    Exempt,
    /// An Owner's own copy, judged by the vault's rule. `untold`: the copy
    /// made again because the people of the mailboxes it carried could not
    /// be told; it carries none of them and uses no approval.
    Owner { untold: bool },
}

impl MemberMailPass {
    /// The pass's reading of the rule in its own snapshot `txn`, as the
    /// PERSON `reader` exports as: `None` for a copy the rule does not
    /// judge, and in a personal vault.
    ///
    /// # Errors
    ///
    /// Storage and codec failures.
    pub(super) fn plan_in(
        self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        reader: WriteActor,
    ) -> Result<Option<MemberMailboxPlan>> {
        match self {
            Self::Exempt => Ok(None),
            Self::Owner { untold } => {
                MemberMailboxPlan::read_in(vault, txn, reader.entity_ref(), untold)
            }
        }
    }
}

/// What an Owner's copy carries beside its entity rows, judged by its pass
/// (fix list row 15416): the rows it carries outside them (a custody record,
/// the session of an epoch floor, the rows a saved output was made from), and
/// each row a carried row was folded from, or a receipt it cites keeps the
/// body of was made from, by that row.
#[derive(Default)]
pub(super) struct MailboxLineage {
    carried: BTreeSet<EntityId>,
    folded: Vec<(EntityId, EntityId)>,
}

impl MailboxLineage {
    /// Whether the pass's `judge`, when it has one, carries the row `id`, its
    /// bytes `raw`: a row the copy carries outside its entity rows.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(super) fn carries(
        &mut self,
        judge: Option<&mut ExportJudge<'_, '_, '_>>,
        id: EntityId,
        raw: Option<&[u8]>,
    ) -> Result<bool> {
        let Some(judge) = judge else {
            return Ok(true);
        };
        let carried = judge.carries(id, raw)?;
        if carried {
            self.carried.insert(id);
        }
        Ok(carried)
    }

    /// Whether the pass's `judge`, when it has one, carries the row `source`
    /// that the row `row` is folded from; no source, nothing to judge.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(super) fn folds(
        &mut self,
        judge: Option<&mut ExportJudge<'_, '_, '_>>,
        row: EntityId,
        source: Option<&EntityId>,
    ) -> Result<bool> {
        let (Some(judge), Some(source)) = (judge, source) else {
            return Ok(true);
        };
        let carried = judge.carries(*source, None)?;
        if carried {
            self.folded.push((row, *source));
        }
        Ok(carried)
    }

    /// Why the pass's `judge`, when it has one, keeps home a saved output
    /// made from exactly the rows `inputs`, if it does: one row of a
    /// member's mailbox the copy leaves out, or rows not all known.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(super) fn output_withheld(
        &mut self,
        judge: Option<&mut ExportJudge<'_, '_, '_>>,
        inputs: Option<&[EntityId]>,
    ) -> Result<Option<&'static str>> {
        let Some(judge) = judge else {
            return Ok(None);
        };
        if judge.carries_all(inputs)? {
            self.carried.extend(inputs.into_iter().flatten().copied());
            return Ok(None);
        }
        Ok(Some(if inputs.is_some() {
            RESULT_MEMBER_MAILBOX
        } else {
            RESULT_SOURCE_UNIDENTIFIED
        }))
    }

    /// The native receipt `receipt` the row `row` cites, as the copy carries
    /// it: its body, unless the pass's `judge`, when it has one, keeps home
    /// what was made from the rows its attempt read; then why, as a saved
    /// output's ([`Self::output_withheld`]). Those rows count as carried only
    /// through a body the copy keeps, of a row it ships.
    ///
    /// # Errors
    ///
    /// Storage failures, and a receipt whose record names another id.
    pub(super) fn receipt_source(
        &mut self,
        judge: Option<&mut ExportJudge<'_, '_, '_>>,
        row: EntityId,
        receipt_id: String,
        receipt: &ReceiptRecord,
    ) -> Result<ExportReceiptSource> {
        let Some(judge) = judge else {
            return ExportReceiptSource::from_record(receipt_id, Some(receipt));
        };
        let inputs = receipt.pack_source_rows();
        if !judge.carries_all(inputs.as_deref())? {
            return Ok(ExportReceiptSource::Unavailable {
                receipt_id,
                reason: if inputs.is_some() {
                    ReceiptSourceOmission::MemberMailbox
                } else {
                    ReceiptSourceOmission::SourceUnidentified
                },
            });
        }
        let source = ExportReceiptSource::from_record(receipt_id, Some(receipt))?;
        if matches!(source, ExportReceiptSource::Preserved { .. }) {
            self.folded
                .extend(inputs.into_iter().flatten().map(|input| (row, input)));
        }
        Ok(source)
    }

    /// What the copy left out and carries, once its rows are final: the
    /// entity rows the writer carried (`rows`) but the diaries whose read was
    /// not logged (`unlogged`), each row one of them was folded from, and
    /// the rows carried outside them. Nothing for a pass with no `plan`.
    pub(super) fn outcome(
        self,
        plan: Option<MemberMailboxPlan>,
        verdicts: Option<ExportVerdicts>,
        rows: &BTreeSet<EntityId>,
        unlogged: &BTreeSet<EntityId>,
    ) -> (Vec<MailboxExportNotice>, Option<CarriedMemberMailboxes>) {
        let (Some(plan), Some(mut verdicts)) = (plan, verdicts) else {
            return (Vec::new(), None);
        };
        for row in rows.difference(unlogged) {
            verdicts.ships(*row);
        }
        for (row, source) in &self.folded {
            if rows.contains(row) && !unlogged.contains(row) {
                verdicts.ships(*source);
            }
        }
        for row in &self.carried {
            verdicts.ships(*row);
        }
        plan.outcome(&verdicts.met())
    }
}

/// One Owner's whole-vault copy as each of its passes makes it.
pub(crate) struct OwnerCopyPass {
    pub(crate) destination: ReadDestination,
    pub(crate) cut: ExportCut,
    pub(crate) include_secrets: bool,
    /// Whose diary reads the copy makes (OF-490), and the Owner it is for.
    pub(crate) reader: WriteActor,
}

/// An Owner's copy made and recorded: the anonymous spool file holding it,
/// its length and BLAKE3 (lowercase hex) as its audit records them, and its
/// receipt, its holder requests as the audit recorded them.
pub(crate) struct ReleasedCopy {
    pub(crate) file: File,
    pub(crate) bytes: u64,
    pub(crate) digest: String,
    pub(crate) receipt: WholeVaultExportReceipt,
}

impl ReleasedCopy {
    /// Writes the copy to `sink`, from the copy's start.
    ///
    /// # Errors
    ///
    /// The spool or `sink` failed.
    pub(crate) fn release_to<W: Write>(&mut self, sink: &mut W) -> Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        std::io::copy(&mut self.file, sink)?;
        sink.flush()?;
        Ok(())
    }

    /// The copy read whole, for a door that answers in one frame.
    ///
    /// # Errors
    ///
    /// The spool failed.
    pub(crate) fn read_whole(&mut self) -> Result<Vec<u8>> {
        self.file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        self.file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }
}

impl Vault {
    /// The Owner's own whole-vault copy `pass` describes, recorded once and
    /// only then handed back to be released (fix list row 15416): `admit`
    /// admits the Owner in each pass's own snapshot, `account` is the copy's
    /// audit from its receipt, length and digest. A copy that carries
    /// another member's personal mailbox, or uses an approval, is recorded
    /// in the one write that tells each person ([`record_member_mail_export`]);
    /// when that write does not commit, the copy is made once more without
    /// those mailboxes, each named, and recorded as any other copy is
    /// ([`record_export`]), which never withholds it.
    ///
    /// # Errors
    ///
    /// The admission's refusal, or a pass that failed.
    pub(crate) fn release_owner_copy<E: From<Error>>(
        &self,
        pass: &OwnerCopyPass,
        admit: impl Fn(&heed::RoTxn<'_>) -> std::result::Result<(), E>,
        account: impl Fn(&mut WholeVaultExportReceipt, u64, &str) -> ExportCopy,
    ) -> std::result::Result<ReleasedCopy, E> {
        let mut copy = self.prepare_owner_copy(pass, false, &admit)?;
        let audit = account(&mut copy.receipt, copy.bytes, &copy.digest);
        let Some(mailboxes) = copy.receipt.member_mail.take() else {
            copy.receipt.holder_requests = record_export(self, audit);
            return Ok(copy);
        };
        match record_member_mail_export(self, audit, &mailboxes) {
            Ok(holder_requests) => {
                copy.receipt.holder_requests = holder_requests;
                Ok(copy)
            }
            // The write did not commit: no audit row, notice or use of it
            // stands, and its copy is dropped unread.
            Err(error) => {
                tracing::warn!(
                    %error,
                    "export: members' mailboxes left out, their people not told"
                );
                drop(copy);
                let mut copy = self.prepare_owner_copy(pass, true, &admit)?;
                if copy.receipt.member_mail.is_some() {
                    return Err(Error::InvariantViolation(
                        "an export whose mailboxes' people were not told carries a mailbox",
                    )
                    .into());
                }
                let audit = account(&mut copy.receipt, copy.bytes, &copy.digest);
                copy.receipt.holder_requests = record_export(self, audit);
                Ok(copy)
            }
        }
    }

    /// One pass of the Owner's copy `pass` describes, written to a spool of
    /// its own and read back for its length and digest.
    fn prepare_owner_copy<E: From<Error>>(
        &self,
        pass: &OwnerCopyPass,
        untold: bool,
        admit: &impl Fn(&heed::RoTxn<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<ReleasedCopy, E> {
        let mut file = self.archive_spool_file()?;
        let (_, receipt) = self.export_archive_snapshot(
            pass.destination.clone(),
            None,
            pass.cut,
            pass.include_secrets,
            pass.reader,
            true,
            MemberMailPass::Owner { untold },
            admit,
            &mut file,
        )?;
        let (bytes, digest) = written_digest(&mut file).map_err(Error::from)?;
        Ok(ReleasedCopy {
            file,
            bytes,
            digest,
            receipt,
        })
    }
}

/// The length and BLAKE3 (lowercase hex) of what `sink` holds, read back
/// from its start.
///
/// # Errors
///
/// `sink` failed.
pub(crate) fn written_digest<R: Read + Seek>(sink: &mut R) -> std::io::Result<(u64, String)> {
    sink.seek(SeekFrom::Start(0))?;
    let mut hasher = blake3::Hasher::new();
    let bytes = std::io::copy(sink, &mut hasher)?;
    Ok((bytes, hasher.finalize().to_hex().to_string()))
}
