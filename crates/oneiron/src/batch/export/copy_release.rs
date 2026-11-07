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

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use super::archive_side_tables::SideProvenance;
use super::{ExportCut, ExportReceiptSource, ReceiptSourceOmission, WholeVaultExportReceipt};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::mail_pack::{CarriedMemberMailboxes, MailboxExportNotice, MemberMailboxPlan};
use crate::memory::{ExportCopy, record_export, record_member_mail_export};
use crate::settings::ReadDestination;
use crate::source_audience::{ExportJudge, ExportVerdicts};
use crate::store::Store;
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
/// (fix list row 15416): the rows it writes outside them (a custody record,
/// the session of an epoch floor, the rows a saved output was made from, the
/// rows each side row it serializes names), each row a carried row was
/// folded from or names beside its lineage, by that row, and the rows each
/// receipt a row cites was made from, by that row and the receipt's id. It
/// holds what the side ledgers record each row's body was made from, read
/// once in the pass's snapshot, and judges it before any body is read.
#[derive(Default)]
pub(super) struct MailboxLineage {
    carried: BTreeSet<EntityId>,
    folded: Vec<(EntityId, EntityId)>,
    receipts: BTreeMap<(EntityId, String), BTreeSet<EntityId>>,
    recorded: SideProvenance,
}

impl MailboxLineage {
    /// The lineage of one pass reading the snapshot `txn`: with what the side
    /// ledgers record each row's body was made from ([`SideProvenance`]) for
    /// a pass its judge judges (`judged`), and with nothing for a pass the
    /// rule does not judge.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(super) fn read_in(store: &Store, txn: &heed::RoTxn<'_>, judged: bool) -> Result<Self> {
        let recorded = if judged {
            SideProvenance::read_in(store, txn)?
        } else {
            SideProvenance::default()
        };
        Ok(Self {
            recorded,
            ..Self::default()
        })
    }

    /// Whether the pass's `judge`, when it has one, carries the row `id` (its
    /// bytes `raw`, else as the pass's view holds them) and every row the
    /// side ledgers record its body was made from
    /// ([`SideProvenance::admitted`]): the one check every row meets before
    /// its body is read, in an archive and an OKF copy alike. Those rows
    /// count as carried only once `id` ships ([`Self::outcome`]).
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(super) fn admits(
        &mut self,
        judge: Option<&mut ExportJudge<'_, '_, '_>>,
        id: EntityId,
        raw: Option<&[u8]>,
    ) -> Result<bool> {
        let Some(judge) = judge else {
            return Ok(true);
        };
        let carried = judge.carries(id, raw)?;
        match self.recorded.admitted(judge, id)? {
            Some(sources) if carried => {
                self.folded
                    .extend(sources.into_iter().map(|source| (id, source)));
                Ok(true)
            }
            Some(_) | None => Ok(false),
        }
    }

    /// The rows `rows`, each one the pass's judge carries, went into the copy
    /// outside its entity rows: a custody record or an epoch floor's session
    /// it wrote, or the rows a side row it serialized names.
    pub(super) fn ships(&mut self, rows: impl IntoIterator<Item = EntityId>) {
        self.carried.extend(rows);
    }

    /// Whether the pass's `judge`, when it has one, carries every row `names`
    /// that the row `row` names beside its own lineage (a version's ledger
    /// claim's made_by); `None`, names not all known, is carried by no judge.
    /// They count as carried only once `row` ships ([`Self::outcome`]).
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(super) fn supplements(
        &mut self,
        judge: Option<&mut ExportJudge<'_, '_, '_>>,
        row: EntityId,
        names: Option<&[EntityId]>,
    ) -> Result<bool> {
        let Some(judge) = judge else {
            return Ok(true);
        };
        if !judge.carries_all(names)? {
            return Ok(false);
        }
        self.folded
            .extend(names.into_iter().flatten().map(|name| (row, *name)));
        Ok(true)
    }

    /// Whether the pass's `judge`, when it has one, carries the row `source`
    /// that the row `row` is folded from, and every row the side ledgers
    /// record its body was made from, as [`Self::admits`] judges a row; no
    /// source, nothing to judge. They count as carried once `row` ships.
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
        match self.recorded.admitted(judge, *source)? {
            Some(recorded) if carried => {
                self.folded.push((row, *source));
                self.folded
                    .extend(recorded.into_iter().map(|recorded| (row, recorded)));
                Ok(true)
            }
            Some(_) | None => Ok(false),
        }
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
    /// through a body the copy serializes, of a row it ships.
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
        if let Some(judge) = judge
            && let Some(reason) =
                self.receipt_withheld(judge, row, &receipt_id, receipt.pack_source_rows())?
        {
            return Ok(ExportReceiptSource::Unavailable { receipt_id, reason });
        }
        ExportReceiptSource::from_record(receipt_id, Some(receipt))
    }

    /// The archived receipt sources `sources` the row `row` cites, as the
    /// copy carries them: each kept body's record judged as a native
    /// receipt's is ([`Self::receipt_source`]), by every row its attempt
    /// read, and one the pass's `judge`, when it has one, keeps home goes as
    /// unavailable, and why, under its own id, so no native receipt of that
    /// id stands in for it. A kept body whose record does not read names no
    /// rows it was made from.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(super) fn archived_receipt_sources(
        &mut self,
        judge: Option<&mut ExportJudge<'_, '_, '_>>,
        row: EntityId,
        sources: &mut BTreeMap<String, ExportReceiptSource>,
    ) -> Result<()> {
        let Some(judge) = judge else {
            return Ok(());
        };
        for (receipt_id, source) in sources.iter_mut() {
            if !matches!(source, ExportReceiptSource::Preserved { .. }) {
                continue;
            }
            let inputs = source
                .record()
                .ok()
                .flatten()
                .and_then(|record| record.pack_source_rows());
            if let Some(reason) = self.receipt_withheld(judge, row, receipt_id, inputs)? {
                *source = ExportReceiptSource::Unavailable {
                    receipt_id: receipt_id.clone(),
                    reason,
                };
            }
        }
        Ok(())
    }

    /// Why `judge` keeps home the body of the receipt `receipt_id` the row
    /// `row` cites, made from exactly the rows `inputs`, if it does: one row
    /// of a member's mailbox the copy leaves out, or rows not all known.
    /// Else those rows are kept, to count as carried once the copy
    /// serializes that body for `row` ([`Self::outcome`]).
    fn receipt_withheld(
        &mut self,
        judge: &mut ExportJudge<'_, '_, '_>,
        row: EntityId,
        receipt_id: &str,
        inputs: Option<Vec<EntityId>>,
    ) -> Result<Option<ReceiptSourceOmission>> {
        if !judge.carries_all(inputs.as_deref())? {
            return Ok(Some(if inputs.is_some() {
                ReceiptSourceOmission::MemberMailbox
            } else {
                ReceiptSourceOmission::SourceUnidentified
            }));
        }
        self.receipts.insert(
            (row, receipt_id.to_owned()),
            inputs.into_iter().flatten().collect(),
        );
        Ok(None)
    }

    /// What the copy left out and carries, once its rows are final: the
    /// entity rows the writer carried (`rows`) but the diaries whose read was
    /// not logged (`unlogged`), each row one of them was folded from or names
    /// beside its lineage, the rows each receipt body the writer serialized
    /// for one of them (`receipts`, by row and receipt id) was made from, and
    /// the rows written outside them. Nothing for a pass with no `plan`.
    pub(super) fn outcome(
        self,
        plan: Option<MemberMailboxPlan>,
        verdicts: Option<ExportVerdicts>,
        rows: &BTreeSet<EntityId>,
        receipts: &BTreeSet<(EntityId, String)>,
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
        for (cited, inputs) in &self.receipts {
            if receipts.contains(cited) && !unlogged.contains(&cited.0) {
                for input in inputs {
                    verdicts.ships(*input);
                }
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
