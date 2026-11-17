//! The Owner's own copy of every record, recorded as an Owner's whole-vault
//! copy is ([`Vault::record_owner_copy`]) before it is answered (fix list
//! row 15416): each pass holds its records in memory and answers none before
//! the copy is recorded, its length and digest read from their one encoding
//! ([`records_digest`]).

use std::collections::BTreeSet;

use super::OwnerRecordExport;
use super::copy_release::MailboxLineage;
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::Scope;
use crate::federation::record_scope::ScopedRecord;
use crate::mail_pack::{CarriedMemberMailboxes, MailboxExportNotice, MemberMailboxPlan};
use crate::memory::{raw_records_copy, turn_thread_root};
use crate::settings::ReadDestination;
use crate::source_audience::ExportJudge;
use crate::workspace_roster::ExportThreadRoots;

/// One pass of the Owner's own copy of every record: the records as it
/// answers them, each member's mailbox it left out, the members' mailboxes
/// it carries and the approvals it uses, the root of each thread a TURN it
/// carries is of, and the length and BLAKE3 (lowercase hex) of its records
/// in their one encoding ([`records_digest`]), as its audit records them.
struct OwnerRecordPass {
    records: Vec<ScopedRecord>,
    mailbox_notices: Vec<MailboxExportNotice>,
    member_mail: Option<CarriedMemberMailboxes>,
    thread_roots: ExportThreadRoots,
    bytes: u64,
    digest: String,
}

impl Vault {
    /// The embedded owner's own copy of every record the vault holds,
    /// toward `destination` (fix list row 15416): each record as an export
    /// of records carries it, through a door that withholds no position.
    /// Every check that export makes still stands: the world settings of
    /// each machine it goes to (an on-device destination is read as one
    /// nobody proved), the causal, epoch and text fences, withdrawn words,
    /// the release filter, a marked item's masked copy, and each birth
    /// naming only the rows the copy carries. It carries no custody record,
    /// no unpublished LFS chunk and no row secret exhaust tainted.
    ///
    /// The scoped record doors are never this copy, whatever scopes they
    /// are given. In a shared vault it leaves out each row of another
    /// member's personal mailbox the vault's rule does not carry, and each
    /// row whose words came from one, judged in the copy's own snapshot
    /// before the row's body is read, and names each such mailbox in its
    /// answer. The copy is in the vault's export audit before it is answered
    /// (FIX 6427), and one that carries another member's mailbox, or uses an
    /// approval of the Owner's request for one, only once each mailbox's
    /// person is told and each approval used, in one write; when that write
    /// does not commit, the copy is made again without those mailboxes, each
    /// named.
    pub fn export_owner_records(&self, destination: &ReadDestination) -> Result<OwnerRecordExport> {
        self.release_owner_records(
            super::document_snapshot::owner_reader()?.entity_ref(),
            destination,
        )
    }

    /// The Owner `exporter`'s own copy of every record, toward
    /// `destination`, recorded once ([`Self::record_owner_copy`]) and only
    /// then answered (fix list row 15416). Each pass reads the vault's rule
    /// for the other members' personal mailboxes in its own snapshot, as the
    /// PERSON `exporter` exports as, and judges each row by it before the
    /// row's body is read, a separate conjunct beside every check a scoped
    /// export makes ([`Self::export_records_in_txn`]): a row it leaves out
    /// is in no record, and the answer names each mailbox it left out.
    ///
    /// # Errors
    ///
    /// A pass that failed.
    pub(super) fn release_owner_records(
        &self,
        exporter: EntityId,
        destination: &ReadDestination,
    ) -> Result<OwnerRecordExport> {
        let (pass, _) = self.record_owner_copy(
            |untold| self.owner_records_pass(exporter, destination, untold),
            |pass: &mut OwnerRecordPass| {
                let audit = raw_records_copy(
                    exporter,
                    pass.bytes,
                    std::mem::take(&mut pass.digest),
                    std::mem::take(&mut pass.thread_roots),
                );
                (audit, pass.member_mail.take())
            },
        )?;
        Ok(OwnerRecordExport {
            records: pass.records,
            mailbox_notices: pass.mailbox_notices,
        })
    }

    /// One pass of [`Self::release_owner_records`], in a snapshot of its
    /// own: with `untold`, it carries no member's mailbox and uses no
    /// approval. A member's mailbox counts as carried only through a record
    /// the pass answers, by the stored row it stands for.
    ///
    /// # Errors
    ///
    /// Storage and codec failures.
    fn owner_records_pass(
        &self,
        exporter: EntityId,
        destination: &ReadDestination,
        untold: bool,
    ) -> Result<OwnerRecordPass> {
        let txn = self.store.env.read_txn()?;
        let plan = MemberMailboxPlan::read_in(self, &txn, exporter, untold)?;
        let dbs = self.store.read();
        let mut judge = plan
            .as_ref()
            .map(|plan| plan.judge(self, &dbs, &txn))
            .transpose()?;
        let mut lineage = MailboxLineage::read_in(&self.store, &txn, judge.is_some())?;
        // The Owner's copy is of every record: its door withholds no
        // position.
        let top = Scope::top();
        let (records, ships) = self.export_records_in_txn(
            &txn,
            [&top, &top, &top],
            destination,
            |id, entity_type, raw| {
                lineage.row_admitted(judge.as_mut(), &self.store, &txn, id, entity_type, raw)
            },
        )?;
        // Each carried thread's binding, read in this snapshot, so its
        // members are told should its root go before the audit (FIX 6427,
        // 6681).
        let mut thread_roots = ExportThreadRoots::default();
        for record in &records {
            if let Some(header) = EntityMetadataHeader::parse(&record.bytes)
                && let Some(body) = record.bytes.get(ENTITY_METADATA_HEADER_LEN..)
            {
                thread_roots.extend(turn_thread_root(header.entity_type, body));
            }
        }
        thread_roots.capture_in(&dbs, &txn);
        let verdicts = judge.map(ExportJudge::settle);
        let (mailbox_notices, member_mail) =
            lineage.outcome(plan, verdicts, &ships, &BTreeSet::new(), &BTreeSet::new());
        let (bytes, digest) = records_digest(&records)?;
        Ok(OwnerRecordPass {
            records,
            mailbox_notices,
            member_mail,
            thread_roots,
            bytes,
            digest,
        })
    }
}

/// The length and BLAKE3 (lowercase hex) of `records`, as one Owner's copy
/// of them is audited (fix list row 15416), read in their one encoding: each
/// record in order, as its length, a little-endian u64, then the record
/// itself, its 16-byte id followed by its bytes, its position and its birth,
/// each as its length, a little-endian u64, then itself. A position and a
/// birth are their JSON; an absent one is empty.
///
/// # Errors
///
/// A position or a birth that does not encode.
fn records_digest(records: &[ScopedRecord]) -> Result<(u64, String)> {
    let length =
        |len: usize| u64::try_from(len).map_err(|_| Error::IndexOverflow("records copy length"));
    let prefix = std::mem::size_of::<u64>();
    let mut hasher = blake3::Hasher::new();
    let mut total = 0_usize;
    for record in records {
        let scope = json_field(record.scope.as_ref())?;
        let birth = json_field(record.birth.as_ref())?;
        let id = record.id.as_bytes();
        let fields = [record.bytes.as_slice(), scope.as_slice(), birth.as_slice()];
        let frame = id.len()
            + fields
                .iter()
                .map(|field| prefix + field.len())
                .sum::<usize>();
        hasher.update(&length(frame)?.to_le_bytes());
        hasher.update(id);
        for field in fields {
            hasher.update(&length(field.len())?.to_le_bytes());
            hasher.update(field);
        }
        total += prefix + frame;
    }
    Ok((length(total)?, hasher.finalize().to_hex().to_string()))
}

/// `value` as JSON, for [`records_digest`]; empty when absent.
fn json_field<T: serde::Serialize>(value: Option<&T>) -> Result<Vec<u8>> {
    match value {
        Some(value) => serde_json::to_vec(value)
            .map_err(|_| Error::InvariantViolation("records copy field encode failed")),
        None => Ok(Vec::new()),
    }
}
