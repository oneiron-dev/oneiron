//! What one revision of a drafted reply with files, a Gmail, a Graph or an
//! SMTP one, keeps sealed beside its draft (fix list row 17645), each record
//! under that revision's own erasable custody key, a ConnectorResume leaf
//! whose ref derives from the draft, the revision and the nonce its landing
//! drew at random, under a domain of the record's own, apart from every
//! connector call's and ledger row's. The draft's row keeps that nonce, and
//! so does each record's row, so each landing seals under refs custody never
//! held; a draft an erase dropped and drafted again under its request key
//! also lands above every revision it was (`reply_erase`'s revision floor):
//!
//! - **The message**: the exact RFC 5322 bytes the revision sends, written
//!   once at draft. The send opens it, checks it against the revision's
//!   frozen length and BLAKE3, and sends it as it is: nothing is read,
//!   masked or written again.
//! - **The plan stub**: the kept Gmail plan a Gmail reply's send dispatches,
//!   its words with its manifest's digest and its carrier's ref. A Graph or
//!   an SMTP reply keeps none: its frozen message rides in its draft's row,
//!   naming the same digest and carrier.
//! - **The manifest**: the files the revision carries, its exact message's
//!   length and BLAKE3, and the message it answers. The draft's own row names
//!   it only by its digest, so no image of that row carries a file's name,
//!   ref or hash; the draft's readers open it here.
//!
//! The message and the plan stub retire in the writer that ends the send (a
//! redraft, a discard, a settled send, an erase); the manifest in the writer
//! that ends the revision (a redraft, an erase). Custody destroys each key
//! after that writer commits, so a restored image of a row opens nothing.

use heed::{RoTxn, RwTxn};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::channel_identity_provider::mail_attachments::MailMessageIdentity;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::secret_custody::{
    open_connector_resume_in_txn, retire_connector_resume_in_txn, seal_connector_resume_in_txn,
};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

/// The nonce one landing of a revision with files draws at random: every
/// custody ref of that landing derives from it, with the draft and the
/// revision.
pub(super) type ReplyCustodyNonce = [u8; ENTITY_ID_LEN];

/// A fresh nonce for one landing of a revision with files, from the OS
/// random source.
pub(super) fn draw_reply_custody_nonce() -> ReplyCustodyNonce {
    let mut nonce = [0; ENTITY_ID_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// One record a revision keeps sealed beside its draft: the table it rests
/// in, each row the revision it is, u64be, the nonce its landing drew, then
/// the record sealed (key: id16(draft)), and the domain its custody ref
/// derives under.
struct SealedRecord {
    table: SideTable<EntityId, Vec<u8>, Raw>,
    domain: &'static str,
    label: &'static str,
}

/// The revision's exact message.
const MESSAGE: SealedRecord = SealedRecord {
    table: SideTable::new(&side_table::MAIL_PACK_REPLY_COPY),
    domain: "oneiron mail reply copy custody v1",
    label: "mail reply retained message",
};

/// The revision's kept Gmail plan.
const PLAN_STUB: SealedRecord = SealedRecord {
    table: SideTable::new(&side_table::MAIL_PACK_REPLY_PLAN_STUB),
    domain: "oneiron mail reply plan stub custody v1",
    label: "mail reply plan stub",
};

/// The revision's files, message and answered message.
const MANIFEST: SealedRecord = SealedRecord {
    table: SideTable::new(&side_table::MAIL_PACK_REPLY_MANIFEST),
    domain: "oneiron mail reply manifest custody v1",
    label: "mail reply manifest",
};

/// The revision a stored row is, the nonce its landing drew, and its
/// sealed record.
fn split_row(row: &[u8]) -> Option<(u64, ReplyCustodyNonce, &[u8])> {
    let (revision, rest) = row.split_first_chunk::<{ size_of::<u64>() }>()?;
    let (nonce, sealed) = rest.split_first_chunk::<{ ENTITY_ID_LEN }>()?;
    Some((u64::from_be_bytes(*revision), *nonce, sealed))
}

impl SealedRecord {
    /// The custody ref revision `revision` of the draft `draft`, landed with
    /// the nonce `nonce`, seals this record under: one per draft, revision
    /// and landing, at the custody's first generation.
    fn custody_ref(
        &self,
        draft: &EntityId,
        revision: u64,
        nonce: &ReplyCustodyNonce,
    ) -> Result<EntityId> {
        let mut hasher = blake3::Hasher::new_derive_key(self.domain);
        hasher.update(draft.as_bytes());
        hasher.update(&revision.to_le_bytes());
        hasher.update(nonce);
        let derived = hasher.finalize();
        let bytes = derived.as_bytes()[..ENTITY_ID_LEN]
            .try_into()
            .map_err(|_| Error::InvariantViolation("mail reply custody ref"))?;
        EntityId::from_bytes(bytes).map_err(|_| Error::InvariantViolation("mail reply custody ref"))
    }

    /// Seals `record` for revision `revision` of the draft `draft`, landed
    /// with the nonce `nonce`, in `wtxn`, the writer that lands that
    /// revision: its key is minted and journaled before the row commits, and
    /// the row replaces the draft's earlier one, whose retirement the caller
    /// staged first.
    fn seal_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        draft: &EntityId,
        revision: u64,
        nonce: &ReplyCustodyNonce,
        record: &[u8],
    ) -> Result<()> {
        let sealed = seal_connector_resume_in_txn(
            store,
            wtxn,
            &self.custody_ref(draft, revision, nonce)?,
            0,
            record,
        )?;
        let mut row = revision.to_be_bytes().to_vec();
        row.extend_from_slice(nonce);
        row.extend_from_slice(&sealed);
        self.table.put(store, wtxn, draft, &row)
    }

    /// Whether the draft `draft` holds this record of revision `revision`
    /// as the landing that drew `nonce` sealed it, read in `txn`, without
    /// opening it.
    fn holds_in(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        draft: &EntityId,
        revision: u64,
        nonce: &ReplyCustodyNonce,
    ) -> Result<bool> {
        Ok(self
            .table
            .get_borrowed(store, txn, draft)?
            .is_some_and(|row| {
                split_row(&row).is_some_and(|(held, drawn, _)| held == revision && drawn == *nonce)
            }))
    }

    /// This record of revision `revision` of the draft `draft`, as the
    /// landing that drew `nonce` sealed it, opened in `txn` (a writer, or a
    /// snapshot under the custody read guard); `None` when the draft holds
    /// none of that revision and landing.
    fn open_in(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        draft: &EntityId,
        revision: u64,
        nonce: &ReplyCustodyNonce,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let Some(row) = self.table.get_borrowed(store, txn, draft)? else {
            return Ok(None);
        };
        let Some((held, drawn, sealed)) = split_row(&row) else {
            return Err(Error::CorruptedIndex(self.label));
        };
        if held != revision || drawn != *nonce {
            return Ok(None);
        }
        open_connector_resume_in_txn(
            store,
            txn,
            &self.custody_ref(draft, revision, nonce)?,
            0,
            sealed,
        )
        .map(Some)
    }

    /// Drops the draft `draft`'s record, whichever revision and landing it
    /// is, and stages the retirement of the key its row names, by its
    /// revision and its landing's nonce, in `wtxn`, the writer that ends it.
    /// A draft that holds none changes nothing.
    fn retire_in_txn(&self, store: &Store, wtxn: &mut RwTxn<'_>, draft: &EntityId) -> Result<()> {
        let held = self
            .table
            .get_borrowed(store, wtxn, draft)?
            .map(|row| split_row(&row).map(|(revision, nonce, _)| (revision, nonce)));
        let Some(held) = held else {
            return Ok(());
        };
        if let Some((revision, nonce)) = held {
            retire_connector_resume_in_txn(
                store,
                wtxn,
                &self.custody_ref(draft, revision, &nonce)?,
            )?;
        }
        self.table.delete(store, wtxn, draft)?;
        Ok(())
    }
}

/// The ref a kept Gmail plan names the carrier of revision `revision` of
/// the draft `draft`, landed with the nonce `nonce`, by: its message's
/// custody ref, 32-hex (fix list row 17645).
///
/// # Errors
///
/// The derivation's invariant failure.
pub(super) fn reply_carrier_ref(
    draft: &EntityId,
    revision: u64,
    nonce: &ReplyCustodyNonce,
) -> Result<String> {
    Ok(MESSAGE.custody_ref(draft, revision, nonce)?.to_hex())
}

/// Seals `message`, the exact bytes revision `revision` of the draft
/// `draft` sends, in `wtxn`, the writer that lands that revision with the
/// nonce `nonce`.
///
/// # Errors
///
/// Custody and storage faults.
pub(super) fn seal_reply_message_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    draft: &EntityId,
    revision: u64,
    nonce: &ReplyCustodyNonce,
    message: &[u8],
) -> Result<()> {
    MESSAGE.seal_in_txn(store, wtxn, draft, revision, nonce, message)
}

/// Whether the draft `draft` holds the retained message of revision
/// `revision`, landed with the nonce `nonce`, read in `txn`, without opening
/// it.
///
/// # Errors
///
/// Storage faults.
pub(super) fn holds_reply_message_in(
    store: &Store,
    txn: &RoTxn<'_>,
    draft: &EntityId,
    revision: u64,
    nonce: &ReplyCustodyNonce,
) -> Result<bool> {
    MESSAGE.holds_in(store, txn, draft, revision, nonce)
}

/// The retained message of revision `revision` of the draft `draft`,
/// landed with the nonce `nonce`, opened in `txn` (a writer, or a snapshot
/// under the custody read guard) and checked against `message`, its frozen
/// length and BLAKE3; `None` when the draft holds no message of that
/// revision and landing.
///
/// # Errors
///
/// A key that does not open it, a message other than the frozen one, and
/// storage faults.
pub(super) fn open_reply_message_in(
    store: &Store,
    txn: &RoTxn<'_>,
    draft: &EntityId,
    revision: u64,
    nonce: &ReplyCustodyNonce,
    message: &MailMessageIdentity,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let Some(opened) = MESSAGE.open_in(store, txn, draft, revision, nonce)? else {
        return Ok(None);
    };
    if !message.matches(&opened) {
        return Err(Error::CorruptedIndex(MESSAGE.label));
    }
    Ok(Some(opened))
}

/// Drops the draft `draft`'s retained message, whichever revision it is,
/// and stages its key's retirement in `wtxn`, the writer that ends its send.
/// A draft that holds none changes nothing.
///
/// # Errors
///
/// Custody and storage faults.
pub(super) fn retire_reply_message_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    draft: &EntityId,
) -> Result<()> {
    MESSAGE.retire_in_txn(store, wtxn, draft)
}

/// Seals `stub`, the kept Gmail plan revision `revision` of the draft
/// `draft` dispatches (`GmailSendPlan::stub`), in `wtxn`, the writer that
/// lands that revision with the nonce `nonce`.
///
/// # Errors
///
/// Custody and storage faults.
pub(super) fn seal_reply_plan_stub_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    draft: &EntityId,
    revision: u64,
    nonce: &ReplyCustodyNonce,
    stub: &[u8],
) -> Result<()> {
    PLAN_STUB.seal_in_txn(store, wtxn, draft, revision, nonce, stub)
}

/// The kept Gmail plan of revision `revision` of the draft `draft`, landed
/// with the nonce `nonce`, opened in `txn` (a snapshot under the custody
/// read guard); `None` when the draft holds none of that revision and
/// landing.
///
/// # Errors
///
/// A key that does not open it, and storage faults.
pub(super) fn open_reply_plan_stub_in(
    store: &Store,
    txn: &RoTxn<'_>,
    draft: &EntityId,
    revision: u64,
    nonce: &ReplyCustodyNonce,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    PLAN_STUB.open_in(store, txn, draft, revision, nonce)
}

/// Drops the draft `draft`'s kept Gmail plan, whichever revision it is, and
/// stages its key's retirement in `wtxn`, the writer that ends its send.
///
/// # Errors
///
/// Custody and storage faults.
pub(super) fn retire_reply_plan_stub_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    draft: &EntityId,
) -> Result<()> {
    PLAN_STUB.retire_in_txn(store, wtxn, draft)
}

/// Seals `manifest`, what revision `revision` of the draft `draft` froze
/// with its files, in `wtxn`, the writer that lands that revision with the
/// nonce `nonce`.
///
/// # Errors
///
/// Custody and storage faults.
pub(super) fn seal_reply_manifest_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    draft: &EntityId,
    revision: u64,
    nonce: &ReplyCustodyNonce,
    manifest: &[u8],
) -> Result<()> {
    MANIFEST.seal_in_txn(store, wtxn, draft, revision, nonce, manifest)
}

/// The manifest of revision `revision` of the draft `draft`, landed with
/// the nonce `nonce`, opened in `txn` (a writer, or a snapshot under the
/// custody read guard); `None` when the draft holds none of that revision
/// and landing.
///
/// # Errors
///
/// A key that does not open it, and storage faults.
pub(super) fn open_reply_manifest_in(
    store: &Store,
    txn: &RoTxn<'_>,
    draft: &EntityId,
    revision: u64,
    nonce: &ReplyCustodyNonce,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    MANIFEST.open_in(store, txn, draft, revision, nonce)
}

/// Drops the draft `draft`'s manifest, whichever revision it is, and stages
/// its key's retirement in `wtxn`, the writer that ends that revision.
///
/// # Errors
///
/// Custody and storage faults.
pub(super) fn retire_reply_manifest_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    draft: &EntityId,
) -> Result<()> {
    MANIFEST.retire_in_txn(store, wtxn, draft)
}
