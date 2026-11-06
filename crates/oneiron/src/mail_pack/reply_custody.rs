//! A drafted Gmail reply's retained message (fix list row 17645): the exact
//! RFC 5322 bytes one revision sends, written once at draft and sealed once
//! under that revision's own erasable custody key, a ConnectorResume leaf
//! whose ref derives from the draft and the revision under a domain of its
//! own, apart from every connector call's and ledger row's. The send opens
//! it, checks it against the revision's frozen length and BLAKE3, and sends
//! it as it is: nothing is read, masked or written again. Its row and its
//! key retire in the writer that ends the revision (a redraft, a discard, a
//! settled send, an erase); custody destroys the key after that writer
//! commits, so a restored image of the row opens nothing.

use heed::{RoTxn, RwTxn};
use zeroize::Zeroizing;

use crate::channel_identity_provider::mail_attachments::MailMessageIdentity;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::secret_custody::{
    open_connector_resume_in_txn, retire_connector_resume_in_txn, seal_connector_resume_in_txn,
};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

/// Each draft's retained message: the revision it is, u64be, then the
/// message sealed. Key: id16(draft).
const COPIES: SideTable<EntityId, Vec<u8>, Raw> = SideTable::new(&side_table::MAIL_PACK_REPLY_COPY);

/// The domain a revision's custody ref derives under.
const CUSTODY_REF_DOMAIN: &str = "oneiron mail reply copy custody v1";

/// The custody ref revision `revision` of the draft `draft` seals under: one
/// per draft and revision, at the custody's first generation.
fn custody_ref(draft: &EntityId, revision: u64) -> Result<EntityId> {
    let mut hasher = blake3::Hasher::new_derive_key(CUSTODY_REF_DOMAIN);
    hasher.update(draft.as_bytes());
    hasher.update(&revision.to_le_bytes());
    let derived = hasher.finalize();
    let bytes = derived.as_bytes()[..ENTITY_ID_LEN]
        .try_into()
        .map_err(|_| Error::InvariantViolation("mail reply custody ref"))?;
    EntityId::from_bytes(bytes).map_err(|_| Error::InvariantViolation("mail reply custody ref"))
}

/// The ref a kept Gmail plan names the carrier of revision `revision` of
/// the draft `draft` by: its custody ref, 32-hex (fix list row 17645).
///
/// # Errors
///
/// The derivation's invariant failure.
pub(super) fn reply_carrier_ref(draft: &EntityId, revision: u64) -> Result<String> {
    Ok(custody_ref(draft, revision)?.to_hex())
}

/// The revision a stored row is, and its sealed message.
fn split_row(row: &[u8]) -> Option<(u64, &[u8])> {
    let (revision, sealed) = row.split_first_chunk::<{ size_of::<u64>() }>()?;
    Some((u64::from_be_bytes(*revision), sealed))
}

/// Seals `message`, the exact bytes revision `revision` of the draft
/// `draft` sends, in `wtxn`, the writer that lands that revision: its key is
/// minted and journaled before the row commits, and the row replaces the
/// draft's earlier one, whose retirement the caller staged first.
///
/// # Errors
///
/// Custody and storage faults.
pub(super) fn seal_reply_message_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    draft: &EntityId,
    revision: u64,
    message: &[u8],
) -> Result<()> {
    let sealed =
        seal_connector_resume_in_txn(store, wtxn, &custody_ref(draft, revision)?, 0, message)?;
    let mut row = revision.to_be_bytes().to_vec();
    row.extend_from_slice(&sealed);
    COPIES.put(store, wtxn, draft, &row)
}

/// Whether the draft `draft` holds the retained message of revision
/// `revision`, read in `txn`, without opening it.
///
/// # Errors
///
/// Storage faults.
pub(super) fn holds_reply_message_in(
    store: &Store,
    txn: &RoTxn<'_>,
    draft: &EntityId,
    revision: u64,
) -> Result<bool> {
    Ok(COPIES
        .get_borrowed(store, txn, draft)?
        .is_some_and(|row| split_row(&row).is_some_and(|(held, _)| held == revision)))
}

/// The retained message of revision `revision` of the draft `draft`, opened
/// in `txn` (a writer, or a snapshot under the custody read guard) and
/// checked against `message`, its frozen length and BLAKE3; `None` when the
/// draft holds no message of that revision.
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
    message: &MailMessageIdentity,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let Some(row) = COPIES.get_borrowed(store, txn, draft)? else {
        return Ok(None);
    };
    let Some((held, sealed)) = split_row(&row) else {
        return Err(Error::CorruptedIndex("mail reply retained message"));
    };
    if held != revision {
        return Ok(None);
    }
    let opened =
        open_connector_resume_in_txn(store, txn, &custody_ref(draft, revision)?, 0, sealed)?;
    if !message.matches(&opened) {
        return Err(Error::CorruptedIndex("mail reply retained message"));
    }
    Ok(Some(opened))
}

/// Drops the draft `draft`'s retained message, whichever revision it is,
/// and stages its key's retirement in `wtxn`, the writer that ends that
/// revision. A draft that holds none changes nothing.
///
/// # Errors
///
/// Custody and storage faults.
pub(super) fn retire_reply_message_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    draft: &EntityId,
) -> Result<()> {
    let held = COPIES
        .get_borrowed(store, wtxn, draft)?
        .map(|row| split_row(&row).map(|(revision, _)| revision));
    let Some(held) = held else {
        return Ok(());
    };
    if let Some(revision) = held {
        retire_connector_resume_in_txn(store, wtxn, &custody_ref(draft, revision)?)?;
    }
    COPIES.delete(store, wtxn, draft)?;
    Ok(())
}
