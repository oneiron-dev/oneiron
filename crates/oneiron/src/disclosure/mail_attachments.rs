//! The files a drafted mail message carries, judged for every recipient it
//! goes to (fix list row 17645). Each recipient is an external party: never
//! the owner alone, so the clamp's own admission runs in full for each. A
//! recipient is every contact the Gate's own send lookup finds for its
//! address on email (party key and channel class, the claims the Gate reads),
//! each one a party of its own whose clearance meets the others' (no contact
//! is picked over another); one found revoked, or none found, stands as an
//! unknown party, public-only. Each file is shown to that recipient only when
//! the clamp admits each of its rows (live, below Tier A, inside the met
//! clearance) and P7 discloses each row's stored revision and every record
//! its words came from. A file's rows are its own three and every record its
//! pinned version's own binding says it quotes (a reminder wording's source
//! claim, FIX 4997), each judged the same way: a recipient cleared for the
//! file but not for a source it quotes is not shown the file. One file not
//! shown to one recipient refuses the whole message: no recipient and no
//! file is dropped. Everything reads in one snapshot, the caller's. This
//! judges disclosure only: the send itself, STOP, opt-outs, grants and the
//! owner's one press stay the Gate's.

use heed::RoTxn;

use super::DisclosureContext;
use super::disclosable_set::discloses_raw;
use crate::Vault;
use crate::counterparty_contact::{
    CounterpartyContactStatus, counterparty_contacts_for_send_with_ids_in_claims_in_txn,
    normalize_channel_class,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::interlocutor::{Interlocutor, InterlocutorSet};
use crate::ports::EntityStoreRead;

/// The rows one file of a message is: the artifact, its pinned version's
/// CLAIM and the ASSET its bytes are, then every record that version's own
/// binding says its words quote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MailAttachmentRows {
    /// The artifact, its pinned version's CLAIM and its ASSET.
    pub(crate) file: [EntityId; 3],
    /// Each record the pinned version quotes, as its own binding names it.
    pub(crate) quoted: Vec<EntityId>,
}

impl MailAttachmentRows {
    /// Every row, the file's own three first.
    pub(crate) fn ids(&self) -> impl Iterator<Item = &EntityId> {
        self.file.iter().chain(&self.quoted)
    }
}

/// The first recipient and file, by their slots in the frozen lists, that
/// the recipient may not be shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MailAttachmentDenial {
    pub(crate) recipient: usize,
    pub(crate) attachment: usize,
}

/// Judges every file of `attachments` for every address of `recipients`,
/// the message's frozen canonical To and Cc, in the caller's snapshot `txn`:
/// `None` when each recipient may be shown each file, else the first pair
/// that may not.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn mail_attachment_denial_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    recipients: &[String],
    attachments: &[MailAttachmentRows],
) -> Result<Option<MailAttachmentDenial>> {
    let channel_class = normalize_channel_class("email");
    for (recipient, address) in recipients.iter().enumerate() {
        let context = recipient_context_in(vault, txn, address, &channel_class)?;
        for (attachment, rows) in attachments.iter().enumerate() {
            if !discloses_rows_in(vault, txn, &context, rows)? {
                return Ok(Some(MailAttachmentDenial {
                    recipient,
                    attachment,
                }));
            }
        }
    }
    Ok(None)
}

/// The audience one recipient address is: each contact the Gate's send
/// lookup finds for it on `channel_class`, a known party while active and an
/// unknown one once revoked, or one unknown party when none is found. The
/// owner is never present in it.
fn recipient_context_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    address: &str,
    channel_class: &str,
) -> Result<DisclosureContext> {
    let mut parties = Vec::new();
    for (contact, record) in counterparty_contacts_for_send_with_ids_in_claims_in_txn(
        &vault.store,
        txn,
        address,
        channel_class,
    )? {
        parties.push(match record.status {
            CounterpartyContactStatus::Active => {
                Interlocutor::known_contact(contact, record.counterparty, record.first_touch)
            }
            CounterpartyContactStatus::Revoked => Interlocutor::unknown(record.counterparty, false),
        });
    }
    if parties.is_empty() {
        parties.push(Interlocutor::unknown(address, false));
    }
    DisclosureContext::resolve_in(vault, txn, InterlocutorSet::without_owner(parties))
}

/// Whether `context` is shown each of `rows`, a quoted source as its file:
/// the clamp admits it, and P7 discloses its stored revision with every
/// record its words came from. A row that does not resolve is shown to no
/// one.
fn discloses_rows_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    context: &DisclosureContext,
    rows: &MailAttachmentRows,
) -> Result<bool> {
    for id in rows.ids() {
        let Some(row) = vault.store.port_entity_record(txn, id)? else {
            return Ok(false);
        };
        if !context.admits(&vault.store, txn, id, row.entity_type, None)?
            || !discloses_raw(vault, txn, context.scope(), *id, &row.encode())?
        {
            return Ok(false);
        }
    }
    Ok(true)
}
