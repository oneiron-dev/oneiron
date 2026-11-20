//! A drafted reply's ask (fix list row 17644): each new revision raises one
//! inbox Ask to the mailbox's own person, the one who approves it, so its
//! review needs no polling of `vault.mail.reply.drafts`.
//!
//! The Ask names the draft (its result) and the revision (its event), and
//! carries none of the reply's words: the drafts door shows them to a reader
//! of the thread. Only its person reads it. It clears, seen and acked, when
//! that revision is approved, discarded or drafted again. While the revision
//! still waits, its taps approve it or discard it; each door judges the
//! draft again when called, and the approve door takes the mailbox person's
//! own proof, owner of the vault or not.

use super::reply::reply_awaits_in;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::inbox::{
    NotificationAction, NotificationEvent, NotificationKind, NotificationRow, NotificationSource,
    decode_notification_body, notification_id,
};
use crate::memory::Memory;
use crate::registry::ENTITY_TYPE_NOTIFICATION;
use crate::vault::{LiveEntityRow, Vault, live_entity_row_in_txn};

/// Producer name of a drafted reply's Ask.
pub(crate) const MAIL_REPLY_ASK_PRODUCER: &str = "mail.reply";
/// The tap that approves the revision the Ask names.
const MAIL_REPLY_APPROVE_VERB: &str = "vault.mail.reply.approve";
/// The tap that discards the draft.
const MAIL_REPLY_DISCARD_VERB: &str = "vault.mail.reply.discard";

/// The Ask's source for revision `revision` of the draft `draft`: the event
/// `<draft>:<revision>` keys one Ask per revision, and the result names the
/// draft.
fn ask_source(draft: &EntityId, revision: u64) -> NotificationSource {
    let draft = draft.to_hex();
    NotificationSource {
        producer: MAIL_REPLY_ASK_PRODUCER.to_owned(),
        event: format!("{draft}:{revision}"),
        result: Some(draft),
        ..NotificationSource::default()
    }
}

/// Raises the Ask of revision `revision` of the draft `draft` to `person`,
/// the mailbox's own person, in `txn`. Raising it again finds its row. The
/// caller signals notification readers after its commit.
///
/// # Errors
///
/// Storage failures.
pub(super) fn raise_reply_ask_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    draft: &EntityId,
    revision: u64,
    person: EntityId,
) -> Result<()> {
    let created_at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    vault.record_notification_in_txn(
        txn,
        &NotificationEvent {
            kind: NotificationKind::Ask,
            source: ask_source(draft, revision),
            subject_refs: Vec::new(),
            recipient: Some(person),
            created_at,
            origin_conversation: None,
        },
    )?;
    Ok(())
}

/// Clears the Ask of revision `revision` of the draft `draft`, seen and
/// acked for its person, in `txn`. An Ask already acked, or never raised,
/// stays as it is. The caller signals notification readers after its
/// commit.
///
/// # Errors
///
/// Storage and codec failures.
pub(super) fn clear_reply_ask_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    draft: &EntityId,
    revision: u64,
) -> Result<()> {
    let id = notification_id(&ask_source(draft, revision))?;
    let LiveEntityRow::Live { entity_type, body } =
        live_entity_row_in_txn(&vault.store, &*txn, &id)?
    else {
        return Ok(());
    };
    if entity_type != ENTITY_TYPE_NOTIFICATION {
        return Ok(());
    }
    let mut body = decode_notification_body(&body)?;
    let Some(person) = body.recipient.clone() else {
        return Ok(());
    };
    if body.acked_by.get(&person) == Some(&true) {
        return Ok(());
    }
    body.seen_by.insert(person.clone(), true);
    body.acked_by.insert(person, true);
    vault.put_notification_in_txn(txn, &id, &body)?;
    Ok(())
}

/// Takes the Ask of revision `revision` of the draft `draft` out whole, in
/// `txn`, the writer of an erase that drops the draft (fix list row 17645),
/// through the same delete its own rows' erase takes. An Ask under a legal
/// hold stays: it names only the draft, and its taps find none.
///
/// # Errors
///
/// Storage failures.
pub(super) fn erase_reply_ask_in_txn(
    write: &crate::secret_custody::CustodyWrite<'_>,
    txn: &mut heed::RwTxn<'_>,
    draft: &EntityId,
    revision: u64,
) -> Result<()> {
    let store = write.store;
    let id = notification_id(&ask_source(draft, revision))?;
    let LiveEntityRow::Live { entity_type, .. } = live_entity_row_in_txn(store, &*txn, &id)? else {
        return Ok(());
    };
    if entity_type != ENTITY_TYPE_NOTIFICATION
        || crate::store::legal_hold::held_in_txn(store, &*txn, id.as_bytes())?
    {
        return Ok(());
    }
    let (_, vector, graph, neighbors) = crate::batch::deindex_entity(write, txn, &id)?;
    crate::batch::stage_cascade_tombstone_in_txn(store, txn, &id)?;
    crate::ppr::invalidate_ppr_for_delete(store, txn, &id, &neighbors)?;
    if graph {
        crate::ppr::increment_graph_version(store, txn)?;
    }
    if vector {
        crate::hnsw::increment_vector_version(store, txn)?;
    }
    Ok(())
}

impl Memory<'_> {
    /// The taps a drafted reply's Ask offers its caller now: approve the
    /// revision it names, or discard the draft, while that revision still
    /// waits for the caller, the mailbox's own person. Any other row, and a
    /// revision approved, discarded or drafted again, offers none.
    pub(crate) fn mail_reply_ask_actions(&self, row: &NotificationRow) -> Vec<NotificationAction> {
        let Some((draft_ref, revision)) = row.source.event.split_once(':') else {
            return Vec::new();
        };
        let (Ok(draft), Ok(revision)) = (EntityId::from_hex(draft_ref), revision.parse::<u64>())
        else {
            return Vec::new();
        };
        let vault = self.vault();
        let awaits = vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)
            .and_then(|txn| reply_awaits_in(vault, &txn, &draft, revision, self.actor()));
        if !matches!(awaits, Ok(true)) {
            return Vec::new();
        }
        vec![
            NotificationAction {
                verb: MAIL_REPLY_APPROVE_VERB.to_owned(),
                args: serde_json::json!({ "draft_ref": draft_ref, "revision": revision }),
            },
            NotificationAction {
                verb: MAIL_REPLY_DISCARD_VERB.to_owned(),
                args: serde_json::json!({ "draft_ref": draft_ref }),
            },
        ]
    }
}
