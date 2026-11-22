//! A drafted reply's ask (fix list row 17644): each new revision raises one
//! inbox Ask to the mailbox's own person, the one who approves it, so its
//! review needs no polling of `vault.mail.reply.drafts`.
//!
//! The Ask names the draft (its result) and the revision (its event), and
//! carries none of the reply's words: the drafts door shows them to a reader
//! of the thread. Only its person reads it, and only while they read the
//! thread and the message it answers: its birth names both, so its floor is
//! theirs, and the vault's owner reads it only when he reads them
//! (RECIPIENT-NOTICE-READ-BY-ANY-READER, owner half). It clears, seen and
//! acked, when that revision is approved, sent by its drafter (or left
//! uncertain by that send), discarded or drafted again. While the revision
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
use crate::provenance::birth::RowBirth;
use crate::provenance::made_by::MadeByClass;
use crate::registry::ENTITY_TYPE_NOTIFICATION;
use crate::vault::{LiveEntityRow, Vault, live_entity_row_in_txn};

/// Producer name of a drafted reply's Ask.
pub(crate) const MAIL_REPLY_ASK_PRODUCER: &str = "mail.reply";
/// The tap that approves the revision the Ask names.
const MAIL_REPLY_APPROVE_VERB: &str = "vault.mail.reply.approve";
/// The tap that discards the draft.
const MAIL_REPLY_DISCARD_VERB: &str = "vault.mail.reply.discard";
/// The door whose drafts raise the Ask, named in the Ask's birth.
const MAIL_REPLY_DRAFT_DOOR: &str = "vault.mail.reply.draft";

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
/// the mailbox's own person, in `txn`; `drafter` drafted it from
/// `answered`, the thread and the message the reply answers, which the Ask's
/// birth names. Raising it again finds its row. The caller signals
/// notification readers after its commit.
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
    drafter: crate::WriteActor,
    answered: &[EntityId],
) -> Result<()> {
    let created_at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    let event = NotificationEvent {
        kind: NotificationKind::Ask,
        source: ask_source(draft, revision),
        subject_refs: Vec::new(),
        recipient: Some(person),
        created_at,
        origin_conversation: None,
    };
    if let Some(birth) = RowBirth::written(
        drafter,
        MadeByClass::Concluded,
        MAIL_REPLY_DRAFT_DOOR,
        answered,
        &[],
        created_at,
    ) {
        vault.record_derived_notification_in_txn(txn, &event, &birth)?;
    } else {
        vault.record_notification_in_txn(txn, &event)?;
    }
    Ok(())
}

/// Whether the Ask of revision `revision` of the draft `draft` stands, not
/// yet acked by its person. A test door: built only under
/// `--cfg oneiron_test_support`.
///
/// # Errors
///
/// Storage and codec failures.
#[cfg(oneiron_test_support)]
pub(crate) fn reply_ask_open(vault: &Vault, draft: &EntityId, revision: u64) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    let id = notification_id(&ask_source(draft, revision))?;
    let LiveEntityRow::Live { entity_type, body } =
        live_entity_row_in_txn(&vault.store, &txn, &id)?
    else {
        return Ok(false);
    };
    if entity_type != ENTITY_TYPE_NOTIFICATION {
        return Ok(false);
    }
    let body = decode_notification_body(&body)?;
    Ok(body
        .recipient
        .as_ref()
        .is_some_and(|person| body.acked_by.get(person) != Some(&true)))
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
    // The Ask's birth goes with it, as on every other erase
    // (`provenance::erase_row_provenance_in_txn`).
    crate::provenance::birth::erase_row_birth_in_txn(store, txn, &id)?;
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
