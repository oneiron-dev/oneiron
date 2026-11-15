//! Landing a searched message inside an off-record session (ARCH-0063
//! #searched-mail, UNBUILT-01): "In an off-record conversation, it stays in
//! the session overlay and is dropped at close." The message's rows (its
//! thread's CONVERSATION and its TURN when the session does not read them
//! yet, the revision's MESSAGE, their edges and its search text) and its
//! occurrence stage in the session's overlay, in one segment, under the
//! session's write route and byte budget. Base keeps no row of it: no sync
//! count, body queue, thread epoch, source-audience binding or header
//! retirement.
//!
//! The rows ride no turn of the session (`SESSION_WRITES_RIDE_NO_TURN`): no
//! promote or save replays them, and close drops them with the overlay. They
//! carry no source-audience obligation, which an overlay never births (fix
//! list row 16256), and name no `AuthoredBy` PERSON, whose resolution can
//! write base rows; the raw `From` stays in the MESSAGE's provenance. The
//! session's own reads (overlay over base) are what the next search's held
//! check and this landing's prior reads see, so a message a search staged
//! earlier in the session is not fetched again.

use std::cell::RefCell;

use super::super::source::{MailSourceRow, MailSourceStatus, SOURCES};
use super::super::state::{
    MailOccurrence, MailPresence, MailReplyHeaders, MailStage, OCCURRENCES, THREAD_EPOCHS,
    occurrence_key, thread_hash,
};
use super::super::wire::{MailFull, MailHeaders};
use super::{
    LandOutcome, Landing, content, conversation_body, conversation_of, derive, import_source,
    label, provenance, refused, thread_key,
};
use crate::batch::BatchOp;
use crate::edge::EdgeKind;
use crate::entity_id::{EntityId, derived_domains};
use crate::memory::{
    MEMORY_CODE_INVALID_STATE, MemoryError, MemoryResult, WitnessAuthor, WitnessMessage,
};
use crate::off_record::OffRecordSession;
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::session_overlay::SessionWriteRoute;
use crate::temporal::TimeRange;

/// What the landing read on the session's view before its writer opened.
struct SessionPrior {
    occurrence: Option<MailOccurrence>,
    conversation: EntityId,
    turn: EntityId,
    conversation_held: bool,
    turn_held: bool,
    order: u64,
    author: WitnessAuthor,
}

impl Landing<'_> {
    /// Stages the whole message `full` in `session`'s overlay through
    /// `route`, as the next revision of its provider message, unless the
    /// session reads that revision already or base forgot the message. The
    /// occurrence it stages is kept as a search's.
    pub(in crate::mail_pack) fn land_in_session(
        &self,
        session: &OffRecordSession<'_>,
        route: &SessionWriteRoute,
        row: &MailSourceRow,
        full: &MailFull,
    ) -> MemoryResult<LandOutcome> {
        let vault = self.vault;
        let source = self.source_ref;
        let source_hex = source.to_hex();
        let stamp_source = import_source(row.provider);
        let headers = &full.headers;
        let thread_key = thread_key(headers);
        let text = content(headers, full.body_text.as_deref());
        let hash = blake3::hash(text.as_bytes()).to_hex().to_string();
        let key = occurrence_key(source, &headers.provider_id);
        let prior = {
            let view = session.read_view()?;
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            let occurrence = OCCURRENCES.get(&view, &txn, &key)?;
            if let Some(held) = &occurrence
                && (matches!(held.presence, MailPresence::Forgotten { .. })
                    || held.content_hashes.contains(&hash))
            {
                return Ok(LandOutcome::Same);
            }
            let (conversation, turn) = match &occurrence {
                Some(held) => (held.conversation, held.turn),
                None => {
                    let epoch = THREAD_EPOCHS
                        .get(&view, &txn, &(source, thread_hash(&thread_key)))?
                        .unwrap_or(0);
                    (
                        conversation_of(&source_hex, &thread_key, epoch)?,
                        derive(
                            derived_domains::MAIL_TURN,
                            &[&source_hex, &headers.provider_id],
                        )?,
                    )
                }
            };
            let author =
                match crate::memory::stored_witness_turn_author(&view, &txn, &turn)? {
                    Some(author @ (WitnessAuthor::User | WitnessAuthor::Counterparty)) => author,
                    _ if headers.sent_by_mailbox => WitnessAuthor::User,
                    _ => WitnessAuthor::Counterparty,
                };
            SessionPrior {
                conversation_held: view.port_entity_record(&txn, &conversation)?.is_some(),
                turn_held: view.port_entity_record(&txn, &turn)?.is_some(),
                order: crate::memory::next_witness_message_order(&view, &txn, &turn)?,
                occurrence,
                conversation,
                turn,
                author,
            }
        };
        let message = derive(
            derived_domains::MAIL_MESSAGE,
            &[&source_hex, &headers.provider_id, &hash],
        )?;
        let occurred_at = witnessed_at(headers);
        let witnessed = WitnessMessage {
            id: Some(message.to_hex()),
            author: prior.author,
            message_type: format!("import.{stamp_source}"),
            content: text.clone(),
            parts: None,
            metadata: Some(provenance(
                source,
                row,
                headers,
                Some(full),
                MailStage::Body,
            )),
            is_visible: true,
            order: u32::try_from(prior.order).unwrap_or(u32::MAX),
            quote: None,
        };
        let ops = self.session_ops(
            &prior,
            message,
            &witnessed,
            stamp_source,
            &thread_key,
            headers,
        )?;
        let occurrence = self.staged_occurrence(&prior, headers, full, &thread_key, message, hash);
        let occurred = TimeRange {
            start: occurred_at,
            end: occurred_at,
        };
        // A refusal met in the writer aborts the segment and its base
        // transaction; it is kept here so the landing answers it as the base
        // landing does.
        let refusal: RefCell<Option<MemoryError>> = RefCell::new(None);
        let refuse = |error: MemoryError| {
            *refusal.borrow_mut() = Some(error);
            crate::Error::InvariantViolation("a searched message's session landing was refused")
        };
        let conversation_shell = session.overlay_conversation_shell()?;
        let staged = session.overlay_write_routed(route, |wtxn, apply| {
            self.owner
                .revalidate_in_txn(vault, wtxn)
                .map_err(&refuse)?;
            let active = SOURCES
                .get(&vault.store, wtxn, &source)?
                .is_some_and(|current| current.status == MailSourceStatus::Active);
            if !active {
                return Err(refuse(MemoryError::new(
                    MEMORY_CODE_INVALID_STATE,
                    "the mail source is not syncing",
                    &[],
                )));
            }
            // Another landing of this message, in base or in this session,
            // since the read above goes first.
            if OCCURRENCES.get(&session.read_view()?, wtxn, &key)? != prior.occurrence {
                return Err(refuse(MemoryError::new(
                    MEMORY_CODE_INVALID_STATE,
                    "another landing wrote this message first",
                    &[],
                )));
            }
            session.stage_session_support_ops_in_txn(
                wtxn,
                apply,
                conversation_shell,
                message,
                occurred,
                self.imported_at,
                &[],
                ops,
            )?;
            OCCURRENCES.put(&session.read_view()?, wtxn, &key, &occurrence)
        });
        match staged {
            Ok(()) => Ok(LandOutcome::Landed),
            Err(error) => refused(refusal.into_inner().unwrap_or_else(|| error.into())),
        }
    }

    /// The ops that stage one revision in a session: its thread's
    /// CONVERSATION and its TURN with the TURN's `ChildOf` edge, each only
    /// when the session does not read it yet, then the MESSAGE, its
    /// `PartOf` and `BelongsTo` edges and its search text.
    fn session_ops(
        &self,
        prior: &SessionPrior,
        message: EntityId,
        witnessed: &WitnessMessage,
        stamp_source: &'static str,
        thread_key: &str,
        headers: &MailHeaders,
    ) -> MemoryResult<Vec<BatchOp>> {
        let put = |id: EntityId, entity_type: u8, data: Vec<u8>| BatchOp::Put {
            id,
            entity_type,
            occurred: TimeRange {
                start: witnessed_at(headers),
                end: witnessed_at(headers),
            },
            learned_at: self.imported_at,
            row_version: None,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        };
        let edge = |src: EntityId, kind: EdgeKind, tgt: EntityId| BatchOp::Edge {
            src,
            kind,
            tgt,
            weight: 1.0,
            vad: oneiron_contracts::affect::Vad::NEUTRAL,
        };
        let mut ops = Vec::new();
        if !prior.conversation_held {
            let thread_ref = prior
                .occurrence
                .as_ref()
                .map_or(thread_key, |held| held.thread_key.as_str());
            ops.push(put(
                prior.conversation,
                ENTITY_TYPE_CONVERSATION,
                conversation_body(stamp_source, thread_ref, headers.subject.as_deref())?,
            ));
        }
        if !prior.turn_held {
            ops.push(put(
                prior.turn,
                ENTITY_TYPE_TURN,
                crate::memory::imported_turn_body_unstamped(
                    std::slice::from_ref(witnessed),
                    stamp_source,
                )?,
            ));
            ops.push(edge(prior.turn, EdgeKind::ChildOf, prior.conversation));
        }
        ops.push(put(
            message,
            ENTITY_TYPE_MESSAGE,
            crate::memory::witness_message_body(witnessed)?,
        ));
        ops.push(edge(message, EdgeKind::PartOf, prior.turn));
        ops.push(edge(message, EdgeKind::BelongsTo, prior.conversation));
        if !witnessed.content.is_empty() {
            ops.push(BatchOp::Text {
                id: message,
                fields: vec![("content".to_owned(), witnessed.content.clone())],
            });
        }
        Ok(ops)
    }

    /// The occurrence a session keeps for the revision `message` of
    /// `headers`'s message, read whole as `full`: the one the session read,
    /// or a new one, advanced as a base landing advances it, and kept as a
    /// search's.
    fn staged_occurrence(
        &self,
        prior: &SessionPrior,
        headers: &MailHeaders,
        full: &MailFull,
        thread_key: &str,
        message: EntityId,
        hash: String,
    ) -> MailOccurrence {
        let mut occurrence = prior.occurrence.clone().unwrap_or_else(|| MailOccurrence {
            provider_id: headers.provider_id.clone(),
            thread_key: thread_key.to_owned(),
            conversation: prior.conversation,
            turn: prior.turn,
            messages: Vec::new(),
            content_hashes: Vec::new(),
            stage: MailStage::Body,
            presence: MailPresence::Present,
            presence_generation: 0,
            labels: Vec::new(),
            rfc_message_id: None,
            from: None,
            subject: None,
            received_at: headers.received_at,
            searched: true,
            attachments: Vec::new(),
            reply: None,
            listed_in: None,
            content_digest: None,
            landed_at: self.imported_at,
            updated_at: self.imported_at,
        });
        occurrence.messages.push(message);
        occurrence.content_hashes.push(hash);
        occurrence.stage = MailStage::Body;
        occurrence.labels.clone_from(&headers.labels);
        if headers.from.is_some() {
            occurrence.from = headers.from.as_deref().map(label);
        }
        if headers.subject.is_some() {
            occurrence.subject = headers.subject.as_deref().map(label);
        }
        if headers.rfc_message_id.is_some() {
            occurrence
                .rfc_message_id
                .clone_from(&headers.rfc_message_id);
        }
        occurrence.searched = true;
        occurrence.attachments.clone_from(&full.attachments);
        occurrence.content_digest = occurrence.content_digest.or(full.content_digest);
        occurrence.reply = Some(MailReplyHeaders::of(headers));
        occurrence.updated_at = self.imported_at;
        occurrence
    }
}

/// When a revision of `headers`'s message occurred: its `Date`, else when
/// the mailbox received it.
fn witnessed_at(headers: &MailHeaders) -> u64 {
    headers.date.unwrap_or(headers.received_at)
}
