//! Drafted replies (FIX 12559 row 5, fix list row 15420): an agent drafts a
//! reply to a mail thread it reads; the draft stays local, and only the
//! vault's owner, whose own mailbox it is, sends it, by approving that exact
//! revision. Never auto-sent: the draft door freezes the provider send plan
//! and dispatches nothing, and the approve door mints the one approve-once
//! proof for exactly that plan before it dispatches it through the common
//! recorded dispatcher. A changed draft is a new revision with its own plan;
//! an approval names the revision it saw.
//!
//! A reply is one plain-text message to the answered message's `Reply-To`,
//! else its sender, threaded by `In-Reply-To`, `References` and the
//! subject. A reply to all adds the answered message's own To and Cc in
//! their roles, and the drafter may name Cc recipients of its own (fix list
//! row 17645, `reply_recipients`): one message, one approval and one send
//! for every recipient, each judged by the Gate, none dropped. It leaves by
//! the mailbox's own provider:
//!
//! - **Google** (Workspace or not): through the source's delegated identity
//!   granted `gmail.send`, on the Gmail thread (`threadId`); the plan is
//!   kept by the Gmail plan store until it sends, or its draft is discarded
//!   or redrafted (fix list row 17646).
//! - **IMAP** (fix list row 17872): submitted over SMTP to the server the
//!   mailbox's credential names, as the mailbox's own account.
//! - **Microsoft 365** (fix list row 17643): one MIME `sendMail` on Graph
//!   with the mailbox's own token.
//!
//! An IMAP or Microsoft 365 reply names no sender identity: the frozen
//! message rides in the draft itself, its dispatch pins as one
//! communication (FIX 6606, a provider rail), and the owner's one press is
//! minted for exactly that send's digest. A group sender is refused, not
//! dropped.
//!
//! A Google mailbox's reply may carry files (fix list row 17645,
//! `reply_attachments`): each one exact version of an artifact the drafter
//! reads, every recipient cleared for each. Its message is written once at
//! draft, kept sealed beside the draft (`reply_custody`) and sent exactly as
//! it was frozen; an erase of a row it depends on ends the draft whole
//! (`reply_erase`). An IMAP or Microsoft 365 reply with files is refused
//! before anything is read.
//!
//! Each new revision asks the mailbox's person in their inbox (fix list
//! row 17644, `reply_ask`); the Ask clears when that revision is
//! approved, discarded or drafted again.

use serde::{Deserialize, Serialize};

use super::inbox::sources_by_audience_in;
use super::reply_ask::{clear_reply_ask_in_txn, raise_reply_ask_in_txn};
use super::reply_attachments::{
    MailReplyAttachment, MailReplyAttachmentView, ReplyAttached, ReplyRetainedMessage,
    freeze_gmail_reply, frozen_addresses, reader_reads_attachments_in,
    readmit_reply_attachments_in, standing_refusal_in,
};
use super::reply_custody::seal_reply_message_in_txn;
use super::reply_erase::{
    register_reply_dependencies_in_txn, retire_reply_revision_in_txn, retire_reply_send_in_txn,
};
use super::reply_mime::{REPLY_MESSAGE_REF_PREFIX, ReplyDraft, ReplyMessage};
use super::reply_recipients::{addresses_in, reply_recipients};
use super::reply_send::{ReplySink, ReplyTransport};
use super::source::{MailProvider, MailSourceKind, MailSourceRow, MailSourceStatus, SOURCES};
use super::state::{MailOccurrence, MailPresence, MailReplyHeaders, OCCURRENCES};
use crate::channel_identity_provider::gmail::{
    GmailDelegatedAdapter, GmailReplyThread, GmailSendPlan, GmailSendSink, HttpGmailSendWire,
};
use crate::claim::ClaimReadStatus;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::derived_domains;
use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
    OutboundDispatchOutcome, OutboundDispatchRequest, OutboundIntent, OutboundIntentDraft,
    OutboundIntentTrigger, OutboundRecipient, OutboundRecipientRole,
};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault, source_audience};

/// Each drafted reply, by its draft id.
pub(super) const DRAFTS: SideTable<EntityId, MailReplyDraftRow, Named> =
    SideTable::new(&side_table::MAIL_PACK_REPLY_DRAFT);

/// The longest reply body a draft takes, in bytes.
const MAX_REPLY_BODY_BYTES: usize = 64 * 1024;
/// The longest request key a draft takes, in bytes.
const MAX_REQUEST_KEY_BYTES: usize = 200;

/// Where one drafted reply stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MailReplyDraftState {
    /// Drafted, waiting for the owner's approval of this revision.
    Proposed,
    /// Approved; its send was dispatched and its outcome is not known yet,
    /// or the send was held: approving it again dispatches it again, and the
    /// ledger replays what it already recorded.
    Approved,
    /// The provider accepted the send.
    Sent,
    /// The dispatch failed, or its outcome is uncertain: the ledger holds it,
    /// and nothing sends it again by itself.
    Unsettled,
    /// Discarded by its drafter or the owner; it never sends.
    Discarded,
}

/// One stored draft.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct MailReplyDraftRow {
    pub(super) source: EntityId,
    /// The thread's CONVERSATION.
    thread: EntityId,
    /// The TURN of the message it answers.
    parent_turn: EntityId,
    /// The delegated identity a Gmail reply sends through; `None` for one
    /// sent as the mailbox's own account (SMTP, Graph).
    identity: Option<EntityId>,
    /// Bumped by each changed draft under the same request key.
    pub(super) revision: u64,
    /// The frozen send's content ref: a Gmail send plan's
    /// (`gmail:plan:v1:...`, or `gmail:plan:v2:...` for one with files),
    /// or the frozen message's (`mail-reply:message:v1:...`).
    pub(super) plan_ref: String,
    /// The logical send this revision is: one per revision.
    send_ref: String,
    /// The reply's first recipient, in To.
    pub(super) to: String,
    /// Every recipient of a reply to several, in its role and place, `to`
    /// first (fix list row 17645); empty for a reply to `to` alone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) recipients: Vec<OutboundRecipient>,
    subject: String,
    body: String,
    /// The HTML alternative, as the mail HTML gate wrote it (fix list row
    /// 17645).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    body_html: Option<String>,
    /// Who drafted it; `None` once that actor was erased.
    drafted_by: Option<EntityId>,
    pub(super) state: MailReplyDraftState,
    /// When the owner's approve-once proof for this revision was minted.
    approved_at: Option<u64>,
    /// What the last dispatch answered, for the reader.
    outcome: Option<String>,
    drafted_at: u64,
    updated_at: u64,
    /// The frozen message an IMAP or Microsoft 365 reply sends; `None` for a
    /// Gmail reply, whose plan the Gmail plan store keeps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message: Option<ReplyMessage>,
    /// The files a Gmail reply carries, the exact message they send in and
    /// every row the revision depends on (fix list row 17645); `None` for a
    /// reply without files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) attached: Option<ReplyAttached>,
}

/// `vault.mail.reply.draft`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailReplyDraftRequest {
    /// The thread's CONVERSATION, 32-hex.
    pub thread_ref: String,
    /// The message answered, by its TURN, 32-hex; the thread's newest
    /// message this mailbox did not send when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_turn_ref: Option<String>,
    /// The reply's plain text: the whole reply for a reader without HTML.
    pub body: String,
    /// The reply as HTML, sent beside the text as its alternative: text,
    /// links (`http`, `https`, `mailto`), paragraphs, line breaks, headings,
    /// lists, quotes, code and simple emphasis, with `dir` and `lang`. Any
    /// other element or attribute is refused, not dropped; no image, style or
    /// script is sent. At most 256 KiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_html: Option<String>,
    /// Replies to all: the answered message's own To and Cc recipients
    /// receive the reply too, in their roles, beside its `Reply-To` (else its
    /// sender). The mailbox's own address never does.
    #[serde(default)]
    pub reply_all: bool,
    /// More recipients in Cc, each one bare address (`name@example.com`). A
    /// list's address is one recipient; no group is expanded. To, Cc and
    /// these together name at most 50 recipients; more is refused, not cut.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cc: Vec<String>,
    /// Files the reply carries, in their order, from a Google mailbox only:
    /// each one exact version of an artifact the caller reads, sent as the
    /// caller's own copy of it. Every recipient must be cleared to see every
    /// file; one who is not refuses the whole draft, never dropped. The
    /// whole message, files included, is at most Gmail's 35 MiB.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<MailReplyAttachment>,
    /// The caller's key for this draft: the same key with the same body,
    /// recipients and files is the same draft; with others, its next
    /// revision.
    pub request_key: String,
}

/// One draft, as its readers see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailReplyDraftView {
    /// 32-hex.
    pub draft_ref: String,
    pub revision: u64,
    pub source_ref: String,
    pub thread_ref: String,
    pub parent_turn_ref: String,
    /// Every To recipient, in its place: the answered message's `Reply-To`
    /// (else its sender) first.
    pub to: Vec<String>,
    /// Every Cc recipient, in its place (fix list row 17645).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cc: Vec<String>,
    pub subject: String,
    pub body: String,
    /// The HTML alternative that sends beside the text, exactly as it
    /// sends; show it inert (fix list row 17645).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_html: Option<String>,
    /// The files that send with the reply, in their order, each exactly
    /// the copy that sends (fix list row 17645).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<MailReplyAttachmentView>,
    /// The length in octets of the exact message a reply with files sends,
    /// as Gmail receives it before its own transport encoding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_octets: Option<u64>,
    /// BLAKE3 of that exact message, 64 lower-hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_blake3: Option<String>,
    /// The frozen send plan the owner approves, exactly.
    pub plan_ref: String,
    pub state: MailReplyDraftState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    pub drafted_at: u64,
    pub updated_at: u64,
}

/// One draft named: by its ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailReplyDraftRef {
    /// 32-hex.
    pub draft_ref: String,
}

/// `vault.mail.reply.approve`'s input: the draft and the revision the owner
/// reviewed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailReplyApproveRequest {
    /// 32-hex.
    pub draft_ref: String,
    pub revision: u64,
}

/// `vault.mail.reply.drafts`' input.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailReplyDraftsRequest {
    /// One thread only, 32-hex; every thread the reader reads when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_ref: Option<String>,
    /// Lists sent and discarded drafts too.
    #[serde(default)]
    pub include_settled: bool,
}

/// The drafts a reader reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailReplyDraftPage {
    pub drafts: Vec<MailReplyDraftView>,
}

fn invalid_state(message: &str) -> MemoryError {
    MemoryError::new(MEMORY_CODE_INVALID_STATE, message, &[])
}

fn view(id: EntityId, row: &MailReplyDraftRow) -> MailReplyDraftView {
    let (to, cc) = if row.recipients.is_empty() {
        (vec![row.to.clone()], Vec::new())
    } else {
        (
            addresses_in(&row.recipients, OutboundRecipientRole::To),
            addresses_in(&row.recipients, OutboundRecipientRole::Cc),
        )
    };
    MailReplyDraftView {
        draft_ref: id.to_hex(),
        revision: row.revision,
        source_ref: row.source.to_hex(),
        thread_ref: row.thread.to_hex(),
        parent_turn_ref: row.parent_turn.to_hex(),
        to,
        cc,
        subject: row.subject.clone(),
        body: row.body.clone(),
        body_html: row.body_html.clone(),
        attachments: row
            .attached
            .as_ref()
            .map_or_else(Vec::new, ReplyAttached::views),
        message_octets: row
            .attached
            .as_ref()
            .map(|attached| attached.message.octets),
        message_blake3: row
            .attached
            .as_ref()
            .map(|attached| crate::blob_artifact::hash_hex(&attached.message.blake3)),
        plan_ref: row.plan_ref.clone(),
        state: row.state,
        outcome: row.outcome.clone(),
        drafted_at: row.drafted_at,
        updated_at: row.updated_at,
    }
}

/// The subject a reply carries: the parent's, marked as a reply once.
fn reply_subject(subject: &str) -> String {
    let subject = subject.trim();
    let marked = subject
        .get(..3)
        .is_some_and(|head| head.eq_ignore_ascii_case("re:"));
    if marked {
        subject.to_owned()
    } else {
        format!("Re: {subject}")
    }
}

/// The thread `conversation` as `actor` reads it: its source, that source's
/// row, and the thread's present messages.
fn thread_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    conversation: EntityId,
) -> MemoryResult<(EntityId, MailSourceRow, Vec<MailOccurrence>)> {
    let unknown = || MemoryError::not_found("no mail thread by that ref");
    super::pack::require_pack_active_in(vault, txn)?;
    let thread = source_audience::binding_in(vault, txn, &conversation)?.ok_or_else(unknown)?;
    if !source_audience::actor_reads_in(vault, txn, &thread, actor)? {
        return Err(unknown());
    }
    let (source_policy, _) =
        source_audience::thread_shares_in(vault, txn, &thread)?.ok_or_else(unknown)?;
    let sources = sources_by_audience_in(vault, txn)?;
    let (source, row) = sources.get(&source_policy).ok_or_else(unknown)?;
    let mut messages = Vec::new();
    for occurrence in OCCURRENCES.iter_from(&vault.store, txn, source.as_bytes())? {
        let (_, occurrence) = occurrence?;
        if occurrence.conversation == conversation
            && matches!(occurrence.presence, MailPresence::Present)
        {
            messages.push(occurrence);
        }
    }
    messages.sort_by_key(|occurrence| occurrence.received_at);
    Ok((*source, row.clone(), messages))
}

/// How a source's replies leave it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplyRoute {
    /// Through the source's delegated Gmail identity.
    Gmail(EntityId),
    /// As the mailbox's own account.
    Account(ReplyTransport),
}

/// How the source `row` replies: an active personal mailbox of Google
/// (through its delegated identity), IMAP (SMTP) or Microsoft 365 (Graph).
fn reply_route(row: &MailSourceRow) -> MemoryResult<ReplyRoute> {
    if row.kind != MailSourceKind::PersonalMailbox {
        return Err(MemoryError::bad_request(
            "a drafted reply sends from a personal mailbox only; a group address needs its own approvers",
        ));
    }
    if row.status != MailSourceStatus::Active {
        return Err(invalid_state("the mail source is not syncing"));
    }
    match row.provider {
        MailProvider::GoogleWorkspace | MailProvider::Google => {
            row.channel_identity.map(ReplyRoute::Gmail).ok_or_else(|| {
                MemoryError::bad_request(
                    "the mail source reads through no delegated identity that could send",
                )
            })
        }
        MailProvider::Imap => Ok(ReplyRoute::Account(ReplyTransport::Smtp)),
        MailProvider::Microsoft365 => Ok(ReplyRoute::Account(ReplyTransport::Graph)),
        MailProvider::Caldav | MailProvider::Ics => Err(MemoryError::bad_request(
            "a drafted reply sends from a mailbox; a calendar sends no mail",
        )),
    }
}

/// The actor a delegated identity is bound to: its sends go out as that
/// actor, whoever approved them.
fn bound_sender(vault: &Vault, identity: EntityId) -> MemoryResult<EntityId> {
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    crate::channel_identity::channel_identity_facts_in_txn(&vault.store, &txn, &identity)?
        .and_then(|facts| facts.binding.actor_ref())
        .ok_or_else(|| {
            MemoryError::bad_request_with(
                "the mailbox's identity is bound to no sender",
                &["reconnect the mailbox with the gmail.send scope"],
            )
        })
}

/// The adapter of a delegated identity granted `gmail.send`.
fn adapter_of(vault: &Vault, identity: EntityId) -> MemoryResult<GmailDelegatedAdapter> {
    GmailDelegatedAdapter::from_campaign_sender_row(vault, identity).map_err(|error| {
        MemoryError::bad_request_with(
            format!("the mailbox cannot send: {error}"),
            &["reconnect the mailbox with the gmail.send scope"],
        )
    })
}

/// The message a reply answers, with its whole reply headers.
fn parent_of(
    messages: &[MailOccurrence],
    parent_turn: Option<EntityId>,
) -> MemoryResult<(EntityId, MailReplyHeaders)> {
    let parent = match parent_turn {
        Some(turn) => messages.iter().find(|occurrence| occurrence.turn == turn),
        None => messages.iter().rev().find(|occurrence| {
            occurrence
                .reply
                .as_ref()
                .is_some_and(|reply| !reply.sent_by_mailbox)
        }),
    }
    .ok_or_else(|| MemoryError::not_found("no message on the thread to reply to"))?;
    let reply = parent.reply.clone().ok_or_else(|| {
        invalid_state("the message landed before replies were drafted; sync it again")
    })?;
    Ok((parent.turn, reply))
}

/// The first recipient of `recipients`, a reply's whole list, and the list
/// it freezes: empty for a reply to that one alone, whose message, send and
/// approval stay those of a reply to one (fix list row 17645).
fn split_recipients(
    recipients: &[OutboundRecipient],
) -> MemoryResult<(&str, &[OutboundRecipient])> {
    match recipients {
        [] => Err(MemoryError::bad_request("the reply names no recipient")),
        [only] => Ok((only.address.as_str(), &[])),
        [first, ..] => Ok((first.address.as_str(), recipients)),
    }
}

/// The message a reply to `parent` from the mailbox `from` sends as that
/// mailbox's own account: to `recipients`, its whole list, threaded by its
/// `Message-ID` and `References`.
fn message_for(
    from: &str,
    send_ref: &str,
    parent: &MailReplyHeaders,
    recipients: &[OutboundRecipient],
    body: &str,
    html: Option<&str>,
    composed_at: u64,
) -> MemoryResult<ReplyMessage> {
    let (to, recipients) = split_recipients(recipients)?;
    let parent_message_id = parent
        .rfc_message_id
        .as_deref()
        .ok_or_else(|| MemoryError::bad_request("the message carries no Message-ID"))?;
    let subject = reply_subject(parent.subject.as_deref().unwrap_or_default());
    ReplyMessage::new(&ReplyDraft {
        from,
        to,
        recipients,
        subject: &subject,
        body,
        html,
        parent_message_id,
        parent_references: &parent.references,
        send_ref,
        composed_at,
    })
    .map_err(|error| MemoryError::bad_request(error.to_string()))
}

/// The plan a reply to `parent` sends: from the adapter's mailbox to
/// `recipients`, its whole list, threaded on the provider.
fn plan_for(
    adapter: &GmailDelegatedAdapter,
    send_ref: &str,
    parent: &MailReplyHeaders,
    recipients: &[OutboundRecipient],
    body: &str,
    html: Option<&str>,
    composed_at: u64,
) -> MemoryResult<GmailSendPlan> {
    let refuse = |message: &str| MemoryError::bad_request(message.to_owned());
    let (to, recipients) = split_recipients(recipients)?;
    let thread_id = parent
        .thread_id
        .as_deref()
        .ok_or_else(|| refuse("the message carries no provider thread"))?;
    let parent_id = parent
        .rfc_message_id
        .as_deref()
        .ok_or_else(|| refuse("the message carries no Message-ID"))?;
    let thread = GmailReplyThread::new(thread_id, parent_id, &parent.references)
        .map_err(|error| refuse(&error.to_string()))?;
    let subject = reply_subject(parent.subject.as_deref().unwrap_or_default());
    let plan = GmailSendPlan::new(
        adapter,
        send_ref,
        to,
        &subject,
        body,
        Some(thread),
        composed_at,
    )
    .and_then(|plan| plan.with_recipients(recipients))
    .map_err(|error| refuse(&error.to_string()))?;
    match html {
        Some(html) => plan
            .with_html(html)
            .map_err(|error| refuse(&error.to_string())),
        None => Ok(plan),
    }
}

/// What sends an approved reply.
enum ReplyDispatcher<'v> {
    /// The mailbox's delegated Gmail identity.
    Gmail {
        adapter: Box<GmailDelegatedAdapter>,
        identity: EntityId,
    },
    /// The mailbox's own account (SMTP, Graph).
    Account(Box<ReplySink<'v>>),
}

/// Drops the Gmail send plan the revision `row` kept, its words with it; a
/// reply sent as the mailbox's own account keeps none. A drop that fails is
/// logged: the plan sends nothing without its draft's approval.
fn forget_kept_plan(vault: &Vault, row: &MailReplyDraftRow) {
    if row.message.is_some() {
        return;
    }
    if let Err(error) = GmailSendPlan::drop_kept(vault, &row.plan_ref) {
        tracing::warn!(%error, "a superseded reply draft's kept Gmail plan stays");
    }
}

/// The mailbox's owner as the human actor its account reply is sent by:
/// the person who approves it sends it.
fn human_actor(person: EntityId) -> OutboundDispatchActor {
    OutboundDispatchActor {
        actor_class: "human".to_owned(),
        actor_ref: Some(person.to_hex()),
        actor_entity_ref: Some(person),
    }
}

/// Whether `effect` is the send of one drafted reply its mailbox's owner
/// approved, sent as the mailbox's own account (fix list rows 17872,
/// 17643): `email`/`send` by a human actor naming no sender identity, its
/// content the frozen message of a draft that stands Approved at exactly
/// that revision and send, to exactly its recipients (each of a reply to
/// several, fix list row 17645, the Gate judging each as the counterparty),
/// from an active IMAP or Microsoft 365 personal mailbox whose owner is that
/// actor. The gate takes the owner's one press for exactly that send's
/// digest as its authority, as it takes a member-mail press.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn approved_source_reply_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    effect: &crate::gate::ExternalEffectGateInput,
) -> Result<bool> {
    if effect.channel != "email"
        || effect.verb != "send"
        || effect.channel_identity_ref.is_some()
        || effect.actor.actor_class != "human"
    {
        return Ok(false);
    }
    let Some(actor) = effect.provenance.actor_entity_ref else {
        return Ok(false);
    };
    let Some(content_ref) = effect
        .provenance
        .mail_content_ref
        .as_deref()
        .filter(|content_ref| content_ref.starts_with(REPLY_MESSAGE_REF_PREFIX))
    else {
        return Ok(false);
    };
    let Some(send_ref) = effect.send_ref.as_deref() else {
        return Ok(false);
    };
    let Some(draft) = send_ref
        .strip_prefix("outbound:mail-reply:")
        .and_then(|rest| rest.split_once(':'))
        .and_then(|(draft, _)| EntityId::from_hex(draft).ok())
    else {
        return Ok(false);
    };
    let Some(row) = DRAFTS.get(store, txn, &draft)? else {
        return Ok(false);
    };
    let counterparty = effect.counterparty.as_deref();
    let addressed = if row.recipients.is_empty() {
        counterparty == Some(row.to.as_str())
    } else {
        row.recipients
            .iter()
            .any(|named| counterparty == Some(named.address.as_str()))
    };
    if row.plan_ref != content_ref
        || row.identity.is_some()
        || row.message.is_none()
        || row.state != MailReplyDraftState::Approved
        || row.approved_at.is_none()
        || send_ref != format!("outbound:{}", row.send_ref)
        || effect.provenance.mail_recipients != row.recipients
        || !addressed
    {
        return Ok(false);
    }
    let Some(source) = SOURCES.get(store, txn, &row.source)? else {
        return Ok(false);
    };
    Ok(source.owner == Some(actor)
        && source.status == MailSourceStatus::Active
        && source.kind == MailSourceKind::PersonalMailbox
        && matches!(
            source.provider,
            MailProvider::Imap | MailProvider::Microsoft365
        ))
}

/// The one dispatch request a draft's revision is, sent as `actor`: a
/// Gmail reply's identity's bound sender, or the mailbox's owner for one
/// sent as the mailbox's own account, which names no sender identity. A
/// reply to several is one message to its whole list (fix list row 17645).
fn request_for(
    id: EntityId,
    row: &MailReplyDraftRow,
    actor: OutboundDispatchActor,
    now: u64,
) -> OutboundDispatchRequest {
    let author = actor.actor_ref.clone().unwrap_or_default();
    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new(author, "send", "email", row.to.clone())
            .content_ref(row.plan_ref.clone()),
        OutboundIntentTrigger::agent_immediate(format!("mail-reply:{}", id.to_hex())),
    )
    .with_recipients(row.recipients.clone());
    let request = OutboundDispatchRequest::new(
        format!("outbound:{}", row.send_ref),
        row.send_ref.clone(),
        intent,
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        now,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .counterparty_ref(row.to.clone());
    match row.identity {
        Some(identity) => request.channel_identity_ref(identity),
        None => request,
    }
}

impl Memory<'_> {
    /// Drafts a reply to a mail thread the caller reads, or its next
    /// revision under the same request key. It sends nothing: the draft
    /// waits for the owner's approval of this exact revision.
    pub fn mail_reply_draft(
        &self,
        input: &MailReplyDraftRequest,
    ) -> MemoryResult<MailReplyDraftView> {
        let vault = self.vault();
        let actor = self.actor();
        let conversation = EntityId::from_hex(&input.thread_ref)?;
        let parent_turn = input
            .parent_turn_ref
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()?;
        if input.body.trim().is_empty() || input.body.len() > MAX_REPLY_BODY_BYTES {
            return Err(MemoryError::bad_request(format!(
                "a reply body is 1 to {MAX_REPLY_BODY_BYTES} bytes"
            )));
        }
        if input.request_key.trim().is_empty() || input.request_key.len() > MAX_REQUEST_KEY_BYTES {
            return Err(MemoryError::bad_request(format!(
                "a request key is 1 to {MAX_REQUEST_KEY_BYTES} bytes"
            )));
        }
        let id = EntityId::derive(
            derived_domains::MAIL_REPLY_DRAFT,
            &[
                actor.to_hex().as_bytes(),
                conversation.to_hex().as_bytes(),
                input.request_key.as_bytes(),
            ],
        )?;
        let (source, row, messages, prior) = {
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            let (source, row, messages) = thread_in(vault, &txn, actor, conversation)?;
            let prior = DRAFTS.get(&vault.store, &txn, &id)?;
            (source, row, messages, prior)
        };
        let route = reply_route(&row)?;
        // Files ride a Google mailbox's reply alone: an IMAP or Microsoft 365
        // reply with files is refused before any file is read (fix list row
        // 17645).
        if !input.attachments.is_empty() && !matches!(route, ReplyRoute::Gmail(_)) {
            return Err(MemoryError::bad_request(
                "a reply carries files from a Google mailbox only; draft it without them",
            ));
        }
        // The mailbox's own person approves it, so they are asked.
        let asked = row.owner.filter(|person| *person != actor);
        let (parent_turn, parent) = parent_of(&messages, parent_turn)?;
        // Every recipient the reply names, as it would send, so a redraft to
        // the same people is the same revision (fix list row 17645). The
        // mailbox's own address is never one of them; one no mail can go to
        // is no recipient's either.
        let own: Vec<String> =
            crate::channel_identity_provider::native_mail::canonical_recipient(&row.address)
                .ok()
                .into_iter()
                .collect();
        let recipients = reply_recipients(&parent, &own, input.reply_all, &input.cc)?;
        // The HTML as it would send, so a redraft of the same words is the
        // same revision (fix list row 17645).
        let html = input
            .body_html
            .as_deref()
            .map(crate::channel_identity_provider::mail_html::sanitize_mail_html)
            .transpose()
            .map_err(|error| MemoryError::bad_request(error.to_string()))?;
        // Each file as it would send: pinned and judged for every recipient
        // under the caller's own read lane, then its copy exported once, so
        // a redraft with the same copies is the same revision (fix list row
        // 17645). The lane judges them again in the writer.
        let (lane, mut admitted) = if input.attachments.is_empty() {
            (None, None)
        } else {
            let lane = self.read_lane(ClaimReadStatus::Recorded)?;
            let (to, listed) = split_recipients(&recipients)?;
            let addresses = frozen_addresses(to, listed)
                .iter()
                .map(String::as_str)
                .map(crate::channel_identity_provider::native_mail::canonical_recipient)
                .collect::<crate::Result<Vec<_>>>()
                .map_err(|error| MemoryError::bad_request(error.to_string()))?;
            let admitted =
                self.reply_attachments_admitted(&lane, &input.attachments, &addresses)?;
            (Some(lane), Some(admitted))
        };
        if let Some(prior) = &prior {
            if prior.state != MailReplyDraftState::Proposed {
                return Err(invalid_state(
                    "the draft was approved or discarded; draft under another request key",
                ));
            }
            if prior.body == input.body
                && prior.body_html == html
                && prior.parent_turn == parent_turn
                && split_recipients(&recipients)?
                    == (prior.to.as_str(), prior.recipients.as_slice())
                && prior
                    .attached
                    .as_ref()
                    .map(|attached| &attached.attachments)
                    == admitted.as_ref().map(|admitted| &admitted.attachments)
            {
                return Ok(view(id, prior));
            }
        }
        let revision = prior.as_ref().map_or(1, |prior| prior.revision + 1);
        let send_ref = format!("mail-reply:{}:{revision}", id.to_hex());
        let now = crate::unix_seconds_now();
        let raw_html = input.body_html.as_deref();
        let mut frozen = None;
        let (identity, plan_ref, to, frozen_recipients, body_html, message) = match route {
            ReplyRoute::Gmail(identity) => {
                let adapter = adapter_of(vault, identity)?;
                let mut plan = plan_for(
                    &adapter,
                    &send_ref,
                    &parent,
                    &recipients,
                    &input.body,
                    raw_html,
                    now,
                )?;
                match admitted.take() {
                    None => plan.keep(vault)?,
                    // A reply with files freezes its exact message here,
                    // once; its plan lands with its draft (fix list row
                    // 17645).
                    Some(admitted) => {
                        let answered = messages
                            .iter()
                            .filter(|occurrence| occurrence.turn == parent_turn)
                            .flat_map(|occurrence| occurrence.messages.iter().copied());
                        let dependencies = admitted.dependencies(
                            [conversation, parent_turn]
                                .into_iter()
                                .chain(answered)
                                .chain([source]),
                        );
                        let reply = freeze_gmail_reply(plan, admitted, dependencies)?;
                        plan = reply.plan.clone();
                        frozen = Some(reply);
                    }
                }
                (
                    Some(identity),
                    plan.content_ref().to_owned(),
                    plan.recipient().to_owned(),
                    plan.recipients().to_vec(),
                    plan.body_html().map(str::to_owned),
                    None,
                )
            }
            ReplyRoute::Account(_) => {
                let message = message_for(
                    &row.address,
                    &send_ref,
                    &parent,
                    &recipients,
                    &input.body,
                    raw_html,
                    now,
                )?;
                (
                    None,
                    message.content_ref(),
                    message.to.clone(),
                    message.recipients.clone(),
                    message.html.clone(),
                    Some(message),
                )
            }
        };
        let row = MailReplyDraftRow {
            source,
            thread: conversation,
            parent_turn,
            identity,
            revision,
            plan_ref,
            send_ref,
            to,
            recipients: frozen_recipients,
            subject: reply_subject(parent.subject.as_deref().unwrap_or_default()),
            body: input.body.clone(),
            body_html,
            drafted_by: Some(actor),
            state: MailReplyDraftState::Proposed,
            approved_at: None,
            outcome: None,
            drafted_at: prior.as_ref().map_or(now, |prior| prior.drafted_at),
            updated_at: now,
            message,
            attached: frozen.as_ref().map(|frozen| frozen.attached.clone()),
        };
        vault.try_with_write_txn_grouped(|txn| -> MemoryResult<()> {
            // The draft lands only over exactly the row this call read, a
            // proposed one or none: a concurrent revision, approval or
            // discard wins.
            if DRAFTS.get(&vault.store, txn, &id)? != prior {
                return Err(crate::Error::InvalidConfig(
                    "the draft changed while it was redrafted".to_owned(),
                )
                .into());
            }
            // A reply with files lands only while its files still stand and
            // every recipient is still cleared for each, judged again here
            // (fix list row 17645).
            if let (Some(frozen), Some(lane)) = (&frozen, &lane) {
                readmit_reply_attachments_in(
                    vault,
                    lane,
                    txn,
                    &frozen.attached,
                    &frozen_addresses(&row.to, &row.recipients),
                )?;
            }
            // The revision it replaces ends here: one with files loses its
            // message, its plan and its index rows in this writer.
            if let Some(prior) = &prior {
                retire_reply_revision_in_txn(&vault.store, txn, &id, prior)?;
            }
            // This one lands with its message, its plan and its index rows.
            if let Some(frozen) = &frozen {
                seal_reply_message_in_txn(&vault.store, txn, &id, row.revision, &frozen.message)?;
                frozen.plan.keep_in_txn(&vault.store, txn)?;
                register_reply_dependencies_in_txn(
                    &vault.store,
                    txn,
                    &id,
                    &frozen.attached.dependencies,
                )?;
            }
            DRAFTS.put(&vault.store, txn, &id, &row)?;
            // The revision it replaces is no longer asked; this one is.
            if let Some(prior) = &prior {
                clear_reply_ask_in_txn(vault, txn, &id, prior.revision)?;
            }
            if let Some(person) = asked {
                raise_reply_ask_in_txn(vault, txn, &id, row.revision, person)?;
            }
            Ok(())
        })?;
        vault.store.notify_notification_updates();
        // The revision it replaces never sends: its kept plan goes with its
        // words (fix list row 17646); one with files lost it in the writer.
        if let Some(prior) = &prior
            && prior.attached.is_none()
        {
            forget_kept_plan(vault, prior);
        }
        Ok(view(id, &row))
    }

    /// The drafts on the threads the caller reads, newest first.
    pub fn mail_reply_drafts(
        &self,
        input: &MailReplyDraftsRequest,
    ) -> MemoryResult<MailReplyDraftPage> {
        let vault = self.vault();
        let actor = self.actor();
        let only = input
            .thread_ref
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()?;
        let mut drafts = Vec::new();
        let mut attached = Vec::new();
        {
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            super::pack::require_pack_active_in(vault, &txn)?;
            for entry in DRAFTS.iter_from(&vault.store, &txn, &[])? {
                let (id, row) = entry?;
                if only.is_some_and(|only| only != row.thread)
                    || (!input.include_settled
                        && matches!(
                            row.state,
                            MailReplyDraftState::Sent | MailReplyDraftState::Discarded
                        ))
                {
                    continue;
                }
                let Some(thread) = source_audience::binding_in(vault, &txn, &row.thread)? else {
                    continue;
                };
                if !source_audience::actor_reads_in(vault, &txn, &thread, actor)? {
                    continue;
                }
                if row.attached.is_some() {
                    attached.push((id, row));
                } else {
                    drafts.push(view(id, &row));
                }
            }
        }
        // A draft with files shows only to a reader whose own lane reads each
        // of them, its version's rows with it: reading the thread is not
        // reading its files (fix list row 17645).
        if !attached.is_empty() {
            let lane = self.read_lane(ClaimReadStatus::Recorded)?;
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            for (id, row) in attached {
                if let Some(files) = &row.attached
                    && reader_reads_attachments_in(vault, &lane, &txn, files)?
                {
                    drafts.push(view(id, &row));
                }
            }
        }
        drafts.sort_by_key(|draft| std::cmp::Reverse(draft.updated_at));
        Ok(MailReplyDraftPage { drafts })
    }

    /// Discards a draft that has not sent: its drafter or the mailbox's
    /// owner may. It never sends.
    pub fn mail_reply_discard(
        &self,
        input: &MailReplyDraftRef,
    ) -> MemoryResult<MailReplyDraftView> {
        let vault = self.vault();
        let actor = self.actor();
        let id = EntityId::from_hex(&input.draft_ref)?;
        let unknown = || MemoryError::not_found("no reply draft by that ref");
        let row = vault.try_with_write_txn_grouped(|txn| -> MemoryResult<MailReplyDraftRow> {
            let mut row = DRAFTS.get(&vault.store, txn, &id)?.ok_or_else(unknown)?;
            let owner = SOURCES
                .get(&vault.store, txn, &row.source)?
                .and_then(|source| source.owner);
            if row.drafted_by != Some(actor) && owner != Some(actor) {
                return Err(unknown());
            }
            if row.state != MailReplyDraftState::Proposed {
                return Err(invalid_state(
                    "only a draft that was not approved is discarded",
                ));
            }
            row.state = MailReplyDraftState::Discarded;
            row.updated_at = crate::unix_seconds_now();
            DRAFTS.put(&vault.store, txn, &id, &row)?;
            clear_reply_ask_in_txn(vault, txn, &id, row.revision)?;
            // One with files loses its message and its plan in this writer
            // (fix list row 17645).
            if row.attached.is_some() {
                retire_reply_send_in_txn(&vault.store, txn, &id, &row)?;
            }
            Ok(row)
        })?;
        vault.store.notify_notification_updates();
        // A discarded draft never sends: its kept plan goes with its words
        // (fix list row 17646).
        if row.attached.is_none() {
            forget_kept_plan(vault, &row);
        }
        Ok(view(id, &row))
    }

    /// `vault.mail.reply.approve` on this device, as its embedded owner.
    pub fn mail_reply_approve(
        &self,
        input: &MailReplyApproveRequest,
    ) -> MemoryResult<MailReplyDraftView> {
        let owner = self.embedded_owner("vault.mail.reply.approve")?;
        self.vault().approve_mail_reply(&owner, input)
    }
}

impl Vault {
    /// A mailbox's own person approves one revision of a drafted reply from
    /// that mailbox, and it sends (FIX 15420). `owner` is that person's own
    /// proof, the vault's owner or a member (fix list row 17644 follow-up):
    /// the door acts only on their own mailbox, and the proof lends no owner
    /// authority. The approve-once proof for exactly that revision's frozen
    /// plan is minted with the draft's approval in one writer; then the
    /// common recorded dispatcher sends it the way the mailbox sends,
    /// threaded on the provider. Approving it
    /// again after a held, failed or interrupted dispatch dispatches it
    /// again, and the ledger replays what it recorded rather than sending
    /// twice.
    ///
    /// # Errors
    ///
    /// The draft unknown, discarded, sent, of another revision or of a
    /// mailbox not the caller's; the mailbox unable to send; the dispatch
    /// refused.
    pub fn approve_mail_reply(
        &self,
        owner: &AuthenticatedOwner,
        input: &MailReplyApproveRequest,
    ) -> MemoryResult<MailReplyDraftView> {
        let id = EntityId::from_hex(&input.draft_ref)?;
        let unknown = || MemoryError::not_found("no reply draft by that ref");
        // The mailbox's own person, owner of the vault or not: the door
        // acts only on their own mailbox's reply.
        let actor = owner.revalidate_person(self)?;
        let (row, source) = {
            let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
            super::pack::require_pack_active_in(self, &txn)?;
            let row = DRAFTS.get(&self.store, &txn, &id)?.ok_or_else(unknown)?;
            let source = SOURCES
                .get(&self.store, &txn, &row.source)?
                .ok_or_else(unknown)?;
            (row, source)
        };
        if source.owner != Some(actor) {
            return Err(MemoryError::bad_request(
                "only the mailbox's own person approves its replies",
            ));
        }
        if row.revision != input.revision {
            return Err(invalid_state(
                "the draft changed since it was reviewed; review its current revision",
            ));
        }
        match row.state {
            MailReplyDraftState::Proposed | MailReplyDraftState::Approved => {}
            MailReplyDraftState::Unsettled => {
                return Err(invalid_state(
                    "the send's outcome is uncertain; the ledger holds it",
                ));
            }
            MailReplyDraftState::Sent => return Ok(view(id, &row)),
            MailReplyDraftState::Discarded => {
                return Err(invalid_state("the draft was discarded; it never sends"));
            }
        }
        let now = crate::unix_seconds_now();
        // The reply leaves the way its draft froze, while the mailbox still
        // sends that way.
        let (request, digest, dispatcher) = match (
            reply_route(&source)?,
            row.identity,
            &row.message,
        ) {
            (ReplyRoute::Gmail(identity), Some(drafted), None) if identity == drafted => {
                let adapter = adapter_of(self, identity)?;
                // The reply goes out as the actor the identity is bound to
                // (an agent of the owner's, or the owner); the owner's proof
                // is the approval.
                let sender = bound_sender(self, identity)?;
                let request = request_for(id, &row, OutboundDispatchActor::agent(sender), now);
                let digest =
                    crate::channel_identity_provider::native_mail::canonical_mail_send_digest(
                        &request, identity, sender,
                    )?;
                let dispatcher = ReplyDispatcher::Gmail {
                    adapter: Box::new(adapter),
                    identity,
                };
                (request, digest, dispatcher)
            }
            (ReplyRoute::Account(transport), None, Some(message)) => {
                // Sent as the mailbox's own account, by its owner; the one
                // press is minted for exactly this send's digest (FIX 6606).
                let request = request_for(id, &row, human_actor(actor), now);
                let digest = crate::outbound::outbound_approve_once_digest(self, &request)
                    .map_err(|error| {
                        MemoryError::bad_request(format!("the reply cannot be approved: {error}"))
                    })?
                    .ok_or_else(|| {
                        invalid_state("the reply's send resolves a sender identity; draft again")
                    })?;
                let mail_source = self.mail_sync_source(row.source)?.ok_or_else(unknown)?;
                let sink = ReplySink::new(self, mail_source, message.clone(), transport);
                (request, digest, ReplyDispatcher::Account(Box::new(sink)))
            }
            _ => {
                return Err(invalid_state(
                    "the mailbox now sends another way or through another identity; draft again",
                ));
            }
        };
        // A reply with files sends only the message it was frozen with:
        // before the press, its send still stands and that message opens as
        // it was frozen (fix list row 17645).
        let retained = match &row.attached {
            Some(_) => Some(ReplyRetainedMessage::for_press(self, id, &row)?),
            None => None,
        };
        let row = self.try_with_write_txn_grouped(|txn| -> MemoryResult<MailReplyDraftRow> {
            // Every press, a retry too, proves the owner again in the writer
            // that acts, and finds the mailbox still theirs.
            if owner.revalidate_person_in_txn(self, txn)? != actor
                || SOURCES
                    .get(&self.store, txn, &row.source)?
                    .and_then(|source| source.owner)
                    != Some(actor)
            {
                return Err(MemoryError::bad_request(
                    "only the mailbox's own person approves its replies",
                ));
            }
            let mut held = DRAFTS.get(&self.store, txn, &id)?.ok_or_else(unknown)?;
            if held.revision != row.revision || held.plan_ref != row.plan_ref {
                return Err(invalid_state(
                    "the draft changed since it was reviewed; review its current revision",
                ));
            }
            if !matches!(
                held.state,
                MailReplyDraftState::Proposed | MailReplyDraftState::Approved
            ) {
                return Err(invalid_state(
                    "the draft was discarded, sent or left uncertain since it was read",
                ));
            }
            // And it still stands in the writer that presses it.
            if let Some(refusal) = standing_refusal_in(self, txn, &id, &held)? {
                return Err(MemoryError::bad_request(refusal));
            }
            if held.approved_at.is_none() {
                self.approve_once_as_person_in_txn(txn, owner, digest)?;
                held.approved_at = Some(now);
                held.state = MailReplyDraftState::Approved;
                held.updated_at = now;
                DRAFTS.put(&self.store, txn, &id, &held)?;
                // The press answers the revision's Ask.
                clear_reply_ask_in_txn(self, txn, &id, held.revision)?;
            }
            Ok(held)
        })?;
        self.store.notify_notification_updates();
        let answer = match dispatcher {
            ReplyDispatcher::Gmail { adapter, identity } => {
                let wire = HttpGmailSendWire::new()?;
                let mut sink = GmailSendSink::new(self, &adapter, identity, wire);
                if let Some(retained) = &retained {
                    sink = sink.with_retained_message(retained);
                }
                adapter.dispatch_send_recorded(self, request, &mut sink)
            }
            ReplyDispatcher::Account(mut sink) => {
                self.dispatch_outbound_intent_recorded(request, sink.as_mut())
            }
        };
        let (state, outcome) = match &answer {
            Ok(result) => match result.outcome {
                OutboundDispatchOutcome::DeliveredToChannel => (
                    MailReplyDraftState::Sent,
                    result.outcome.as_str().to_owned(),
                ),
                OutboundDispatchOutcome::Held => (
                    MailReplyDraftState::Approved,
                    format!("held: {}", result.gate_reason_codes.join(", ")),
                ),
                _ => (
                    MailReplyDraftState::Unsettled,
                    result.outcome.as_str().to_owned(),
                ),
            },
            Err(error) => (MailReplyDraftState::Approved, format!("refused: {error}")),
        };
        let row = self.try_with_write_txn_grouped(|txn| -> MemoryResult<MailReplyDraftRow> {
            let mut held = DRAFTS.get(&self.store, txn, &id)?.ok_or_else(unknown)?;
            if held.revision == row.revision {
                held.state = state;
                held.outcome = Some(outcome);
                held.updated_at = crate::unix_seconds_now();
                DRAFTS.put(&self.store, txn, &id, &held)?;
                // A reply with files that sent, or whose outcome is
                // uncertain, never sends again: its message and its plan go
                // in this writer (fix list row 17645).
                if held.attached.is_some()
                    && matches!(
                        state,
                        MailReplyDraftState::Sent | MailReplyDraftState::Unsettled
                    )
                {
                    retire_reply_send_in_txn(&self.store, txn, &id, &held)?;
                }
            }
            Ok(held)
        })?;
        if let Err(error) = answer {
            return Err(MemoryError::bad_request(format!(
                "the reply did not dispatch: {error}"
            )));
        }
        Ok(view(id, &row))
    }
}

/// Whether revision `revision` of the draft `draft` still waits for
/// `person`'s approval: it is the draft's current revision, proposed, and
/// its mailbox is `person`'s own. Its Ask's taps stand only while it does.
///
/// # Errors
///
/// Storage failures.
pub(super) fn reply_awaits_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    draft: &EntityId,
    revision: u64,
    person: EntityId,
) -> Result<bool> {
    let Some(row) = DRAFTS.get(&vault.store, txn, draft)? else {
        return Ok(false);
    };
    if row.revision != revision || row.state != MailReplyDraftState::Proposed {
        return Ok(false);
    }
    Ok(SOURCES
        .get(&vault.store, txn, &row.source)?
        .is_some_and(|source| source.owner == Some(person)))
}

/// Forgets `actor` as the drafter of every draft, in `txn` (an actor's
/// erase): the drafts stay, nameless.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn erase_reply_drafter_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    for (id, mut row) in DRAFTS.scan(&vault.store, txn)? {
        if row.drafted_by == Some(*actor) {
            row.drafted_by = None;
            DRAFTS.put(&vault.store, txn, &id, &row)?;
        }
    }
    Ok(())
}
