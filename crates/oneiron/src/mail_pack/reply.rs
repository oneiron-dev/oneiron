//! Drafted replies (FIX 12559 row 5, fix list row 15420): an agent drafts a
//! reply to a mail thread it reads; the draft stays local, and only the
//! vault's owner, whose own mailbox it is, sends it, by approving that exact
//! revision. Never auto-sent: the draft door freezes the provider send plan
//! and dispatches nothing, and the approve door mints the one approve-once
//! proof for exactly that plan before it dispatches it through the common
//! recorded dispatcher. A changed draft is a new revision with its own plan;
//! an approval names the revision it saw.
//!
//! This first slice sends from a Google mailbox (Workspace or not) whose
//! source reads through a delegated identity granted `gmail.send`: one
//! plain-text reply to the message's `Reply-To`, else its sender, threaded on
//! the provider (`threadId`, `In-Reply-To`, `References`, the subject). A
//! group address, a Microsoft 365 mailbox, more than one recipient and
//! attachments are refused, not dropped.

use serde::{Deserialize, Serialize};

use super::inbox::sources_by_audience_in;
use super::source::{MailProvider, MailSourceKind, MailSourceRow, MailSourceStatus, SOURCES};
use super::state::{MailOccurrence, MailPresence, MailReplyHeaders, OCCURRENCES};
use crate::channel_identity_provider::gmail::{
    GmailDelegatedAdapter, GmailReplyThread, GmailSendPlan, GmailSendSink, HttpGmailSendWire,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::derived_domains;
use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
    OutboundDispatchOutcome, OutboundDispatchRequest, OutboundIntent, OutboundIntentDraft,
    OutboundIntentTrigger,
};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault, source_audience};

/// Each drafted reply, by its draft id.
const DRAFTS: SideTable<EntityId, MailReplyDraftRow, Named> =
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
    source: EntityId,
    /// The thread's CONVERSATION.
    thread: EntityId,
    /// The TURN of the message it answers.
    parent_turn: EntityId,
    /// The delegated identity it sends through.
    identity: EntityId,
    /// Bumped by each changed draft under the same request key.
    revision: u64,
    /// The frozen Gmail send plan's content ref (`gmail:plan:v1:...`).
    plan_ref: String,
    /// The logical send this revision is: one per revision.
    send_ref: String,
    to: String,
    subject: String,
    body: String,
    /// Who drafted it; `None` once that actor was erased.
    drafted_by: Option<EntityId>,
    state: MailReplyDraftState,
    /// When the owner's approve-once proof for this revision was minted.
    approved_at: Option<u64>,
    /// What the last dispatch answered, for the reader.
    outcome: Option<String>,
    drafted_at: u64,
    updated_at: u64,
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
    /// The reply's plain text.
    pub body: String,
    /// The caller's key for this draft: the same key with the same body is
    /// the same draft; with another body, its next revision.
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
    pub to: String,
    pub subject: String,
    pub body: String,
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
    MailReplyDraftView {
        draft_ref: id.to_hex(),
        revision: row.revision,
        source_ref: row.source.to_hex(),
        thread_ref: row.thread.to_hex(),
        parent_turn_ref: row.parent_turn.to_hex(),
        to: row.to.clone(),
        subject: row.subject.clone(),
        body: row.body.clone(),
        plan_ref: row.plan_ref.clone(),
        state: row.state,
        outcome: row.outcome.clone(),
        drafted_at: row.drafted_at,
        updated_at: row.updated_at,
    }
}

/// The mailboxes of one address header value, a comma-separated list
/// (`Name <a@b>, c@d`): each one's bare address. Commas inside a quoted
/// display name or an angle address do not split it.
fn mailboxes(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let (mut start, mut quoted, mut angled) = (0, false, false);
    for (at, character) in text.char_indices() {
        match character {
            '"' if !angled => quoted = !quoted,
            '<' if !quoted => angled = true,
            '>' if !quoted => angled = false,
            ',' if !quoted && !angled => {
                parts.push(&text[start..at]);
                start = at + 1;
            }
            _ => {}
        }
    }
    parts.push(&text[start..]);
    parts
        .into_iter()
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| {
            let address = match (part.rfind('<'), part.rfind('>')) {
                (Some(open), Some(close)) if open < close => &part[open + 1..close],
                _ => part,
            };
            address.trim().to_owned()
        })
        .collect()
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

/// Whether `provider` is a Google mailbox this slice sends from.
const fn sends_google_mail(provider: MailProvider) -> bool {
    matches!(
        provider,
        MailProvider::GoogleWorkspace | MailProvider::Google
    )
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

/// The source `row` as one this slice replies from: an active Google
/// personal mailbox whose identity may send. Its identity.
fn sending_identity(row: &MailSourceRow) -> MemoryResult<EntityId> {
    if row.kind != MailSourceKind::PersonalMailbox {
        return Err(MemoryError::bad_request(
            "a drafted reply sends from a personal mailbox only; a group address needs its own approvers",
        ));
    }
    if !sends_google_mail(row.provider) {
        return Err(MemoryError::bad_request(
            "a drafted reply sends from a Google mailbox only for now",
        ));
    }
    if row.status != MailSourceStatus::Active {
        return Err(invalid_state("the mail source is not syncing"));
    }
    row.channel_identity.ok_or_else(|| {
        MemoryError::bad_request(
            "the mail source reads through no delegated identity that could send",
        )
    })
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

/// The plan a reply to `parent` sends: from the adapter's mailbox to the
/// parent's `Reply-To`, else its sender, threaded on the provider.
fn plan_for(
    adapter: &GmailDelegatedAdapter,
    send_ref: &str,
    parent: &MailReplyHeaders,
    body: &str,
    composed_at: u64,
) -> MemoryResult<GmailSendPlan> {
    let refuse = |message: &str| MemoryError::bad_request(message.to_owned());
    // The one mailbox a reply goes to: the Reply-To list, else the From
    // list, each exactly one address; more than one is refused, not cut.
    let named: Vec<String> = if parent.reply_to.is_empty() {
        parent.from.as_deref().map(mailboxes).unwrap_or_default()
    } else {
        parent
            .reply_to
            .iter()
            .flat_map(|entry| mailboxes(entry))
            .collect()
    };
    let to = match named.as_slice() {
        [only] if only.contains('@') => only.clone(),
        [] | [_] => return Err(refuse("the message names no address to reply to")),
        _ => {
            return Err(refuse(
                "the message names more than one address to reply to",
            ));
        }
    };
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
    GmailSendPlan::new(
        adapter,
        send_ref,
        &to,
        &subject,
        body,
        Some(thread),
        composed_at,
    )
    .map_err(|error| refuse(&error.to_string()))
}

/// The one dispatch request a draft's revision is, sent as `actor`, the
/// identity's bound sender.
fn request_for(
    id: EntityId,
    row: &MailReplyDraftRow,
    actor: EntityId,
    now: u64,
) -> OutboundDispatchRequest {
    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new(actor.to_hex(), "send", "email", row.to.clone())
            .content_ref(row.plan_ref.clone()),
        OutboundIntentTrigger::agent_immediate(format!("mail-reply:{}", id.to_hex())),
    );
    OutboundDispatchRequest::new(
        format!("outbound:{}", row.send_ref),
        row.send_ref.clone(),
        intent,
        OutboundDispatchActor::agent(actor),
        OutboundDispatchGate::allow_when_policy_grants(),
        now,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .channel_identity_ref(row.identity)
    .counterparty_ref(row.to.clone())
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
        let identity = sending_identity(&row)?;
        let adapter = adapter_of(vault, identity)?;
        let (parent_turn, parent) = parent_of(&messages, parent_turn)?;
        if let Some(prior) = &prior {
            if prior.state != MailReplyDraftState::Proposed {
                return Err(invalid_state(
                    "the draft was approved or discarded; draft under another request key",
                ));
            }
            if prior.body == input.body && prior.parent_turn == parent_turn {
                return Ok(view(id, prior));
            }
        }
        let revision = prior.as_ref().map_or(1, |prior| prior.revision + 1);
        let send_ref = format!("mail-reply:{}:{revision}", id.to_hex());
        let now = crate::unix_seconds_now();
        let plan = plan_for(&adapter, &send_ref, &parent, &input.body, now)?;
        plan.keep(vault)?;
        let row = MailReplyDraftRow {
            source,
            thread: conversation,
            parent_turn,
            identity,
            revision,
            plan_ref: plan.content_ref().to_owned(),
            send_ref,
            to: plan.recipient().to_owned(),
            subject: reply_subject(parent.subject.as_deref().unwrap_or_default()),
            body: input.body.clone(),
            drafted_by: Some(actor),
            state: MailReplyDraftState::Proposed,
            approved_at: None,
            outcome: None,
            drafted_at: prior.as_ref().map_or(now, |prior| prior.drafted_at),
            updated_at: now,
        };
        vault.with_write_txn_grouped(|txn| {
            // The draft lands only over exactly the row this call read, a
            // proposed one or none: a concurrent revision, approval or
            // discard wins.
            if DRAFTS.get(&vault.store, txn, &id)? != prior {
                return Err(crate::Error::InvalidConfig(
                    "the draft changed while it was redrafted".to_owned(),
                ));
            }
            DRAFTS.put(&vault.store, txn, &id, &row)
        })?;
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
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        super::pack::require_pack_active_in(vault, &txn)?;
        let mut drafts = Vec::new();
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
            if source_audience::actor_reads_in(vault, &txn, &thread, actor)? {
                drafts.push(view(id, &row));
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
            Ok(row)
        })?;
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
    /// The owner approves one revision of a drafted reply from their own
    /// mailbox, and it sends (FIX 15420). The approve-once proof for exactly
    /// that revision's frozen plan is minted with the draft's approval in one
    /// writer; then the common recorded dispatcher sends it through the
    /// mailbox's delegated identity, threaded on the provider. Approving it
    /// again after a held, failed or interrupted dispatch dispatches it
    /// again, and the ledger replays what it recorded rather than sending
    /// twice.
    ///
    /// # Errors
    ///
    /// The draft unknown, discarded, sent, of another revision or of a
    /// mailbox not the owner's; the mailbox unable to send; the dispatch
    /// refused.
    pub fn approve_mail_reply(
        &self,
        owner: &AuthenticatedOwner,
        input: &MailReplyApproveRequest,
    ) -> MemoryResult<MailReplyDraftView> {
        let id = EntityId::from_hex(&input.draft_ref)?;
        let unknown = || MemoryError::not_found("no reply draft by that ref");
        let actor = owner.revalidate(self)?;
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
        let identity = sending_identity(&source)?;
        if identity != row.identity {
            return Err(invalid_state(
                "the mailbox now sends through another identity; draft again",
            ));
        }
        let adapter = adapter_of(self, identity)?;
        // The reply goes out as the actor the identity is bound to (an agent
        // of the owner's, or the owner); the owner's proof is the approval.
        let sender = bound_sender(self, identity)?;
        let now = crate::unix_seconds_now();
        let request = request_for(id, &row, sender, now);
        let digest = crate::channel_identity_provider::native_mail::canonical_mail_send_digest(
            &request, identity, sender,
        )?;
        let row = self.try_with_write_txn_grouped(|txn| -> MemoryResult<MailReplyDraftRow> {
            // Every press, a retry too, proves the owner again in the writer
            // that acts, and finds the mailbox still theirs.
            if owner.revalidate_in_txn(self, txn)? != actor
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
            if held.approved_at.is_none() {
                self.approve_once_in_txn(txn, owner, digest)?;
                held.approved_at = Some(now);
                held.state = MailReplyDraftState::Approved;
                held.updated_at = now;
                DRAFTS.put(&self.store, txn, &id, &held)?;
            }
            Ok(held)
        })?;
        let wire = HttpGmailSendWire::new()?;
        let mut sink = GmailSendSink::new(self, &adapter, identity, wire);
        let answer = adapter.dispatch_send_recorded(self, request, &mut sink);
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
