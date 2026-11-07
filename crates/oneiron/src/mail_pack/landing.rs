//! Landing one provider message as evidence (FIX 12559 row 1): one
//! CONVERSATION per provider thread, one TURN per provider message, one
//! MESSAGE per revision (its headers first, then the whole message), born
//! through the imported witness, so the vault indexes and extracts it as
//! imported evidence and wakes no agent. In the same commit each row is
//! bound to its thread's source audience, so it reads to the source's people
//! alone from its first moment. Each row also carries the source-audience
//! obligation in its own bytes, stamped under the landing's proof (fix list
//! row 16256), so a read knows it for a source's row even where its binding
//! or its TURN has not arrived.

use rmpv::Value as Msgpack;
use serde_json::{Map, Value};

use super::source::{MailProvider, MailSourceRow, MailSourceStatus, SOURCES};
use super::state::{
    BODY_QUEUE, MailOccurrence, MailPresence, MailReplyHeaders, MailStage, OCCURRENCES, SYNC,
    THREAD_EPOCHS, body_queue_key, occurrence_key, owe_header_retirements_in_txn,
    record_occurrence_rows_in_txn, thread_hash,
};
use super::wire::{MailFull, MailHeaders};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::{EntityId, derived_domains};
use crate::memory::{
    IMPORTED_SOURCE_KEY, ImportedTurnStamp, MEMORY_CODE_INTERNAL, MEMORY_CODE_INVALID_STATE,
    Memory, MemoryError, MemoryResult, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use crate::{Result, Vault, source_audience};

/// The longest label a CONVERSATION body carries (a subject, a thread key).
const MAX_LABEL_BYTES: usize = 512;

/// The import source each provider's rows are stamped with: the Dreamer
/// reads what it extracts from them as imported evidence.
pub(super) const fn import_source(provider: MailProvider) -> &'static str {
    match provider {
        MailProvider::GoogleWorkspace => "mail.google_workspace",
        MailProvider::Google => "mail.google",
        MailProvider::Microsoft365 => "mail.microsoft365",
        MailProvider::Imap => "mail.imap",
        MailProvider::Caldav => "calendar.caldav",
        MailProvider::Ics => "calendar.ics",
    }
}

/// What one landing did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum LandOutcome {
    /// A new revision landed.
    Landed,
    /// The vault holds this revision already, or forgot the message.
    Same,
    /// The write door or a gate refused it; the import goes on.
    Refused(String),
}

/// What a landing that met `error` did: an engine fault fails it; any other
/// refusal is the landing's outcome, and the import goes on.
fn refused(error: MemoryError) -> MemoryResult<LandOutcome> {
    if error.code == MEMORY_CODE_INTERNAL {
        return Err(error);
    }
    Ok(LandOutcome::Refused(format!(
        "{}: {}",
        error.code.to_ascii_lowercase(),
        error.message
    )))
}

fn label(text: &str) -> String {
    if text.len() <= MAX_LABEL_BYTES {
        return text.to_owned();
    }
    let mut end = MAX_LABEL_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

fn derive(domain: &[u8], parts: &[&str]) -> Result<EntityId> {
    let parts: Vec<&[u8]> = parts.iter().map(|part| part.as_bytes()).collect();
    EntityId::derive(domain, &parts)
}

/// The CONVERSATION a thread's new message lands in: the thread's own, or
/// after its forgotten ones, the one of its current epoch.
fn conversation_of(source_hex: &str, thread_key: &str, epoch: u64) -> Result<EntityId> {
    if epoch == 0 {
        return derive(
            derived_domains::MAIL_CONVERSATION,
            &[source_hex, thread_key],
        );
    }
    let epoch = epoch.to_string();
    derive(
        derived_domains::MAIL_CONVERSATION,
        &[source_hex, thread_key, epoch.as_str()],
    )
}

/// The thread a message lands in: the provider's thread id, else the root
/// of its RFC reply chain, else the message alone.
pub(super) fn thread_key(headers: &MailHeaders) -> String {
    if let Some(thread) = headers.thread_id.as_deref().filter(|id| !id.is_empty()) {
        return format!("provider:{thread}");
    }
    if let Some(root) = headers
        .references
        .first()
        .or(headers.in_reply_to.as_ref())
        .or(headers.rfc_message_id.as_ref())
    {
        return format!("rfc:{root}");
    }
    format!("message:{}", headers.provider_id)
}

/// The words a revision's MESSAGE carries: its headers as lines, then its
/// body. Searching them finds the message by sender, recipients, subject and
/// text alike.
fn content(headers: &MailHeaders, body: Option<&str>) -> String {
    let mut lines = Vec::new();
    if let Some(from) = &headers.from {
        lines.push(format!("From: {from}"));
    }
    if !headers.to.is_empty() {
        lines.push(format!("To: {}", headers.to.join(", ")));
    }
    if !headers.cc.is_empty() {
        lines.push(format!("Cc: {}", headers.cc.join(", ")));
    }
    if let Some(subject) = &headers.subject {
        lines.push(format!("Subject: {subject}"));
    }
    let mut text = lines.join("\n");
    if let Some(body) = body.filter(|body| !body.trim().is_empty()) {
        text.push_str("\n\n");
        text.push_str(body);
    }
    text
}

/// A revision's provenance, as its MESSAGE metadata.
fn provenance(
    source_ref: EntityId,
    row: &MailSourceRow,
    headers: &MailHeaders,
    full: Option<&MailFull>,
    stage: MailStage,
) -> Value {
    let strings =
        |items: &[String]| Value::from(items.iter().map(|item| label(item)).collect::<Vec<_>>());
    let mut fields = Map::new();
    fields.insert("source".into(), Value::from(import_source(row.provider)));
    fields.insert("mail_source".into(), Value::from(source_ref.to_hex()));
    fields.insert("id".into(), Value::from(label(&headers.provider_id)));
    if let Some(thread) = &headers.thread_id {
        fields.insert("thread".into(), Value::from(label(thread)));
    }
    if let Some(id) = &headers.rfc_message_id {
        fields.insert("rfc_message_id".into(), Value::from(label(id)));
    }
    if let Some(parent) = &headers.in_reply_to {
        fields.insert("in_reply_to".into(), Value::from(label(parent)));
    }
    if !headers.references.is_empty() {
        fields.insert("references".into(), strings(&headers.references));
    }
    if let Some(from) = &headers.from {
        fields.insert("from".into(), Value::from(label(from)));
    }
    fields.insert("to".into(), strings(&headers.to));
    if !headers.cc.is_empty() {
        fields.insert("cc".into(), strings(&headers.cc));
    }
    if let Some(subject) = &headers.subject {
        fields.insert("subject".into(), Value::from(label(subject)));
    }
    if let Some(date) = headers.date {
        fields.insert("date".into(), Value::from(date));
    }
    fields.insert("received_at".into(), Value::from(headers.received_at));
    fields.insert("labels".into(), strings(&headers.labels));
    fields.insert(
        "sent_by_mailbox".into(),
        Value::from(headers.sent_by_mailbox),
    );
    fields.insert(
        "stage".into(),
        Value::from(match stage {
            MailStage::Headers => "headers",
            MailStage::Body => "body",
        }),
    );
    if let Some(full) = full
        && !full.attachments.is_empty()
    {
        fields.insert(
            "attachments".into(),
            serde_json::to_value(&full.attachments).unwrap_or(Value::Null),
        );
    }
    Value::Object(fields)
}

/// The CONVERSATION body of a mail thread: its import stamp, its thread
/// key and, from its first message, its subject.
fn conversation_body(
    source: &'static str,
    thread_key: &str,
    subject: Option<&str>,
) -> MemoryResult<Vec<u8>> {
    let mut fields = vec![
        (Msgpack::from(IMPORTED_SOURCE_KEY), Msgpack::from(source)),
        (
            Msgpack::from("import_conversation"),
            Msgpack::from(label(thread_key)),
        ),
        (Msgpack::from("import_kind"), Msgpack::from("mail_thread")),
    ];
    if let Some(subject) = subject.filter(|subject| !subject.is_empty()) {
        fields.push((Msgpack::from("title"), Msgpack::from(label(subject))));
    }
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Msgpack::Map(fields))
        .map_err(|_| MemoryError::bad_request("a mail thread's body is not encodable"))?;
    Ok(out)
}

/// One source's landings, under the vault owner's write authority. The
/// owner's authority lands the rows; it does not read them: each is bound to
/// its source's audience in the commit that lands it.
pub(super) struct Landing<'v> {
    vault: &'v Vault,
    owner: &'v AuthenticatedOwner,
    memory: Memory<'v>,
    actor: EntityId,
    source_ref: EntityId,
    imported_at: u64,
}

impl<'v> Landing<'v> {
    /// The actor the landings are written as.
    pub(super) const fn actor(&self) -> EntityId {
        self.actor
    }

    pub(super) fn new(
        vault: &'v Vault,
        owner: &'v AuthenticatedOwner,
        source_ref: EntityId,
        imported_at: u64,
    ) -> MemoryResult<Self> {
        let actor = owner.revalidate(vault)?;
        Ok(Self {
            vault,
            owner,
            memory: vault.memory(actor, EdgeActorClass::Human),
            actor,
            source_ref,
            imported_at,
        })
    }

    /// Lands `headers`, or the whole message `full`, as the next revision of
    /// its provider message, unless the vault holds that revision already or
    /// forgot the message. A message a search fetched stays kept.
    pub(super) fn land(
        &self,
        row: &MailSourceRow,
        headers: &MailHeaders,
        full: Option<&MailFull>,
        searched: bool,
    ) -> MemoryResult<LandOutcome> {
        let vault = self.vault;
        let source = self.source_ref;
        let source_hex = source.to_hex();
        let stamp_source = import_source(row.provider);
        let stage = if full.is_some() {
            MailStage::Body
        } else {
            MailStage::Headers
        };
        let thread_key = thread_key(headers);
        let text = content(headers, full.and_then(|full| full.body_text.as_deref()));
        let hash = blake3::hash(text.as_bytes()).to_hex().to_string();
        let key = occurrence_key(source, &headers.provider_id);
        let epoch_key = (source, thread_hash(&thread_key));
        let (prior, order, epoch, birth) = {
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            let epoch = THREAD_EPOCHS
                .get(&vault.store, &txn, &epoch_key)?
                .unwrap_or(0);
            let prior = OCCURRENCES.get(&vault.store, &txn, &key)?;
            if let Some(prior) = &prior
                && matches!(prior.presence, MailPresence::Forgotten { .. })
            {
                return Ok(LandOutcome::Same);
            }
            if let Some(prior) = &prior
                && prior.content_hashes.contains(&hash)
            {
                drop(txn);
                // The same words with the whole message read: the body stage
                // and its attachments land on the occurrence, no new revision.
                if let Some(full) = full {
                    self.settle_full_in_place(&key, full)?;
                }
                return Ok(LandOutcome::Same);
            }
            let turn = prior.as_ref().map_or(
                derive(
                    derived_domains::MAIL_TURN,
                    &[&source_hex, &headers.provider_id],
                ),
                |prior| Ok(prior.turn),
            )?;
            let order = crate::memory::next_witness_message_order(&vault.store, &txn, &turn)?;
            // The landing's proof, under the mailbox's source policy: every
            // row it lands is stamped with the source-audience obligation
            // (fix list row 16256). The writer mints it again below.
            let birth =
                match source_audience::SourceAudienceBirth::mint_in(vault, &txn, &row.audience) {
                    Ok(birth) => birth,
                    Err(error) => return refused(error.into()),
                };
            (prior, order, epoch, birth)
        };
        let conversation = match &prior {
            Some(prior) => prior.conversation,
            None => conversation_of(&source_hex, &thread_key, epoch)?,
        };
        let turn = match &prior {
            Some(prior) => prior.turn,
            None => derive(
                derived_domains::MAIL_TURN,
                &[&source_hex, &headers.provider_id],
            )?,
        };
        let message = derive(
            derived_domains::MAIL_MESSAGE,
            &[&source_hex, &headers.provider_id, &hash],
        )?;
        let occurred = headers.date.unwrap_or(headers.received_at);
        let witness = WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: format!("import.{stamp_source}"),
                content: text,
                parts: None,
                metadata: Some(provenance(source, row, headers, full, stage)),
                is_visible: true,
                order: u32::try_from(order).unwrap_or(u32::MAX),
                quote: None,
            }],
            occurred_at: occurred,
            assertions: Default::default(),
        };
        let stamp = ImportedTurnStamp {
            source: stamp_source,
            imported_at: self.imported_at,
            conversation_body: conversation_body(
                stamp_source,
                &prior
                    .as_ref()
                    .map_or(thread_key.clone(), |prior| prior.thread_key.clone()),
                headers.subject.as_deref(),
            )?,
            message_occurred: vec![occurred],
            source_audience: Some(birth),
        };
        let landed = self.memory.witness_imported(&witness, &stamp, |wtxn| {
            self.owner.revalidate_in_txn(vault, wtxn)?;
            let current = SOURCES
                .get(&vault.store, wtxn, &source)?
                .filter(|current| current.status == MailSourceStatus::Active)
                .ok_or_else(|| {
                    MemoryError::new(
                        MEMORY_CODE_INVALID_STATE,
                        "the mail source is not syncing",
                        &[],
                    )
                })?;
            // Another landing of this message since the read above goes
            // first; this one reads what it left on its next pass.
            if OCCURRENCES.get(&vault.store, wtxn, &key)? != prior {
                return Err(MemoryError::new(
                    MEMORY_CODE_INVALID_STATE,
                    "another landing wrote this message first",
                    &[],
                ));
            }
            // A forget that took the thread's CONVERSATION since the read
            // above moved the thread on: the message lands in its new one at
            // the next step, never in the one being forgotten.
            if prior.is_none()
                && THREAD_EPOCHS
                    .get(&vault.store, wtxn, &epoch_key)?
                    .unwrap_or(0)
                    != epoch
            {
                return Err(MemoryError::new(
                    MEMORY_CODE_INTERNAL,
                    "the thread was forgotten meanwhile; the message lands at the next step",
                    &[],
                ));
            }
            // The proof the rows were stamped under is the one this writer
            // mints from the mailbox's live source policy.
            let minted =
                source_audience::SourceAudienceBirth::mint_in(vault, wtxn, &current.audience)?;
            if stamp.source_audience.as_ref() != Some(&minted) {
                return Err(MemoryError::new(
                    MEMORY_CODE_INVALID_STATE,
                    "the mail source's audience is not the one its rows were stamped under",
                    &[],
                ));
            }
            let thread_ref = prior
                .as_ref()
                .map_or(thread_key.as_str(), |prior| prior.thread_key.as_str());
            let policy = source_audience::thread_policy_in_txn(
                vault,
                wtxn,
                &current.audience,
                thread_ref,
                self.actor,
                self.imported_at,
            )?;
            for record in [conversation, turn, message] {
                source_audience::bind_record_in_txn(vault, wtxn, &record, &policy)?;
            }
            let mut occurrence = prior.clone().unwrap_or_else(|| MailOccurrence {
                provider_id: headers.provider_id.clone(),
                thread_key: thread_key.clone(),
                conversation,
                turn,
                messages: Vec::new(),
                content_hashes: Vec::new(),
                stage,
                presence: MailPresence::Present,
                labels: Vec::new(),
                rfc_message_id: None,
                from: None,
                subject: None,
                received_at: headers.received_at,
                searched,
                attachments: Vec::new(),
                reply: None,
                listed_in: None,
                content_digest: None,
                landed_at: self.imported_at,
                updated_at: self.imported_at,
            });
            // The body supersedes the header-only revisions before it (FIX
            // 15413): they leave the message's erase reach, so their delete
            // does not forget it, and are owed that delete, which runs once
            // this landing commits.
            if stage == MailStage::Body && occurrence.stage == MailStage::Headers {
                owe_header_retirements_in_txn(
                    vault,
                    wtxn,
                    &key,
                    &occurrence.messages,
                    self.imported_at,
                )?;
            }
            occurrence.messages.push(message);
            occurrence.content_hashes.push(hash.clone());
            if stage == MailStage::Body || occurrence.stage == MailStage::Headers {
                occurrence.stage = stage;
            }
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
            occurrence.searched |= searched;
            if let Some(full) = full {
                occurrence.attachments.clone_from(&full.attachments);
                // The first whole read names what the id holds (fix list
                // row 19145).
                occurrence.content_digest = occurrence.content_digest.or(full.content_digest);
            }
            occurrence.reply = Some(MailReplyHeaders::of(headers));
            occurrence.updated_at = self.imported_at;
            let queued = body_queue_key(source, occurrence.received_at, &headers.provider_id);
            if occurrence.stage == MailStage::Headers {
                BODY_QUEUE.put(&vault.store, wtxn, &queued, &headers.provider_id)?;
            } else {
                BODY_QUEUE.delete(&vault.store, wtxn, &queued)?;
            }
            let mut sync = SYNC.get(&vault.store, wtxn, &source)?.unwrap_or_default();
            if prior.is_none() {
                sync.landed += 1;
            }
            if stage == MailStage::Body {
                sync.bodies += 1;
            }
            SYNC.put(&vault.store, wtxn, &source, &sync)?;
            OCCURRENCES.put(&vault.store, wtxn, &key, &occurrence)?;
            record_occurrence_rows_in_txn(
                vault,
                wtxn,
                &key,
                &[conversation, turn, message],
                self.imported_at,
            )?;
            Ok(())
        });
        match landed {
            Ok(_) => {
                super::header_retire::retire_superseded_headers(vault, source);
                Ok(LandOutcome::Landed)
            }
            Err(error) => refused(error),
        }
    }

    /// Takes a message whose body was refused off the body queue, so the
    /// import does not ask for it again: it stays searchable by its headers.
    pub(super) fn drop_from_body_queue(&self, provider_id: &str) -> Result<()> {
        let vault = self.vault;
        let source = self.source_ref;
        vault.with_write_txn_grouped(|txn| {
            let key = occurrence_key(source, provider_id);
            if let Some(occurrence) = OCCURRENCES.get(&vault.store, txn, &key)? {
                BODY_QUEUE.delete(
                    &vault.store,
                    txn,
                    &body_queue_key(source, occurrence.received_at, provider_id),
                )?;
            }
            Ok(())
        })
    }
}

impl Landing<'_> {
    /// Records that the occurrence `key` was read whole when its words are
    /// those it landed with already: its stage is the body, it keeps the
    /// message's attachments and the digest of its first whole read, and it
    /// leaves the body queue.
    fn settle_full_in_place(
        &self,
        key: &(EntityId, [u8; 32]),
        full: &MailFull,
    ) -> MemoryResult<()> {
        let vault = self.vault;
        vault.with_write_txn_grouped(|wtxn| {
            let Some(mut occurrence) = OCCURRENCES.get(&vault.store, wtxn, key)? else {
                return Ok(());
            };
            // A message erased meanwhile stays forgotten: its fence is not
            // given its attachments again.
            if matches!(occurrence.presence, MailPresence::Forgotten { .. }) {
                return Ok(());
            }
            let digest = occurrence.content_digest.or(full.content_digest);
            if occurrence.stage == MailStage::Body
                && occurrence.attachments == full.attachments
                && occurrence.content_digest == digest
            {
                return Ok(());
            }
            let first_body = occurrence.stage == MailStage::Headers;
            occurrence.stage = MailStage::Body;
            occurrence.attachments.clone_from(&full.attachments);
            occurrence.content_digest = digest;
            occurrence.updated_at = self.imported_at;
            BODY_QUEUE.delete(
                &vault.store,
                wtxn,
                &body_queue_key(key.0, occurrence.received_at, &occurrence.provider_id),
            )?;
            if first_body {
                let mut sync = SYNC.get(&vault.store, wtxn, &key.0)?.unwrap_or_default();
                sync.bodies += 1;
                SYNC.put(&vault.store, wtxn, &key.0, &sync)?;
            }
            OCCURRENCES.put(&vault.store, wtxn, key, &occurrence)
        })?;
        Ok(())
    }
}
