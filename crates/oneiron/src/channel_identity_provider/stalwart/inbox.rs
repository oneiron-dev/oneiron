//! Authenticated JMAP reads, raw quarantine, then the mail ingress door.
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{StalwartClient, StalwartMailbox, array, invalid, method_result, string};
use crate::channel_identity_provider::mail_placement::{MailPlacement, PlacementPolicy};
use crate::channel_identity_provider::native_mail::{
    NativeMailAdapter, archive_native_mail_inbound, mailbox_local_part,
};
use crate::channel_identity_provider::{
    ChannelIdentityProviderAdapter, ChannelIdentityProviderInbound, EmailProviderInbound,
    EmailThreadHeaders,
};
use crate::limit_ask::EngineLimit;
use crate::surface_event::SurfaceEventAdmission;
use crate::{EntityId, Result, Vault};

const INBOX_PAGE_SIZE: usize = 100;

/// Host-owned progress. Persist only a successfully returned cursor. A mailbox,
/// instance or placement change invalidates it. A changed query resumes from
/// the server's changes since the cursor's state; a server that cannot
/// calculate them restarts safely through the durable SurfaceEvent dedupe
/// door.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StalwartInboxCursor {
    instance_ref: String,
    identity_ref: EntityId,
    placement_policy: PlacementPolicy,
    query_state: String,
    position: u64,
}

#[derive(Debug, Clone)]
pub struct StalwartInboxOutcome {
    pub admissions: Vec<SurfaceEventAdmission>,
    /// Where the next poll resumes; the end of the mailbox when this poll
    /// read to it, so the next poll reads only what changed. After a stop it
    /// names the stopped message, so every message before it keeps its
    /// progress.
    pub next_cursor: Option<StalwartInboxCursor>,
    /// Whether more mail waits after this page now: poll again from
    /// `next_cursor`.
    pub more: bool,
    /// The message this poll stopped at, or `None` when it read its page
    /// whole. Poll again later to retry it; the messages after it wait.
    pub stopped: Option<StalwartInboxStop>,
}

/// A cursor mapped onto the server's current query state.
struct InboxChanges {
    query_state: String,
    /// Every message before it was read.
    position: u64,
    total: Option<u64>,
}

/// One polled message that could not be quarantined or admitted, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StalwartInboxStop {
    /// The JMAP email id the server returned.
    pub message_id: String,
    pub reason: String,
}

/// Raw inbound bytes are host quarantine, not agent instructions. The host
/// retains this directory alongside its MTA; vault events carry references only.
#[derive(Debug, Clone)]
pub struct StalwartQuarantine {
    root: PathBuf,
}

impl StalwartQuarantine {
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        fs::create_dir_all(root.as_ref())?;
        Ok(Self {
            root: fs::canonicalize(root)?,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Streams one message's bytes into quarantine through `fill`, which
    /// writes them to the open file. A message already held under `digest`
    /// is not fetched again: a retried page reuses the bytes it captured.
    /// Only a whole, synced file takes the name. Returns the reference and
    /// whether this call wrote the file.
    fn capture_with(
        &self,
        digest: &str,
        fill: impl FnOnce(&mut fs::File) -> Result<u64>,
    ) -> Result<(String, bool)> {
        let reference = format!("native-mail:quarantine:{digest}");
        let path = self.root.join(format!("{digest}.eml"));
        if path.try_exists()? {
            return Ok((reference, false));
        }
        let mut file = tempfile::NamedTempFile::new_in(&self.root)?;
        fill(file.as_file_mut())?;
        file.as_file().sync_all()?;
        match file.persist_noclobber(path) {
            Ok(_) => {}
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.error.into()),
        }
        Ok((reference, true))
    }

    /// Free bytes on the filesystem that holds the quarantine, where the
    /// platform reports them.
    fn free_bytes(&self) -> Option<u64> {
        #[cfg(unix)]
        {
            rustix::fs::statvfs(self.root.as_path())
                .ok()
                .map(|stat| stat.f_bavail.saturating_mul(stat.f_frsize))
        }
        #[cfg(not(unix))]
        {
            None
        }
    }

    /// Resolve only a reference this quarantine format can have produced.
    pub fn read(&self, payload_ref: &str) -> Result<Vec<u8>> {
        let digest = payload_ref
            .strip_prefix("native-mail:quarantine:")
            .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| invalid("invalid native mail quarantine reference"))?;
        Ok(fs::read(self.root.join(format!("{digest}.eml")))?)
    }
}

impl StalwartClient {
    pub fn poll_inbox(
        &self,
        vault: &Vault,
        adapter: &NativeMailAdapter<StalwartClient>,
        identity_ref: EntityId,
        policy: PlacementPolicy,
        cursor: Option<&StalwartInboxCursor>,
        quarantine: &StalwartQuarantine,
        now: u64,
    ) -> Result<StalwartInboxOutcome> {
        vault.require_builtin_channel_pack("native_mail")?;
        // Channel and mailbox are the identity's facts (OF-272); whether it
        // is delegated is custody, on the local row.
        let identity = vault
            .get_channel_identity(&identity_ref)?
            .ok_or(crate::Error::EntityNotFound)?;
        let facts = vault
            .channel_identity_facts(&identity_ref)?
            .ok_or(crate::Error::EntityNotFound)?;
        // The identity's own address, derived or named, is its mailbox.
        if facts.channel != "email"
            || identity.is_delegated()
            || mailbox_local_part(&self.config.domain, identity_ref, &facts.address_or_handle)
                .is_err()
        {
            return Err(invalid(
                "native inbox identity differs from the instance mailbox",
            ));
        }
        let mailbox = self.mailbox(identity_ref, &facts.address_or_handle)?;
        let boxes = self.mailboxes(&mailbox)?;
        let role_ids = |role: &str| -> Vec<String> {
            boxes
                .iter()
                .filter(|row| row.get("role").and_then(Value::as_str) == Some(role))
                .filter_map(|row| row.get("id").and_then(Value::as_str).map(str::to_owned))
                .collect()
        };
        let inbox = role_ids("inbox");
        let junk = role_ids("junk");
        let trash = role_ids("trash");
        let excluded: Vec<_> = [role_ids("sent"), role_ids("drafts")]
            .into_iter()
            .flatten()
            .collect();
        let mut conditions = Vec::new();
        if policy == PlacementPolicy::InboxOnly {
            if inbox.len() != 1 {
                return Err(invalid("native mailbox lacks a unique inbox"));
            }
            conditions.push(json!({"inMailbox": &inbox[0]}));
        }
        for id in excluded.iter().chain(
            junk.iter()
                .chain(&trash)
                .filter(|_| policy != PlacementPolicy::EntireMailbox),
        ) {
            conditions.push(json!({"operator": "NOT", "conditions": [{"inMailbox": id}]}));
        }
        let filter = if conditions.is_empty() {
            Value::Null
        } else {
            json!({"operator": "AND", "conditions": conditions})
        };
        let binding = cursor.filter(|c| {
            c.instance_ref == self.config.instance_ref
                && c.identity_ref == identity_ref
                && c.placement_policy == policy
        });
        let sort = json!([{"property": "receivedAt", "isAscending": true}]);
        // A cursor resumes from its query state's changes; the full read
        // from position 0 is only for a first poll, a cursor for another
        // binding, or a server that cannot calculate the changes.
        let changes = match binding {
            Some(c) => self.query_changes(&mailbox.account_id, &filter, &sort, c)?,
            None => None,
        };
        if let Some(changes) = &changes
            && changes.total.is_some_and(|total| changes.position >= total)
        {
            return Ok(StalwartInboxOutcome {
                admissions: Vec::new(),
                next_cursor: Some(StalwartInboxCursor {
                    instance_ref: self.config.instance_ref.clone(),
                    identity_ref: mailbox.identity_ref,
                    placement_policy: policy,
                    query_state: changes.query_state.clone(),
                    position: changes.position,
                }),
                more: false,
                stopped: None,
            });
        }
        let query_page = |position| {
            self.call(
                "Email/query",
                json!({
                    "accountId": &mailbox.account_id, "filter": &filter, "sort": &sort,
                    "position": position, "limit": INBOX_PAGE_SIZE, "calculateTotal": true
                }),
            )
        };
        let mut position = changes.as_ref().map_or(0, |changes| changes.position);
        let mut query = query_page(position)?;
        // Mail that moved between the two calls leaves the mapped position
        // unproved, so the read starts over.
        if changes.as_ref().is_some_and(|changes| {
            query.get("queryState").and_then(Value::as_str) != Some(changes.query_state.as_str())
        }) {
            position = 0;
            query = query_page(0)?;
        }
        let query_state = string(&query, "queryState")?.to_owned();
        let ids = array(&query, "ids")?;
        if ids.len() > INBOX_PAGE_SIZE {
            return Err(invalid("native inbox page exceeds requested size"));
        }
        // Progress is per message: a message that fails stops the page
        // there, and the cursor resumes at it with every earlier message
        // kept. No byte cap stops one, since its bytes stream to disk.
        let mut admissions = Vec::new();
        let mut stopped = None;
        if !ids.is_empty() {
            let reply = self.call(
                "Email/get",
                json!({
                    "accountId": &mailbox.account_id, "ids": ids,
                    "properties": [
                        "id", "blobId", "mailboxIds", "from", "receivedAt",
                        "messageId", "inReplyTo", "references"
                    ]
                }),
            )?;
            let messages = array(&reply, "list")?;
            let read_one = |id: &str| -> Result<SurfaceEventAdmission> {
                let message = messages
                    .iter()
                    .find(|row| row.get("id").and_then(Value::as_str) == Some(id))
                    .ok_or_else(|| invalid("native inbox changed during page read; retry page"))?;
                let placements = message
                    .get("mailboxIds")
                    .and_then(Value::as_object)
                    .ok_or_else(|| invalid("native inbox message omitted mailbox placement"))?;
                let in_boxes = |ids: &[String]| {
                    ids.iter()
                        .any(|id| placements.get(id).and_then(Value::as_bool) == Some(true))
                };
                let placement = if in_boxes(&junk) {
                    MailPlacement::Spam
                } else if in_boxes(&trash) {
                    MailPlacement::Trash
                } else if in_boxes(&inbox) {
                    MailPlacement::Inbox
                } else {
                    MailPlacement::Archive
                };
                policy.require(placement)?;
                if in_boxes(&excluded) {
                    return Err(invalid("native inbox query returned an outgoing message"));
                }
                self.admit_message(vault, adapter, &mailbox, quarantine, message, id, now)
            };
            for id in ids {
                let id = id
                    .as_str()
                    .ok_or_else(|| invalid("invalid native inbox message id"))?;
                match read_one(id) {
                    Ok(admission) => admissions.push(admission),
                    Err(error) => {
                        stopped = Some(StalwartInboxStop {
                            message_id: id.to_owned(),
                            reason: error.to_string(),
                        });
                        break;
                    }
                }
            }
        }
        let read = admissions.len() as u64;
        let next_position = position.saturating_add(read);
        let total = query
            .get("total")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("native inbox query omitted its total"))?;
        Ok(StalwartInboxOutcome {
            admissions,
            next_cursor: Some(StalwartInboxCursor {
                instance_ref: self.config.instance_ref.clone(),
                identity_ref: mailbox.identity_ref,
                placement_policy: policy,
                query_state,
                position: next_position,
            }),
            more: stopped.is_none() && next_position < total && read > 0,
            stopped,
        })
    }

    /// Where `cursor` resumes under the server's current query state, from
    /// `Email/queryChanges` since the cursor's state, or `None` when the
    /// server answers `cannotCalculateChanges`.
    ///
    /// Every message before the cursor's position was read. A message in
    /// the current results is unread only if it was added since, or sat at
    /// or after that position; a message that stayed keeps its order, so it
    /// moves down by at most the removed count. The resume position is the
    /// lower of the first added index and the position less the removed
    /// count: every message before it was read, and one after it that was
    /// read already is admitted again through the dedupe door.
    fn query_changes(
        &self,
        account_id: &str,
        filter: &Value,
        sort: &Value,
        cursor: &StalwartInboxCursor,
    ) -> Result<Option<InboxChanges>> {
        let reply = self.raw_call(
            "Email/queryChanges",
            json!({
                "accountId": account_id, "filter": filter, "sort": sort,
                "sinceQueryState": &cursor.query_state, "calculateTotal": true
            }),
        )?;
        let refusal = array(&reply, "methodResponses")?
            .iter()
            .find(|row| row.get(2).and_then(Value::as_str) == Some("mail"))
            .filter(|row| row.get(0).and_then(Value::as_str) == Some("error"))
            .and_then(|row| row.pointer("/1/type"))
            .and_then(Value::as_str);
        if refusal == Some("cannotCalculateChanges") {
            return Ok(None);
        }
        let changes = method_result(&reply, "Email/queryChanges")?;
        let removed = array(changes, "removed")?.len() as u64;
        let mut first_added: Option<u64> = None;
        for row in array(changes, "added")? {
            let index = row
                .get("index")
                .and_then(Value::as_u64)
                .ok_or_else(|| invalid("native inbox change omitted its index"))?;
            first_added = Some(first_added.map_or(index, |first| first.min(index)));
        }
        let kept = cursor.position.saturating_sub(removed);
        Ok(Some(InboxChanges {
            query_state: string(changes, "newQueryState")?.to_owned(),
            position: first_added.map_or(kept, |first| kept.min(first)),
            total: changes.get("total").and_then(Value::as_u64),
        }))
    }

    /// Quarantines one listed message and hands it to the mail ingress door.
    /// Its bytes stream from the server into the quarantine file, so memory
    /// never holds the message whole; the vault keeps its metadata and
    /// quarantine reference as its provider event. A capture that leaves the quarantine's
    /// disk below `[limits] code_result_disk_floor_bytes` asks that row's
    /// question and keeps the message. Threading headers take it to its
    /// thread (`Vault::enqueue_inbound_email`); without them it takes the
    /// generic door.
    #[allow(clippy::too_many_arguments)]
    fn admit_message(
        &self,
        vault: &Vault,
        adapter: &NativeMailAdapter<StalwartClient>,
        mailbox: &StalwartMailbox,
        quarantine: &StalwartQuarantine,
        message: &Value,
        id: &str,
        now: u64,
    ) -> Result<SurfaceEventAdmission> {
        let blob = string(message, "blobId")?;
        let mut hasher = blake3::Hasher::new();
        for part in [
            self.config.instance_ref.as_str(),
            self.config.owner_ref.as_str(),
            mailbox.address.as_str(),
            id,
        ] {
            hasher.update(&(part.len() as u64).to_le_bytes());
            hasher.update(part.as_bytes());
        }
        let digest = hasher.finalize().to_hex().to_string();
        let (payload_ref, written) = quarantine.capture_with(&digest, |file| {
            self.download_blob_into(&mailbox.account_id, blob, file)
        })?;
        if written && let Some(free_bytes) = quarantine.free_bytes() {
            vault
                .limit_watch()
                .floor(EngineLimit::CodeResultDiskFloorBytes, free_bytes);
        }
        let received_at = chrono::DateTime::parse_from_rfc3339(string(message, "receivedAt")?)
            .map_err(|_| invalid("invalid native message receive time"))?
            .timestamp();
        let received_at =
            u64::try_from(received_at).map_err(|_| invalid("native message predates the epoch"))?;
        let sender = message
            .get("from")
            .and_then(Value::as_array)
            .and_then(|from| from.first())
            .and_then(|from| from.get("email"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let mut inbound = EmailProviderInbound::new(
            format!("stalwart:{digest}"),
            &mailbox.address,
            sender,
            received_at,
        )
        .with_payload_ref(payload_ref);
        inbound.thread_headers = thread_headers(message);
        archive_native_mail_inbound(vault, &mut inbound, now)?;
        let thread = inbound.thread_headers.clone();
        let input = adapter.parse_inbound(ChannelIdentityProviderInbound::Email(inbound))?;
        vault.enqueue_inbound_email(input, thread.as_ref(), now)
    }
}

/// The message's RFC 5322 threading headers as JMAP parsed them: `messageId`,
/// `inReplyTo` and `references` are each a msg-id list or null. A message
/// with no Message-ID has nothing to thread on. The first `In-Reply-To` id is
/// the parent; any further parent joins the references, which the passport
/// de-duplicates.
fn thread_headers(message: &Value) -> Option<EmailThreadHeaders> {
    let ids = |key: &str| -> Vec<String> {
        message
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    };
    let message_id = ids("messageId").into_iter().next()?;
    let mut references = ids("references");
    let mut parents = ids("inReplyTo").into_iter();
    let in_reply_to = parents.next();
    references.extend(parents);
    Some(EmailThreadHeaders::new(message_id, references, in_reply_to))
}
