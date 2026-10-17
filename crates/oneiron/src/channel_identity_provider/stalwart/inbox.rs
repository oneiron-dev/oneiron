//! Authenticated JMAP reads, raw quarantine, then the existing CID-6 door.
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{StalwartClient, array, invalid, string};
use crate::channel_identity_provider::mail_placement::{MailPlacement, PlacementPolicy};
use crate::channel_identity_provider::native_mail::NativeMailAdapter;
use crate::channel_identity_provider::{
    ChannelIdentityProviderAdapter, ChannelIdentityProviderInbound, EmailProviderInbound,
};
use crate::surface_event::SurfaceEventAdmission;
use crate::{EntityId, Result, Vault};

const INBOX_PAGE_SIZE: usize = 100;

/// Host-owned progress. Persist only a successfully returned cursor. A mailbox,
/// instance or placement change invalidates it; a changed query restarts safely
/// through the durable SurfaceEvent dedupe door.
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
    pub next_cursor: Option<StalwartInboxCursor>,
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

    fn capture(&self, digest: &str, raw: &[u8]) -> Result<String> {
        let path = self.root.join(format!("{digest}.eml"));
        let mut file = tempfile::NamedTempFile::new_in(&self.root)?;
        file.write_all(raw)?;
        file.as_file().sync_all()?;
        match file.persist_noclobber(path) {
            Ok(_) => {}
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.error.into()),
        }
        Ok(format!("native-mail:quarantine:{digest}"))
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
        let address = self.address_for_identity(identity_ref);
        if facts.channel != "email" || identity.is_delegated() || facts.address_or_handle != address
        {
            return Err(invalid(
                "native inbox identity differs from the instance mailbox",
            ));
        }
        let mailbox = self.mailbox(identity_ref)?;
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
        let mut position = binding.map_or(0, |c| c.position);
        let query_page = |position| {
            self.call(
                "Email/query",
                json!({
                    "accountId": &mailbox.account_id, "filter": &filter,
                    "sort": [{"property": "receivedAt", "isAscending": true}],
                    "position": position, "limit": INBOX_PAGE_SIZE, "calculateTotal": true
                }),
            )
        };
        let mut query = query_page(position)?;
        if binding.is_some_and(|c| {
            query.get("queryState").and_then(Value::as_str) != Some(c.query_state.as_str())
        }) {
            position = 0;
            query = query_page(0)?;
        }
        let query_state = string(&query, "queryState")?.to_owned();
        let ids = array(&query, "ids")?;
        if ids.len() > INBOX_PAGE_SIZE {
            return Err(invalid("native inbox page exceeds requested size"));
        }
        let mut admissions = Vec::new();
        if !ids.is_empty() {
            let reply = self.call(
                "Email/get",
                json!({
                    "accountId": &mailbox.account_id, "ids": ids,
                    "properties": ["id", "blobId", "mailboxIds", "from", "receivedAt"]
                }),
            )?;
            let messages = array(&reply, "list")?;
            for id in ids {
                let id = id
                    .as_str()
                    .ok_or_else(|| invalid("invalid native inbox message id"))?;
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
                let blob = string(message, "blobId")?;
                let raw = self.download_blob(&mailbox.account_id, blob)?;
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
                let payload_ref = quarantine.capture(&digest, &raw)?;
                let received_at =
                    chrono::DateTime::parse_from_rfc3339(string(message, "receivedAt")?)
                        .map_err(|_| invalid("invalid native message receive time"))?
                        .timestamp();
                let received_at = u64::try_from(received_at)
                    .map_err(|_| invalid("native message predates the epoch"))?;
                let sender = message
                    .get("from")
                    .and_then(Value::as_array)
                    .and_then(|from| from.first())
                    .and_then(|from| from.get("email"))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let inbound = EmailProviderInbound::new(
                    format!("stalwart:{digest}"),
                    &mailbox.address,
                    sender,
                    received_at,
                )
                .with_payload_ref(payload_ref);
                let input =
                    adapter.parse_inbound(ChannelIdentityProviderInbound::Email(inbound))?;
                admissions.push(vault.enqueue_inbound_surface_event(input, now)?);
            }
        }
        let next_position = position.saturating_add(ids.len() as u64);
        let total = query
            .get("total")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("native inbox query omitted its total"))?;
        let next_cursor =
            (next_position < total && !ids.is_empty()).then_some(StalwartInboxCursor {
                instance_ref: self.config.instance_ref.clone(),
                identity_ref: mailbox.identity_ref,
                placement_policy: policy,
                query_state,
                position: next_position,
            });
        Ok(StalwartInboxOutcome {
            admissions,
            next_cursor,
        })
    }
}
