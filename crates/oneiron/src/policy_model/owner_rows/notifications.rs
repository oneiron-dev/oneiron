//! Manifest-authored notification rules and recipient-owned delivery preferences.
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::ops::Bound;

use super::{
    authority,
    ledger::{PolicyChangedEvent, PolicyRowReceipt},
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::gate::{PolicyRowScope, default_policy_manifest_id};
use crate::{EntityId, Vault};

const RULE_KEY: &str = crate::gate::POLICY_OWNER_POLICY_NOTIFY_KEY;
const PREF: &[u8] = b"owner_policy:notification:preference:v1:";
pub(super) const QUEUED: &[u8] = b"owner_policy:notification:queued:v1:";
const QUEUE_CURSOR: &[u8] = b"owner_policy:notification:cursor:v1";
const QUEUE_FAILURE: &[u8] = b"owner_policy:notification:failure:v1:";
const DIGEST_WINDOW: &[u8] = b"owner_policy:notification:digest_window:v1:";
const DIGEST_RECIPIENT: &[u8] = b"owner_policy:notification:digest_recipient:v1:";
const DIGEST_BATCH_LIMIT: usize = 64;
const MAX_DIGEST_INTERVAL: u64 = 31_536_000;
const RULE_RECEIPT: &[u8] = b"owner_policy:notification:rule_receipt:v1:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyNotificationRule {
    PushOtherHolders,
    LogOnly,
}
impl PolicyNotificationRule {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PushOtherHolders => "push_other_holders",
            Self::LogOnly => "log_only",
        }
    }
    fn parse(text: &str) -> Result<Self> {
        match text {
            "push_other_holders" => Ok(Self::PushOtherHolders),
            "log_only" => Ok(Self::LogOnly),
            _ => Err(invalid()),
        }
    }
}

/// The manifest rule being edited; no fabricated world/project scope is used
/// for an all-overrides rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyNotificationTarget {
    VaultDefault,
    AllOverrides,
}
impl PolicyNotificationTarget {
    const fn row_scope(self) -> &'static str {
        match self {
            Self::VaultDefault => "vault",
            Self::AllOverrides => "override",
        }
    }
    const fn grant_target(self) -> &'static str {
        match self {
            Self::VaultDefault => "policy-notification:vault-default",
            Self::AllOverrides => "policy-notification:all-overrides",
        }
    }
}

/// Recipient-owned delivery override. Absence inherits the manifest rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyNotificationMode {
    Inherit,
    PushAll,
    Digest,
    LogOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyQueuedNotification {
    pub receipt_id: String,
    pub recipient: String,
    pub author: String,
    /// Exact source policy scope and grant target, revalidated before delivery.
    pub scope: PolicyRowScope,
    pub grant_target: String,
    pub mode: PolicyNotificationMode,
    pub followup_task: Option<String>,
    /// Digest window shared by all pending changes for this recipient.
    #[serde(default)]
    pub digest_due_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyNotificationFailure {
    pub receipt_id: String,
    pub recipient: String,
    pub attempts: u64,
    pub last_attempt_at: u64,
    pub next_retry_at: u64,
    pub last_error_kind: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NotificationPreference {
    mode: PolicyNotificationMode,
    digest_interval_seconds: Option<u64>,
}

fn invalid() -> Error {
    Error::InvalidConfig("invalid owner policy notification row".to_owned())
}
fn key(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    [prefix, suffix].concat()
}
fn failure_key(queue_key: &[u8]) -> Vec<u8> {
    key(QUEUE_FAILURE, &queue_key[QUEUED.len()..])
}
fn digest_recipient_prefix(recipient: EntityId) -> Vec<u8> {
    [DIGEST_RECIPIENT, recipient.as_bytes(), b":"].concat()
}
fn digest_recipient_key(recipient: EntityId, due: u64, receipt_id: &str) -> Vec<u8> {
    [
        digest_recipient_prefix(recipient).as_slice(),
        &due.to_be_bytes(),
        b":",
        receipt_id.as_bytes(),
    ]
    .concat()
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value)
        .map_err(|_| Error::InvariantViolation("policy notification encode"))
}
fn decode<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T> {
    rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("policy notification"))
}
fn field<'a>(entries: &'a [(Value, Value)], name: &str) -> Result<&'a Value> {
    let mut found = entries.iter().filter(|(key, _)| key.as_str() == Some(name));
    let value = &found.next().ok_or_else(invalid)?.1;
    if found.next().is_some() {
        return Err(invalid());
    }
    Ok(value)
}
fn manifest_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<(EntityId, Vec<u8>, Value)> {
    let id = default_policy_manifest_id()?;
    let raw = vault
        .store
        .entities
        .get(txn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("policy manifest header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_POLICY_MANIFEST {
        return Err(invalid());
    }
    let bytes = raw.get(ENTITY_METADATA_HEADER_LEN..).ok_or(invalid())?;
    if !crate::gate::manifest_authenticity::manifest_is_trusted(&vault.store, txn, &id, bytes)? {
        return Err(invalid());
    }
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid());
    }
    Ok((id, bytes.to_vec(), value))
}
pub(super) fn read_rule_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    vault_scope: bool,
) -> Result<(PolicyNotificationRule, u64)> {
    let (_, _, value) = manifest_in(vault, txn)?;
    let Value::Map(entries) = value else {
        return Err(invalid());
    };
    let Value::Array(rows) = field(&entries, RULE_KEY)? else {
        return Err(invalid());
    };
    let scope = if vault_scope { "vault" } else { "override" };
    let mut found = None;
    for row in rows {
        let Value::Map(fields) = row else {
            return Err(invalid());
        };
        let name = field(fields, "scope")?.as_str().ok_or_else(invalid)?;
        let value = field(fields, "delivery")?.as_str().ok_or_else(invalid)?;
        let interval = field(fields, "digest_interval_seconds")?
            .as_u64()
            .filter(|seconds| (1..=MAX_DIGEST_INTERVAL).contains(seconds))
            .ok_or_else(invalid)?;
        if name == scope
            && found
                .replace((PolicyNotificationRule::parse(value)?, interval))
                .is_some()
        {
            return Err(invalid());
        }
    }
    found.ok_or_else(invalid)
}
fn preference_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    recipient: EntityId,
) -> Result<NotificationPreference> {
    vault
        .store
        .vault_meta
        .get(txn, &key(PREF, recipient.as_bytes()))?
        .map(|raw| decode(&raw))
        .transpose()
        .map(|v| {
            v.unwrap_or(NotificationPreference {
                mode: PolicyNotificationMode::Inherit,
                digest_interval_seconds: None,
            })
        })
}

pub(super) fn enqueue_change_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    receipt: &PolicyRowReceipt,
    holders: &[EntityId],
    now: u64,
) -> Result<()> {
    let vault_scope = matches!(receipt.change.scope(), PolicyRowScope::Vault);
    let (rule, manifest_interval) = read_rule_in(vault, txn, vault_scope)?;
    for recipient in holders.iter().copied() {
        if recipient.to_hex() == receipt.author {
            continue;
        }
        let preference = preference_in(vault, txn, recipient)?;
        let mode = match preference.mode {
            PolicyNotificationMode::Inherit => match rule {
                PolicyNotificationRule::PushOtherHolders => PolicyNotificationMode::PushAll,
                PolicyNotificationRule::LogOnly => PolicyNotificationMode::LogOnly,
            },
            other => other,
        };
        if mode == PolicyNotificationMode::LogOnly {
            continue;
        }
        // Queue atomically with the policy change. Delivery is a separate
        // fallible pass: an offline holder or absent contact route must never
        // veto a holder's policy edit.
        let digest_due_at = if mode == PolicyNotificationMode::Digest {
            let window_key = key(DIGEST_WINDOW, recipient.as_bytes());
            if let Some(raw) = vault.store.vault_meta.get(txn, &window_key)? {
                Some(u64::from_be_bytes(raw.as_ref().try_into().map_err(
                    |_| Error::CorruptedIndex("policy digest window"),
                )?))
            } else {
                let interval = preference
                    .digest_interval_seconds
                    .unwrap_or(manifest_interval);
                let due = now.saturating_add(interval);
                vault
                    .store
                    .vault_meta
                    .put(txn, &window_key, &due.to_be_bytes())?;
                Some(due)
            }
        } else {
            None
        };
        let entry = PolicyQueuedNotification {
            receipt_id: receipt.receipt_id.clone(),
            recipient: recipient.to_hex(),
            author: receipt.author.clone(),
            scope: receipt.change.scope().clone(),
            grant_target: super::policy_row_grant_target(
                receipt.change.scope(),
                receipt.change.row_ref(),
            ),
            mode,
            followup_task: None,
            digest_due_at,
        };
        let storage_key = key(
            QUEUED,
            format!("{}:{}", receipt.receipt_id, recipient.to_hex()).as_bytes(),
        );
        vault
            .store
            .vault_meta
            .put(txn, &storage_key, &encode(&entry)?)?;
        if let Some(due) = digest_due_at {
            vault.store.vault_meta.put(
                txn,
                &digest_recipient_key(recipient, due, &entry.receipt_id),
                &storage_key,
            )?;
        }
    }
    Ok(())
}

impl Vault {
    /// Recipient's own dial, bound to the authenticated human actor.
    pub fn set_policy_notification_mode(
        &self,
        actor: &AuthenticatedOwner,
        mode: PolicyNotificationMode,
    ) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        actor.revalidate_in_txn(self, &txn)?;
        let mut preference = preference_in(self, &txn, actor.actor())?;
        preference.mode = mode;
        self.store.vault_meta.put(
            &mut txn,
            &key(PREF, actor.actor().as_bytes()),
            &encode(&preference)?,
        )?;
        txn.commit()?;
        Ok(())
    }

    /// Recipient-owned cadence override; absent uses the selected manifest row.
    /// An open digest window keeps its original due time when this dial changes.
    pub fn set_policy_notification_digest_interval(
        &self,
        actor: &AuthenticatedOwner,
        interval_seconds: Option<u64>,
    ) -> Result<()> {
        if interval_seconds.is_some_and(|n| !(1..=MAX_DIGEST_INTERVAL).contains(&n)) {
            return Err(invalid());
        }
        let mut txn = self.store.env.write_txn()?;
        actor.revalidate_in_txn(self, &txn)?;
        let mut preference = preference_in(self, &txn, actor.actor())?;
        preference.digest_interval_seconds = interval_seconds;
        self.store.vault_meta.put(
            &mut txn,
            &key(PREF, actor.actor().as_bytes()),
            &encode(&preference)?,
        )?;
        txn.commit()?;
        Ok(())
    }

    /// What was durably queued for holders; delivery itself uses the human follow-up driver.
    pub fn policy_queued_notifications(&self) -> Result<Vec<PolicyQueuedNotification>> {
        let txn = self.store.env.read_txn()?;
        let mut rows = Vec::new();
        for entry in self.store.vault_meta.prefix_iter(&txn, QUEUED)? {
            let (_, value) = entry?;
            rows.push(decode(&value)?);
        }
        Ok(rows)
    }

    /// Durable retry records, including rows with no current contact route.
    pub fn policy_notification_failures(&self) -> Result<Vec<PolicyNotificationFailure>> {
        let txn = self.store.env.read_txn()?;
        let mut failures = Vec::new();
        for entry in self.store.vault_meta.prefix_iter(&txn, QUEUE_FAILURE)? {
            let (_, raw) = entry?;
            failures.push(decode(&raw)?);
        }
        Ok(failures)
    }

    /// Inspect at most `limit` queue positions, not just `limit` successes.
    /// The persisted round-robin cursor advances on every inspected position,
    /// so old unreachable holders cannot starve later entries after a restart.
    /// Each TASK and its queue links commit together; one bad author rolls back
    /// only that TASK attempt and persists a separate retry receipt.
    pub fn drive_policy_notification_queue(&self, now: u64, limit: usize) -> Result<usize> {
        if limit == 0 {
            return Ok(0);
        }
        let (selected, failure_retry) = {
            let txn = self.store.env.read_txn()?;
            let cursor = self
                .store
                .vault_meta
                .get(&txn, QUEUE_CURSOR)?
                .map(|raw| raw.to_vec());
            // Seek from the durable cursor, reading only the next bounded
            // page. A second bounded range wraps once when the end is reached.
            // Never materialize the entire queue just to find page N.
            let mut upper = QUEUED.to_vec();
            *upper.last_mut().expect("nonempty prefix") += 1;
            let mut selected = Vec::with_capacity(limit.min(64));
            let lower: Bound<&[u8]> = match cursor.as_deref() {
                Some(key) if key.starts_with(QUEUED) => Bound::Excluded(key),
                Some(_) => return Err(Error::CorruptedIndex("policy notification cursor")),
                None => Bound::Included(QUEUED),
            };
            for entry in self
                .store
                .vault_meta
                .range(&txn, &(lower, Bound::Excluded(upper.as_slice())))?
            {
                let (key, _) = entry?;
                selected.push(key.to_vec());
                if selected.len() == limit {
                    break;
                }
            }
            if selected.len() < limit
                && let Some(end) = cursor.as_ref()
            {
                for entry in self.store.vault_meta.range(
                    &txn,
                    &(Bound::Included(QUEUED), Bound::Included(end.as_slice())),
                )? {
                    let (key, _) = entry?;
                    selected.push(key.to_vec());
                    if selected.len() == limit {
                        break;
                    }
                }
            }
            let mut failure_retry = BTreeMap::new();
            for key in &selected {
                if let Some(raw) = self.store.vault_meta.get(&txn, &failure_key(key))? {
                    let state: PolicyNotificationFailure = decode(&raw)?;
                    failure_retry.insert(key.clone(), state.next_retry_at);
                }
            }
            (selected, failure_retry)
        };
        let mut linked = 0;
        let mut processed_digests = BTreeSet::new();
        for key in selected {
            // Cursor advancement is independent of the TASK transaction.
            self.with_write_txn(|txn| self.store.vault_meta.put(txn, QUEUE_CURSOR, &key))?;
            if failure_retry.get(&key).is_some_and(|retry| *retry > now) {
                continue;
            }
            let row = {
                let txn = self.store.env.read_txn()?;
                self.store
                    .vault_meta
                    .get(&txn, &key)?
                    .map(|raw| decode::<PolicyQueuedNotification>(&raw))
                    .transpose()
            };
            let row = match row {
                Ok(Some(row)) => row,
                Ok(None) => continue,
                Err(error) => return Err(error),
            };
            if row.followup_task.is_some() || row.mode == PolicyNotificationMode::LogOnly {
                continue;
            }
            if row.mode == PolicyNotificationMode::Digest
                && (!processed_digests.insert(row.recipient.clone())
                    || row.digest_due_at.is_none_or(|due| due > now))
            {
                continue;
            }
            match self.link_notification_in_txn(&key, &row, now) {
                Ok(count) => linked += count,
                Err(error)
                    if matches!(
                        error,
                        Error::Storage(_)
                            | Error::CorruptedIndex(_)
                            | Error::InvariantViolation(_)
                            | Error::MapFull
                    ) =>
                {
                    return Err(error);
                }
                Err(error) => self.record_notification_failure(&key, Some(&row), now, &error)?,
            }
        }
        Ok(linked)
    }

    fn record_notification_failure(
        &self,
        key: &[u8],
        row: Option<&PolicyQueuedNotification>,
        now: u64,
        error: &Error,
    ) -> Result<()> {
        self.with_write_txn(|txn| {
            let failure_key = failure_key(key);
            let prior: Option<PolicyNotificationFailure> = self
                .store
                .vault_meta
                .get(txn, &failure_key)?
                .map(|raw| decode(&raw))
                .transpose()?;
            let failure = PolicyNotificationFailure {
                receipt_id: row
                    .map_or_else(|| String::from("undecodable"), |row| row.receipt_id.clone()),
                recipient: row
                    .map_or_else(|| String::from("undecodable"), |row| row.recipient.clone()),
                attempts: prior.map_or(1, |old| old.attempts.saturating_add(1)),
                last_attempt_at: now,
                next_retry_at: now.saturating_add(60),
                last_error_kind: format!("{:?}", error.kind()),
            };
            self.store
                .vault_meta
                .put(txn, &failure_key, &encode(&failure)?)?;
            Ok(())
        })
    }

    fn link_notification_in_txn(
        &self,
        queue_key: &[u8],
        row: &PolicyQueuedNotification,
        now: u64,
    ) -> Result<usize> {
        let mut txn = self.store.env.write_txn()?;
        let recipient = EntityId::from_hex(&row.recipient)?;
        let live_holders =
            authority::holders_for_in_txn(self, &txn, now, &row.scope, &row.grant_target)?;
        if !live_holders.contains(&recipient) {
            return Err(invalid());
        }
        crate::human_task::resolve_native_human_route_in(self, &txn, recipient)
            .map_err(|_| Error::InvalidConfig("policy notification route unavailable".into()))?;
        let count = if row.mode == PolicyNotificationMode::Digest {
            let mut group = Vec::new();
            let mut retired = Vec::new();
            let prefix = digest_recipient_prefix(recipient);
            for entry in self
                .store
                .vault_meta
                .prefix_iter(&txn, &prefix)?
                .take(DIGEST_BATCH_LIMIT)
            {
                let (index_key, queue_key) = entry?;
                // Indexed by (recipient, due, receipt): future windows follow
                // due windows, so a bounded read cannot miss an older due row.
                let due_start = prefix.len();
                let due: [u8; 8] = index_key
                    .get(due_start..due_start + 8)
                    .ok_or(Error::CorruptedIndex("policy digest recipient index"))?
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("policy digest recipient index"))?;
                if u64::from_be_bytes(due) > now {
                    break;
                }
                let raw = self
                    .store
                    .vault_meta
                    .get(&txn, queue_key.as_ref())?
                    .ok_or(Error::CorruptedIndex("policy digest recipient queue"))?;
                let candidate: PolicyQueuedNotification = decode(&raw)?;
                if candidate.recipient != row.recipient
                    || candidate.mode != PolicyNotificationMode::Digest
                    || candidate.followup_task.is_some()
                    || candidate.digest_due_at != Some(u64::from_be_bytes(due))
                {
                    return Err(Error::CorruptedIndex("policy digest recipient binding"));
                }
                if authority::holders_for_in_txn(
                    self,
                    &txn,
                    now,
                    &candidate.scope,
                    &candidate.grant_target,
                )?
                .contains(&recipient)
                {
                    group.push((queue_key.to_vec(), index_key.to_vec(), candidate));
                } else {
                    // Revoked recipients no longer receive this policy row.
                    // Retire their pending digest entry so they do not block
                    // a later eligible window at the front of the index.
                    retired.push((queue_key.to_vec(), index_key.to_vec(), candidate));
                }
            }
            for (queue_key, index_key, mut item) in retired {
                item.mode = PolicyNotificationMode::LogOnly;
                self.store
                    .vault_meta
                    .put(&mut txn, &queue_key, &encode(&item)?)?;
                self.store.vault_meta.delete(&mut txn, &index_key)?;
            }
            if group.is_empty() {
                txn.commit()?;
                return Ok(0);
            }
            let sender = group
                .iter()
                .filter_map(|(_, _, item)| EntityId::from_hex(&item.author).ok())
                .find(|author| live_holders.contains(author) && *author != recipient)
                .ok_or_else(invalid)?;
            let receipts = group
                .iter()
                .map(|(_, _, item)| item.receipt_id.clone())
                .collect::<Vec<_>>();
            let task = crate::task_verb::enqueue_policy_change_digest_followup_in_txn(
                self, &mut txn, sender, recipient, &receipts, now,
            )?;
            for (key, index_key, mut item) in group {
                item.followup_task = Some(task.to_hex());
                self.store.vault_meta.put(&mut txn, &key, &encode(&item)?)?;
                self.store.vault_meta.delete(&mut txn, &failure_key(&key))?;
                self.store.vault_meta.delete(&mut txn, &index_key)?;
            }
            self.store
                .vault_meta
                .delete(&mut txn, &key(DIGEST_WINDOW, recipient.as_bytes()))?;
            receipts.len()
        } else {
            let sender = EntityId::from_hex(&row.author)?;
            if !live_holders.contains(&sender) {
                return Err(invalid());
            }
            let task = crate::task_verb::enqueue_policy_change_followup_in_txn(
                self,
                &mut txn,
                sender,
                recipient,
                &row.receipt_id,
                now,
            )?;
            let mut linked = row.clone();
            linked.followup_task = Some(task.to_hex());
            self.store
                .vault_meta
                .put(&mut txn, queue_key, &encode(&linked)?)?;
            self.store
                .vault_meta
                .delete(&mut txn, &failure_key(queue_key))?;
            1
        };
        txn.commit()?;
        Ok(count)
    }

    /// Holder changes a manifest-resident delivery rule; the next change reads it.
    pub fn change_policy_notification_rule(
        &self,
        holder: &AuthenticatedOwner,
        target: PolicyNotificationTarget,
        rule: PolicyNotificationRule,
        now: u64,
    ) -> Result<String> {
        let mut txn = self.store.env.write_txn()?;
        holder.revalidate_in_txn(self, &txn)?;
        if !authority::holders_for_in_txn(
            self,
            &txn,
            now,
            &PolicyRowScope::Vault,
            target.grant_target(),
        )?
        .contains(&holder.actor())
        {
            return Err(super::denied());
        }
        let (id, _, mut value) = manifest_in(self, &txn)?;
        let Value::Map(ref mut entries) = value else {
            return Err(invalid());
        };
        let Value::Array(rows) = entries
            .iter_mut()
            .find(|(k, _)| k.as_str() == Some(RULE_KEY))
            .ok_or_else(invalid)
            .map(|(_, v)| v)?
        else {
            return Err(invalid());
        };
        let scope_name = target.row_scope();
        let mut replaced = false;
        for row in rows.iter_mut() {
            let Value::Map(fields) = row else {
                return Err(invalid());
            };
            if field(fields, "scope")?.as_str() == Some(scope_name) {
                let entry = fields
                    .iter_mut()
                    .find(|(key, _)| key.as_str() == Some("delivery"))
                    .ok_or_else(invalid)?;
                entry.1 = Value::from(rule.as_str());
                replaced = true;
            }
        }
        if !replaced {
            return Err(invalid());
        }
        let mut encoded = Vec::new();
        rmpv::encode::write_value(&mut encoded, &value).map_err(|_| invalid())?;
        self.write_owner_policy_manifest_in_txn(holder, &mut txn, id, encoded, now)?;
        let receipt_id = self.store.clock.entity_id()?.to_hex();
        let event = PolicyChangedEvent {
            kind: "policy.changed".to_owned(),
            receipt_id: receipt_id.clone(),
            author: holder.actor().to_hex(),
            scope: None,
            target: Some(target),
            at: now,
        };
        let receipt_key = key(RULE_RECEIPT, receipt_id.as_bytes());
        self.store
            .vault_meta
            .put(&mut txn, &receipt_key, &encode(&event)?)?;
        // Shared typed stream, distinct receipt family.
        let event_key = key(b"owner_policy:change:event:v1:", receipt_id.as_bytes());
        self.store
            .vault_meta
            .put(&mut txn, &event_key, &encode(&event)?)?;
        txn.commit()?;
        Ok(receipt_id)
    }
}
