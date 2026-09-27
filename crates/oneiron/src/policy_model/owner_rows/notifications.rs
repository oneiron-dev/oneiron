//! Manifest-authored notification rules and recipient-owned delivery preferences.
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::io::Cursor;

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
const QUEUED: &[u8] = b"owner_policy:notification:queued:v1:";
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
    pub mode: PolicyNotificationMode,
    pub followup_task: Option<String>,
}

fn invalid() -> Error {
    Error::InvalidConfig("invalid owner policy notification row".to_owned())
}
fn key(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    [prefix, suffix].concat()
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
fn read_rule_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    vault_scope: bool,
) -> Result<PolicyNotificationRule> {
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
        if name == scope {
            if found
                .replace(PolicyNotificationRule::parse(value)?)
                .is_some()
            {
                return Err(invalid());
            }
        }
    }
    found.ok_or_else(invalid)
}
fn preference_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    recipient: EntityId,
) -> Result<PolicyNotificationMode> {
    vault
        .store
        .vault_meta
        .get(txn, &key(PREF, recipient.as_bytes()))?
        .map(|raw| decode(&raw))
        .transpose()
        .map(|v| v.unwrap_or(PolicyNotificationMode::Inherit))
}

pub(super) fn enqueue_change_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    receipt: &PolicyRowReceipt,
    holders: &[EntityId],
    _now: u64,
) -> Result<()> {
    let vault_scope = matches!(receipt.change.scope(), PolicyRowScope::Vault);
    let rule = read_rule_in(vault, txn, vault_scope)?;
    for recipient in holders.iter().copied() {
        if recipient.to_hex() == receipt.author {
            continue;
        }
        let preference = preference_in(vault, txn, recipient)?;
        let mode = match preference {
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
        let followup_task = None;
        let entry = PolicyQueuedNotification {
            receipt_id: receipt.receipt_id.clone(),
            recipient: recipient.to_hex(),
            author: receipt.author.clone(),
            mode,
            followup_task,
        };
        let storage_key = key(
            QUEUED,
            format!("{}:{}", receipt.receipt_id, recipient.to_hex()).as_bytes(),
        );
        vault
            .store
            .vault_meta
            .put(txn, &storage_key, &encode(&entry)?)?;
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
        self.store.vault_meta.put(
            &mut txn,
            &key(PREF, actor.actor().as_bytes()),
            &encode(&mode)?,
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

    /// Connect queued pushes to the existing TASK human follow-up ladder.
    /// Unreachable holders remain queued and can be retried after contact setup.
    pub fn drive_policy_notification_queue(&self, now: u64, limit: usize) -> Result<usize> {
        let mut txn = self.store.env.write_txn()?;
        let mut ready = Vec::new();
        for entry in self.store.vault_meta.prefix_iter(&txn, QUEUED)? {
            let (key, value) = entry?;
            let row: PolicyQueuedNotification = decode(&value)?;
            if matches!(
                row.mode,
                PolicyNotificationMode::PushAll | PolicyNotificationMode::Digest
            ) && row.followup_task.is_none()
            {
                ready.push((key.to_vec(), row));
            }
            if ready.len() >= limit {
                break;
            }
        }
        let mut linked = 0;
        for (key, mut row) in ready {
            let recipient = EntityId::from_hex(&row.recipient)?;
            // No route today is not an authorization to cancel the pending push.
            if crate::human_task::resolve_native_human_route_in(self, &txn, recipient).is_err() {
                continue;
            }
            let task = crate::task_verb::enqueue_policy_change_followup_in_txn(
                self,
                &mut txn,
                EntityId::from_hex(&row.author)?,
                recipient,
                &row.receipt_id,
                now,
            )?;
            row.followup_task = Some(task.to_hex());
            self.store.vault_meta.put(&mut txn, &key, &encode(&row)?)?;
            linked += 1;
        }
        txn.commit()?;
        Ok(linked)
    }

    /// Holder changes a manifest-resident delivery rule; the next change reads it.
    pub fn change_policy_notification_rule(
        &self,
        holder: &AuthenticatedOwner,
        scope: PolicyRowScope,
        rule: PolicyNotificationRule,
        now: u64,
    ) -> Result<String> {
        let vault_scope = match scope {
            PolicyRowScope::Vault => true,
            PolicyRowScope::World(_) | PolicyRowScope::Project(_) => false,
        };
        let mut txn = self.store.env.write_txn()?;
        holder.revalidate_in_txn(self, &txn)?;
        if !authority::holders_in_txn(self, &txn, now)?.contains(&holder.actor()) {
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
        let target = if vault_scope { "vault" } else { "override" };
        let mut replaced = false;
        for row in rows.iter_mut() {
            let Value::Map(fields) = row else {
                return Err(invalid());
            };
            if field(fields, "scope")?.as_str() == Some(target) {
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
            scope,
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
