//! Row-driven shared-vault objection windows. A host executes the returned act;
//! this module never interprets act names or performs irreversible effects.
use super::{
    FederationGrantRole as Role, FederationGrantScope, SharedVaultPreset,
    decode_federation_grant_body,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::{EntityId, Vault};
use std::collections::BTreeSet;

const POLICY_PREFIX: &[u8] = b"shared-act:policy:v1:";
const ACT_PREFIX: &[u8] = b"shared-act:record:v1:";
const EVENT_PREFIX: &[u8] = b"shared-act:event:v1:";

fn invalid() -> Error {
    Error::InvalidConfig("invalid shared-vault act".into())
}
fn key(prefix: &[u8], suffix: &str) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(suffix.as_bytes());
    key
}
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}
fn check_vault(vault: &Vault, txn: &heed::RoTxn<'_>, vault_id: u64) -> Result<()> {
    let raw = vault
        .store
        .vault_meta
        .get(txn, super::shared_creation::CREATION_KEY)?
        .ok_or_else(invalid)?;
    let creation: super::SharedVaultCreation = decode(&raw)?;
    if creation.vault_id != vault_id {
        return Err(invalid());
    }
    Ok(())
}
fn encode<T: serde::Serialize>(row: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(row).map_err(|_| invalid())
}
fn decode<T: serde::de::DeserializeOwned>(row: &[u8]) -> Result<T> {
    serde_json::from_slice(row).map_err(|_| invalid())
}

/// A data row, not a compiled-in act list. No row (or a zero wait) means immediate completion.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedActPolicy {
    pub wait_secs: u64,
    pub objector_roles: Vec<Role>,
}
impl SharedActPolicy {
    fn validate(&self) -> Result<()> {
        if self.wait_secs > 0 && self.objector_roles.is_empty() {
            return Err(invalid());
        }
        if self.objector_roles.iter().collect::<BTreeSet<_>>().len() != self.objector_roles.len() {
            return Err(invalid());
        }
        Ok(())
    }
}
/// The decision is returned as a typed act with its opaque host payload. The host
/// must route irreversible effects through this door rather than bypassing it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingAuthorityAct {
    pub id: String,
    pub vault_id: u64,
    pub act: String,
    pub payload: Vec<u8>,
    pub starter: String,
    pub started_at: u64,
    pub deadline: u64,
    pub objector_roles: Vec<Role>,
    pub objections: BTreeSet<String>,
    pub completed: bool,
}
/// Durable, recipient-specific notification for a holder at the instant the act starts.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingActStarted {
    pub act_id: String,
    pub vault_id: u64,
    pub act: String,
    pub recipient: String,
    pub deadline: u64,
}

impl Vault {
    fn live_act_holders(
        &self,
        txn: &heed::RoTxn<'_>,
        vault_id: u64,
        now: u64,
    ) -> Result<Vec<(EntityId, Role)>> {
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        let mut holders = Vec::new();
        for row in self
            .store
            .type_index
            .prefix_iter(txn, &[crate::registry::ENTITY_TYPE_FEDERATION_GRANT])?
        {
            let (index, _) = row?;
            let id = crate::vault::entity_id_from_type_index_key(&index)?;
            let raw = self
                .store
                .entities
                .get(txn, id.as_bytes())?
                .ok_or_else(invalid)?;
            if EntityMetadataHeader::parse(&raw)
                .is_none_or(|h| h.entity_type != crate::registry::ENTITY_TYPE_FEDERATION_GRANT)
            {
                return Err(invalid());
            }
            let grant = decode_federation_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if grant.scope == FederationGrantScope::vault(vault_id)
                && grant.confers_at(now)
                && fold
                    .pact_for_grant(&id)
                    .is_none_or(|p| p.status == crate::authority::FederationPactStatus::Active)
            {
                holders.push((grant.member_ref, grant.role));
            }
        }
        Ok(holders)
    }
    /// Creation preset rows are written in the same transaction as the membership rows.
    pub(super) fn seed_act_policy(
        &self,
        txn: &mut heed::RwTxn<'_>,
        preset: SharedVaultPreset,
    ) -> Result<()> {
        if preset == SharedVaultPreset::Personal {
            return Ok(());
        }
        let rows: std::collections::BTreeMap<String, SharedActPolicy> =
            serde_json::from_str(include_str!("shared_act_policies.json"))
                .map_err(|_| invalid())?;
        for (act, policy) in rows {
            if !valid_name(&act) {
                return Err(invalid());
            }
            policy.validate()?;
            self.store
                .vault_meta
                .put(txn, &key(POLICY_PREFIX, &act), &encode(&policy)?)?;
        }
        Ok(())
    }
    pub fn shared_act_policy(&self, act: &str) -> Result<Option<SharedActPolicy>> {
        if !valid_name(act) {
            return Err(invalid());
        }
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, &key(POLICY_PREFIX, act))?
            .map(|raw| decode(&raw))
            .transpose()
    }
    /// All live Owners must authenticate a row change. A sole Owner supplies an
    /// empty `co_owners` slice. New acts snapshot the new policy; existing acts
    /// retain their original window.
    pub fn set_shared_act_policy(
        &self,
        owner: &AuthenticatedOwner,
        co_owners: &[&AuthenticatedOwner],
        vault_id: u64,
        act: &str,
        policy: Option<SharedActPolicy>,
        now: u64,
    ) -> Result<()> {
        if !valid_name(act) {
            return Err(invalid());
        }
        if let Some(row) = &policy {
            row.validate()?;
        }
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        check_vault(self, &txn, vault_id)?;
        let live_owners: BTreeSet<EntityId> = self
            .live_act_holders(&txn, vault_id, now)?
            .into_iter()
            .filter_map(|(id, role)| (role == Role::Owner).then_some(id))
            .collect();
        let mut approvals = BTreeSet::from([owner.actor()]);
        for co_owner in co_owners {
            co_owner.revalidate_in_txn(self, &txn)?;
            if !approvals.insert(co_owner.actor()) {
                return Err(invalid());
            }
        }
        if approvals != live_owners {
            return Err(invalid());
        }
        let k = key(POLICY_PREFIX, act);
        if let Some(row) = policy {
            self.store.vault_meta.put(&mut txn, &k, &encode(&row)?)?;
        } else {
            self.store.vault_meta.delete(&mut txn, &k)?;
        }
        txn.commit()?;
        Ok(())
    }
    /// Start an arbitrary host-defined authority act. The host must execute only
    /// when `completed` is true; every named live role holder gets one durable event.
    pub fn start_authority_act(
        &self,
        starter: &AuthenticatedOwner,
        vault_id: u64,
        act: &str,
        payload: Vec<u8>,
        now: u64,
    ) -> Result<PendingAuthorityAct> {
        self.start_authority_act_with_policy_selection(starter, vault_id, act, payload, None, now)
    }

    /// Use a host-selected setting for one request without mutating the stored
    /// policy row. `None` means no wait (for example, mandatory self-erasure).
    /// This is a host policy door, not an untrusted client-selected bypass.
    pub fn start_authority_act_with_setting(
        &self,
        starter: &AuthenticatedOwner,
        vault_id: u64,
        act: &str,
        payload: Vec<u8>,
        setting: Option<SharedActPolicy>,
        now: u64,
    ) -> Result<PendingAuthorityAct> {
        self.start_authority_act_with_policy_selection(
            starter,
            vault_id,
            act,
            payload,
            Some(setting),
            now,
        )
    }

    fn start_authority_act_with_policy_selection(
        &self,
        starter: &AuthenticatedOwner,
        vault_id: u64,
        act: &str,
        payload: Vec<u8>,
        selection: Option<Option<SharedActPolicy>>,
        now: u64,
    ) -> Result<PendingAuthorityAct> {
        if !valid_name(act) || payload.len() > 1024 * 1024 {
            return Err(invalid());
        }
        let mut txn = self.store.env.write_txn()?;
        starter.revalidate_in_txn(self, &txn)?;
        check_vault(self, &txn, vault_id)?;
        let holders = self.live_act_holders(&txn, vault_id, now)?;
        if !holders
            .iter()
            .any(|(id, role)| *id == starter.actor() && *role == Role::Owner)
        {
            return Err(invalid());
        }
        let policy = match selection {
            Some(setting) => setting,
            None => self
                .store
                .vault_meta
                .get(&txn, &key(POLICY_PREFIX, act))?
                .map(|raw| decode(&raw))
                .transpose()?,
        };
        if let Some(row) = &policy {
            row.validate()?;
        }
        let wait = policy.as_ref().map_or(0, |p| p.wait_secs);
        let deadline = now.checked_add(wait).ok_or_else(invalid)?;
        let id = self.store.clock.entity_id()?.to_hex();
        let record = PendingAuthorityAct {
            id: id.clone(),
            vault_id,
            act: act.to_owned(),
            payload,
            starter: starter.actor().to_hex(),
            started_at: now,
            deadline,
            objector_roles: policy.map_or_else(Vec::new, |p| p.objector_roles),
            objections: BTreeSet::new(),
            completed: wait == 0,
        };
        self.store
            .vault_meta
            .put(&mut txn, &key(ACT_PREFIX, &id), &encode(&record)?)?;
        if wait > 0 {
            let mut recipients = BTreeSet::new();
            for (holder, role) in holders {
                if record.objector_roles.contains(&role) && recipients.insert(holder) {
                    let event = PendingActStarted {
                        act_id: id.clone(),
                        vault_id,
                        act: act.to_owned(),
                        recipient: holder.to_hex(),
                        deadline,
                    };
                    let event_key = key(EVENT_PREFIX, &format!("{}:{id}", holder.to_hex()));
                    self.store
                        .vault_meta
                        .put(&mut txn, &event_key, &encode(&event)?)?;
                }
            }
        }
        txn.commit()?;
        Ok(record)
    }
    pub fn pending_authority_act(&self, id: &str) -> Result<Option<PendingAuthorityAct>> {
        let id = EntityId::from_hex(id)?;
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, &key(ACT_PREFIX, &id.to_hex()))?
            .map(|raw| decode(&raw))
            .transpose()
    }
    pub fn pending_act_started_events(
        &self,
        holder: &AuthenticatedOwner,
        vault_id: u64,
        now: u64,
    ) -> Result<Vec<PendingActStarted>> {
        let txn = self.store.env.read_txn()?;
        holder.revalidate_in_txn(self, &txn)?;
        check_vault(self, &txn, vault_id)?;
        if !self
            .live_act_holders(&txn, vault_id, now)?
            .iter()
            .any(|(id, _)| *id == holder.actor())
        {
            return Err(invalid());
        }
        let prefix = key(EVENT_PREFIX, &format!("{}:", holder.actor().to_hex()));
        let mut events = Vec::new();
        for entry in self.store.vault_meta.prefix_iter(&txn, &prefix)? {
            let (_, bytes) = entry?;
            let event: PendingActStarted = decode(&bytes)?;
            if event.vault_id == vault_id {
                events.push(event);
            }
        }
        Ok(events)
    }
    /// Objections are live only while their holder still carries a named role.
    /// Once the deadline has passed, withdrawing the last live objection releases the act.
    pub fn change_authority_objection(
        &self,
        holder: &AuthenticatedOwner,
        id: &str,
        object: bool,
        now: u64,
    ) -> Result<PendingAuthorityAct> {
        let id = EntityId::from_hex(id)?;
        let mut txn = self.store.env.write_txn()?;
        holder.revalidate_in_txn(self, &txn)?;
        let k = key(ACT_PREFIX, &id.to_hex());
        let raw = self.store.vault_meta.get(&txn, &k)?.ok_or_else(invalid)?;
        let mut record: PendingAuthorityAct = decode(&raw)?;
        if record.completed || now < record.started_at || holder.actor().to_hex() == record.starter
        {
            return Err(invalid());
        }
        let holders = self.live_act_holders(&txn, record.vault_id, now)?;
        if !holders
            .iter()
            .any(|(member, role)| *member == holder.actor() && record.objector_roles.contains(role))
        {
            return Err(invalid());
        }
        if object && now >= record.deadline {
            return Err(invalid());
        }
        if object {
            record.objections.insert(holder.actor().to_hex());
        } else {
            record.objections.remove(&holder.actor().to_hex());
        }
        reconcile(&mut record, &holders, now);
        self.store.vault_meta.put(&mut txn, &k, &encode(&record)?)?;
        txn.commit()?;
        Ok(record)
    }
    /// Called by the host clock at/after the deadline. Returns the persisted
    /// completed act for execution; objections still held by live roles block it.
    pub fn advance_authority_act(&self, id: &str, now: u64) -> Result<PendingAuthorityAct> {
        let id = EntityId::from_hex(id)?;
        let mut txn = self.store.env.write_txn()?;
        let k = key(ACT_PREFIX, &id.to_hex());
        let raw = self.store.vault_meta.get(&txn, &k)?.ok_or_else(invalid)?;
        let mut record: PendingAuthorityAct = decode(&raw)?;
        if now < record.started_at {
            return Err(invalid());
        }
        if !record.completed {
            let holders = self.live_act_holders(&txn, record.vault_id, now)?;
            reconcile(&mut record, &holders, now);
            self.store.vault_meta.put(&mut txn, &k, &encode(&record)?)?;
        }
        txn.commit()?;
        Ok(record)
    }
}
fn reconcile(record: &mut PendingAuthorityAct, holders: &[(EntityId, Role)], now: u64) {
    record.objections.retain(|id| {
        holders
            .iter()
            .any(|(member, role)| member.to_hex() == *id && record.objector_roles.contains(role))
    });
    if now >= record.deadline && record.objections.is_empty() {
        record.completed = true;
    }
}

#[cfg(test)]
mod tests;
