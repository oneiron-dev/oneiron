//! Row-driven shared-vault objection windows. A host executes the returned act;
//! this module never interprets act names or performs irreversible effects.
//! Policy rows live in the vault's POLICY_MANIFEST (`shared_act_policies`) and
//! change only through the owner manifest door; act records stay on this node.
use super::{
    FederationGrantRole as Role, FederationGrantScope, SharedVaultCreation, SharedVaultPreset,
    decode_federation_grant_body,
};
use crate::authority::{FederationGrantActivation, federation_grant_activation};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::{EntityId, Vault};
use std::collections::{BTreeMap, BTreeSet};

const ACT_PREFIX: &[u8] = b"shared-act:record:v1:";
const EVENT_PREFIX: &[u8] = b"shared-act:event:v1:";
/// The row an act without its own row resolves to.
const DEFAULT_ROW: &str = "_default";

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
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}
fn check_vault(vault: &Vault, txn: &heed::RoTxn<'_>, vault_id: u64) -> Result<SharedVaultCreation> {
    let creation = vault
        .shared_vault_creation_in_txn(txn)?
        .ok_or_else(invalid)?;
    if creation.vault_id != vault_id {
        return Err(invalid());
    }
    Ok(creation)
}
/// The shipped rows for the vault kind the creation preset chose (X4).
fn shipped_rows(preset: Option<SharedVaultPreset>) -> Result<BTreeMap<String, SharedActPolicy>> {
    let mut kinds: BTreeMap<String, BTreeMap<String, SharedActPolicy>> =
        serde_json::from_str(include_str!("shared_act_policies.json")).map_err(|_| invalid())?;
    let kind = if preset == Some(SharedVaultPreset::Personal) {
        "personal"
    } else {
        "shared"
    };
    let rows = kinds.remove(kind).ok_or_else(invalid)?;
    for (act, row) in &rows {
        row.validate_named(act)?;
    }
    Ok(rows)
}
/// Manifest rows carry the field names of the shipped JSON rows.
fn row_value(row: &SharedActPolicy) -> Result<rmpv::Value> {
    fn convert(value: serde_json::Value) -> Option<rmpv::Value> {
        Some(match value {
            serde_json::Value::Bool(flag) => flag.into(),
            serde_json::Value::Number(number) => number.as_u64()?.into(),
            serde_json::Value::String(text) => text.into(),
            serde_json::Value::Array(items) => {
                rmpv::Value::Array(items.into_iter().map(convert).collect::<Option<_>>()?)
            }
            serde_json::Value::Object(fields) => rmpv::Value::Map(
                fields
                    .into_iter()
                    .map(|(key, value)| Some((key.into(), convert(value)?)))
                    .collect::<Option<_>>()?,
            ),
            serde_json::Value::Null => return None,
        })
    }
    serde_json::to_value(row)
        .ok()
        .and_then(convert)
        .ok_or_else(invalid)
}
/// Replace the manifest's act-policy table; an empty table removes the key.
fn with_act_table(body: &[u8], rows: &BTreeMap<String, SharedActPolicy>) -> Result<Vec<u8>> {
    let key = crate::gate::POLICY_SHARED_ACT_POLICIES_KEY;
    let mut cursor = std::io::Cursor::new(body);
    let Ok(rmpv::Value::Map(mut entries)) = rmpv::decode::read_value(&mut cursor) else {
        return Err(invalid());
    };
    entries.retain(|(name, _)| name.as_str() != Some(key));
    if !rows.is_empty() {
        let table = rows
            .iter()
            .map(|(act, row)| Ok((act.as_str().into(), row_value(row)?)))
            .collect::<Result<Vec<_>>>()?;
        entries.push((key.into(), rmpv::Value::Map(table)));
    }
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &rmpv::Value::Map(entries)).map_err(|_| invalid())?;
    Ok(out)
}
/// The creation preset's rows: the shipped rows for its vault kind, without
/// the default row. A kind that ships only the default row seeds nothing.
pub(super) fn with_preset_act_policies(
    body: Vec<u8>,
    preset: SharedVaultPreset,
) -> Result<Vec<u8>> {
    let mut rows = shipped_rows(Some(preset))?;
    rows.remove(DEFAULT_ROW);
    if rows.is_empty() {
        return Ok(body);
    }
    with_act_table(&body, &rows)
}
fn encode<T: serde::Serialize>(row: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(row).map_err(|_| invalid())
}
fn decode<T: serde::de::DeserializeOwned>(row: &[u8]) -> Result<T> {
    serde_json::from_slice(row).map_err(|_| invalid())
}

/// A data row, not a compiled-in act list. A zero wait means immediate completion.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedActPolicy {
    pub wait_secs: u64,
    pub objector_roles: Vec<Role>,
    pub initiator_roles: Vec<Role>,
    pub policy_editor_roles: Vec<Role>,
    pub required_verb: String,
    pub starter_may_object: bool,
    pub max_act_name_bytes: usize,
    pub max_payload_bytes: usize,
    pub precedence: SharedActPrecedence,
}
/// Whether an individual holder may request a stricter setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedActPrecedence {
    VaultOnly,
    HolderMayNarrow,
}
impl SharedActPolicy {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.wait_secs > 0 && self.objector_roles.is_empty() {
            return Err(invalid());
        }
        if self.objector_roles.iter().collect::<BTreeSet<_>>().len() != self.objector_roles.len() {
            return Err(invalid());
        }
        if self.initiator_roles.is_empty()
            || self.policy_editor_roles.is_empty()
            || !valid_name(&self.required_verb)
            || self.max_act_name_bytes == 0
            || self.max_payload_bytes == 0
        {
            return Err(invalid());
        }
        Ok(())
    }
    /// Decode one manifest row map with the shipped JSON field names. Anything
    /// but a map of strings, unsigned integers, booleans and arrays is refused.
    pub(crate) fn from_manifest_value(value: &rmpv::Value) -> Option<Self> {
        fn convert(value: &rmpv::Value) -> Option<serde_json::Value> {
            Some(match value {
                rmpv::Value::Boolean(flag) => (*flag).into(),
                rmpv::Value::Integer(number) => number.as_u64()?.into(),
                rmpv::Value::String(text) => text.as_str()?.into(),
                rmpv::Value::Array(items) => {
                    serde_json::Value::Array(items.iter().map(convert).collect::<Option<_>>()?)
                }
                rmpv::Value::Map(fields) => {
                    let mut object = serde_json::Map::new();
                    for (key, value) in fields {
                        if object
                            .insert(key.as_str()?.to_owned(), convert(value)?)
                            .is_some()
                        {
                            return None;
                        }
                    }
                    object.into()
                }
                _ => return None,
            })
        }
        if !matches!(value, rmpv::Value::Map(_)) {
            return None;
        }
        serde_json::from_value(convert(value)?).ok()
    }
    /// A row stored under `act`: a valid act name within the row's own name budget.
    pub(crate) fn validate_named(&self, act: &str) -> Result<()> {
        if !valid_name(act) || (act != DEFAULT_ROW && act.len() > self.max_act_name_bytes) {
            return Err(invalid());
        }
        self.validate()
    }
    /// A holder-selected setting cannot weaken any vault-level restriction.
    fn is_narrowing_of(&self, parent: &Self) -> bool {
        self.wait_secs >= parent.wait_secs
            && self
                .objector_roles
                .iter()
                .collect::<BTreeSet<_>>()
                .is_superset(&parent.objector_roles.iter().collect())
            && self
                .initiator_roles
                .iter()
                .all(|role| parent.initiator_roles.contains(role))
            && self
                .policy_editor_roles
                .iter()
                .all(|role| parent.policy_editor_roles.contains(role))
            && self.required_verb == parent.required_verb
            && (!self.starter_may_object || parent.starter_may_object)
            && self.max_act_name_bytes <= parent.max_act_name_bytes
            && self.max_payload_bytes <= parent.max_payload_bytes
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
    pub required_verb: String,
    pub starter_may_object: bool,
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

/// The manifest's stored rows beside the shipped rows for the vault kind.
struct ActPolicies {
    stored: BTreeMap<String, SharedActPolicy>,
    shipped: BTreeMap<String, SharedActPolicy>,
}
impl ActPolicies {
    /// An absent row uses the shipped row for the vault kind, then the default row.
    fn effective(&self, act: &str) -> Result<SharedActPolicy> {
        self.stored
            .get(act)
            .or_else(|| self.shipped.get(act))
            .or_else(|| self.stored.get(DEFAULT_ROW))
            .or_else(|| self.shipped.get(DEFAULT_ROW))
            .cloned()
            .ok_or_else(invalid)
    }
}
enum SettingChoice {
    Stored,
    Host(Option<SharedActPolicy>),
    Holder(SharedActPolicy),
}
struct LiveActHolder {
    member: EntityId,
    role: Role,
    scope: super::Scope,
}
impl LiveActHolder {
    fn can(&self, roles: &[Role], verb: &str) -> bool {
        roles.contains(&self.role) && super::grant_scope::admits_preset(&self.scope, verb)
    }
}
impl Vault {
    fn live_act_holders(
        &self,
        txn: &heed::RoTxn<'_>,
        vault_id: u64,
        now: u64,
    ) -> Result<Vec<LiveActHolder>> {
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        if fold.vault_root_is_conflicted() {
            return Err(invalid());
        }
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
                && matches!(
                    federation_grant_activation(&fold, &id),
                    FederationGrantActivation::Unpacted | FederationGrantActivation::Active
                )
                && crate::consent::person_is_live_in_txn(self, txn, &grant.member_ref)?
            {
                // A pact can further restrict the grant's content ceiling. A
                // non-universal pact cannot confer base authority operations.
                if fold.pact_for_grant(&id).is_some_and(|pact| {
                    !matches!(
                        pact.effective_scope.worlds,
                        super::FederationScopeWorlds::All | super::FederationScopeWorlds::Base
                    ) || !matches!(
                        pact.effective_scope.facets,
                        super::FederationScopeFacets::All
                    ) || !matches!(pact.effective_scope.bands, super::FederationScopeBands::All)
                }) {
                    continue;
                }
                holders.push(LiveActHolder {
                    member: grant.member_ref,
                    role: grant.role,
                    scope: grant.authority_scope,
                });
            }
        }
        Ok(holders)
    }
    /// Policy is read from trusted manifests only; a received or malformed
    /// manifest never supplies a row, and a fail-closed resolution refuses.
    fn act_policies_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        creation: &SharedVaultCreation,
    ) -> Result<ActPolicies> {
        let resolution = crate::gate::resolve_policy_manifest(&self.store, txn)?;
        if resolution.is_fail_closed() {
            return Err(invalid());
        }
        Ok(ActPolicies {
            stored: resolution.shared_act_policies.unwrap_or_default(),
            shipped: shipped_rows(creation.preset)?,
        })
    }
    /// The row stored in the vault's manifest; `None` when the act has none.
    pub fn shared_act_policy(&self, act: &str) -> Result<Option<SharedActPolicy>> {
        if !valid_name(act) {
            return Err(invalid());
        }
        let txn = self.store.env.read_txn()?;
        let resolution = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
        if resolution.is_fail_closed() {
            return Err(invalid());
        }
        Ok(resolution
            .shared_act_policies
            .and_then(|mut rows| rows.remove(act)))
    }
    /// Every live holder of the current row's editor roles must authenticate a
    /// change; a sole editor supplies an empty `co_owners` slice. `None` removes
    /// the stored row, so the shipped row for the vault kind applies again; a
    /// wait is turned off by storing `wait_secs: 0`. The row is written into the
    /// vault's manifest through the owner door in the same transaction. New
    /// acts snapshot the new row; existing acts keep their original window.
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
            row.validate_named(act)?;
        }
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let creation = check_vault(self, &txn, vault_id)?;
        let mut policies = self.act_policies_in_txn(&txn, &creation)?;
        let default = policies.effective(DEFAULT_ROW)?;
        let current = policies.effective(act)?;
        if policy
            .as_ref()
            .is_some_and(|row| !row.is_narrowing_of(&default))
        {
            return Err(invalid());
        }
        let required: BTreeSet<EntityId> = self
            .live_act_holders(&txn, vault_id, now)?
            .into_iter()
            .filter(|holder| holder.can(&current.policy_editor_roles, &current.required_verb))
            .map(|holder| holder.member)
            .collect();
        let mut approvals = BTreeSet::from([owner.actor()]);
        for co_owner in co_owners {
            co_owner.revalidate_in_txn(self, &txn)?;
            if !approvals.insert(co_owner.actor()) {
                return Err(invalid());
            }
        }
        if approvals != required || required.is_empty() {
            return Err(invalid());
        }
        if let Some(row) = policy {
            policies.stored.insert(act.to_owned(), row);
        } else {
            policies.stored.remove(act);
        }
        let id = crate::gate::default_policy_manifest_id()?;
        let raw = self
            .store
            .entities
            .get(&txn, id.as_bytes())?
            .ok_or_else(invalid)?;
        let body = raw.get(ENTITY_METADATA_HEADER_LEN..).ok_or_else(invalid)?;
        // Build only on bytes that passed the owner door, never on a received manifest.
        if !crate::gate::manifest_authenticity::manifest_is_trusted(&self.store, &txn, &id, body)? {
            return Err(invalid());
        }
        let data = with_act_table(body, &policies.stored)?;
        self.write_owner_policy_manifest_in_txn(owner, &mut txn, id, data, now)?;
        txn.commit()?;
        Ok(())
    }
    /// The chosen row is snapshotted into the act in the same transaction.
    /// A holder may request only a stricter row when the vault permits it.
    pub fn start_authority_act_with_holder_setting(
        &self,
        starter: &AuthenticatedOwner,
        vault_id: u64,
        act: &str,
        payload: Vec<u8>,
        setting: SharedActPolicy,
        now: u64,
    ) -> Result<PendingAuthorityAct> {
        self.start_authority_act_with_policy_selection(
            starter,
            vault_id,
            act,
            payload,
            SettingChoice::Holder(setting),
            now,
        )
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
        self.start_authority_act_with_policy_selection(
            starter,
            vault_id,
            act,
            payload,
            SettingChoice::Stored,
            now,
        )
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
            SettingChoice::Host(setting),
            now,
        )
    }

    fn start_authority_act_with_policy_selection(
        &self,
        starter: &AuthenticatedOwner,
        vault_id: u64,
        act: &str,
        payload: Vec<u8>,
        selection: SettingChoice,
        now: u64,
    ) -> Result<PendingAuthorityAct> {
        if !valid_name(act) {
            return Err(invalid());
        }
        let mut txn = self.store.env.write_txn()?;
        starter.revalidate_in_txn(self, &txn)?;
        let creation = check_vault(self, &txn, vault_id)?;
        let base = self.act_policies_in_txn(&txn, &creation)?.effective(act)?;
        let policy = match selection {
            SettingChoice::Stored => base,
            SettingChoice::Host(Some(setting)) => setting,
            SettingChoice::Host(None) => SharedActPolicy {
                wait_secs: 0,
                objector_roles: Vec::new(),
                ..base
            },
            SettingChoice::Holder(setting) => {
                if base.precedence != SharedActPrecedence::HolderMayNarrow
                    || !setting.is_narrowing_of(&base)
                {
                    return Err(invalid());
                }
                setting
            }
        };
        policy.validate()?;
        if act.len() > policy.max_act_name_bytes || payload.len() > policy.max_payload_bytes {
            return Err(invalid());
        }
        let holders = self.live_act_holders(&txn, vault_id, now)?;
        if !holders.iter().any(|holder| {
            holder.member == starter.actor()
                && holder.can(&policy.initiator_roles, &policy.required_verb)
        }) {
            return Err(invalid());
        }
        let wait = policy.wait_secs;
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
            objector_roles: policy.objector_roles.clone(),
            required_verb: policy.required_verb.clone(),
            starter_may_object: policy.starter_may_object,
            objections: BTreeSet::new(),
            completed: wait == 0,
        };
        self.store
            .vault_meta
            .put(&mut txn, &key(ACT_PREFIX, &id), &encode(&record)?)?;
        if wait > 0 {
            let mut recipients = BTreeSet::new();
            for holder in holders {
                if holder.can(&record.objector_roles, &record.required_verb)
                    && recipients.insert(holder.member)
                {
                    let event = PendingActStarted {
                        act_id: id.clone(),
                        vault_id,
                        act: act.to_owned(),
                        recipient: holder.member.to_hex(),
                        deadline,
                    };
                    let event_key = key(EVENT_PREFIX, &format!("{}:{id}", holder.member.to_hex()));
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
            .any(|entry| entry.member == holder.actor())
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
        if record.completed
            || now < record.started_at
            || (holder.actor().to_hex() == record.starter && !record.starter_may_object)
        {
            return Err(invalid());
        }
        let holders = self.live_act_holders(&txn, record.vault_id, now)?;
        if !holders.iter().any(|entry| {
            entry.member == holder.actor()
                && entry.can(&record.objector_roles, &record.required_verb)
        }) {
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
fn reconcile(record: &mut PendingAuthorityAct, holders: &[LiveActHolder], now: u64) {
    record.objections.retain(|id| {
        holders.iter().any(|entry| {
            entry.member.to_hex() == *id && entry.can(&record.objector_roles, &record.required_verb)
        })
    });
    if now >= record.deadline && record.objections.is_empty() {
        record.completed = true;
    }
}

#[cfg(test)]
mod tests;
