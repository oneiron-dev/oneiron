//! Shared-act policy reads and durable changes (DOOR-129). ARCH-0043: "The
//! Owners together may change the list and the waits." Identity: "A
//! shared-act policy change authenticates every editor as a person. The
//! approvals must be exactly the live editor set."
//!
//! A live Owner reads every row: the rows the vault kind ships, the vault's
//! own rows, and the row each act resolves to, with the digest of both
//! sources. One live editor proposes one row change, bound to the vault, the
//! act, the row and that digest; each other live editor answers it under
//! their own credential. One no vetoes the change. The last yes writes the
//! row through the write the one-call setter uses, after the live editor
//! set, the digest and every earlier approver's standing are read again in
//! that writer. Silence never applies a change. No proof is kept or rebuilt
//! from an id: an earlier approval counts only while its holder is still a
//! live editor of the act's current row.
use std::collections::{BTreeMap, BTreeSet};

use super::{
    ActPolicies, DEFAULT_ROW, SharedActPolicy, check_policy_request, check_vault, invalid,
    with_act_table,
};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::side_table::{self, HexId, Named, SideTable};
use crate::{EntityId, Vault};

/// One proposed change. Key: hex32 (change id).
const CHANGES: SideTable<HexId, SharedActPolicyChange, Named> =
    SideTable::new(&side_table::SHARED_ACT_POLICY_CHANGE);
/// The inbox producer of a change's ask to each other live editor; its event
/// is `<change id>:<editor id>`.
pub const NOTIFICATION_PRODUCER_POLICY_CHANGE: &str = "shared_vault.policy_change";
/// The domain of the digest a change binds.
const POLICY_HASH_DOMAIN: &[u8] = b"oneiron/shared-act/policy-hash/v1";
/// Whether a change may name the `_default` row. The read returns it; a
/// change of it waits on a ruling (DOOR-129 call 2).
const DEFAULT_ROW_CHANGEABLE: bool = false;

/// Every shared-act policy row of one shared vault, as a live Owner reads it.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct SharedActPoliciesView {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    /// The rows the vault kind ships, `_default` included.
    pub shipped: BTreeMap<String, SharedActPolicy>,
    /// The vault's own rows, which the Owners changed together.
    pub overrides: BTreeMap<String, SharedActPolicy>,
    /// The row each named act resolves to: its own row, its shipped row,
    /// then the `_default` row. An act named nowhere takes `_default`.
    pub effective: BTreeMap<String, SharedActPolicy>,
    /// The digest of both sources, which a proposed change binds.
    pub policy_hash: String,
}

/// Where a proposed change stands. Only `pending` takes an answer.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SharedActPolicyChangeState {
    /// Waiting on the live editors named in `awaiting`.
    Pending,
    /// Every live editor approved it, and its row was written.
    Applied,
    /// A live editor answered no.
    Vetoed,
    /// The vault's rows moved after it was proposed, so it can never apply.
    Stale,
}

/// One proposed shared-act policy change and its answers.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct SharedActPolicyChange {
    pub id: String,
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    pub act: String,
    /// The act's new row, or `None` to remove the vault's own row so the
    /// shipped row applies again.
    pub policy: Option<SharedActPolicy>,
    /// The `policy_hash` of the rows it was proposed against.
    pub base_policy_hash: String,
    /// The proposer's PERSON id, hex. Proposing is their approval.
    pub proposer: String,
    pub proposed_at: u64,
    /// The PERSON ids, hex, that approved it.
    pub approvals: BTreeSet<String>,
    /// The PERSON id, hex, whose no vetoed it.
    pub vetoed_by: Option<String>,
    pub state: SharedActPolicyChangeState,
    /// When it was applied, vetoed or found stale, on the store clock.
    pub settled_at: Option<u64>,
    /// The live editors, PERSON ids hex, it still waits on, as of this
    /// answer; empty once settled.
    #[serde(default)]
    pub awaiting: BTreeSet<String>,
}

/// One row change the shared write applies: `policy` for `act`, or `None` to
/// remove the vault's own row.
pub(super) struct PolicyEdit<'a> {
    pub(super) vault_id: u64,
    pub(super) act: &'a str,
    pub(super) policy: Option<&'a SharedActPolicy>,
}

impl ActPolicies {
    /// Every row name either source carries, resolved as an act resolves it.
    fn effective_rows(&self) -> Result<BTreeMap<String, SharedActPolicy>> {
        self.shipped
            .keys()
            .chain(self.stored.keys())
            .map(|act| Ok((act.clone(), self.effective(act)?)))
            .collect()
    }

    /// The digest of both sources: any change of either moves it.
    fn digest(&self) -> Result<String> {
        let rows = serde_json::to_vec(&(&self.shipped, &self.stored)).map_err(|_| invalid())?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(POLICY_HASH_DOMAIN);
        hasher.update(&rows);
        Ok(hasher.finalize().to_hex().to_string())
    }
}

impl Vault {
    /// The live holders of `row`'s editor roles and verb in `vault_id`.
    fn live_policy_editors_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        vault_id: u64,
        row: &SharedActPolicy,
        now: u64,
    ) -> Result<BTreeSet<EntityId>> {
        Ok(self
            .live_act_holders(txn, vault_id, now)?
            .into_iter()
            .filter(|holder| holder.can(&row.policy_editor_roles, &row.required_verb))
            .map(|holder| holder.member)
            .collect())
    }

    /// The one write of a shared-act policy row, for the one-call setter
    /// ([`Vault::set_shared_act_policy`]) and a durable change's last yes:
    /// `approvals` must be exactly the live holders of the act's current
    /// editor roles, and not empty. A row must narrow the vault's `_default`
    /// row. It is written into the trusted manifest through `writer`'s owner
    /// door, in `txn`.
    pub(super) fn write_shared_act_policy_in_txn(
        &self,
        writer: &AuthenticatedOwner,
        txn: &mut heed::RwTxn<'_>,
        edit: PolicyEdit<'_>,
        approvals: &BTreeSet<EntityId>,
        now: u64,
    ) -> Result<()> {
        let creation = check_vault(self, txn, edit.vault_id)?;
        let mut policies = self.act_policies_in_txn(txn, &creation)?;
        let default = policies.effective(DEFAULT_ROW)?;
        if edit
            .policy
            .is_some_and(|row| !row.is_narrowing_of(&default))
        {
            return Err(invalid());
        }
        let current = policies.effective(edit.act)?;
        let required = self.live_policy_editors_in_txn(txn, edit.vault_id, &current, now)?;
        if *approvals != required || required.is_empty() {
            return Err(invalid());
        }
        if let Some(row) = edit.policy {
            policies.stored.insert(edit.act.to_owned(), row.clone());
        } else {
            policies.stored.remove(edit.act);
        }
        let id = crate::gate::default_policy_manifest_id()?;
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&self.store, &*txn, &id)?
            .ok_or_else(invalid)?;
        let body = raw.get(ENTITY_METADATA_HEADER_LEN..).ok_or_else(invalid)?;
        // Build only on bytes that passed the owner door, never on a received manifest.
        if !crate::gate::manifest_authenticity::manifest_is_trusted(&self.store, txn, &id, body)? {
            return Err(invalid());
        }
        let data = with_act_table(body, &policies.stored)?;
        self.write_holder_policy_manifest_in_txn(writer, txn, id, data, now)
    }

    /// `vault_id`'s shared-act policy rows, for a live Owner of the vault.
    pub fn shared_act_policies(
        &self,
        owner: &AuthenticatedOwner,
        vault_id: u64,
    ) -> Result<SharedActPoliciesView> {
        let txn = self.store.env.read_txn()?;
        // Owner tier: the rows are the Owners' authority data.
        owner.revalidate_in_txn(self, &txn)?;
        let creation = check_vault(self, &txn, vault_id)?;
        let policies = self.act_policies_in_txn(&txn, &creation)?;
        let effective = policies.effective_rows()?;
        let policy_hash = policies.digest()?;
        Ok(SharedActPoliciesView {
            vault_id,
            shipped: policies.shipped,
            overrides: policies.stored,
            effective,
            policy_hash,
        })
    }

    /// Reads `change` against today's vault: a pending change whose digest
    /// no longer matches is stale, and `awaiting` names the live editors of
    /// the act's current row that have not approved it. Returns those
    /// editors, empty for a settled change.
    fn refresh_policy_change(
        &self,
        txn: &heed::RoTxn<'_>,
        change: &mut SharedActPolicyChange,
        now: u64,
    ) -> Result<BTreeSet<EntityId>> {
        change.awaiting.clear();
        if change.state != SharedActPolicyChangeState::Pending {
            return Ok(BTreeSet::new());
        }
        let creation = check_vault(self, txn, change.vault_id)?;
        let policies = self.act_policies_in_txn(txn, &creation)?;
        let current = policies.effective(&change.act)?;
        let editors = self.live_policy_editors_in_txn(txn, change.vault_id, &current, now)?;
        if policies.digest()? != change.base_policy_hash {
            change.state = SharedActPolicyChangeState::Stale;
            return Ok(editors);
        }
        change.awaiting = editors
            .iter()
            .map(EntityId::to_hex)
            .filter(|editor| !change.approvals.contains(editor))
            .collect();
        Ok(editors)
    }

    /// The approvals that still count: those of live editors.
    fn counted_approvals(
        change: &SharedActPolicyChange,
        editors: &BTreeSet<EntityId>,
    ) -> BTreeSet<EntityId> {
        editors
            .iter()
            .filter(|editor| change.approvals.contains(&editor.to_hex()))
            .copied()
            .collect()
    }

    /// Applies `change` once every live editor approved it.
    fn apply_policy_change_in_txn(
        &self,
        writer: &AuthenticatedOwner,
        txn: &mut heed::RwTxn<'_>,
        change: &mut SharedActPolicyChange,
        approvals: &BTreeSet<EntityId>,
        now: u64,
    ) -> Result<()> {
        let edit = PolicyEdit {
            vault_id: change.vault_id,
            act: &change.act,
            policy: change.policy.as_ref(),
        };
        self.write_shared_act_policy_in_txn(writer, txn, edit, approvals, now)?;
        change.state = SharedActPolicyChangeState::Applied;
        change.awaiting.clear();
        Ok(())
    }

    /// `proposer`, a live editor of `act`'s current row, proposes `policy`
    /// for it (`None` removes the vault's own row), bound to
    /// `expected_policy_hash`, the digest of the rows they read. Proposing is
    /// the proposer's approval, so a sole live editor's change applies at
    /// once; every other live editor gets an inbox ask naming it.
    pub fn propose_shared_act_policy_change(
        &self,
        proposer: &AuthenticatedOwner,
        vault_id: u64,
        act: &str,
        policy: Option<SharedActPolicy>,
        expected_policy_hash: &str,
    ) -> Result<SharedActPolicyChange> {
        check_policy_request(act, policy.as_ref())?;
        if act == DEFAULT_ROW && !DEFAULT_ROW_CHANGEABLE {
            return Err(invalid());
        }
        let mut txn = self.store.env.write_txn()?;
        // Person tier, own holder check: the proposer's editor role below.
        let actor = proposer.revalidate_person_in_txn(self, &txn)?;
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let creation = check_vault(self, &txn, vault_id)?;
        let policies = self.act_policies_in_txn(&txn, &creation)?;
        let base_policy_hash = policies.digest()?;
        if base_policy_hash != expected_policy_hash {
            return Err(Error::ConcurrentWrite(
                "the shared-act policy changed since it was read",
            ));
        }
        let default = policies.effective(DEFAULT_ROW)?;
        if policy
            .as_ref()
            .is_some_and(|row| !row.is_narrowing_of(&default))
        {
            return Err(invalid());
        }
        let current = policies.effective(act)?;
        let editors = self.live_policy_editors_in_txn(&txn, vault_id, &current, now)?;
        if !editors.contains(&actor) {
            return Err(invalid());
        }
        let id = self.store.clock.entity_id()?;
        let mut change = SharedActPolicyChange {
            id: id.to_hex(),
            vault_id,
            act: act.to_owned(),
            policy,
            base_policy_hash,
            proposer: actor.to_hex(),
            proposed_at: now,
            approvals: BTreeSet::from([actor.to_hex()]),
            vetoed_by: None,
            state: SharedActPolicyChangeState::Pending,
            settled_at: None,
            awaiting: editors
                .iter()
                .filter(|editor| **editor != actor)
                .map(EntityId::to_hex)
                .collect(),
        };
        if change.awaiting.is_empty() {
            self.apply_policy_change_in_txn(proposer, &mut txn, &mut change, &editors, now)?;
            change.settled_at = Some(now);
        }
        for editor in editors.iter().filter(|editor| **editor != actor) {
            self.record_notification_in_txn(
                &mut txn,
                &NotificationEvent {
                    kind: NotificationKind::Ask,
                    source: NotificationSource {
                        producer: NOTIFICATION_PRODUCER_POLICY_CHANGE.to_owned(),
                        event: format!("{}:{}", change.id, editor.to_hex()),
                        result: Some(change.id.clone()),
                        ..NotificationSource::default()
                    },
                    subject_refs: Vec::new(),
                    recipient: Some(*editor),
                    created_at: now,
                    origin_conversation: None,
                },
            )?;
        }
        CHANGES.put(&self.store, &mut txn, &HexId(id), &change)?;
        txn.commit()?;
        Ok(change)
    }

    /// `holder`, a live editor of the change's act, answers change
    /// `change_id` under their own credential. A yes is added to the
    /// approvals, and the yes that completes the live editor set writes the
    /// row; a no vetoes the change for good. A change the vault's rows moved
    /// past is settled as stale and the answer is not counted. A settled
    /// change takes no answer.
    pub fn answer_shared_act_policy_change(
        &self,
        holder: &AuthenticatedOwner,
        change_id: &str,
        approve: bool,
    ) -> Result<SharedActPolicyChange> {
        let id = EntityId::from_hex(change_id)?;
        let mut txn = self.store.env.write_txn()?;
        // Person tier, own holder check: the answerer's editor role below.
        let actor = holder.revalidate_person_in_txn(self, &txn)?;
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let mut change = CHANGES
            .get(&self.store, &txn, &HexId(id))?
            .ok_or_else(invalid)?;
        if change.state != SharedActPolicyChangeState::Pending {
            return Err(Error::ConcurrentWrite(
                "the shared-act policy change is already settled",
            ));
        }
        let editors = self.refresh_policy_change(&txn, &mut change, now)?;
        if !editors.contains(&actor) {
            return Err(invalid());
        }
        if change.state == SharedActPolicyChangeState::Pending {
            let me = actor.to_hex();
            if approve {
                change.approvals.insert(me.clone());
                change.awaiting.remove(&me);
                let counted = Self::counted_approvals(&change, &editors);
                if counted == editors {
                    self.apply_policy_change_in_txn(holder, &mut txn, &mut change, &counted, now)?;
                }
            } else {
                change.vetoed_by = Some(me);
                change.state = SharedActPolicyChangeState::Vetoed;
                change.awaiting.clear();
            }
        }
        if change.state != SharedActPolicyChangeState::Pending {
            change.settled_at = Some(now);
        }
        CHANGES.put(&self.store, &mut txn, &HexId(id), &change)?;
        txn.commit()?;
        Ok(change)
    }

    /// Change `change_id`, for a live Owner of its vault. A pending change
    /// the vault's rows moved past reads as stale.
    pub fn shared_act_policy_change(
        &self,
        owner: &AuthenticatedOwner,
        change_id: &str,
    ) -> Result<SharedActPolicyChange> {
        let id = EntityId::from_hex(change_id)?;
        let txn = self.store.env.read_txn()?;
        // Owner tier: a change is the Owners' authority data.
        owner.revalidate_in_txn(self, &txn)?;
        let mut change = CHANGES
            .get(&self.store, &txn, &HexId(id))?
            .ok_or_else(invalid)?;
        check_vault(self, &txn, change.vault_id)?;
        self.refresh_policy_change(&txn, &mut change, self.store.clock.now_recorded_at())?;
        Ok(change)
    }

    /// Every proposed change of `vault_id`'s shared-act policy rows, for a
    /// live Owner of the vault (FIX 4288), ascending by id, each read as
    /// [`Self::shared_act_policy_change`] reads one: a pending change the
    /// vault's rows moved past reads as stale, and settled changes stay
    /// listed as they settled. Nothing is written, settled or swept.
    pub fn shared_act_policy_changes(
        &self,
        owner: &AuthenticatedOwner,
        vault_id: u64,
    ) -> Result<Vec<SharedActPolicyChange>> {
        let txn = self.store.env.read_txn()?;
        // Owner tier: a change is the Owners' authority data.
        owner.revalidate_in_txn(self, &txn)?;
        check_vault(self, &txn, vault_id)?;
        let now = self.store.clock.now_recorded_at();
        let mut changes = Vec::new();
        for (_, mut change) in CHANGES.scan(&self.store, &txn)? {
            if change.vault_id != vault_id {
                continue;
            }
            self.refresh_policy_change(&txn, &mut change, now)?;
            changes.push(change);
        }
        Ok(changes)
    }
}
