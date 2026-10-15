//! The Dreamer's weave rows, the owner's grant that adds them to a vault
//! seeded without them, and the read-only probe hosts check before they start
//! passes.
//!
//! ARCH-0026 has the Dreamer warm by default: it assumes the AI is in the
//! user's corner, and routine reversible work runs automatically. So the
//! shipped manifest a fresh vault seeds carries three rows, each keyed to the
//! vault's Dreamer authority — a vault-wide read-only scoped grant, an Auto
//! actor ceiling, and the `Generated` permit its consolidation lineage needs
//! — in the same narrow, actor-keyed shape as the shipped commitment-projector
//! rows. Class `system` as a whole keeps default-deny, and every other
//! `Generated` writer keeps pending.
//!
//! A vault seeded before the rows shipped has none: its Dreamer reads nothing
//! and lands nothing, and its attempts park on "prepared source not
//! readable". The grant is the owner's edit of one trusted policy pack, in
//! place, adding the same three rows. The pack edited is the vault's one
//! owner-authored pack when there is one, so an untouched seeded default
//! keeps its fallback standing; the seeded default itself only when it is
//! the sole trusted pack. Every other row is kept exactly as it was, so no
//! other present or future system actor, and no other `Generated` writer,
//! inherits anything. Like the retention door, the edit is checked in its
//! own write transaction: it commits only if the Dreamer can then read and
//! land, the policy still resolves open, and the retention and carry-forward
//! policies resolve as before. Re-granting changes nothing.
//!
//! The owner may narrow or remove the rows, seeded or granted. Hosts that probe
//! [`Vault::dreamer_weave_reach`] stop admitting passes; claims already landed
//! stand as written history.
use rmpv::Value;

use super::constants::{
    ACTOR_CEILING_KEY, ACTOR_CLASS_KEY, ACTOR_REF_KEY, POLICY_ACTOR_CEILINGS_KEY,
    POLICY_SCOPED_GRANTS_KEY, POLICY_SOURCE_TRUST_KEY, SCOPED_READ_EFFECTOR_CORE_READ,
    SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY, SOURCE_TRUST_RECEIPTED_KEY, SOURCE_TRUST_WARNED_KEY,
};
use crate::claim::{ClaimSource, ScopedReadActorKey, UNSTAMPED_CLAIM_SENSITIVITY_BAND};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::store::Store;
use crate::{EntityId, Vault};

const DREAMER_ACTOR_CLASS: &str = "system";

/// What the live policy lets the vault's Dreamer do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DreamerWeaveReach {
    /// A receipt-free read grant covering every record names the Dreamer.
    pub reads: bool,
    /// An Auto actor ceiling plus the Dreamer-bound `Generated` permit.
    pub lands_auto: bool,
}

impl DreamerWeaveReach {
    /// Both halves: a pass can read its sources and land what it consolidates.
    #[must_use]
    pub const fn ready(self) -> bool {
        self.reads && self.lands_auto
    }
}

fn invalid(reason: &'static str) -> Error {
    Error::InvariantViolation(reason)
}

fn reach_in(
    policy: &super::PolicyManifestResolution,
    key: &ScopedReadActorKey,
    actor_ref: &str,
) -> DreamerWeaveReach {
    DreamerWeaveReach {
        reads: policy.reads_whole_vault(key),
        lands_auto: policy.lands_generated_auto(DREAMER_ACTOR_CLASS, actor_ref),
    }
}

/// The trusted pack the grant edits, and its body: the one owner-authored
/// pack, else the seeded default, else (a vault with no trusted pack) the
/// shipped default at its id.
fn grant_target(store: &Store, txn: &heed::RoTxn<'_>) -> Result<(EntityId, Vec<u8>)> {
    let default_id = super::default_policy_manifest_id()?;
    let mut owner_packs = Vec::new();
    let mut seeded = None;
    for index_entry in store.port_entity_ids_by_type(txn, ENTITY_TYPE_POLICY_MANIFEST, None)? {
        let id = index_entry?;
        let Some(raw) = store.port_entity_record(txn, &id)? else {
            continue;
        };
        if raw.entity_type != ENTITY_TYPE_POLICY_MANIFEST
            || super::project_depth::is_project_depth_id(&id)
            || super::project_depth::is_project_depth_contribution(&raw.body)
            || super::manifest_authenticity::manifest_is_quarantined(store, txn, &id, &raw.body)?
            || !super::manifest_authenticity::manifest_is_trusted(store, txn, &id, &raw.body)?
        {
            continue;
        }
        if super::manifest_authenticity::manifest_is_seeded_default(store, txn, &id, &raw.body)? {
            seeded = Some((id, raw.body));
        } else {
            owner_packs.push((id, raw.body));
        }
    }
    if owner_packs.len() > 1
        && let Some(index) = owner_packs.iter().position(|(id, _)| *id == default_id)
    {
        return Ok(owner_packs.swap_remove(index));
    }
    match (owner_packs.len(), seeded) {
        (1, _) => Ok(owner_packs.remove(0)),
        (0, Some(seeded)) => Ok(seeded),
        (0, None) => Ok((default_id, super::default_policy_manifest()?)),
        _ => Err(Error::InvalidConfig(
            "the Dreamer grant has no unique owner policy pack to edit".into(),
        )),
    }
}

impl Vault {
    /// Reads the folded policy once. Never writes beyond seeding the Dreamer
    /// principal, which `dreamer_authority` does on first use.
    pub fn dreamer_weave_reach(&self) -> Result<DreamerWeaveReach> {
        let actor_ref = self.dreamer_authority()?.entity_ref().to_hex();
        let key = ScopedReadActorKey::with_actor_class(actor_ref.clone(), DREAMER_ACTOR_CLASS)
            .ok_or_else(|| invalid("dreamer read key"))?;
        let txn = self.store.env.read_txn()?;
        let policy = super::resolve_policy_manifest(&self.store, &txn)?;
        Ok(reach_in(&policy, &key, &actor_ref))
    }

    /// Owner act: adds the Dreamer's three rows to one trusted policy pack.
    /// Returns whether the policy changed; refuses, changing nothing, when
    /// the edit would not let the Dreamer work or would move other policy.
    pub fn grant_dreamer_weave(&self, owner: &AuthenticatedOwner, now: u64) -> Result<bool> {
        let actor_ref = self.dreamer_authority()?.entity_ref().to_hex();
        let key = ScopedReadActorKey::with_actor_class(actor_ref.clone(), DREAMER_ACTOR_CLASS)
            .ok_or_else(|| invalid("dreamer read key"))?;
        let mut txn = self.store.env.write_txn()?;
        let (id, body) = grant_target(&self.store, &txn)?;
        let Some(data) = with_dreamer_rows(&body, &actor_ref)? else {
            return Ok(false);
        };
        let before = super::resolve_policy_manifest(&self.store, &txn)?;
        let retention = super::resolve_gate_decision_retention(&self.store, &txn)?;
        self.write_owner_policy_manifest_in_txn(owner, &mut txn, id, data, now)?;
        let after = super::resolve_policy_manifest(&self.store, &txn)?;
        let moved_other_policy = after.is_fail_closed()
            || after.diagnostics().loaded_manifest_forces_fail_closed()
            || after.carry_forward_confidence != before.carry_forward_confidence
            || super::resolve_gate_decision_retention(&self.store, &txn)? != retention;
        if moved_other_policy || !reach_in(&after, &key, &actor_ref).ready() {
            // Dropping the transaction leaves the policy as it was.
            return Err(Error::InvalidConfig(
                "the Dreamer grant would not take without changing other policy; \
                 the owner's policy rows keep the Dreamer out or conflict"
                    .into(),
            ));
        }
        txn.commit()?;
        Ok(true)
    }
}

/// The value under `key`, inserted as `Nil` when absent.
fn entry_mut<'a>(entries: &'a mut Vec<(Value, Value)>, key: &str) -> &'a mut Value {
    let index = match entries
        .iter()
        .position(|(name, _)| name.as_str() == Some(key))
    {
        Some(index) => index,
        None => {
            entries.push((Value::from(key), Value::Nil));
            entries.len() - 1
        }
    };
    &mut entries[index].1
}

fn names_actor(row: &Value, actor_ref: &str) -> bool {
    row.as_map().is_some_and(|fields| {
        fields.iter().any(|(name, field)| {
            name.as_str() == Some(ACTOR_REF_KEY) && field.as_str() == Some(actor_ref)
        })
    })
}

/// Adds `row` to the list (a lone row becomes a one-row list) unless a row
/// already names the Dreamer. Returns whether it added.
fn push_unless_bound(list: &mut Value, actor_ref: &str, row: Value) -> Result<bool> {
    let mut rows = match std::mem::replace(list, Value::Nil) {
        Value::Nil => Vec::new(),
        Value::Array(rows) => rows,
        single @ Value::Map(_) => vec![single],
        _ => return Err(invalid("policy rows are not a list")),
    };
    let added = !rows.iter().any(|existing| names_actor(existing, actor_ref));
    if added {
        rows.push(row);
    }
    *list = Value::Array(rows);
    Ok(added)
}

/// The shipped manifest with the Dreamer's rows: what a fresh vault seeds.
pub(super) fn with_shipped_dreamer_rows(manifest: Vec<u8>) -> Result<Vec<u8>> {
    let actor_ref = crate::dreamer_runner::authority::dreamer_actor_id()?.to_hex();
    Ok(with_dreamer_rows(&manifest, &actor_ref)?.unwrap_or(manifest))
}

/// The live manifest with the Dreamer's rows added, or `None` when every
/// one is already there.
fn with_dreamer_rows(live: &[u8], actor_ref: &str) -> Result<Option<Vec<u8>>> {
    let Value::Map(mut entries) =
        rmpv::decode::read_value(&mut &live[..]).map_err(|_| invalid("decode live policy"))?
    else {
        return Err(invalid("live policy is not a map"));
    };
    let mut changed = push_unless_bound(
        entry_mut(&mut entries, POLICY_ACTOR_CEILINGS_KEY),
        actor_ref,
        Value::Map(vec![
            (
                Value::from(ACTOR_CLASS_KEY),
                Value::from(DREAMER_ACTOR_CLASS),
            ),
            (Value::from(ACTOR_REF_KEY), Value::from(actor_ref)),
            (Value::from(ACTOR_CEILING_KEY), Value::from("auto")),
        ]),
    )?;
    changed |= push_unless_bound(
        entry_mut(&mut entries, POLICY_SCOPED_GRANTS_KEY),
        actor_ref,
        Value::Map(vec![
            (Value::from(ACTOR_REF_KEY), Value::from(actor_ref)),
            (
                Value::from(ACTOR_CLASS_KEY),
                Value::from(DREAMER_ACTOR_CLASS),
            ),
            (
                Value::from("effector"),
                Value::from(SCOPED_READ_EFFECTOR_CORE_READ),
            ),
            (
                Value::from("scope"),
                crate::federation::scope_codec::encode_scope_value(
                    &crate::federation::scope_codec::read_preset(),
                )?,
            ),
            (Value::from("receipt_required"), Value::Boolean(false)),
        ]),
    )?;
    let sources = entry_mut(&mut entries, POLICY_SOURCE_TRUST_KEY);
    if matches!(sources, Value::Nil) {
        *sources = Value::Map(Vec::new());
    }
    let Value::Map(sources) = sources else {
        return Err(invalid("live source trust is not a map"));
    };
    // The Dreamer's permit sits beside any row already bound to another
    // writer; decode keeps each binding in its own slot.
    changed |= push_unless_bound(
        entry_mut(sources, ClaimSource::Generated.as_str()),
        actor_ref,
        Value::Map(vec![
            (Value::from(ACTOR_REF_KEY), Value::from(actor_ref)),
            (
                Value::from(SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY),
                Value::from(u64::from(UNSTAMPED_CLAIM_SENSITIVITY_BAND)),
            ),
            (
                Value::from(SOURCE_TRUST_RECEIPTED_KEY),
                Value::Boolean(true),
            ),
            (Value::from(SOURCE_TRUST_WARNED_KEY), Value::Boolean(true)),
        ]),
    )?;
    if !changed {
        return Ok(None);
    }
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &Value::Map(entries))
        .map_err(|_| invalid("encode dreamer weave grant"))?;
    Ok(Some(data))
}
