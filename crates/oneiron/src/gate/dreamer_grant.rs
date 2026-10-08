//! The owner's weave grant to the vault's own Dreamer, and the read-only
//! probe hosts check before they start passes.
//!
//! ARCH-0026 has the Dreamer warm by default: routine reversible work runs
//! automatically. The shipped manifest keeps class `system` default-deny and
//! `Generated` output pending, so a stock vault's Dreamer can read nothing
//! and land nothing: its attempts park on "prepared source not readable".
//!
//! The grant is an owner edit of the vault's own live policy manifest, in
//! place: it adds three rows, each keyed to the vault's Dreamer authority —
//! a vault-wide read-only scoped grant, an Auto actor ceiling, and the
//! `Generated` permit its consolidation lineage needs — in the same narrow,
//! actor-keyed shape as the shipped commitment-projector rows. Every other
//! row, including the owner's earlier edits, is kept exactly as it was, so no
//! other present or future system actor, and no other `Generated` writer,
//! inherits anything. Re-granting changes nothing.
//!
//! Reversal: the owner removes the three rows. Hosts that probe
//! [`Vault::dreamer_weave_reach`] stop admitting passes; claims already landed
//! stand as written history.
use rmpv::Value;

use super::constants::{
    ACTOR_CEILING_KEY, ACTOR_CLASS_KEY, ACTOR_REF_KEY, POLICY_ACTOR_CEILINGS_KEY,
    POLICY_SCOPED_GRANTS_KEY, POLICY_SOURCE_TRUST_KEY, SCOPED_READ_EFFECTOR_CORE_READ,
    SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY, SOURCE_TRUST_RECEIPTED_KEY, SOURCE_TRUST_WARNED_KEY,
};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimSource, ScopedReadActorKey, UNSTAMPED_CLAIM_SENSITIVITY_BAND};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;

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

impl Vault {
    /// Reads the folded policy once. Never writes beyond seeding the Dreamer
    /// principal, which `dreamer_authority` does on first use.
    pub fn dreamer_weave_reach(&self) -> Result<DreamerWeaveReach> {
        let actor_ref = self.dreamer_authority()?.entity_ref().to_hex();
        let key = ScopedReadActorKey::with_actor_class(actor_ref.clone(), DREAMER_ACTOR_CLASS)
            .ok_or_else(|| invalid("dreamer read key"))?;
        let txn = self.store.env.read_txn()?;
        let policy = super::resolve_policy_manifest(&self.store, &txn)?;
        Ok(DreamerWeaveReach {
            reads: policy.reads_whole_vault(&key),
            lands_auto: policy.lands_generated_auto(DREAMER_ACTOR_CLASS, &actor_ref),
        })
    }

    /// Owner act: adds the Dreamer's three rows to the vault's live policy
    /// manifest. Returns whether the manifest changed.
    pub fn grant_dreamer_weave(&self, owner: &AuthenticatedOwner, now: u64) -> Result<bool> {
        let actor_ref = self.dreamer_authority()?.entity_ref().to_hex();
        let id = super::default_policy_manifest_id()?;
        let live = match self.get_raw(&id)? {
            Some(raw) => {
                let header =
                    EntityMetadataHeader::parse(&raw).ok_or_else(|| invalid("policy header"))?;
                if header.entity_type != ENTITY_TYPE_POLICY_MANIFEST {
                    return Err(invalid("policy id holds another type"));
                }
                raw[ENTITY_METADATA_HEADER_LEN..].to_vec()
            }
            None => super::default_policy_manifest()?,
        };
        let Some(data) = with_dreamer_rows(&live, &actor_ref)? else {
            return Ok(false);
        };
        self.install_owner_policy_manifest(owner, id, data, now)?;
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
