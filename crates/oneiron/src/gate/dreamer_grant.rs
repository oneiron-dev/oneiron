//! The owner's weave grant to the vault's own Dreamer, and the read-only
//! probe hosts check before they start passes.
//!
//! ARCH-0026 has the Dreamer warm by default: routine reversible work runs
//! automatically. The shipped manifest keeps class `system` default-deny and
//! `Generated` output pending, so a stock vault's Dreamer can read nothing
//! and land nothing: its attempts park on "prepared source not readable".
//!
//! The grant is one owner-installed trusted pack: a copy of the shipped
//! manifest whose only additions are keyed to the vault's Dreamer authority —
//! a read-only scoped grant, an Auto actor ceiling, and the `Generated`
//! permit its consolidation lineage needs — the same narrow, actor-keyed
//! shape as the shipped commitment-projector rows. Every copied row equals
//! its shipped twin, so the fold narrows nothing else; no other present or
//! future system actor, and no other `Generated` writer, inherits anything.
//!
//! Reversal: the owner replaces or removes the pack. Hosts that probe
//! [`Vault::dreamer_weave_reach`] stop admitting passes; claims already landed
//! stand as written history.
use rmpv::Value;

use super::PolicyApprovalCeiling;
use super::constants::{
    ACTOR_CEILING_KEY, ACTOR_CLASS_KEY, ACTOR_REF_KEY, POLICY_ACTOR_CEILINGS_KEY,
    POLICY_PACK_ID_KEY, POLICY_SCOPED_GRANTS_KEY, POLICY_SOURCE_TRUST_KEY,
    SCOPED_READ_EFFECTOR_CORE_READ,
};
use super::grants::{scoped_read_actor_matches, scoped_read_grant_has_read_effector};
use crate::Vault;
use crate::claim::{ClaimSource, ScopedReadActorKey};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};

/// The grant pack's one stable id: re-granting replaces it in place.
const DREAMER_WEAVE_GRANT_ID: [u8; ENTITY_ID_LEN] = [0xD8; ENTITY_ID_LEN];
const DREAMER_WEAVE_GRANT_PACK_ID: &str = "dreamer-weave-grant";
const DREAMER_ACTOR_CLASS: &str = "system";

/// What the live policy lets the vault's Dreamer do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DreamerWeaveReach {
    /// A receipt-free read grant covers the Dreamer's own key.
    pub reads: bool,
    /// The Dreamer's actor ceiling resolves to Auto.
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
        let reads = !policy.is_fail_closed()
            && policy.scoped_grants().iter().any(|grant| {
                scoped_read_grant_has_read_effector(grant)
                    && scoped_read_actor_matches(grant, &key)
                    && !grant.receipt_required
                    && grant.budget.is_none()
            });
        let lands_auto = policy.actor_ceiling(DREAMER_ACTOR_CLASS, Some(&actor_ref))
            == PolicyApprovalCeiling::Auto;
        Ok(DreamerWeaveReach { reads, lands_auto })
    }

    /// Owner act: installs (or refreshes) the Dreamer's weave grant pack.
    /// Returns the pack's id.
    pub fn grant_dreamer_weave(&self, owner: &AuthenticatedOwner, now: u64) -> Result<EntityId> {
        let actor_ref = self.dreamer_authority()?.entity_ref().to_hex();
        let id = EntityId::from_bytes(DREAMER_WEAVE_GRANT_ID)?;
        let data = dreamer_weave_pack(&actor_ref)?;
        self.install_owner_policy_manifest(owner, id, data, now)?;
        Ok(id)
    }
}

fn entry_mut<'a>(entries: &'a mut [(Value, Value)], key: &str) -> Option<&'a mut Value> {
    entries
        .iter_mut()
        .find_map(|(name, value)| (name.as_str() == Some(key)).then_some(value))
}

/// The shipped manifest with the Dreamer-keyed additions and nothing else.
fn dreamer_weave_pack(actor_ref: &str) -> Result<Vec<u8>> {
    let shipped = super::default_policy_manifest()?;
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut shipped.as_slice())
        .map_err(|_| invalid("decode shipped policy"))?
    else {
        return Err(invalid("shipped policy is not a map"));
    };
    *entry_mut(&mut entries, POLICY_PACK_ID_KEY).ok_or_else(|| invalid("shipped pack id"))? =
        Value::from(DREAMER_WEAVE_GRANT_PACK_ID);
    let Some(Value::Array(ceilings)) = entry_mut(&mut entries, POLICY_ACTOR_CEILINGS_KEY) else {
        return Err(invalid("shipped actor ceilings"));
    };
    ceilings.push(Value::Map(vec![
        (
            Value::from(ACTOR_CLASS_KEY),
            Value::from(DREAMER_ACTOR_CLASS),
        ),
        (Value::from(ACTOR_REF_KEY), Value::from(actor_ref)),
        (Value::from(ACTOR_CEILING_KEY), Value::from("auto")),
    ]));
    // The shipped `Generated` row is bound to one other derived writer; this
    // copy rebinds it to the Dreamer. The fold keeps distinct bindings in
    // disjoint slots, so each writer keeps exactly its own permit.
    let Some(Value::Map(sources)) = entry_mut(&mut entries, POLICY_SOURCE_TRUST_KEY) else {
        return Err(invalid("shipped source trust"));
    };
    let Some(Value::Map(generated)) = entry_mut(sources, ClaimSource::Generated.as_str()) else {
        return Err(invalid("shipped generated permit"));
    };
    *entry_mut(generated, ACTOR_REF_KEY).ok_or_else(|| invalid("generated permit binding"))? =
        Value::from(actor_ref);
    let read_grant = Value::Map(vec![
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
    ]);
    match entry_mut(&mut entries, POLICY_SCOPED_GRANTS_KEY) {
        Some(Value::Array(grants)) => grants.push(read_grant),
        Some(_) => return Err(invalid("shipped scoped grants")),
        None => entries.push((
            Value::from(POLICY_SCOPED_GRANTS_KEY),
            Value::Array(vec![read_grant]),
        )),
    }
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &Value::Map(entries))
        .map_err(|_| invalid("encode dreamer weave grant"))?;
    Ok(data)
}
