//! What a restore or an activation needs of its body instances' custody
//! (KS-2A), read off raw `vault_meta` rows before anything is made: every
//! instance a row names is required through the shared custody plan, which
//! the claim keys' rows use too, so one fork copies both. A live instance is
//! landed and read back; a retired one (an erase destroyed it, or committed
//! to) takes its rows with it; a missing one is lost custody, and refuses
//! the restore by name (`body_key_custody_unavailable`): no key is minted
//! for it and no image key stands in.

use std::collections::BTreeSet;

use super::custody::{custody_unavailable, instance_id, instance_state};
use super::response::{RESPONSE_BINDINGS, ResponseBinding};
use super::retention::INLINE_ASSETS;
use super::rows::BODY_KEYS;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::SideKey;
use crate::store::key_custody::{CustodyPlan, EntryState, Requirement};

type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// Every body instance raw `vault_meta` rows name: a file's or an inline
/// result's instance row, an inline ASSET's binding, and a row-held
/// response's binding (KS-2B1). An obligation names no required body.
///
/// # Errors
///
/// A row that does not decode.
pub(crate) fn body_instances_in_rows(rows: &[(Vec<u8>, Vec<u8>)]) -> Result<BTreeSet<[u8; 16]>> {
    let mut instances = BTreeSet::new();
    for (key, value) in rows {
        if key.starts_with(BODY_KEYS.decl().prefix) {
            instances.insert(BODY_KEYS.decode_value(value)?.instance);
        } else if key.starts_with(INLINE_ASSETS.decl().prefix) {
            instances.insert(INLINE_ASSETS.decode_value(value)?);
        } else if key.starts_with(RESPONSE_BINDINGS.decl().prefix) {
            instances.insert(ResponseBinding::of_row(value)?.instance);
        }
    }
    Ok(instances)
}

/// Requires each of `instances` through `plan`, whose source custody the
/// rows bind: the retired ones, whose rows the caller prunes. Refuses with
/// `body_key_custody_unavailable`, naming how many, when any is missing.
///
/// # Errors
///
/// `body_key_custody_unavailable`, and custody's errors.
pub(crate) fn require_body_instances(
    instances: &BTreeSet<[u8; 16]>,
    plan: &mut CustodyPlan,
) -> Result<BTreeSet<[u8; 16]>> {
    if instances.is_empty() {
        return Ok(BTreeSet::new());
    }
    let Some(source) = plan.source().cloned() else {
        return Err(custody_unavailable(instances.len()));
    };
    let mut retired = BTreeSet::new();
    let mut missing = 0usize;
    for instance in instances {
        match plan.require(&instance_id(&source, instance)?) {
            Ok(Requirement::Live) => {}
            Ok(Requirement::Retired) => {
                retired.insert(*instance);
            }
            Err(error) => {
                if instance_state(&source, instance)? != EntryState::Missing {
                    return Err(error);
                }
                missing = missing.saturating_add(1);
            }
        }
    }
    if missing > 0 {
        return Err(custody_unavailable(missing));
    }
    Ok(retired)
}

/// What a prune took from raw rows: the digests whose instance rows went,
/// the entities whose inline ASSET binding went, and the carriers whose
/// row-held response binding went (KS-2B1).
#[derive(Default)]
pub(crate) struct PrunedBodies {
    pub(crate) digests: BTreeSet<[u8; 32]>,
    pub(crate) assets: BTreeSet<EntityId>,
    pub(crate) responses: BTreeSet<Vec<u8>>,
}

impl PrunedBodies {
    /// The full `vault_meta` keys of the rows the prune takes: each pruned
    /// digest's instance row and result row, each pruned ASSET's binding,
    /// each pruned response's binding.
    pub(crate) fn row_keys(&self) -> BTreeSet<Vec<u8>> {
        self.digests
            .iter()
            .flat_map(|digest| {
                [
                    BODY_KEYS.key_bytes(digest),
                    crate::code_run::code_run_body_row_key(digest),
                ]
            })
            .chain(
                self.assets
                    .iter()
                    .map(|entity| INLINE_ASSETS.key_bytes(entity)),
            )
            .chain(
                self.responses
                    .iter()
                    .map(|carrier| RESPONSE_BINDINGS.key_bytes(carrier)),
            )
            .collect()
    }
}

/// Takes the rows of every `retired` instance out of raw `vault_meta`
/// rows, as the erase that retired it took them from its vault: its
/// instance row, an inline result's row and every descriptor holding its
/// digest, which stays explicitly incomplete with nothing to show, never an
/// unreadable complete body; an inline ASSET's binding, whose entity the
/// caller leaves its shell; and a row-held response's binding, whose row
/// the caller leaves its erased disposition. Rows stay in order.
///
/// # Errors
///
/// A row that does not decode.
pub(crate) fn prune_retired_bodies_in_rows(
    rows: &mut Rows,
    retired: &BTreeSet<[u8; 16]>,
) -> Result<PrunedBodies> {
    let mut pruned = PrunedBodies::default();
    if retired.is_empty() {
        return Ok(pruned);
    }
    for (key, value) in rows.iter() {
        if let Some(digest) = key
            .strip_prefix(BODY_KEYS.decl().prefix)
            .and_then(<[u8; 32]>::decode_key)
            && retired.contains(&BODY_KEYS.decode_value(value)?.instance)
        {
            pruned.digests.insert(digest);
        } else if let Some(entity) = key
            .strip_prefix(INLINE_ASSETS.decl().prefix)
            .and_then(EntityId::decode_key)
            && retired.contains(&INLINE_ASSETS.decode_value(value)?)
        {
            pruned.assets.insert(entity);
        } else if let Some(carrier) = key.strip_prefix(RESPONSE_BINDINGS.decl().prefix)
            && retired.contains(&ResponseBinding::of_row(value)?.instance)
        {
            pruned.responses.insert(carrier.to_vec());
        }
    }
    let gone = pruned.row_keys();
    rows.retain(|(key, _)| !gone.contains(key));
    for digest in &pruned.digests {
        crate::provenance::body::prune_digest_in_rows(rows, digest)?;
    }
    Ok(pruned)
}
