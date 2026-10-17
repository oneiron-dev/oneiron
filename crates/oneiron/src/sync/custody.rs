//! OF-422: owner-signed custody transitions on the window plane (ARCH-0069
//! `#custody-seal-planned`).
//!
//! A custody record never rides a window; its transition does, in the base
//! window's `custody` map under the record's id, in the window of the month it
//! was signed in. The month a transition was signed in is the month its door
//! ran, so a fresh transition lands in a window every peer holds open.
//!
//! - Admission refuses every insert into the map that is not a whole
//!   transition signed for this vault, in the latest state, at a snapshot's
//!   root and in every retained operation.
//! - Reverse rematerialization mirrors the transitions this vault signed.
//! - Forward rematerialization and Observer B judge each signer against this
//!   vault's folded roster as it is now, and write what stands into this
//!   vault's custody through the local door, with the value this machine
//!   opens. A machine the value was not sealed to keeps the transition unread.

use loro::event::MapDelta;
use loro::{LoroDoc, LoroMap, LoroValue, ValueOrContainer};

use super::loro_support::{map_get_bytes, map_insert_bytes};
use super::types::WindowKey;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::secret_custody::{
    CustodyApplied, CustodyTransition, apply_custody_transition_in_txn, custody_transitions,
};

/// The base window root map that carries custody transitions.
pub(crate) const CUSTODY_MAP: &str = "custody";

/// The window a transition rides: the base month it was signed in.
pub(crate) fn transition_window(transition: &CustodyTransition) -> WindowKey {
    WindowKey::from_timestamp(transition.signed_at)
}

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("custody transition refused: {reason}"))
}

/// Admits one insert into window `key`'s custody map: a whole transition
/// signed for this vault, filed under its record's id, in its signing month's
/// base window. Whether its signer is the owner's is judged where it is
/// written ([`apply_carriers`]), so a window keeps relaying one whose signer
/// the roster later drops. Without a vault, nothing is admitted.
pub(crate) fn admit_custody_carrier(
    vault: Option<&Vault>,
    key: Option<&WindowKey>,
    map_key: &str,
    value: &LoroValue,
) -> Result<()> {
    let Some(vault) = vault else {
        return Err(refused("no vault to judge the signer by"));
    };
    let LoroValue::Binary(bytes) = value else {
        return Err(refused("not bytes"));
    };
    let transition = CustodyTransition::decode(bytes)?;
    if transition.id.to_hex() != map_key {
        return Err(refused("filed under another id"));
    }
    if key.is_some_and(|key| *key != transition_window(&transition)) {
        return Err(refused("outside its signing month's base window"));
    }
    let rtxn = vault.store.env.read_txn()?;
    let vault_id = vault
        .authority_view_readonly_in_txn(&rtxn)?
        .vault_id
        .ok_or_else(|| refused("the vault has no authority genesis"))?;
    transition.verify_signed(&vault_id)
}

/// [`admit_custody_carrier`] over every row `map` holds.
pub(crate) fn admit_custody_map(
    vault: Option<&Vault>,
    key: Option<&WindowKey>,
    map: &LoroMap,
) -> Result<()> {
    let mut rows = Vec::new();
    let mut nested = false;
    map.for_each(|map_key, value| match value {
        ValueOrContainer::Value(value) => rows.push((map_key.to_owned(), value)),
        ValueOrContainer::Container(_) => nested = true,
    });
    if nested {
        return Err(refused("nested container"));
    }
    for (map_key, value) in &rows {
        admit_custody_carrier(vault, key, map_key, value)?;
    }
    Ok(())
}

/// Writes into `doc` the latest transition this vault signed of each
/// credential whose transition rides window `key`, never over a later one
/// the window already holds. Returns whether it wrote any; the caller
/// commits.
pub(crate) fn mirror_custody_transitions(
    vault: &Vault,
    doc: &LoroDoc,
    key: &WindowKey,
) -> Result<bool> {
    if key.world().is_some() {
        return Ok(false);
    }
    let mut due = Vec::new();
    for (id, carrier) in custody_transitions(vault)? {
        if let Ok(transition) = CustodyTransition::decode(&carrier)
            && transition_window(&transition) == *key
        {
            due.push((id, carrier, transition.order()));
        }
    }
    if due.is_empty() {
        return Ok(false);
    }
    let map = doc.get_map(CUSTODY_MAP);
    let mut wrote = false;
    for (id, carrier, order) in due {
        let hex = id.to_hex();
        let held = map_get_bytes(&map, &hex);
        if held.as_deref() == Some(carrier.as_slice())
            || held
                .and_then(|held| CustodyTransition::decode(&held).ok())
                .is_some_and(|held| held.order() >= order)
        {
            continue;
        }
        map_insert_bytes(&map, &hex, &carrier)?;
        wrote = true;
    }
    Ok(wrote)
}

/// Writes every transition window `key`'s document holds into this vault's
/// custody, as a window open does. A transition that fails is logged and
/// left; it never stops the open.
pub(crate) fn apply_custody_map(vault: &Vault, doc: &LoroDoc, key: &WindowKey) {
    if key.world().is_some() {
        return;
    }
    // Looking a root up by name creates it: look first.
    let LoroValue::Map(roots) = doc.get_value() else {
        return;
    };
    if !roots.contains_key(CUSTODY_MAP) {
        return;
    }
    let mut rows = Vec::new();
    doc.get_map(CUSTODY_MAP).for_each(|map_key, value| {
        if let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value {
            rows.push((map_key.to_owned(), bytes.to_vec()));
        }
    });
    apply_carriers(vault, key.as_str(), rows);
}

/// Observer B for the custody map: each transition an import changed.
pub(crate) fn materialize_custody_from_delta(
    _doc: &LoroDoc,
    delta: &MapDelta<'_>,
    vault: &Vault,
    window_key: &str,
    _lease_vault_id: u64,
) -> Option<Vec<EntityId>> {
    let rows = delta
        .updated
        .iter()
        .filter_map(|(key, value)| match value {
            Some(ValueOrContainer::Value(LoroValue::Binary(bytes))) => {
                Some((key.to_string(), bytes.to_vec()))
            }
            _ => None,
        })
        .collect();
    apply_carriers(vault, window_key, rows);
    Some(Vec::new())
}

/// Judges each carrier against this vault's folded roster, opens the value
/// sealed to this machine, and writes what stands through the custody door.
fn apply_carriers(vault: &Vault, window: &str, rows: Vec<(String, Vec<u8>)>) {
    if rows.is_empty() {
        return;
    }
    // The keystore is read before any transaction opens. A host that is not
    // one of the owner's machines has no secret, and keeps every value sealed.
    let secret = vault.machine_secret_outside_txn().ok();
    let outcome = (|| -> Result<usize> {
        let judged = {
            let rtxn = vault.store.env.read_txn()?;
            let fold = vault.authority_view_readonly_in_txn(&rtxn)?;
            let mut judged = Vec::new();
            for (map_key, bytes) in &rows {
                let transition = match CustodyTransition::decode(bytes) {
                    Ok(transition) if transition.id.to_hex() == *map_key => transition,
                    _ => {
                        tracing::warn!(window, key = %map_key, "custody transition malformed; left out");
                        continue;
                    }
                };
                if let Err(error) = transition.verify(&fold) {
                    tracing::warn!(window, key = %map_key, error = %error, "custody transition does not stand here; left out");
                    continue;
                }
                let value = match (&secret, fold.vault_id) {
                    (Some(secret), Some(vault_id)) => {
                        transition.open_value(&vault_id, secret.machine, &secret.secret)
                    }
                    _ => None,
                };
                judged.push((transition, value));
            }
            judged
        };
        vault.with_write_txn_grouped(|wtxn| {
            let mut written = 0;
            for (transition, value) in &judged {
                let value = value.as_ref().map(|value| value.as_slice());
                if apply_custody_transition_in_txn(
                    vault,
                    wtxn,
                    transition,
                    value,
                    transition.signed_at,
                )? == CustodyApplied::Written
                {
                    written += 1;
                }
            }
            Ok(written)
        })
    })();
    match outcome {
        Ok(written) if written > 0 => {
            tracing::debug!(window, written, "custody transitions applied");
        }
        Ok(_) => {}
        Err(error) => {
            tracing::warn!(window, error = %error, "custody transitions not applied");
        }
    }
}

impl Vault {
    /// Mirrors this vault's custody transitions into the live window they
    /// ride, after the door that wrote one committed (OF-422). Best effort:
    /// a window opened later mirrors them as it opens.
    pub(crate) fn refresh_custody_in_live_window(&self, transition: &CustodyTransition) {
        let key = transition_window(transition);
        let Some((window, _, _)) = self.live_window(&key) else {
            return;
        };
        match mirror_custody_transitions(self, &window.doc, &window.key) {
            Ok(true) => {
                window
                    .doc
                    .commit_with(loro::CommitOptions::new().origin(super::bridge::BRIDGE_ORIGIN));
            }
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(window = %window.key, error = %error, "custody transition not mirrored");
            }
        }
    }
}
