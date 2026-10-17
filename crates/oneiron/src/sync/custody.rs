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
//! - Reverse rematerialization mirrors the latest transition this vault holds
//!   of each record, and drops from an older window the carrier it
//!   supersedes.
//! - Forward rematerialization and Observer B judge each signer against this
//!   vault's folded roster as it is now, and write what stands into this
//!   vault's custody through the local door, with the value this machine
//!   opens. A machine the value was not sealed to keeps the transition unread.
//! - A machine the roster gains gets the value from a re-seal: the latest
//!   transition signed again by a machine that holds the record, at the same
//!   generation and status ([`Vault::reseal_custody_for_roster`]).

use loro::event::MapDelta;
use loro::{LoroDoc, LoroMap, LoroValue, ValueOrContainer};

use super::loro_support::{map_delete, map_get_bytes, map_insert_bytes};
use super::types::WindowKey;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::secret_custody::{
    CustodyApplied, CustodyTransition, apply_custody_transition_in_txn, custody_transitions,
    remember_custody_transition_in_txn, reseal_custody_transitions_in_txn,
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

/// Brings window `key`'s custody map up to this vault's latest transitions.
/// One that rides the window is written unless the map holds it or one that
/// supersedes it. A record whose latest transition rides another window has
/// its carrier here dropped once that transition supersedes it, so a rotated
/// or revoked value's ciphertext stops riding the month it was signed in; a
/// closed window catches up as it opens. Returns whether it wrote any; the
/// caller commits.
pub(crate) fn mirror_custody_transitions(
    vault: &Vault,
    doc: &LoroDoc,
    key: &WindowKey,
) -> Result<bool> {
    if key.world().is_some() {
        return Ok(false);
    }
    let mut due = Vec::new();
    let mut elsewhere = Vec::new();
    for (_, carrier) in custody_transitions(vault)? {
        let Ok(latest) = CustodyTransition::decode(&carrier) else {
            continue;
        };
        if transition_window(&latest) == *key {
            due.push((latest, carrier));
        } else {
            elsewhere.push(latest);
        }
    }
    let mut wrote = false;
    if !due.is_empty() {
        let map = doc.get_map(CUSTODY_MAP);
        for (latest, carrier) in due {
            let hex = latest.id.to_hex();
            let held = map_get_bytes(&map, &hex);
            if held.as_deref() == Some(carrier.as_slice())
                || held
                    .and_then(|held| CustodyTransition::decode(&held).ok())
                    .is_some_and(|held| !latest.supersedes(&held))
            {
                continue;
            }
            map_insert_bytes(&map, &hex, &carrier)?;
            wrote = true;
        }
    }
    if !elsewhere.is_empty() && holds_custody_map(doc) {
        let map = doc.get_map(CUSTODY_MAP);
        for latest in elsewhere {
            let hex = latest.id.to_hex();
            if map_get_bytes(&map, &hex)
                .and_then(|held| CustodyTransition::decode(&held).ok())
                .is_some_and(|held| latest.supersedes(&held))
            {
                map_delete(&map, &hex)?;
                wrote = true;
            }
        }
    }
    Ok(wrote)
}

/// Copies `source`'s custody map into `target`, as an own machine's
/// promotion covers it. Copies nothing when `source` holds none.
pub(crate) fn copy_custody_map(source: &LoroDoc, target: &LoroDoc) -> Result<()> {
    if !holds_custody_map(source) {
        return Ok(());
    }
    let mut rows = Vec::new();
    source.get_map(CUSTODY_MAP).for_each(|map_key, value| {
        if let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value {
            rows.push((map_key.to_owned(), bytes.to_vec()));
        }
    });
    let map = target.get_map(CUSTODY_MAP);
    for (map_key, bytes) in rows {
        map_insert_bytes(&map, &map_key, &bytes)?;
    }
    target.commit();
    Ok(())
}

/// Whether `doc` holds a custody map. Looking a root up by name creates it:
/// look first.
fn holds_custody_map(doc: &LoroDoc) -> bool {
    matches!(doc.get_value(), LoroValue::Map(roots) if roots.contains_key(CUSTODY_MAP))
}

/// Writes every transition window `key`'s document holds into this vault's
/// custody, as a window open does. A transition that fails is logged and
/// left; it never stops the open.
pub(crate) fn apply_custody_map(vault: &Vault, doc: &LoroDoc, key: &WindowKey) {
    if key.world().is_some() || !holds_custody_map(doc) {
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
/// Each that stands is kept as the record's latest when it supersedes the one
/// this vault holds.
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
                remember_custody_transition_in_txn(vault, wtxn, transition)?;
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
    /// Mirrors this vault's latest custody transitions into every live base
    /// window after a door or a re-seal wrote one (OF-422): the window a
    /// transition rides takes it, and one it left drops the carrier it
    /// supersedes. Best effort: a window opened later catches up as it opens.
    pub(crate) fn refresh_custody_in_live_windows(&self) {
        for window in self.live_windows() {
            if window.key.world().is_some() {
                continue;
            }
            match mirror_custody_transitions(self, &window.doc, &window.key) {
                Ok(true) => {
                    window.doc.commit_with(
                        loro::CommitOptions::new().origin(super::bridge::BRIDGE_ORIGIN),
                    );
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(window = %window.key, error = %error, "custody transition not mirrored");
                }
            }
        }
    }

    /// Seals each portable credential's value again for the machines the
    /// roster gained since its latest transition, then brings the live
    /// windows up to this vault's latest transitions (OF-422). A sync lane
    /// runs it on its upkeep tick, after the authority rows it took. Returns
    /// how many it sealed again.
    pub(crate) fn reseal_custody_for_roster(&self) -> Result<usize> {
        // The install key loads before the write transaction opens.
        let _ = self.load_install_signing_if_minted();
        let at = self.now_recorded_at();
        let written =
            self.with_write_txn_grouped(|wtxn| reseal_custody_transitions_in_txn(self, wtxn, at))?;
        self.refresh_custody_in_live_windows();
        Ok(written.len())
    }
}
