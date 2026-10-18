//! OF-422: custody transitions on the window plane (ARCH-0069
//! `#custody-seal-planned`), each enacting an admitted custody request (WILL
//! L04 row 04).
//!
//! A custody record never rides a window; its transition does, in the base
//! window's `custody` map under the record's id, in the window of the month it
//! was signed in. The month a transition was signed in is the month its door
//! ran, so a fresh transition lands in a window every peer holds open. The
//! protected input an active change hands its holder rides beside the
//! transitions as a row of its own, keyed `input:` and its ciphertext
//! digest, in the window of the month it was sealed in: never inside a
//! transition.
//!
//! - Admission refuses every insert into the map that is not a whole
//!   transition signed for this vault, or a whole input filed under its own
//!   digest, in the latest state, at a snapshot's root and in every retained
//!   operation.
//! - Reverse rematerialization mirrors the latest transition this vault holds
//!   of each record, and drops from an older window the carrier it
//!   supersedes; it relays each input this vault keeps while its request
//!   awaits the holder, and drops an input row once the request is answered.
//! - Forward rematerialization and Observer B judge each transition against
//!   this vault's fold as it is now: the request it enacts counts, its named
//!   executor signed it, and it carries exactly the request's generation,
//!   input and permits (CALLS CUSTODY_PAYLOAD). What stands is written into
//!   this vault's custody through the local door, judged again in the
//!   committing transaction, with the value this machine opens. A machine
//!   the value was not sealed to keeps the transition unread. The holder a
//!   pending request names keeps the input it names.
//! - A machine the roster gains gets no value on its own: only a rewrap the
//!   owner records permits it (CALLS CUSTODY_PERMITS).

use loro::event::MapDelta;
use loro::{LoroDoc, LoroMap, LoroValue, ValueOrContainer};

use std::collections::BTreeSet;

use super::loro_support::{map_delete, map_get_bytes, map_insert_bytes};
use super::types::WindowKey;
use crate::Vault;
use crate::authority::{AuthorityFold, OwnerWorkBody};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::secret_custody::{
    CustodyApplied, CustodyTransition, RelayedInput, apply_custody_transition_in_txn,
    custody_transitions, held_inputs, keep_input_in_txn, remember_custody_transition_in_txn,
};

/// The base window root map that carries custody transitions and inputs.
pub(crate) const CUSTODY_MAP: &str = "custody";

/// The key prefix of a protected input's row in the custody map, before its
/// ciphertext digest in hex. A checkpoint image keeps transitions only.
pub(crate) const INPUT_ROW_PREFIX: &str = "input:";

fn input_row(digest: &[u8; 32]) -> String {
    format!("{INPUT_ROW_PREFIX}{}", bytes_to_hex_lower(digest))
}

/// Whether the request a relayed input is for still awaits its holder.
fn input_open(fold: &AuthorityFold, input: &RelayedInput) -> bool {
    fold.owner_work_request(&input.request).is_some()
        && fold.owner_work_result(&input.request).is_none()
}

/// The window a transition rides: the base month it was signed in.
pub(crate) fn transition_window(transition: &CustodyTransition) -> WindowKey {
    WindowKey::from_timestamp(transition.signed_at)
}

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("custody transition refused: {reason}"))
}

/// Admits one insert into window `key`'s custody map: a whole transition
/// signed for this vault, filed under its record's id, in its signing month's
/// base window, or a whole input filed under its digest in its sealing
/// month's. Whether a transition's request stands is judged where it is
/// written ([`apply_carriers`]), so a window keeps relaying one whose request
/// this vault has not folded yet. Without a vault, nothing is admitted.
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
    if let Some(digest) = map_key.strip_prefix(INPUT_ROW_PREFIX) {
        let input = RelayedInput::decode(bytes).ok_or_else(|| refused("malformed input"))?;
        if bytes_to_hex_lower(&input.digest()) != digest {
            return Err(refused("input filed under another digest"));
        }
        if key.is_some_and(|key| *key != WindowKey::from_timestamp(input.sealed_at)) {
            return Err(refused("input outside its sealing month's base window"));
        }
        return Ok(());
    }
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
    let mut wrote = mirror_custody_inputs(vault, doc, key)?;
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

/// Relays each input this vault keeps into window `key`, the base window of
/// its sealing month, while its request awaits the holder, and drops from
/// the window every input row whose request is answered. Returns whether it
/// wrote any.
fn mirror_custody_inputs(vault: &Vault, doc: &LoroDoc, key: &WindowKey) -> Result<bool> {
    let kept = held_inputs(vault)?;
    let holds = holds_custody_map(doc);
    if kept.is_empty() && !holds {
        return Ok(false);
    }
    let fold = {
        let rtxn = vault.store.env.read_txn()?;
        vault.authority_view_readonly_in_txn(&rtxn)?
    };
    let mut wrote = false;
    for (digest, bytes) in kept {
        let Some(input) = RelayedInput::decode(&bytes) else {
            continue;
        };
        if WindowKey::from_timestamp(input.sealed_at) != *key || !input_open(&fold, &input) {
            continue;
        }
        let map = doc.get_map(CUSTODY_MAP);
        let row = input_row(&digest);
        if map_get_bytes(&map, &row).as_deref() != Some(bytes.as_slice()) {
            map_insert_bytes(&map, &row, &bytes)?;
            wrote = true;
        }
    }
    if holds {
        let map = doc.get_map(CUSTODY_MAP);
        let mut answered = Vec::new();
        map.for_each(|map_key, value| {
            if !map_key.starts_with(INPUT_ROW_PREFIX) {
                return;
            }
            if let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value
                && RelayedInput::decode(&bytes).is_some_and(|input| !input_open(&fold, &input))
            {
                answered.push(map_key.to_owned());
            }
        });
        for row in answered {
            map_delete(&map, &row)?;
            wrote = true;
        }
    }
    Ok(wrote)
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

/// Judges each carrier against this vault's fold, opens the value sealed to
/// this machine, and writes what stands through the custody door. Each that
/// stands is kept as the record's latest when it supersedes the one this
/// vault holds. Input rows go to [`keep_relayed_inputs`].
fn apply_carriers(vault: &Vault, window: &str, rows: Vec<(String, Vec<u8>)>) {
    let (inputs, rows): (Vec<_>, Vec<_>) = rows
        .into_iter()
        .partition(|(map_key, _)| map_key.starts_with(INPUT_ROW_PREFIX));
    keep_relayed_inputs(vault, window, inputs);
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
                    tracing::warn!(window, key = %map_key, error = %error, "custody transition does not stand on its request here; left out");
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
                let applied = apply_custody_transition_in_txn(
                    vault,
                    wtxn,
                    transition,
                    value,
                    transition.signed_at,
                )?;
                if applied == CustodyApplied::Written {
                    written += 1;
                }
                // A carrier an admitted revoke of its id refused, or that no
                // longer stands on this transaction's fold, is not kept, so
                // it is never relayed from here (WILL L04 row 04).
                if !matches!(
                    applied,
                    CustodyApplied::Refused | CustodyApplied::Unadmitted
                ) {
                    remember_custody_transition_in_txn(vault, wtxn, transition)?;
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

/// Keeps each relayed input whose digest a pending request naming this
/// install as its holder names, so its pickup can open it. Any other input
/// row stays in the window, unread. A row that fails is logged and left.
fn keep_relayed_inputs(vault: &Vault, window: &str, rows: Vec<(String, Vec<u8>)>) {
    if rows.is_empty() {
        return;
    }
    let outcome = (|| -> Result<usize> {
        let due: Vec<RelayedInput> = {
            let rtxn = vault.store.env.read_txn()?;
            let Some(machine) = crate::identity::read_machine_id_in_txn(vault, &rtxn)? else {
                return Ok(0);
            };
            let fold = vault.authority_view_readonly_in_txn(&rtxn)?;
            let wanted: BTreeSet<[u8; 32]> = fold
                .pending_owner_work_for(machine)
                .filter_map(|(_, request)| match &request.work {
                    OwnerWorkBody::Custody {
                        input: Some(input), ..
                    } => Some(*input),
                    _ => None,
                })
                .collect();
            rows.iter()
                .filter_map(|(map_key, bytes)| {
                    let input = RelayedInput::decode(bytes)?;
                    let digest = input.digest();
                    (*map_key == input_row(&digest) && wanted.contains(&digest)).then_some(input)
                })
                .collect()
        };
        if due.is_empty() {
            return Ok(0);
        }
        vault.with_write_txn_grouped(|wtxn| {
            for input in &due {
                keep_input_in_txn(vault, wtxn, input)?;
            }
            Ok(due.len())
        })
    })();
    match outcome {
        Ok(kept) if kept > 0 => {
            tracing::debug!(window, kept, "custody inputs kept for this holder");
        }
        Ok(_) => {}
        Err(error) => {
            tracing::warn!(window, error = %error, "custody inputs not kept");
        }
    }
}

impl Vault {
    /// Mirrors this vault's latest custody transitions, and the inputs it
    /// relays, into every live base window after a door or an executor wrote
    /// one (OF-422): the window a transition rides takes it, and one it left
    /// drops the carrier it supersedes. Best effort: a window opened later
    /// catches up as it opens.
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
}
