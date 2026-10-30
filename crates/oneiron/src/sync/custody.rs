//! OF-422: custody transitions on the window plane (ARCH-0069
//! `#custody-seal-planned`), each enacting an admitted custody request (WILL
//! L04 row 04).
//!
//! A custody record never rides a window; its transition does, in the base
//! window's `custody` map under the record's id, each further piece of it
//! under the id and its place (CALLS `Phase2 custody pieces request bound`),
//! in the window of the month it
//! was signed in. The month a transition was signed in is the month its door
//! ran, so a fresh transition lands in a window every peer holds open. The
//! protected input an active change hands its holder rides beside the
//! transitions as a row of its own, keyed `input:` and its ciphertext
//! digest, in the window of the month it was sealed in: never inside a
//! transition. An input longer than one row carries rides as its numbered
//! parts, each a row keyed by its own part key, carrying the part list the
//! digest is over (Rule 5: split, never skip).
//!
//! - Admission refuses every insert into the map that is not a whole
//!   transition signed for this vault, or a whole input, or one part of a
//!   split one that matches the part list its digest is over, filed under
//!   its own key with its signed request as witness (FIX 4996), in the
//!   latest state, at a snapshot's root and in every retained operation.
//! - Reverse rematerialization mirrors the latest transition this vault holds
//!   of each record, and drops from an older window the carrier it
//!   supersedes, and every carrier that still seals a value an admitted
//!   revoke ended (CALLS CUSTODY_REVOKE_ERASE); it relays each input this
//!   vault keeps while its request awaits the holder, and drops an input row
//!   once its witnessed request is folded here terminal or invalid (CALLS
//!   CUSTODY_INPUT_PRUNE).
//! - Forward rematerialization and Observer B judge each transition against
//!   this vault's fold as it is now: the request it enacts counts, its named
//!   executor signed it, and it carries exactly the request's generation,
//!   input and permits (CALLS CUSTODY_PAYLOAD). A piece that stands is kept
//!   first, the rest of its transition owed; only a whole group of pieces,
//!   verified as one (`CustodyPieces::verify`), is written into this vault's
//!   custody through the local door, judged again in the committing
//!   transaction, with the value this machine opens. A machine the value
//!   was not sealed to keeps the transition unread. The holder a
//!   pending request names keeps the input it names, each part as it
//!   arrives, rechecked in the transaction that keeps it; its pickup joins
//!   the parts and waits while one is missing.
//! - A machine the roster gains that is the owner's (mine under the holder's
//!   pin) gets each portable value from a rewrap its holder records on its
//!   own after the admission and on this upkeep (CALLS
//!   CUSTODY_ROSTER_REWRAP); any other linked machine only from a rewrap the
//!   owner records (CALLS CUSTODY_PERMITS).
//! - A witness past one row rides as signed numbered parts of its own, and
//!   each input row with a signed reference to them (FIX 8088, `witness`).
//!   Every input and witness row commits on its own.

pub(super) mod checkpoint;
mod witness;

use std::collections::BTreeMap;

use loro::event::MapDelta;
use loro::{LoroDoc, LoroMap, LoroValue, ValueOrContainer};

use super::loro_support::{map_delete, map_get_bytes, map_insert_bytes};
use super::types::WindowKey;
use crate::Vault;
use crate::authority::{AuthorityFold, OwnerWorkBody};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result, SyncEngineContext};
use crate::secret_custody::{
    CustodyApplied, CustodyTransition, RelayedInput, SecretCustodyStatus,
    apply_custody_transition_in_txn, completed_custody_groups_in_txn, custody_transitions,
    held_inputs, holds_custody_carrier_in_txn, keep_custody_piece_in_txn, keep_input_in_txn,
};

/// Which input rows a window admits and prunes (CALLS CUSTODY_INPUT_PRUNE,
/// Engine ruling 10-19 for FIX 4996).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyInputPrune {
    /// Admission requires the signed request witness: a row carries its
    /// request's signed entry, which hashes to the request the row names and
    /// names the row's input digest. A row leaves the window only once this
    /// vault folds that request terminal (answered, valid without effect, or
    /// on a secret an admitted revoke ended) or invalid (a chain of its
    /// carrier names the key that signed it, and the fold judged the entry
    /// invalid). A row whose request this vault has not folded, or whose
    /// signer it does not know yet, stays, so an input that arrives before
    /// its request still reaches its holder: no time, count or frontier
    /// drops one. So does a row whose witness a key no machine of this vault
    /// ever holds signed: the witness proves the row self-consistent, not
    /// its signer the vault's, so the request never folds and the row stays
    /// until its base window retires (FIX 5405, reported, not narrowed). The
    /// relay logs how many rows a window keeps whose request is not folded
    /// here, by count alone.
    WitnessedTerminalOrInvalid,
}

const CUSTODY_INPUT_PRUNE: CustodyInputPrune = CustodyInputPrune::WitnessedTerminalOrInvalid;

/// The base window root map that carries custody transitions and inputs.
pub(crate) const CUSTODY_MAP: &str = "custody";

/// The key prefix of a protected input's row in the custody map, before its
/// row key in hex: the ciphertext digest its request names, or for a part of
/// a split input, that part's own key. A checkpoint image keeps transitions
/// only.
pub(crate) const INPUT_ROW_PREFIX: &str = "input:";

fn input_row(key: &[u8; 32]) -> String {
    format!("{INPUT_ROW_PREFIX}{}", bytes_to_hex_lower(key))
}

/// Whether the request a relayed input is for still awaits its holder.
fn input_open(fold: &AuthorityFold, input: &RelayedInput) -> bool {
    fold.owner_work_request(&input.request).is_some()
        && fold.owner_work_result(&input.request).is_none()
}

/// Whether a window's input row is due to leave it (CALLS
/// CUSTODY_INPUT_PRUNE): its witnessed request is folded here answered,
/// without effect or on a revoked secret, or folded invalid.
fn input_row_done(fold: &AuthorityFold, input: &RelayedInput) -> bool {
    match CUSTODY_INPUT_PRUNE {
        CustodyInputPrune::WitnessedTerminalOrInvalid => {
            // A row whose witness travels in parts proves its request by its
            // signed reference, and leaves once that request is terminal
            // here (FIX 8088).
            let invalid = match input.witnessed() {
                Some(witnessed) => witnessed.folded_invalid(fold, &input.request),
                None if input.witness_group().is_some() => false,
                None => return false,
            };
            fold.owner_work_result(&input.request).is_some()
                || fold.refused_owner_work().contains(&input.request)
                || fold
                    .owner_work_request(&input.request)
                    .is_some_and(|request| fold.custody_revoked(&request.act.target))
                || invalid
        }
    }
}

/// Whether `input` is the one a counted, unanswered request naming `machine`
/// as executor names, by the request's own hash and the input's digest: what
/// that holder keeps.
fn input_awaits(fold: &AuthorityFold, machine: EntityId, input: &RelayedInput) -> bool {
    let digest = input.digest();
    fold.counted_owner_work_request(&input.request)
        .is_some_and(|request| {
            request.executor == machine
                && fold.owner_work_result(&input.request).is_none()
                && names_input(&request.work, &digest)
        })
}

/// Whether `work` is a custody change whose protected input is `digest`.
fn names_input(work: &OwnerWorkBody, digest: &[u8; 32]) -> bool {
    matches!(
        work,
        OwnerWorkBody::Custody {
            input: Some(named),
            ..
        } if named == digest
    )
}

/// Whether `transition` still seals a value of a secret an admitted revoke
/// ended: no window carries it (CALLS CUSTODY_REVOKE_ERASE).
fn sealed_after_revoke(fold: &AuthorityFold, transition: &CustodyTransition) -> bool {
    transition.status != SecretCustodyStatus::Revoked && fold.custody_revoked(&transition.id)
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
/// base window, or a whole input, or one checked part of a split one, filed
/// under its row key in its sealing month's, with the signed request it names
/// as witness (CALLS CUSTODY_INPUT_PRUNE). Whether a transition's request
/// stands is judged where it is written ([`apply_carriers`]), so a window
/// keeps relaying one whose request this vault has not folded yet. Without a
/// vault, nothing is admitted.
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
    if let Some(row_key) = map_key.strip_prefix(INPUT_ROW_PREFIX) {
        let input = RelayedInput::decode(bytes).ok_or_else(|| refused("malformed input"))?;
        if bytes_to_hex_lower(&input.row_key()) != row_key {
            return Err(refused("input filed under another digest"));
        }
        // Its signed request whole, or its signed reference to a witness
        // that travels in parts (FIX 8088).
        if input.witnessed().is_none() && input.witness_group().is_none() {
            return Err(refused("input without its signed request"));
        }
        if key.is_some_and(|key| *key != WindowKey::from_timestamp(input.sealed_at)) {
            return Err(refused("input outside its sealing month's base window"));
        }
        return Ok(());
    }
    if let Some(row_key) = map_key.strip_prefix(witness::WITNESS_ROW_PREFIX) {
        return witness::admit_witness_part(key, row_key, bytes);
    }
    let transition = CustodyTransition::decode(bytes)?;
    if transition.row_key() != map_key {
        return Err(refused("filed under another id or piece"));
    }
    if key.is_some_and(|key| *key != transition_window(&transition)) {
        return Err(refused("outside its signing month's base window"));
    }
    // Reading this vault's own authority is the store's work: its fault is
    // this machine's, never the peer's refused update (FIX 5925).
    let rtxn = vault.store.env.read_txn().map_err(admission_read_fault)?;
    let vault_id = vault
        .authority_view_readonly_in_txn(&rtxn)
        .map_err(admission_read_fault)?
        .vault_id
        .ok_or_else(|| refused("the vault has no authority genesis"))?;
    transition.verify_signed(&vault_id)
}

/// A failure reading this vault's own state while admitting a window's
/// custody row (FIX 5925): the store's fault, typed so the server closes it
/// as its own and never as the peer's refused update.
fn admission_read_fault(error: impl Into<Error>) -> Error {
    Error::sync_engine(SyncEngineContext::WindowAdmissionRead, error.into())
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
/// closed window catches up as it opens. Each piece commits on its own, so
/// no one update outgrows a frame and a transition rides across commits;
/// the rest commits at the end. Returns whether it wrote any.
pub(crate) fn mirror_custody_transitions(
    vault: &Vault,
    doc: &LoroDoc,
    key: &WindowKey,
) -> Result<bool> {
    if key.world().is_some() {
        return Ok(false);
    }
    let (fold, erased) = {
        let rtxn = vault.store.env.read_txn()?;
        let erased = vault.store.erased_credentials_in_txn(&rtxn);
        (vault.authority_view_readonly_in_txn(&rtxn)?, erased)
    };
    let mut wrote = mirror_custody_inputs(vault, doc, key, &fold)?;
    // Every piece this vault holds rides its window under its own key
    // (CALLS `Phase2 custody pieces request bound`).
    let mut due = Vec::new();
    let mut latest: BTreeMap<EntityId, CustodyTransition> = BTreeMap::new();
    for piece in custody_transitions(vault)? {
        // An erased credential's rides none (KS-6 part 2).
        if sealed_after_revoke(&fold, &piece) || erased.contains(&piece.id) {
            continue;
        }
        if transition_window(&piece) == *key {
            due.push(piece.clone());
        }
        latest.entry(piece.id).or_insert(piece);
    }
    if !due.is_empty() {
        let map = doc.get_map(CUSTODY_MAP);
        for piece in due {
            let row = piece.row_key();
            let carrier = piece.encode();
            let held = map_get_bytes(&map, &row);
            if held.as_deref() == Some(carrier.as_slice())
                || held
                    .and_then(|held| CustodyTransition::decode(&held).ok())
                    .is_some_and(|held| !piece.supersedes(&held))
            {
                continue;
            }
            // Writes waiting before the first piece commit apart from it.
            if wrote {
                commit_custody(doc);
            }
            map_insert_bytes(&map, &row, &carrier)?;
            commit_custody(doc);
            wrote = true;
        }
    }
    // A carrier this vault's latest supersedes leaves every window, each
    // piece of it, as does one that still seals a value an admitted revoke
    // ended, and every carrier of a credential an erase fenced here.
    if holds_custody_map(doc) {
        let map = doc.get_map(CUSTODY_MAP);
        let mut gone = Vec::new();
        map.for_each(|map_key, value| {
            if let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value
                && !map_key.starts_with(INPUT_ROW_PREFIX)
                && let Ok(held) = CustodyTransition::decode(&bytes)
                && (sealed_after_revoke(&fold, &held)
                    || erased.contains(&held.id)
                    || latest
                        .get(&held.id)
                        .is_some_and(|latest| latest.supersedes(&held)))
            {
                gone.push(map_key.to_owned());
            }
        });
        for row in gone {
            map_delete(&map, &row)?;
            wrote = true;
        }
    }
    if wrote {
        commit_custody(doc);
    }
    Ok(wrote)
}

fn commit_custody(doc: &LoroDoc) {
    doc.commit_with(loro::CommitOptions::new().origin(super::bridge::BRIDGE_ORIGIN));
}

/// Relays each input this vault keeps into window `key`, the base window of
/// its sealing month, while its request awaits the holder, and drops from
/// the window every input row `fold` holds done ([`input_row_done`]).
/// Returns whether it wrote any.
fn mirror_custody_inputs(
    vault: &Vault,
    doc: &LoroDoc,
    key: &WindowKey,
    fold: &AuthorityFold,
) -> Result<bool> {
    let kept = held_inputs(vault)?;
    let holds = holds_custody_map(doc);
    if kept.is_empty() && !holds {
        return witness::mirror_witness_parts(vault, doc, key, fold);
    }
    let mut wrote = false;
    for (digest, bytes) in kept {
        let Some(input) = RelayedInput::decode(&bytes) else {
            continue;
        };
        if WindowKey::from_timestamp(input.sealed_at) != *key || !input_open(fold, &input) {
            continue;
        }
        let map = doc.get_map(CUSTODY_MAP);
        let row = input_row(&digest);
        if map_get_bytes(&map, &row).as_deref() != Some(bytes.as_slice()) {
            // Each row commits on its own: no one update outgrows a frame.
            map_insert_bytes(&map, &row, &bytes)?;
            commit_custody(doc);
            wrote = true;
        }
    }
    wrote |= witness::mirror_witness_parts(vault, doc, key, fold)?;
    if holds {
        let map = doc.get_map(CUSTODY_MAP);
        let mut done = Vec::new();
        let mut unfolded = 0_usize;
        map.for_each(|map_key, value| {
            if !map_key.starts_with(INPUT_ROW_PREFIX) {
                return;
            }
            let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value else {
                return;
            };
            let Some(input) = RelayedInput::decode(&bytes) else {
                return;
            };
            if input_row_done(fold, &input) {
                done.push(map_key.to_owned());
            } else if fold.owner_work_request(&input.request).is_none() {
                // A row whose request this vault has not folded yet may still
                // be its holder's, and stays (FIX 5405).
                unfolded += 1;
            }
        });
        for row in done {
            map_delete(&map, &row)?;
            wrote = true;
        }
        if unfolded > 0 {
            tracing::debug!(
                window = %key,
                unfolded,
                "custody input rows kept whose request this vault has not folded: not here yet, \
                 or signed by a key no machine of this vault holds (CALLS CUSTODY_INPUT_PRUNE)"
            );
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
    apply_custody_rows(vault, doc, key, false);
}

/// [`apply_custody_map`]'s body: with `skip_held`, a transition this vault
/// already holds byte for byte is not judged again.
fn apply_custody_rows(vault: &Vault, doc: &LoroDoc, key: &WindowKey, skip_held: bool) {
    if key.world().is_some() || !holds_custody_map(doc) {
        return;
    }
    let mut rows = Vec::new();
    doc.get_map(CUSTODY_MAP).for_each(|map_key, value| {
        if let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value {
            rows.push((map_key.to_owned(), bytes.to_vec()));
        }
    });
    apply_carriers(vault, key.as_str(), rows, skip_held);
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
    apply_carriers(vault, window_key, rows, false);
    Some(Vec::new())
}

/// Judges each carrier, one piece, against this vault's fold and keeps each
/// that stands beside the pieces of its transition this vault holds, as the
/// record's latest when it supersedes the one held. Only a group of pieces
/// that is then whole and stands as one has custody effects: its value
/// sealed to this machine is opened and written through the custody door.
/// Input rows go to [`keep_relayed_inputs`]. With `skip_held`, a piece this
/// vault already holds byte for byte is left alone.
fn apply_carriers(vault: &Vault, window: &str, rows: Vec<(String, Vec<u8>)>, skip_held: bool) {
    let (inputs, rows): (Vec<_>, Vec<_>) = rows
        .into_iter()
        .partition(|(map_key, _)| map_key.starts_with(INPUT_ROW_PREFIX));
    keep_relayed_inputs(vault, window, inputs);
    let (witnesses, rows): (Vec<_>, Vec<_>) = rows
        .into_iter()
        .partition(|(map_key, _)| map_key.starts_with(witness::WITNESS_ROW_PREFIX));
    witness::keep_relayed_witnesses(vault, window, witnesses);
    if rows.is_empty() {
        return;
    }
    // The keystore is read before any transaction opens. A host that is not
    // one of the owner's machines has no secret, and keeps every value sealed.
    let secret = vault.machine_secret_outside_txn().ok();
    let outcome = (|| -> Result<usize> {
        let (arrived, whole) = {
            let rtxn = vault.store.env.read_txn()?;
            let fold = vault.authority_view_readonly_in_txn(&rtxn)?;
            let mut arrived = Vec::new();
            for (map_key, bytes) in &rows {
                let transition = match CustodyTransition::decode(bytes) {
                    Ok(transition) if transition.row_key() == *map_key => transition,
                    _ => {
                        tracing::warn!(window, key = %map_key, "custody transition malformed; left out");
                        continue;
                    }
                };
                if skip_held && holds_custody_carrier_in_txn(vault, &rtxn, &transition)? {
                    continue;
                }
                if let Err(error) = transition.verify(&fold) {
                    tracing::warn!(window, key = %map_key, error = %error, "custody transition does not stand on its request here; left out");
                    continue;
                }
                arrived.push(transition);
            }
            // A piece alone has no custody effect: only a group the pieces
            // make with those kept here, whole and standing as one, does.
            let mut whole = Vec::new();
            for group in completed_custody_groups_in_txn(vault, &rtxn, &arrived)? {
                if group.verify(&fold).is_err() {
                    continue;
                }
                let value = match (&secret, fold.vault_id) {
                    (Some(secret), Some(vault_id)) => {
                        group.open_value(&vault_id, secret.machine, &secret.secret)
                    }
                    _ => None,
                };
                whole.push((group, value));
            }
            (arrived, whole)
        };
        if arrived.is_empty() {
            return Ok(0);
        }
        vault.with_write_txn_grouped(|wtxn| {
            // Every piece that stands is kept first, the rest of its
            // transition owed; a piece an admitted revoke of its id refused,
            // or that no longer stands on this transaction's fold, is not
            // kept, so it is never relayed from here (WILL L04 row 04).
            let fold = vault.authority_view_readonly_in_txn(wtxn)?;
            for piece in &arrived {
                keep_custody_piece_in_txn(vault, wtxn, &fold, piece)?;
            }
            let mut written = 0;
            for (group, value) in &whole {
                let value = value.as_ref().map(|value| value.as_slice());
                let at = group.lead().signed_at;
                let applied = apply_custody_transition_in_txn(vault, wtxn, group, value, at)?;
                if applied == CustodyApplied::Written {
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

/// Keeps each relayed input row, whole or one part, that a counted,
/// unanswered request naming this install as its holder names, by the
/// request's hash and the input's digest, so its pickup can join and open
/// it: one whose reference names the request's own signer (FIX 8088), in
/// place of a kept row that does not. The writer that keeps it checks that
/// again against its own fold. Any other input row stays in the window,
/// unread. A row that fails is logged and left.
fn keep_relayed_inputs(vault: &Vault, window: &str, rows: Vec<(String, Vec<u8>)>) {
    if rows.is_empty() {
        return;
    }
    let outcome = (|| -> Result<usize> {
        let (machine, due) = {
            let rtxn = vault.store.env.read_txn()?;
            let Some(machine) = crate::identity::read_machine_id_in_txn(vault, &rtxn)? else {
                return Ok(0);
            };
            let fold = vault.authority_view_readonly_in_txn(&rtxn)?;
            let mut due: Vec<RelayedInput> = Vec::new();
            for (map_key, bytes) in &rows {
                let Some(input) = RelayedInput::decode(bytes) else {
                    continue;
                };
                let key = input.row_key();
                if *map_key == input_row(&key)
                    && input_awaits(&fold, machine, &input)
                    && witness::input_genuine(vault, &rtxn, &input)?
                    && witness::input_slot_open(vault, &rtxn, &key)?
                {
                    due.push(input);
                }
            }
            (machine, due)
        };
        if due.is_empty() {
            return Ok(0);
        }
        vault.with_write_txn_grouped(|wtxn| {
            let fold = vault.authority_view_readonly_in_txn(wtxn)?;
            let mut kept = 0;
            for input in &due {
                if input_awaits(&fold, machine, input)
                    && witness::input_genuine(vault, wtxn, input)?
                    && witness::input_slot_open(vault, wtxn, &input.row_key())?
                {
                    keep_input_in_txn(vault, wtxn, input)?;
                    kept += 1;
                }
            }
            Ok(kept)
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
    /// Judges again every custody transition and input the live base
    /// windows carry, as a window open does: one whose request this vault
    /// had not folded when it arrived stands once the request is in, and
    /// the holder a request names keeps its input. A rebind this vault keeps
    /// pending because its live floor refused the bindings is judged again
    /// from its kept carrier, and applies once the floor admits it (CALLS
    /// CUSTODY_REBIND_PENDING_FLOOR). The owner work drain runs it after an
    /// authority catch-up and on the served tick.
    pub(crate) fn reapply_custody_in_live_windows(&self) {
        for window in self.live_windows() {
            apply_custody_rows(self, &window.doc, &window.key, true);
        }
        match self.apply_pending_rebinds() {
            Ok(rebound) if rebound > 0 => {
                tracing::debug!(rebound, "pending custody rebinds applied");
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(error = %error, "pending custody rebinds not applied");
            }
        }
    }

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
            // It commits what it writes, a piece to a commit.
            match mirror_custody_transitions(self, &window.doc, &window.key) {
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(window = %window.key, error = %error, "custody transition not mirrored");
                }
            }
        }
    }
}
