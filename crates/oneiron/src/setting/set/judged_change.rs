//! Read-only checks and importance for changes at the Setting door.

use oneiron_authority::authority::{Direction, Permitted};
use oneiron_setting_contract::ChangeDirection;

use super::super::SettingSync;
use super::super::project::slot_refused_here_in_txn;
use super::super::restored::{RESTORED_NOT_JOINED_CHANGE, restored_unjoined_in_txn};
use super::{
    Change, StoredRow, agent_reading_in_txn, authority_direction, checked_slot, checked_weight,
    direction_in_txn, person_reading_in_txn, refuse_loose_move_of_all_quorum, rooted_in_txn,
    table_of, travels,
};
use crate::Vault;
use crate::batch::secret_scan::{SecretScanMode, secret_scan_mode_in_txn};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::setting::{EncodedValue, SetSetting, Setter, SettingCaller, SettingMode};
use crate::world_keys::OwnerActImportance;

/// The Setting door's judgment of one change against the rows its transaction sees.
pub(super) struct JudgedChange {
    /// The actor who asked for the change, if it names an actor.
    pub(super) by: Option<EntityId>,
    /// The setter the move rule admits, or none when it admits no move for this caller.
    pub(super) setter: Option<Setter>,
    /// The slot's stored bytes before the change, if the slot held a row.
    pub(super) prior_bytes: Option<Vec<u8>>,
    /// The slot's readable value before the change, if it held one.
    pub(super) prior_value: Option<EncodedValue>,
    /// Whether the slot held a readable row that counts as the owner's.
    pub(super) prior_row_by_owner: bool,
    /// The row's revision before the change, or zero if no readable row stood.
    pub(super) revision: u64,
    /// Whether the change leaves the slot's row as it is.
    pub(super) unchanged: bool,
    /// The direction the setting order gives the change.
    pub(super) direction: ChangeDirection,
    /// The direction of the change under the authority rule.
    pub(super) moved: Direction,
}

/// Judges a change against the rows `txn` sees, on a read or in the write, without writing.
/// It reads who asks and what they may do, the slot's prior row, whether the change leaves it as
/// it is, and which way it moves.
pub(super) fn judge_change_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    change: &Change<'_>,
    caller: SettingCaller<'_>,
    request: &SetSetting,
) -> Result<JudgedChange> {
    if request.surface.is_some() && !matches!(caller, SettingCaller::Owner(_)) {
        return Err(Error::InvalidConfig(
            "only the owner's change names where the owner said so: an act surface is the owner's"
                .into(),
        ));
    }
    if change.key.mode == SettingMode::Carried && change.value.is_some() {
        return Err(Error::InvalidConfig(
            "only a move writes a carried row; a set may only clear one".into(),
        ));
    }
    if change.key.mode == SettingMode::Pin && matches!(caller, SettingCaller::Engine(_)) {
        return Err(Error::InvalidConfig(
            "the engine sets a value row, never a pin: a pin is the owner's".into(),
        ));
    }
    // Who asks, and what it may do: A0's reading of the actor, its proof checked in this write.
    let (by, reading) = match caller {
        SettingCaller::Owner(owner) => (
            Some(owner.revalidate_in_txn(vault, txn)?),
            Some((Setter::Owner, Permitted::AnyMove)),
        ),
        SettingCaller::Engine(engine) => (
            None,
            Some((Setter::Engine { ask: engine.ask }, Permitted::AnyMove)),
        ),
        SettingCaller::Person(person) => {
            let person = person.revalidate_person_in_txn(vault, txn)?;
            (
                Some(person),
                person_reading_in_txn(vault, txn, change, person)?,
            )
        }
        SettingCaller::Agent(agent) => (
            Some(agent),
            agent_reading_in_txn(vault, txn, change, agent)?,
        ),
    };
    let table = table_of(change.spec);
    let key_bytes = change.key.encode();
    let prior_bytes = table.get_bytes(&vault.store, txn, &key_bytes)?;
    let prior = prior_bytes
        .as_deref()
        .map(|bytes| rmp_serde::from_slice::<StoredRow>(bytes).ok());
    let revision = prior
        .as_ref()
        .map_or(0, |row| row.as_ref().map_or(0, |row| row.change));
    if let Some(expected) = request.expected_revision
        && expected != revision
    {
        return Err(Error::InvalidConfig(format!(
            "the row's revision is {revision}, not {expected}: read it again"
        )));
    }
    // A row that does not decode is never "the same value": a clear removes it, a set replaces it.
    let readable = !matches!(prior, Some(None));
    let prior_row = prior.flatten();
    let prior_row_by_owner = prior_row.as_ref().is_some_and(StoredRow::by_owner);
    // The no-op test is on the slot's own row (DESIGN 1.6, pass 15e F6): an equal value writes
    // where the row changes hands, and the row becomes the caller's. Over the engine's row any
    // other caller's does; over a row the owner did not set (a holder's, a subject's, a standing
    // approval's, an approved check-in's) the owner's does, so a later move of a non-owner meets
    // the owner's row (FIX SETTING-OWNER-EQUAL-VALUE-OVER-HOLDER-ROW = A). A copy of a pack's
    // default is no one's choice: over it every caller's equal value writes, and the row it leaves
    // is explicit (stage 7c-2).
    let setter_changes = prior_row.as_ref().is_some_and(|row| {
        row.seeded
            || match caller {
                SettingCaller::Owner(_) => !matches!(row.setter, Setter::Owner),
                SettingCaller::Agent(_) | SettingCaller::Person(_) => {
                    matches!(row.setter, Setter::Engine { .. })
                }
                SettingCaller::Engine(_) => false,
            }
    });
    let prior_weight = prior_row.as_ref().and_then(|row| row.weight_runs);
    let prior_value = prior_row.map(|row| row.value);
    // The owner's equal value of a travelling row signs its act all the same where this
    // install's hook refused the row's acts, or where the row is one of the owner's change of
    // several rows as one act (row SETTING-PROJECTED-ROW-REFUSING-HOOKS): the act replaces the
    // refused one on every machine, the one step the refusal's notice offers, and heads every row
    // that step names, so a machine that refused the peer's act takes the peer's value from it
    // too (`project/refusal.rs`; REVIEW-10306 round 2).
    let signs_equal_value = matches!(caller, SettingCaller::Owner(_))
        && travels(change.spec)
        && (change.act_of_several_rows || slot_refused_here_in_txn(vault, txn, &change.key)?);
    // An owner's equal write on a key with `records_equal_owner_write` is itself the act
    // (the answer-schema re-arm): it records a change and runs on_change. A clear of an
    // absent row stays a no-op.
    let equal_owner_write_records = change.spec.records_equal_owner_write
        && matches!(caller, SettingCaller::Owner(_))
        && change.value.is_some();
    let unchanged = readable
        && !setter_changes
        && !signs_equal_value
        && !equal_owner_write_records
        && prior_value.as_ref() == change.value
        && prior_weight == change.weight_runs;
    // An install born of a restore that has not joined changes no setting the vault's machines
    // share (stage 7c-4; DESIGN 1.6, "Restore"), whoever asks: it is no machine of the vault, so
    // no act of its own counts. A change that leaves the row as it is still answers.
    if !unchanged
        && change.spec.sync == SettingSync::Vault
        && restored_unjoined_in_txn(&vault.store, txn)?
    {
        return Err(crate::authority::authority_refused(
            RESTORED_NOT_JOINED_CHANGE,
        ));
    }
    let by_owner = matches!(caller, SettingCaller::Owner(_) | SettingCaller::Engine(_));
    // Which way the change moves its row, against the rows this write sees (A3: the key's
    // comparator gives the direction). A change that leaves the row as it is moves nothing.
    let direction = if unchanged {
        ChangeDirection::Tighter
    } else if readable {
        direction_in_txn(vault, txn, change, prior_value.as_ref(), by_owner)?
    } else {
        ChangeDirection::Unordered
    };
    // Over a row the owner set, a non-owner makes no widening (DESIGN 1.2 step 4: its value
    // stays inside the owner's row): it tightens the owner's row, and asks to loosen it. The
    // owner's standing approval for the key or the scope is the owner's yes to that widening.
    let owners_row = prior_row_by_owner && !by_owner;
    let reading = reading.map(|(setter, permitted)| {
        if owners_row && !matches!(setter, Setter::Standing { .. }) {
            (setter, permitted.limited_by(Permitted::NoWidening))
        } else {
            (setter, permitted)
        }
    });
    let moved = authority_direction(direction);
    let admitted = reading
        .and_then(|(setter, permitted)| permitted.admit(moved).map(|admitted| (setter, admitted)));
    Ok(JudgedChange {
        by,
        setter: admitted.map(|(setter, _)| setter),
        prior_bytes,
        prior_value,
        prior_row_by_owner,
        revision,
        unchanged,
        direction,
        moved,
    })
}

/// Whether the write's wall reads `json`: the owner's scan switch is on in `txn` and the value is
/// anything but a bare number, a flag or null. The wall places a handle only in text, and refuses
/// only what text spells, so it stores a bare number, a flag or null as offered. Any other value
/// it may store as another one, or refuse, and only the write knows which: a direction derived
/// from the request is then no ground for an ordinary act. This reads the switch and the value's
/// shape and nothing else. What custody holds is no part of it, so no answer the door gives
/// before it asks, and none its write gives under an ordinary witness, says what custody holds.
pub(super) fn wall_reads_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    json: &serde_json::Value,
) -> Result<bool> {
    if matches!(
        json,
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_)
    ) {
        return Ok(false);
    }
    Ok(secret_scan_mode_in_txn(vault, txn)? != SecretScanMode::Off)
}

/// The importance of the owner's change as it stands before the door asks.
pub(super) fn owner_change_importance(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    request: &SetSetting,
) -> Result<OwnerActImportance> {
    let (spec, key) = checked_slot(request)?;
    let txn = vault.store.env.read_txn()?;
    // A value the wall reads is not typed here: the write gives the wall's answer first and the
    // type's after it, as it did before the door read first.
    if let Some(json) = &request.value
        && wall_reads_in_txn(vault, &txn, json)?
    {
        owner.revalidate_in_txn(vault, &txn)?;
        return Ok(OwnerActImportance::Important);
    }
    let value = match request.value.clone() {
        Some(json) => Some(spec.kind.from_json(json)?),
        None => None,
    };
    let change = Change {
        spec,
        key: &key,
        value: value.as_ref(),
        weight_runs: checked_weight(spec, request)?,
        act_of_several_rows: false,
    };
    let judged = judge_change_in_txn(vault, &txn, &change, SettingCaller::Owner(owner), request)?;
    if !judged.unchanged {
        refuse_loose_move_of_all_quorum(spec, judged.moved)?;
        // A travelling act can wait for proof regardless of direction. A PIN-bound key only
        // proves inside a PIN window, so leave the answer to the ask and the write.
        if travels(spec) && rooted_in_txn(vault, &txn)? {
            let fold = vault.authority_view_readonly_in_txn(&txn)?;
            if !vault.holds_proving_owner_key(&fold) {
                return Ok(OwnerActImportance::Important);
            }
        }
    }
    Ok(OwnerActImportance::of_direction(judged.moved))
}
