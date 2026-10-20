//! Device-local step progression rows (Started/ResponseReceived/Logged) in the typed
//! `DREAMER_STEP_STATE` side table.

use super::codec::{expect_key, expect_map, expect_u64, invalid_step, pinned_key_index};
use super::types::{
    DREAMER_STEP_STATE_KEYS, DREAMER_STEP_STATE_SCHEMA_VERSION, DurableStepContext,
    KEY_PROGRESSION, KEY_RESPONSE, KEY_SCHEMA_VERSION, KEY_STARTED_AT, KEY_STATE_ACTOR,
    KEY_STATE_CLAIM, KEY_STATE_ERASED, KEY_STATE_SUBJECT, KEY_UPDATED_AT, StepProgression,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable, SideTableDbs};
use crate::store::ResponseCarriage;
use rmpv::Value;

// ---------------------------------------------------------------------------
// Private step-state rows (device-local live progression)
// ---------------------------------------------------------------------------
pub(super) struct StepStateRow {
    pub(super) progression: StepProgression,
    pub(super) started_at: u64,
    pub(super) updated_at: u64,
    pub(super) response_payload: Option<Vec<u8>>,
    /// Whose the response is, stamped as the row is written (KS-2B1).
    pub(super) owners: StepStateOwners,
    /// Its owner's erase took the response (KS-2B1): the step is over, and
    /// is never asked again.
    pub(super) erased: bool,
}

/// Who a step-state row's response belongs to, stamped from its step's
/// context as the row is written (KS-2B1): its actor and its subject, and
/// the terminal claim that logged it. An erase of any of them takes the
/// payload, and retires every image's copy of it. A payer alone is never
/// an owner.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct StepStateOwners {
    pub(super) actor: Option<EntityId>,
    pub(super) subject: Option<EntityId>,
    pub(super) claim: Option<EntityId>,
}

impl StepStateOwners {
    /// The owners `ctx`'s step stamps: its envelope actor and subject.
    pub(super) const fn of(ctx: &DurableStepContext<'_>) -> Self {
        Self {
            actor: Some(ctx.envelope_actor.entity_ref()),
            subject: Some(ctx.subject),
            claim: None,
        }
    }

    fn ids(&self) -> Vec<EntityId> {
        [self.actor, self.subject, self.claim]
            .into_iter()
            .flatten()
            .collect()
    }
}

const STEP_STATE: SideTable<(AttemptId, [u8; 32]), StepStateRow, Raw> =
    SideTable::new(&side_table::DREAMER_STEP_STATE);

fn id_value(id: EntityId) -> Value {
    Value::Binary(id.as_bytes().to_vec())
}

fn id_of(value: &Value) -> std::result::Result<EntityId, CodecError> {
    let Value::Binary(bytes) = value else {
        return Err(invalid_step("dreamer step state owner must be binary").into());
    };
    let raw: [u8; 16] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_step("dreamer step state owner must be 16 bytes"))?;
    Ok(EntityId::from_bytes(raw)?)
}

impl RawValue for StepStateRow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut entries = vec![
            (
                Value::from(KEY_SCHEMA_VERSION),
                Value::from(DREAMER_STEP_STATE_SCHEMA_VERSION),
            ),
            (
                Value::from(KEY_PROGRESSION),
                Value::from(u64::from(self.progression.as_u8())),
            ),
            (Value::from(KEY_STARTED_AT), Value::from(self.started_at)),
            (Value::from(KEY_UPDATED_AT), Value::from(self.updated_at)),
        ];
        if let Some(payload) = &self.response_payload {
            entries.push((Value::from(KEY_RESPONSE), Value::Binary(payload.clone())));
        }
        for (key, owner) in [
            (KEY_STATE_ACTOR, self.owners.actor),
            (KEY_STATE_SUBJECT, self.owners.subject),
            (KEY_STATE_CLAIM, self.owners.claim),
        ] {
            if let Some(owner) = owner {
                entries.push((Value::from(key), id_value(owner)));
            }
        }
        if self.erased {
            entries.push((Value::from(KEY_STATE_ERASED), Value::Boolean(true)));
        }
        let mut encoded = Vec::new();
        rmpv::encode::write_value(&mut encoded, &Value::Map(entries))
            .map_err(|_| invalid_step("dreamer step state row MessagePack encode failed"))?;
        Ok(encoded)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let value = rmpv::decode::read_value(&mut std::io::Cursor::new(bytes))
            .map_err(|_| invalid_step("dreamer step state row MessagePack decode failed"))?;
        let entries = expect_map(&value, "dreamer step state row must be a MessagePack map")?;

        let mut schema_version = None;
        let mut progression = None;
        let mut started_at = None;
        let mut updated_at = None;
        let mut response_payload = None;
        let mut owners = StepStateOwners::default();
        let mut erased = false;
        let mut seen = [false; DREAMER_STEP_STATE_KEYS.len()];

        for (key, value) in entries {
            let key = expect_key(key, "dreamer step state row keys must be strings")?;
            let index = pinned_key_index(key, &DREAMER_STEP_STATE_KEYS)
                .ok_or(invalid_step("dreamer step state row key is not pinned"))?;
            if seen[index] {
                return Err(invalid_step("duplicate dreamer step state row key").into());
            }
            seen[index] = true;

            match DREAMER_STEP_STATE_KEYS[index] {
                KEY_SCHEMA_VERSION => {
                    schema_version = Some(expect_u64(
                        value,
                        "dreamer step state schema_version must be an integer",
                    )?);
                }
                KEY_PROGRESSION => {
                    let raw =
                        expect_u64(value, "dreamer step state progression must be an integer")?;
                    let raw = u8::try_from(raw)
                        .map_err(|_| invalid_step("dreamer step state progression out of range"))?;
                    progression = Some(
                        StepProgression::from_u8(raw)
                            .ok_or(invalid_step("unknown dreamer step state progression"))?,
                    );
                }
                KEY_STARTED_AT => {
                    started_at = Some(expect_u64(
                        value,
                        "dreamer step state started_at must be an integer",
                    )?);
                }
                KEY_UPDATED_AT => {
                    updated_at = Some(expect_u64(
                        value,
                        "dreamer step state updated_at must be an integer",
                    )?);
                }
                KEY_RESPONSE => {
                    let Value::Binary(bytes) = value else {
                        return Err(
                            invalid_step("dreamer step state response must be binary").into()
                        );
                    };
                    response_payload = Some(bytes.clone());
                }
                KEY_STATE_ACTOR => owners.actor = Some(id_of(value)?),
                KEY_STATE_SUBJECT => owners.subject = Some(id_of(value)?),
                KEY_STATE_CLAIM => owners.claim = Some(id_of(value)?),
                KEY_STATE_ERASED => {
                    erased = value
                        .as_bool()
                        .ok_or(invalid_step("dreamer step state erased must be a boolean"))?;
                }
                _ => unreachable!("index resolved from DREAMER_STEP_STATE_KEYS"),
            }
        }

        let schema_version =
            schema_version.ok_or(invalid_step("missing dreamer step state schema_version"))?;
        if schema_version != DREAMER_STEP_STATE_SCHEMA_VERSION {
            return Err(invalid_step("unsupported dreamer step state schema_version").into());
        }

        Ok(StepStateRow {
            progression: progression
                .ok_or(invalid_step("missing dreamer step state progression"))?,
            started_at: started_at.ok_or(invalid_step("missing dreamer step state started_at"))?,
            updated_at: updated_at.ok_or(invalid_step("missing dreamer step state updated_at"))?,
            response_payload,
            owners,
            erased,
        })
    }
}

/// A step-state row as an earlier writer seeded it, with no owner stamped.
#[cfg(test)]
pub(super) fn step_state_write(
    vault: &Vault,
    attempt_id: AttemptId,
    step_hash: &[u8; 32],
    progression: StepProgression,
    response_payload: Option<&[u8]>,
    now_ms: u64,
) -> Result<()> {
    step_state_write_owned(
        vault,
        attempt_id,
        step_hash,
        progression,
        StepStateOwners::default(),
        response_payload,
        now_ms,
    )
    .map(|_| ())
}

/// What a step-state write kept (KS-2B1, FIX 6226).
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StepStateDisposition {
    /// The row as it was written.
    Kept,
    /// The row's erased skeleton: an earlier erase took its response, or an
    /// owner it stamps is gone here. It holds no payload, now or later; the
    /// step is over and is never asked, or paid for, again.
    Erased,
}

/// Writes one step-state row, its owners stamped from its step (KS-2B1),
/// and says what it kept: a late answer for a gone owner keeps none.
pub(super) fn step_state_write_owned(
    vault: &Vault,
    attempt_id: AttemptId,
    step_hash: &[u8; 32],
    progression: StepProgression,
    owners: StepStateOwners,
    response_payload: Option<&[u8]>,
    now_ms: u64,
) -> Result<StepStateDisposition> {
    let started_at =
        step_state_read(vault, attempt_id, step_hash)?.map_or(now_ms, |row| row.started_at);
    let mut wtxn = vault.store.env.write_txn()?;
    let disposition = step_state_put_in_txn(
        vault,
        &mut wtxn,
        attempt_id,
        step_hash,
        &StepStateRow {
            progression,
            started_at,
            updated_at: now_ms,
            response_payload: response_payload.map(<[u8]>::to_vec),
            owners,
            erased: false,
        },
    )?;
    wtxn.commit()?;
    Ok(disposition)
}

/// Writes `row` at `(attempt_id, step_hash)` in `wtxn`, its owners checked
/// in this same write (FIX 6226). An erase is sticky: a row an erase took
/// is never written again. When an owner the row stamps is gone here, the
/// row keeps its erased skeleton, with no payload, so a late answer never
/// lands after the erase that took its owner. Either way, an owner's erase
/// takes the step's kept requests too (FIX 6659).
pub(super) fn step_state_put_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt_id: AttemptId,
    step_hash: &[u8; 32],
    row: &StepStateRow,
) -> Result<StepStateDisposition> {
    let key = (attempt_id, *step_hash);
    if STEP_STATE
        .get(vault, &*wtxn, &key)?
        .is_some_and(|prior| prior.erased)
    {
        remove_erased_sources_in_txn(vault, wtxn, attempt_id, step_hash, &row.owners)?;
        return Ok(StepStateDisposition::Erased);
    }
    if !row.erased && !owner_gone_in_txn(vault, &*wtxn, &row.owners.ids())? {
        STEP_STATE.put(vault, wtxn, &key, row)?;
        return Ok(StepStateDisposition::Kept);
    }
    let skeleton = StepStateRow {
        progression: row.progression,
        started_at: row.started_at,
        updated_at: row.updated_at,
        response_payload: None,
        owners: row.owners,
        erased: true,
    };
    STEP_STATE.put(vault, wtxn, &key, &skeleton)?;
    remove_erased_sources_in_txn(vault, wtxn, attempt_id, step_hash, &row.owners)?;
    Ok(StepStateDisposition::Erased)
}

/// Whether an owner of `owners` is gone in `txn`, by the markers a program
/// step's actor is read by (FIX 5710): a deletion of its row other than an
/// archive, or its hard-delete or identity soft-delete marker. An archive is
/// reversible and withholds nothing. A step's request capture keeps nothing
/// for an owner gone by this same check (FIX 6659).
pub(crate) fn owner_gone_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owners: &[EntityId],
) -> Result<bool> {
    for owner in owners {
        if crate::ports::removed_in_txn(&vault.store, txn, owner)?
            || owner_erased_in_txn(vault, txn, owner)?
            || vault
                .store
                .port_deletion_marked(txn, DeletionMarker::IdentitySoftDelete, owner)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether `owner` was erased in `txn`: its hard-delete marker.
fn owner_erased_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, owner: &EntityId) -> Result<bool> {
    vault
        .store
        .port_deletion_marked(txn, DeletionMarker::HardDelete, owner)
}

/// The erase of an owner `owners` stamps takes every request kept for the
/// step (FIX 6659), each lease and call of it, in `wtxn`, beside the scrub
/// its erase ran. A soft delete keeps them, as it keeps the rest of its
/// owner's rows for a restore: only an erase takes them.
fn remove_erased_sources_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt_id: AttemptId,
    step_hash: &[u8; 32],
    owners: &StepStateOwners,
) -> Result<()> {
    for owner in owners.ids() {
        if owner_erased_in_txn(vault, &*wtxn, &owner)? {
            return crate::self_heal::blocked_reports::remove_step_sources_in_txn(
                vault, wtxn, attempt_id, step_hash,
            );
        }
    }
    Ok(())
}

pub(super) fn step_state_read(
    vault: &Vault,
    attempt_id: AttemptId,
    step_hash: &[u8; 32],
) -> Result<Option<StepStateRow>> {
    let rtxn = vault.store.env.read_txn()?;
    STEP_STATE.get(&vault.store, &rtxn, &(attempt_id, *step_hash))
}

pub(super) fn step_state_delete(
    vault: &Vault,
    attempt_id: AttemptId,
    step_hash: &[u8; 32],
) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    STEP_STATE.delete(&vault.store, &mut wtxn, &(attempt_id, *step_hash))?;
    wtxn.commit()?;
    Ok(())
}

/// What a checkpoint carries of the step-state row `value` (KS-2B1): its
/// response payload, the row without it, marked erased, as the stub its
/// erased disposition keeps whole: the step is over and is never asked, or
/// paid for, again. `None` for a row with no payload and for one that does
/// not decode.
pub(crate) fn step_state_carriage(value: &[u8]) -> Option<ResponseCarriage> {
    let mut row = StepStateRow::from_raw(value).ok()?;
    row.response_payload.take()?;
    row.erased = true;
    let stub = row.to_raw().ok()?;
    Some(ResponseCarriage {
        keep: 0,
        retired: stub.len(),
        stub,
    })
}

/// Who owns the step-state row `value`'s response, by its stamps: none for
/// a row that does not decode.
pub(crate) fn step_state_owners(value: &[u8]) -> Vec<EntityId> {
    StepStateRow::from_raw(value)
        .map(|row| row.owners.ids())
        .unwrap_or_default()
}

/// The erase of `owner` takes the response out of every step-state row its
/// stamps name (KS-2B1), in the erase's own writer: the row stays, marked
/// erased, so its step is never asked, or paid for, again. A row that does
/// not decode names no owner and stays as it is. Images' copies retire
/// through the rows' obligations.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_step_state_owner_in_txn(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    owner: &EntityId,
) -> Result<()> {
    let mut owned = Vec::new();
    for row in STEP_STATE.iter_raw_from(dbs, wtxn, &[])? {
        let (key, bytes) = row?;
        if let Ok(mut state) = StepStateRow::from_raw(&bytes)
            && state.response_payload.is_some()
            && state.owners.ids().contains(owner)
        {
            state.response_payload = None;
            state.erased = true;
            owned.push((key, state));
        }
    }
    for (key, state) in owned {
        let Some(key) = <(AttemptId, [u8; 32]) as crate::side_table::SideKey>::decode_key(&key)
        else {
            continue;
        };
        STEP_STATE.put(dbs, wtxn, &key, &state)?;
    }
    Ok(())
}
