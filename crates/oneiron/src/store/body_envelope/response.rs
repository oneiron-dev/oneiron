//! Row-held response bodies under body custody (KS-2B1, FIX 5683 part B1;
//! owner KEY STORE = A).
//!
//! A response a row holds is one body instance like any other: a turn
//! program's STEP body (FIX 5719), an LLM step-state payload, a terminal
//! `dreamer.step` claim's inline response (an LLM or a compaction step's)
//! and a code run's replay outcomes. Each is bound lazily, the first time a
//! checkpoint carries its row, as an inline body is (KS-2A): the binding
//! pass mints the instance outside every writer and binds it in one short
//! writer, so no live read or write of the row touches custody and no live
//! path gains a key failure.
//!
//! - The binding ([`RESPONSE_BINDINGS`]) names the row's instance and the
//!   BLAKE3 of the bytes it was bound to. It rides every image: a restore
//!   requires the instance, lands the exact bytes under a live one, and the
//!   row's erased disposition under a retired one. A row whose bytes moved
//!   since is bound again, under a fresh instance.
//! - The obligations name, for each owner the row's write-time stamps name
//!   (its actor, subject and source refs; a payer alone never), every
//!   instance an image of it was carried under. They outlive the row: an
//!   overwrite, a delete or an expiry drops the binding and keeps every key,
//!   so the restore window stays; an erase of any owner retires every
//!   instance they name, the older images' included.
//! - The erase cause comes from the provenance door alone
//!   (`erase_row_provenance_in_txn` with `erase`); no actor scrub, which a
//!   delete runs too, retires anything. A wait's settled reply is shared by
//!   its holders: one holder's erase owes its retirement to the final
//!   holder's release ([`shared_wait`], FIX 6588).

mod shared_wait;

use std::collections::BTreeMap;

use heed::{RoTxn, RwTxn};

use super::opaque_response::{OPAQUE_ERASED, ResponseOwners, ResponseScan};
use super::retention::{ErasedNotes, stage_erase};
use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideKey, SideTable, SideTableDbs};
use crate::store::{ManifestDbs, MediaKey, Store};
pub(crate) use shared_wait::{response_owed_to_all_in_txn, settle_shared_response_in_txn};

type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// A row-held response's binding, by its carrier: its instance, then the
/// BLAKE3 of the bytes bound.
pub(crate) const RESPONSE_BINDINGS: SideTable<Vec<u8>, [u8; 48], Raw> =
    SideTable::new(&side_table::PROVENANCE_BODY_RESPONSE);

/// The obligations: each instance a row's response was carried under, by
/// each owner its stamps name, with the row's carrier.
const RESPONSE_OWNERS: SideTable<(EntityId, [u8; 16]), Vec<u8>, Raw> =
    SideTable::new(&side_table::PROVENANCE_BODY_RESPONSE_OWNER);

/// Where a row-held response rests: KS-2B2's HTTP idempotency entries and
/// media jobs rest in `sync_state`; an agent dispatch's payload text in
/// `job_records` (FIX 7115).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResponseDb {
    VaultMeta,
    Entities,
    SyncState,
    Attempts,
}

impl ResponseDb {
    const fn tag(self) -> u8 {
        match self {
            Self::VaultMeta => 0,
            Self::Entities => 1,
            Self::SyncState => 2,
            Self::Attempts => 3,
        }
    }

    const fn of_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::VaultMeta),
            1 => Some(Self::Entities),
            2 => Some(Self::SyncState),
            3 => Some(Self::Attempts),
            _ => None,
        }
    }

    /// The database by the name an image gives it.
    pub(crate) fn of_name(name: &str) -> Option<Self> {
        match name {
            "vault_meta" => Some(Self::VaultMeta),
            "entities" => Some(Self::Entities),
            "sync_state" => Some(Self::SyncState),
            "job_records" => Some(Self::Attempts),
            _ => None,
        }
    }

    /// The database's name, as an image gives it.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::VaultMeta => "vault_meta",
            Self::Entities => "entities",
            Self::SyncState => "sync_state",
            Self::Attempts => "job_records",
        }
    }
}

/// The carrier of the row `key` of `db`: the database's tag, then the
/// row's full key.
pub(crate) fn response_carrier(db: ResponseDb, key: &[u8]) -> Vec<u8> {
    let mut carrier = Vec::with_capacity(key.len() + 1);
    carrier.push(db.tag());
    carrier.extend_from_slice(key);
    carrier
}

/// The database and the full row key `carrier` names.
pub(crate) fn carrier_row(carrier: &[u8]) -> Option<(ResponseDb, &[u8])> {
    let (tag, key) = carrier.split_first()?;
    Some((ResponseDb::of_tag(*tag)?, key))
}

/// A row's binding: its instance, and the BLAKE3 of the bytes bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ResponseBinding {
    pub(crate) instance: [u8; 16],
    pub(crate) digest: [u8; 32],
}

impl ResponseBinding {
    fn encode(&self) -> [u8; 48] {
        let mut raw = [0u8; 48];
        raw[..16].copy_from_slice(&self.instance);
        raw[16..].copy_from_slice(&self.digest);
        raw
    }

    fn decode(raw: &[u8; 48]) -> Self {
        let mut instance = [0u8; 16];
        let mut digest = [0u8; 32];
        instance.copy_from_slice(&raw[..16]);
        digest.copy_from_slice(&raw[16..]);
        Self { instance, digest }
    }

    /// The binding a raw binding row holds.
    ///
    /// # Errors
    ///
    /// A row that does not decode.
    pub(crate) fn of_row(value: &[u8]) -> Result<Self> {
        Ok(Self::decode(&RESPONSE_BINDINGS.decode_value(value)?))
    }
}

/// What a checkpoint carries of one row's response: how many of the row's
/// bytes come before it (`keep`); the stub the image row holds in the row's
/// place, which starts with those bytes and never holds the response; and
/// how many of the stub's bytes the row keeps when an erase retired the
/// instance, its erased disposition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResponseCarriage {
    pub(crate) keep: usize,
    pub(crate) stub: Vec<u8>,
    pub(crate) retired: usize,
}

/// A family of row-held responses (KS-2B1; KS-2B2 adds the host's HTTP
/// idempotency entries and media jobs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResponseFamily {
    /// A turn program's STEP row: a send's kept body (FIX 5719).
    ProgramStep,
    /// An LLM step's device-local progression row: its response payload.
    StepState,
    /// A terminal `dreamer.step` claim: its inline response.
    StepClaim,
    /// A code run's replay record: its bridge outcomes and output previews.
    Replay,
    /// An HTTP idempotency cache entry: its request, headers, target and
    /// response (KS-2B2).
    Http,
    /// A media job's row: its request and its end (KS-2B2).
    MediaJob,
    /// One of a media job's clips, in a row of its own beside the job's.
    MediaPart,
    /// A blocked report's captured request: a receipt row or a durable
    /// step's row of the replay-source table (FIX 6708), carried whole.
    BlockedCapture,
    /// The reply a parked run was delivered (FIX 6588).
    WaitDelivery,
    /// A wait's settled reply, shared by every holder of the wait (FIX
    /// 6588): only the index's settled rows, never its waiters.
    WaitSettled,
    /// A Dreamer agent dispatch's attempt row: its target's instructions,
    /// briefing and direct spawn receipt (FIX 7115).
    AttemptPayload,
    /// A public model-step submission: its request and its result, kept
    /// beside the receipt's metadata (FIX 9929).
    ModelStepSubmission,
}

impl ResponseFamily {
    /// The family of the canonical row `key` of `db`, holding `value`.
    pub(crate) fn of_row(db: ResponseDb, key: &[u8], value: &[u8]) -> Option<Self> {
        match db {
            // Recognized by key, so a retired stub is too.
            ResponseDb::VaultMeta => [
                (&side_table::DREAMER_TURN_PROGRAM_STEP, Self::ProgramStep),
                (&side_table::DREAMER_STEP_STATE, Self::StepState),
                (&side_table::CODE_RUN_REPLAY, Self::Replay),
                (&side_table::COACH_BLOCKED_SOURCE, Self::BlockedCapture),
                (&side_table::CODE_RUN_WAIT_DELIVERY, Self::WaitDelivery),
                (&side_table::MODEL_STEP_SUBMISSION, Self::ModelStepSubmission),
            ]
            .into_iter()
            .find(|(decl, _)| key.starts_with(decl.prefix))
            .map(|(_, family)| family)
            .or_else(|| crate::code_run::settled_wait_key(key).then_some(Self::WaitSettled)),
            ResponseDb::Entities => EntityMetadataHeader::parse(value)
                .filter(|header| header.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
                .map(|_| Self::StepClaim),
            ResponseDb::SyncState => {
                if key.starts_with(side_table::HTTP_IDEMPOTENCY_REPLY.prefix) {
                    return Some(Self::Http);
                }
                crate::store::media_key(key).map(|media| match media {
                    MediaKey::Job => Self::MediaJob,
                    MediaKey::Part { .. } => Self::MediaPart,
                })
            }
            ResponseDb::Attempts => crate::attempt_queue::attempt_payload_family(key, value)
                .then_some(Self::AttemptPayload),
        }
    }

    /// The database the family's rows rest in.
    pub(crate) const fn database(self) -> ResponseDb {
        match self {
            Self::StepClaim => ResponseDb::Entities,
            Self::Http | Self::MediaJob | Self::MediaPart => ResponseDb::SyncState,
            Self::AttemptPayload => ResponseDb::Attempts,
            Self::ProgramStep
            | Self::StepState
            | Self::Replay
            | Self::BlockedCapture
            | Self::WaitDelivery
            | Self::WaitSettled
            | Self::ModelStepSubmission => ResponseDb::VaultMeta,
        }
    }

    /// Whether the family's response is shared by every holder its
    /// obligations name, so one holder's erase owes its retirement to the
    /// final holder's release (FIX 6588).
    pub(crate) fn shared(self) -> bool {
        self == Self::WaitSettled
    }

    /// What a checkpoint carries of the row `key`, the one scanner every
    /// census, binding, stale and retire path reads it through: no response
    /// (a bodyless step, a state with no payload, a claim whose response
    /// rests in an artifact, an erased reply or marker, a dispatch with no
    /// text), a decoded one, or, for a STEP, step-state, replay or step
    /// claim row that does not decode, an opaque one (FIX 6227).
    pub(crate) fn scan(self, key: &[u8], value: &[u8]) -> ResponseScan {
        let whole = |stub: Vec<u8>| ResponseCarriage {
            keep: 0,
            retired: stub.len(),
            stub,
        };
        // An opaque response's erased form holds nothing.
        if value == OPAQUE_ERASED {
            return ResponseScan::NotResponse;
        }
        match self {
            Self::ProgramStep => crate::dreamer_runner::program_step_carriage(value),
            Self::StepState => crate::llm::step_state_carriage(value),
            Self::StepClaim => crate::llm::step_claim_carriage(value),
            Self::Replay => crate::code_run::replay_carriage(value),
            Self::Http => ResponseScan::decoded(crate::store::http_carriage(value).map(whole)),
            Self::MediaJob => {
                ResponseScan::decoded(crate::store::media_job_carriage(value).map(whole))
            }
            Self::MediaPart => {
                ResponseScan::decoded(crate::store::media_part_carriage(value).map(whole))
            }
            // The whole row; nothing stays once retired: the row goes.
            Self::BlockedCapture => ResponseScan::decoded(
                crate::self_heal::blocked_reports::blocked_capture_stub(key, value).map(whole),
            ),
            Self::WaitDelivery | Self::WaitSettled => {
                ResponseScan::decoded(crate::code_run::wait_reply_stub(value).map(whole))
            }
            Self::AttemptPayload => ResponseScan::decoded(
                crate::attempt_queue::attempt_payload_stub(key, value).map(whole),
            ),
            Self::ModelStepSubmission => crate::llm::submission_carriage(value),
        }
    }

    /// Who owns the opaque response in the row `key`, as far as its key
    /// proves (FIX 6227): a claim's is its own id; a STEP row's its run and
    /// step, a replay record's its run and the actor a program's run runs
    /// as, the rest of what their rows stamp unknown; a step-state row's
    /// none.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn opaque_owners(
        self,
        store: &Store,
        txn: &RoTxn<'_>,
        key: &[u8],
        value: &[u8],
    ) -> Result<ResponseOwners> {
        if self == Self::Replay {
            let Some(run) = key
                .strip_prefix(side_table::CODE_RUN_REPLAY.prefix)
                .and_then(|raw| <[u8; 16]>::try_from(raw).ok())
                .and_then(|raw| EntityId::from_bytes(raw).ok())
            else {
                return Ok(ResponseOwners::Unknown);
            };
            let mut owners = vec![run];
            owners.extend(crate::dreamer_runner::program_run_actor_in_txn(
                store, txn, &run,
            )?);
            return Ok(ResponseOwners::Partial(owners));
        }
        let owners = self.owners(store, txn, key, value)?;
        Ok(match self {
            Self::StepClaim => ResponseOwners::Known(owners),
            _ if owners.is_empty() => ResponseOwners::Unknown,
            _ => ResponseOwners::Partial(owners),
        })
    }

    /// Who owns the row's response, by the stamps written with it.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn owners(
        self,
        store: &Store,
        txn: &RoTxn<'_>,
        key: &[u8],
        value: &[u8],
    ) -> Result<Vec<EntityId>> {
        match self {
            Self::ProgramStep => crate::dreamer_runner::program_step_owners(store, txn, key, value),
            Self::StepState => Ok(crate::llm::step_state_owners(value)),
            Self::StepClaim => Ok(vec![EntityId::from_bytes(
                key.try_into()
                    .map_err(|_| Error::CorruptedIndex("entity key"))?,
            )?]),
            Self::Replay => crate::code_run::replay_owners(store, txn, value),
            Self::Http => Ok(crate::store::http_owners(value)),
            Self::MediaJob => Ok(crate::store::media_job_owners(value)),
            Self::BlockedCapture => Ok(crate::self_heal::blocked_reports::blocked_capture_owners(
                key, value,
            )),
            Self::WaitDelivery => crate::code_run::wait_delivery_owners(store, txn, key),
            Self::WaitSettled => crate::code_run::wait_settled_owners(store, txn, key),
            Self::AttemptPayload => Ok(crate::attempt_queue::attempt_payload_owners(key, value)),
            Self::ModelStepSubmission => Ok(crate::llm::submission_owners(value)),
            // A clip's owners are its job's, as the job's row stamps them.
            Self::MediaPart => {
                let Some(MediaKey::Part { job }) = crate::store::media_key(key) else {
                    return Ok(Vec::new());
                };
                Ok(store
                    .side_sync_state()?
                    .get(txn, sync_state_key(&key[..job])?)?
                    .map(|row| crate::store::media_job_owners(&row))
                    .unwrap_or_default())
            }
        }
    }

    /// What the erased disposition of the retired row `key` takes beside the
    /// row itself, in raw image rows: a claim's step-index rows and its
    /// projection rows go, and its soft-delete marker and fence are left, as
    /// an erase leaves them (FIX 6661); a retired clip's row goes, and so
    /// does a retired captured request's (FIX 6708).
    ///
    /// # Errors
    ///
    /// A row that does not decode.
    pub(crate) fn retire_in_rows(
        self,
        databases: &mut BTreeMap<String, Rows>,
        key: &[u8],
    ) -> Result<()> {
        match self {
            Self::StepClaim => crate::llm::retire_step_claim_in_rows(databases, key),
            // A retired clip's row goes: its job keeps its erased form.
            Self::MediaPart => {
                drop_row(databases, ResponseDb::SyncState, key);
                Ok(())
            }
            Self::BlockedCapture => {
                drop_row(databases, ResponseDb::VaultMeta, key);
                Ok(())
            }
            Self::ProgramStep
            | Self::StepState
            | Self::Replay
            | Self::Http
            | Self::MediaJob
            | Self::WaitDelivery
            | Self::WaitSettled
            | Self::AttemptPayload
            | Self::ModelStepSubmission => Ok(()),
        }
    }

    /// Leaves the live row `key` its erased disposition in `wtxn`, as
    /// `carriage` names it: an activation's prune of a row whose instance
    /// its source retired. A `vault_meta` row takes its stub as far as the
    /// disposition keeps it (an opaque one's, its erased marker); a claim,
    /// the erase's shell beside its markers.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn retire_in_txn(
        self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        key: &[u8],
        carriage: &ResponseCarriage,
    ) -> Result<()> {
        let kept = || {
            carriage
                .stub
                .get(..carriage.retired)
                .ok_or(Error::InvariantViolation(
                    "a response stub shorter than it keeps",
                ))
        };
        match self {
            Self::StepClaim => crate::llm::retire_step_claim_in_txn(store, wtxn, key),
            Self::ProgramStep
            | Self::StepState
            | Self::Replay
            | Self::WaitDelivery
            | Self::WaitSettled
            | Self::ModelStepSubmission => store.side_vault_meta().put(wtxn, key, kept()?),
            Self::BlockedCapture => {
                store.side_vault_meta().delete(wtxn, key)?;
                Ok(())
            }
            Self::AttemptPayload => {
                crate::attempt_queue::retire_attempt_payload_in_txn(store, wtxn, key, kept()?)
            }
            Self::Http | Self::MediaJob => {
                store
                    .side_sync_state()?
                    .put(wtxn, sync_state_key(key)?, kept()?)
            }
            Self::MediaPart => {
                store
                    .side_sync_state()?
                    .delete(wtxn, sync_state_key(key)?)?;
                Ok(())
            }
        }
    }
}

/// Takes the row `key` out of `db`'s raw image rows.
fn drop_row(databases: &mut BTreeMap<String, Rows>, db: ResponseDb, key: &[u8]) {
    if let Some(rows) = databases.get_mut(db.name()) {
        rows.retain(|(row, _)| row.as_slice() != key);
    }
}

/// The `sync_state` row key `key` as the text such a key is.
fn sync_state_key(key: &[u8]) -> Result<&str> {
    std::str::from_utf8(key).map_err(|_| Error::CorruptedIndex("sync_state row key"))
}

/// The binding of the row `carrier` names, as `txn` holds it.
///
/// # Errors
///
/// Storage errors, and a row that does not decode.
pub(crate) fn response_binding_in_txn<D: SideTableDbs>(
    dbs: &D,
    txn: &RoTxn<'_>,
    carrier: &[u8],
) -> Result<Option<ResponseBinding>> {
    Ok(RESPONSE_BINDINGS
        .get(dbs, txn, &carrier.to_vec())?
        .map(|raw| ResponseBinding::decode(&raw)))
}

/// Binds the row `carrier` names to `binding` in `wtxn`, with an
/// obligation for each of `owners`. A binding the row held before is
/// replaced; its instance's obligations stay. Returns the obligation rows,
/// which the writer journals in custody before it commits (FIX 6229).
///
/// # Errors
///
/// Storage errors.
pub(crate) fn bind_response_in_txn<D: SideTableDbs>(
    dbs: &D,
    wtxn: &mut RwTxn<'_>,
    carrier: &[u8],
    binding: ResponseBinding,
    owners: &[EntityId],
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    RESPONSE_BINDINGS.put(dbs, wtxn, &carrier.to_vec(), &binding.encode())?;
    let carrier = carrier.to_vec();
    let mut history = Vec::with_capacity(owners.len());
    for owner in owners {
        let key = (*owner, binding.instance);
        RESPONSE_OWNERS.put(dbs, wtxn, &key, &carrier)?;
        history.push((
            RESPONSE_OWNERS.key_bytes(&key),
            RESPONSE_OWNERS.encode_value(&carrier)?,
        ));
    }
    Ok(history)
}

/// Drops the binding of the row `carrier` names, when it no longer holds
/// the bytes bound: a delete, an overwrite or an expiry, which keeps every
/// key and every obligation.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn release_response_in_txn<D: SideTableDbs>(
    dbs: &D,
    wtxn: &mut RwTxn<'_>,
    carrier: &[u8],
) -> Result<()> {
    RESPONSE_BINDINGS.delete(dbs, wtxn, &carrier.to_vec())?;
    Ok(())
}

/// The erase of `owner`'s row-held responses, in the erase's own
/// transaction, from the provenance door: every instance its obligations
/// name retires, noted for its receipt, so each image it was carried in
/// reads as its row's erased disposition from then on; a row still bound
/// to one is unbound, and the next checkpoint carries what the erase left
/// of it under a fresh instance. A shared reply another holder still keeps
/// is owed instead, until the final holder's release (FIX 6588).
///
/// # Errors
///
/// Storage and custody errors.
pub(crate) fn erase_response_owner_in_txn<D: ManifestDbs + SideTableDbs>(
    dbs: &D,
    wtxn: &mut RwTxn<'_>,
    owner: &EntityId,
) -> Result<()> {
    let mut owed = Vec::new();
    for row in RESPONSE_OWNERS.iter_raw_from(dbs, wtxn, owner.as_bytes())? {
        let (key, carrier) = row?;
        // An erase never fails on a row that does not decode (FIX 5736).
        if let Some((_, instance)) = <(EntityId, [u8; 16]) as SideKey>::decode_key(&key) {
            owed.push((instance, carrier));
        }
    }
    let mut notes = ErasedNotes::default();
    for (instance, carrier) in owed {
        RESPONSE_OWNERS.delete(dbs, wtxn, &(*owner, instance))?;
        if shared_wait::still_held(dbs, wtxn, &carrier, &instance)? {
            shared_wait::owe(dbs, wtxn, (owner, &mut notes), &carrier, &instance)?;
            continue;
        }
        shared_wait::discharge(dbs, wtxn, &instance)?;
        stage_erase(dbs, wtxn, (Some(owner), &mut notes), &instance)?;
        if response_binding_in_txn(dbs, wtxn, &carrier)
            .ok()
            .flatten()
            .is_some_and(|binding| binding.instance == instance)
        {
            release_response_in_txn(dbs, wtxn, &carrier)?;
        }
    }
    notes.journal(dbs)
}

/// Every instance a response binding names in `txn`: `None` when one does
/// not decode, so the instance it names is not known (FIX 6022).
///
/// # Errors
///
/// Storage errors.
pub(super) fn bound_instances_in_txn<D: SideTableDbs>(
    dbs: &D,
    txn: &RoTxn<'_>,
) -> Result<Option<std::collections::BTreeSet<[u8; 16]>>> {
    let mut bound = std::collections::BTreeSet::new();
    for row in RESPONSE_BINDINGS.iter_raw_from(dbs, txn, &[])? {
        let Ok(binding) = ResponseBinding::of_row(&row?.1) else {
            return Ok(None);
        };
        bound.insert(binding.instance);
    }
    Ok(Some(bound))
}

/// Expires every obligation naming one of `instances`, in `wtxn`: each is
/// retiring by retention, which no image, holder or hold needs any longer
/// (FIX 6228). The custody fold drops them once their instances are
/// retired.
///
/// # Errors
///
/// Storage errors.
pub(super) fn forget_obligations_in_txn<D: SideTableDbs>(
    dbs: &D,
    wtxn: &mut RwTxn<'_>,
    instances: &std::collections::BTreeSet<[u8; 16]>,
) -> Result<()> {
    if instances.is_empty() {
        return Ok(());
    }
    let mut gone = Vec::new();
    for row in RESPONSE_OWNERS.iter_raw_from(dbs, wtxn, &[])? {
        let (key, _) = row?;
        if let Some(key) = <(EntityId, [u8; 16]) as SideKey>::decode_key(&key)
            && instances.contains(&key.1)
        {
            gone.push(key);
        }
    }
    for key in gone {
        RESPONSE_OWNERS.delete(dbs, wtxn, &key)?;
    }
    Ok(())
}

/// Whether any row is still bound to `instance`, so its retirement waits.
/// A binding that does not decode names no instance.
///
/// # Errors
///
/// Storage errors.
pub(super) fn response_names_instance_in_txn<D: SideTableDbs>(
    dbs: &D,
    txn: &RoTxn<'_>,
    instance: &[u8; 16],
) -> Result<bool> {
    for row in RESPONSE_BINDINGS.iter_raw_from(dbs, txn, &[])? {
        if ResponseBinding::of_row(&row?.1).is_ok_and(|binding| binding.instance == *instance) {
            return Ok(true);
        }
    }
    Ok(false)
}
