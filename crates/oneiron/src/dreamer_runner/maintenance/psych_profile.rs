//! Psych Mirror profiles run on the maintenance lane with a host's lent job
//! runner (untangle 6.9i, RULING S69I-PR2-START = A).
//!
//! The server's home timer sweeps the PERSONs the Dreamer reads. Each
//! profile key (a PERSON, a facet and a world) under which an eligible claim
//! stands, and whose stored profile is missing, withdrawn or at least a day
//! old, gets one `dreamer.psych_profile` attempt, deduped per key while it is
//! pending. A stored profile of a PERSON under whose key no eligible claim
//! stands any more (each retracted, hidden, restricted or gone) is withdrawn:
//! it stands on nothing, and no attempt would rewrite it. The attempt input names the key; the host's job reads that
//! key's ranked claims, asks one bound step for the three tiers and commits
//! one PsychProfile item.

use rmpv::Value;

use super::super::{
    DreamerAttemptPayload, DreamerParkCause, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::claim::ScopedReadActorKey;
use crate::dreamer_wake::DreamerAttemptExecution;
use crate::edge::EdgeActorClass;
use crate::ports::RetrievalIndex;
use crate::psych_profile::{PsychProfileKey, psych_profile_entity_id};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_PSYCH_PROFILE};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Error, Result, Vault};

/// The maintenance job type for one Psych Mirror profile.
pub const PSYCH_PROFILE_FACET: &str = "dreamer.psych_profile";

/// Canon (ARCH-0025): a stored profile regenerates at most daily per key.
pub const PSYCH_PROFILE_REGENERATE_SECS: u64 = 86_400;

/// A profile job waits for a host to lend its job runner.
#[must_use]
pub fn unlent() -> DreamerAttemptExecution {
    DreamerAttemptExecution::Park {
        reason: "no host lends this pass the psych profile job".to_owned(),
        cause: DreamerParkCause::Retry,
    }
}

/// The attempt input that names `key`: its PERSON, and its facet and world
/// when it has them, each as the id's bytes.
#[must_use]
pub fn psych_profile_attempt_input(key: &PsychProfileKey) -> Value {
    let id = |id: &EntityId| Value::Binary(id.as_bytes().to_vec());
    let mut entries = vec![(Value::from("person"), id(&key.person))];
    if let Some(facet) = &key.facet {
        entries.push((Value::from("facet"), id(facet)));
    }
    if let Some(world) = &key.world {
        entries.push((Value::from("world"), id(world)));
    }
    Value::Map(entries)
}

/// The profile key a `dreamer.psych_profile` attempt's input names.
///
/// # Errors
///
/// `InvalidConfig` for an input that is not a map of `person` and optional
/// `facet` and `world` ids, each at most once.
pub fn psych_profile_key_of_input(input: &Value) -> Result<PsychProfileKey> {
    let invalid = |reason: &str| Error::InvalidConfig(format!("psych profile input {reason}"));
    let Value::Map(entries) = input else {
        return Err(invalid("is not a map"));
    };
    let (mut person, mut facet, mut world) = (None, None, None);
    for (name, value) in entries {
        let Value::Binary(bytes) = value else {
            return Err(invalid("holds a non-id"));
        };
        let bytes: [u8; 16] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| invalid("holds a non-id"))?;
        let id = EntityId::from_bytes(bytes)?;
        let slot = match name.as_str() {
            Some("person") => &mut person,
            Some("facet") => &mut facet,
            Some("world") => &mut world,
            _ => return Err(invalid("names an unknown key")),
        };
        if slot.replace(id).is_some() {
            return Err(invalid("repeats a key"));
        }
    }
    Ok(PsychProfileKey {
        person: person.ok_or_else(|| invalid("names no person"))?,
        facet,
        world,
    })
}

impl DreamerRunnerStore<'_> {
    /// Enqueues the profile attempt of `key` in the caller's transaction.
    /// A pending attempt holds the key's dedupe entry until its chain ends.
    ///
    /// # Errors
    ///
    /// The queue's, authority-stamp, run-tree and storage errors.
    pub fn enqueue_psych_profile_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        key: &PsychProfileKey,
        run_id: Option<String>,
        now: u64,
    ) -> Result<bool> {
        let outcome = self.enqueue_kind_in_txn(
            txn,
            super::MAINTENANCE_QUEUE_KIND,
            DreamerAttemptPayload {
                attempt_type: PSYCH_PROFILE_FACET.into(),
                input: psych_profile_attempt_input(key),
                parent_attempt: None,
            },
            Some(format!(
                "{PSYCH_PROFILE_FACET}:{}",
                psych_profile_entity_id(key).to_hex()
            )),
            run_id,
            now,
        )?;
        Ok(matches!(outcome, EnqueueDreamerAttemptOutcome::Enqueued(_)))
    }
}

/// Enqueues the profile attempt of every due key at `now` (seconds): each
/// key under which a claim the Dreamer reads is eligible (an active,
/// surfaced claim about the PERSON below the restricted band), whose stored
/// profile is missing or withdrawn, or was written at least
/// [`PSYCH_PROFILE_REGENERATE_SECS`] ago. Like other parentless host
/// maintenance, an attempt has no recipe run id. In the same write, a stored
/// profile of a PERSON no eligible claim stands under any more is withdrawn
/// (stale-marked, so it reads as none), checked again in that write: a claim
/// and a fresh profile that landed under its key after the read keep it. The stored profiles are read on
/// their own for this, never through the claims the Dreamer reads, which a
/// retracted claim has left. Returns how many attempts were enqueued.
///
/// # Errors
///
/// A vault with no Dreamer actor, and storage and queue errors.
pub fn enqueue_due_psych_profiles(vault: &Vault, now: u64) -> Result<usize> {
    let sweep = read_psych_profile_sweep(vault, now)?;
    write_psych_profile_sweep(vault, &sweep, now)
}

/// What one sweep's read found at `now`: the keys due for an attempt, and
/// the stored profiles no eligible claim stood under. The sweep's write acts
/// on it.
#[derive(Debug, Default)]
pub(crate) struct PsychProfileSweep {
    pub(crate) due: Vec<PsychProfileKey>,
    pub(crate) withdrawn: Vec<EntityId>,
}

/// The read of [`enqueue_due_psych_profiles`], in one snapshot: the PERSON
/// and profile type indexes are scanned in the transaction that reads the
/// claims and the stored profiles.
///
/// # Errors
///
/// A vault with no Dreamer actor, and storage errors.
pub(crate) fn read_psych_profile_sweep(vault: &Vault, now: u64) -> Result<PsychProfileSweep> {
    let mut sweep = PsychProfileSweep::default();
    let read = profile_reader(vault)?;
    vault.store.authorization_now()?;
    let txn = vault.store.env.read_txn()?;
    let persons = entity_ids_of_type_in(vault, &txn, ENTITY_TYPE_PERSON)?;
    if persons.is_empty() {
        return Ok(sweep);
    }
    let profiles = entity_ids_of_type_in(vault, &txn, ENTITY_TYPE_PSYCH_PROFILE)?;
    // The profiles some eligible claim still stands under.
    let mut standing = std::collections::BTreeSet::new();
    for person in &persons {
        for (key, _) in
            crate::psych_profile::sources::person_claims_in(vault, &read, &txn, *person)?
        {
            let id = psych_profile_entity_id(&key);
            if standing.insert(id) && profile_due_in(vault, &txn, &id, now)? {
                sweep.due.push(key);
            }
        }
    }
    let persons: std::collections::BTreeSet<EntityId> = persons.into_iter().collect();
    for id in profiles {
        if standing.contains(&id) || crate::ports::stale_in_txn(&vault.store, &txn, &id)? {
            continue;
        }
        // A row that does not decode is left as it stands.
        let Ok(Some(profile)) = vault.get_psych_profile_in_txn(&txn, &id) else {
            continue;
        };
        if persons.contains(&profile.subject_ref) {
            sweep.withdrawn.push(id);
        }
    }
    Ok(sweep)
}

/// The write of [`enqueue_due_psych_profiles`] over what its read found at
/// `now`: each profile found standing on nothing is withdrawn unless an
/// eligible claim stands under its key in this write, and each due key is
/// enqueued. Returns how many attempts were enqueued.
///
/// # Errors
///
/// A vault with no Dreamer actor, and storage and queue errors.
pub(crate) fn write_psych_profile_sweep(
    vault: &Vault,
    sweep: &PsychProfileSweep,
    now: u64,
) -> Result<usize> {
    if sweep.due.is_empty() && sweep.withdrawn.is_empty() {
        return Ok(0);
    }
    let read = profile_reader(vault)?;
    let enqueued = vault.with_write_txn(|txn| {
        for id in &sweep.withdrawn {
            if profile_stands_in(vault, &read, txn, id)? {
                continue;
            }
            vault.port_retrieval_mark_stale(txn, id)?;
        }
        let store = DreamerRunnerStore::new(vault);
        let mut enqueued = 0;
        for key in &sweep.due {
            if store.enqueue_psych_profile_in_txn(txn, key, None, now)? {
                enqueued += 1;
            }
        }
        Ok(enqueued)
    })?;
    if enqueued > 0 {
        vault.store.notify_attempt_observers();
    }
    Ok(enqueued)
}

/// Every entity id of `entity_type` in `txn`, the scan counted as
/// [`Vault::entities_by_type`] counts it.
fn entity_ids_of_type_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity_type: u8,
) -> Result<Vec<EntityId>> {
    let mut count = crate::store::scan_count::ScanCount::start(
        &vault.store,
        txn,
        crate::store::EngineScan::TypeIndexRows,
        &[entity_type],
    )?;
    let mut ids = Vec::new();
    for entry in crate::ports::EntityStoreRead::port_entity_ids_by_type(
        &vault.store,
        txn,
        entity_type,
        None,
    )? {
        count.row();
        ids.push(entry?);
    }
    count.finish(vault);
    Ok(ids)
}

/// The Dreamer's own scoped read, through which a sweep reads the claims
/// about each PERSON.
fn profile_reader(vault: &Vault) -> Result<crate::claim::ScopedRead<'_>> {
    let reader = WriteActor::new(
        super::super::authority::dreamer_actor_id()?,
        EdgeActorClass::System,
    );
    Ok(vault.scoped_read(
        ScopedReadActorKey::for_engine_actor(reader)
            .ok_or_else(|| Error::InvalidConfig("invalid Dreamer profile reader".into()))?,
    ))
}

/// Whether an eligible claim stands under the key of the profile stored at
/// `id` in `txn`, the sweep's write. A row that does not decode stands, left
/// as it is.
fn profile_stands_in(
    vault: &Vault,
    read: &crate::claim::ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let Ok(Some(profile)) = vault.get_psych_profile_in_txn(txn, id) else {
        return Ok(true);
    };
    Ok(
        crate::psych_profile::sources::person_claims_in(vault, read, txn, profile.subject_ref)?
            .iter()
            .any(|(key, _)| psych_profile_entity_id(key) == *id),
    )
}

/// Whether the profile stored at `id` regenerates at `now`: none is stored,
/// it is withdrawn, or it was written at least a day ago.
fn profile_due_in(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId, now: u64) -> Result<bool> {
    if crate::ports::stale_in_txn(&vault.store, txn, id)? {
        return Ok(true);
    }
    let Some(raw) = vault.get_raw_in(txn, id)? else {
        return Ok(true);
    };
    let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
        return Ok(true);
    };
    Ok(now.saturating_sub(header.learned_at) >= PSYCH_PROFILE_REGENERATE_SECS)
}
