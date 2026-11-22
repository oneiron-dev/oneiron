//! Psych Mirror profile attempts for the host's job adapter, and the reads
//! the named test asserts (untangle 6.9i). The attempt is enqueued by the
//! production sweep and admitted through the maintenance lane's own
//! admission. Nothing here mints a binding or commits.

use crate::claim::ScopedReadActorKey;
use crate::companion::CompanionProfileAdmission;
use crate::dreamer_runner::maintenance::PSYCH_PROFILE_FACET;
use crate::dreamer_runner::{
    AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerAdmittedAttempt, DreamerRunnerStore,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::psych_profile::{PsychProfile, PsychProfileKey, PsychProfileState};
use crate::settings::ReadDestination;
use crate::vault::Vault;
use crate::write_envelope::WriteActor;

/// The lease owner every psych profile admission here takes.
pub const PSYCH_PROFILE_LEASE_OWNER: &str = "psych-profile-binding-worker";

/// Every profile key the Dreamer reads an eligible claim of `person` under,
/// in claim order, each once.
///
/// # Errors
///
/// The vault's.
pub fn psych_profile_keys(vault: &Vault, person: EntityId) -> Result<Vec<PsychProfileKey>> {
    let read = vault.scoped_read(dreamer_read_key(vault)?);
    let txn = vault.store.env.read_txn()?;
    let mut keys: Vec<PsychProfileKey> = Vec::new();
    for (key, _) in crate::psych_profile::sources::person_claims_in(vault, &read, &txn, person)? {
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    Ok(keys)
}

/// Admits the next maintenance attempt as a psych profile job under
/// [`PSYCH_PROFILE_LEASE_OWNER`] at `now`, through the lane's own admission.
///
/// # Errors
///
/// The vault's, or an admission of nothing or of another job type.
pub fn admit_psych_profile_attempt(vault: &Vault, now: u64) -> Result<DreamerAdmittedAttempt> {
    let DreamerAdmissionOutcome::Admitted(admitted) = DreamerRunnerStore::new(vault)
        .admit_next_maintenance(AdmitDreamerAttempt {
            lease_owner: PSYCH_PROFILE_LEASE_OWNER.to_owned(),
            now,
            budget_id: "psych-profile-binding".to_owned(),
            budget_total_units: 10_000,
            reserve_units: 1,
            started_milestone: None,
        })?
    else {
        return Err(Error::InvalidConfig(
            "no psych profile attempt was admitted".into(),
        ));
    };
    if admitted.status.payload.attempt_type != PSYCH_PROFILE_FACET {
        return Err(Error::InvalidConfig(format!(
            "the maintenance lane admitted {}",
            admitted.status.payload.attempt_type
        )));
    }
    Ok(*admitted)
}

/// The content hash of the words `claim` holds at `revision`, as a profile
/// source pins them; `None` when the vault keeps no such revision of it.
///
/// # Errors
///
/// The vault's.
pub fn claim_words_hash_at(
    vault: &Vault,
    claim: EntityId,
    revision: crate::vault::RevisionRef,
) -> Result<Option<[u8; 32]>> {
    let Some(raw) = vault.get_raw_with_mode(&claim, crate::vault::ReadMode::Pinned(revision))?
    else {
        return Ok(None);
    };
    Ok(raw
        .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
        .map(crate::store::consolidation_evidence::swarm_evidence_content_hash))
}

/// The content hash of the words `claim` holds now; `None` for no row.
///
/// # Errors
///
/// The vault's.
pub fn claim_words_hash(vault: &Vault, claim: EntityId) -> Result<Option<[u8; 32]>> {
    Ok(vault.get_raw(&claim)?.and_then(|raw| {
        raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
            .map(crate::store::consolidation_evidence::swarm_evidence_content_hash)
    }))
}

/// The profile `principal`'s companion read of `key` returns when the read
/// is judged under the Dreamer's own scoped read, which reads the claims a
/// profile it wrote cites; `None` when the read returns no profile.
///
/// # Errors
///
/// The vault's.
pub fn companion_profile_under_dreamer_read(
    vault: &Vault,
    principal: EntityId,
    key: &PsychProfileKey,
) -> Result<Option<PsychProfile>> {
    let read = vault.scoped_read(dreamer_read_key(vault)?);
    companion_profile_under(vault, principal, key, &read)
}

/// The profile `principal`'s companion read of `key` returns when the read
/// is judged under `reader`'s read that reads no row, so no source of the
/// profile reads for it; `None` when the read returns no profile.
///
/// # Errors
///
/// The vault's.
pub fn companion_profile_under_reader_of_nothing(
    vault: &Vault,
    principal: EntityId,
    key: &PsychProfileKey,
    reader: EntityId,
) -> Result<Option<PsychProfile>> {
    let read = vault.scoped_read(
        ScopedReadActorKey::read_nothing(reader.to_hex(), "system")
            .ok_or_else(|| Error::InvalidConfig("a reader with no read key".into()))?,
    );
    companion_profile_under(vault, principal, key, &read)
}

fn companion_profile_under(
    vault: &Vault,
    principal: EntityId,
    key: &PsychProfileKey,
    read: &crate::claim::ScopedRead<'_>,
) -> Result<Option<PsychProfile>> {
    Ok(
        match vault.companion_profile_snapshot_admitted(
            &principal,
            key,
            &ReadDestination::on_device(),
            Some(read),
            None,
        )? {
            CompanionProfileAdmission::Admitted {
                state: PsychProfileState::Fresh(profile),
                ..
            } => Some(profile),
            _ => None,
        },
    )
}

fn dreamer_read_key(vault: &Vault) -> Result<ScopedReadActorKey> {
    ScopedReadActorKey::for_engine_actor(WriteActor::new(
        vault.dreamer_authority()?.entity_ref(),
        EdgeActorClass::System,
    ))
    .ok_or_else(|| Error::InvalidConfig("the Dreamer has no read key".into()))
}
