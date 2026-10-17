//! A live agent run's attachment to the one credential that may act for it
//! (OF-181).
//!
//! The host that runs a leased AGENT_DEF attempt holds the run's lease proof
//! ([`HostBinding`], from
//! [`super::HostSelfDispatcher::live_run_host_binding`]). A harness holding a
//! credential paired to that exact agent attaches to the run and gets an
//! opaque handle back; its actions through that handle run under the proof.
//!
//! [`CodeRunLiveRunBinding`] is that attachment as the run's replay row keeps
//! it: the issued handle id, the credential's identity digest and locality,
//! the agent, and the lease (attempt, owner, generation) it was attached
//! under. It is association metadata, never authority: decoding one grants
//! nothing, and a handle resolves only while the runner that holds the same
//! lease has registered the run with its host.

use rand_core::{OsRng, RngCore};

use crate::attempt_queue::{AttemptId, AttemptRecord, AttemptState};
use crate::claim::CallerLocality;
use crate::task_verb::HostBinding;
use crate::task_verb::sdk::RunVerb;
use crate::{EdgeActorClass, EntityId, Error, Result, Vault, WriteActor};

/// The bytes of an issued handle id.
pub const LIVE_RUN_ISSUED_LEN: usize = 16;

/// The most bytes a caller's own idempotency key holds, as an action's.
const CLIENT_KEY_MAX_BYTES: usize = 256;

/// The credential an attach or an action presents: a digest of its
/// idempotency identity (principal, instrument and scopes) and the locality
/// its connection sits at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveRunCredential {
    pub(super) digest: [u8; 32],
    pub(super) locality: CallerLocality,
}

impl LiveRunCredential {
    /// The credential whose idempotency identity is `principal`, on a
    /// connection at `locality`.
    #[must_use]
    pub fn of(principal: &str, locality: CallerLocality) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key("oneiron live-run credential v1");
        hasher.update(principal.as_bytes());
        Self {
            digest: *hasher.finalize().as_bytes(),
            locality,
        }
    }
}

/// One credential's attachment to one lease of a live agent run, as the
/// run's replay row keeps it. Its executor is the row's own run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRunLiveRunBinding {
    pub(super) issued: [u8; LIVE_RUN_ISSUED_LEN],
    pub(super) credential: LiveRunCredential,
    pub(super) actor: EntityId,
    pub(super) actor_class: EdgeActorClass,
    pub(super) attempt: AttemptId,
    pub(super) lease_owner: String,
    pub(super) lease_generation: u32,
}

impl CodeRunLiveRunBinding {
    /// The handle id the host issued at attach.
    #[must_use]
    pub const fn issued(&self) -> [u8; LIVE_RUN_ISSUED_LEN] {
        self.issued
    }

    /// Whether `credential`, and no other, is the one attached.
    #[must_use]
    pub fn is_for_credential(&self, credential: &LiveRunCredential) -> bool {
        self.credential == *credential
    }

    /// Whether this attachment is `actor`'s under exactly `leased`'s lease:
    /// its attempt, owner and generation. Another generation needs a new
    /// attach.
    #[must_use]
    pub fn is_for_lease(&self, actor: WriteActor, leased: &AttemptRecord) -> bool {
        self.actor == actor.entity_ref()
            && self.actor_class == actor.actor_class()
            && self.attempt == leased.id
            && leased.lease_owner.as_deref() == Some(self.lease_owner.as_str())
            && self.lease_generation == leased.attempt_count
    }

    /// The idempotency key an action sent through this attachment runs
    /// under: the caller's `key`, hashed into the namespace of the issued
    /// handle and the attached credential, so no other attachment or
    /// credential replays its answer. The action keeps its run's own
    /// attempt and generation partition besides.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for a blank key or one past 256 bytes, as an
    /// action's own key.
    pub fn action_key(&self, key: &str) -> Result<String> {
        if key.trim().is_empty() || key.len() > CLIENT_KEY_MAX_BYTES {
            return Err(Error::InvalidConfig(
                "action arguments do not match declared schema".to_owned(),
            ));
        }
        let mut hasher = blake3::Hasher::new_derive_key("oneiron live-run action key v1");
        for part in [
            self.issued.as_slice(),
            self.credential.digest.as_slice(),
            key.as_bytes(),
        ] {
            hasher.update(&(part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        Ok(format!("live-run:{}", hasher.finalize().to_hex()))
    }
}

/// The attachment run `run_id`'s replay row keeps, if any.
///
/// # Errors
///
/// Storage and decode errors.
pub fn live_run_binding(vault: &Vault, run_id: &EntityId) -> Result<Option<CodeRunLiveRunBinding>> {
    Ok(vault
        .get_code_run_replay_record(run_id)?
        .and_then(|record| record.live_run))
}

/// Attaches `credential` to the live run `run_id`, which `actor` runs under
/// the lease of `leased`: mints a fresh handle id and stores the attachment
/// on the run's replay row in place of any older one. `None` when the run
/// has no replay row yet.
///
/// The host calls this only while it holds the run's guard, so it never
/// races the runner's own save of the row.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when `leased` holds no lease; storage errors,
/// and a concurrent write of the row.
pub fn attach_live_run(
    vault: &Vault,
    run_id: &EntityId,
    actor: WriteActor,
    leased: &AttemptRecord,
    credential: LiveRunCredential,
) -> Result<Option<CodeRunLiveRunBinding>> {
    let lease_owner = leased
        .lease_owner
        .clone()
        .filter(|_| leased.state == AttemptState::Leased)
        .ok_or(Error::InvalidClaimBody("the run's lease no longer holds"))?;
    let Some(mut record) = vault.get_code_run_replay_record(run_id)? else {
        return Ok(None);
    };
    let mut issued = [0; LIVE_RUN_ISSUED_LEN];
    OsRng
        .try_fill_bytes(&mut issued)
        .map_err(|_| Error::InvariantViolation("os randomness unavailable"))?;
    let binding = CodeRunLiveRunBinding {
        issued,
        credential,
        actor: actor.entity_ref(),
        actor_class: actor.actor_class(),
        attempt: leased.id,
        lease_owner,
        lease_generation: leased.attempt_count,
    };
    let generation = record.generation()?;
    record.live_run = Some(binding.clone());
    vault.put_code_run_replay_record_if_generation(&record, Some(generation))?;
    Ok(Some(binding))
}

/// Whether `proof`'s lease still holds in `vault`, read live: the same try,
/// still leased, by the same owner, at the same generation.
///
/// # Errors
///
/// Storage errors.
pub fn live_run_lease_holds(vault: &Vault, proof: &HostBinding) -> Result<bool> {
    match proof.leased_record(vault) {
        Ok(_) => Ok(true),
        Err(Error::InvalidClaimBody(_)) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Whether `verb` is a run row that acts on its caller's live run, so a call
/// of it must name one.
#[must_use]
pub fn is_live_run_verb(verb: &str) -> bool {
    RunVerb::from_name(verb)
        .is_some_and(|verb| super::run_verb_call::LIVE_RUN_VERBS.contains(&verb))
}
