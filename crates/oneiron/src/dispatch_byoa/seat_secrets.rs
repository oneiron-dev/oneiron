//! The secrets a seat run declares, and the holder its T1 grants are minted
//! for (FIX 10624; ARCH-0069's custody ladder, T1 "injected at
//! materialization, revoked at teardown").
//!
//! A seat run's declaration is its repository's secret manifest at the commit
//! its checkout pins (ARCH-0068 RC4: names, refs and bindings, never a value).
//! Only entries that name an environment variable reach a run's process
//! environment; the host narrows them further to the destinations it serves.
//! The grants are held by one derived Agent PERSON, bound to the run's
//! attempt, so a grant names the run it was minted for and no other run can
//! redeem or retire it.

use std::path::Path;

use super::error::{ByoaError, ByoaResult, invalid};
use super::exhaust::ensure_derived_agent_in_txn;
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::checkout::lease::CheckoutLeaseAct;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, SecretError};
use crate::git_wire::GitWire;
use crate::origin::secret_manifest::manifest_bytes;
use crate::secret_lease::SecretGrantCaller;
use crate::secret_manifest::{SecretManifest, parse_secret_manifest};
use crate::store::code_snapshot::RepoRef;
use crate::temporal::TimeRange;

/// The hash domain of the Agent PERSON that holds every seat run's T1 grants.
const SEAT_SECRET_HOLDER_DOMAIN: &[u8] = b"oneiron:byoa-seat-secret-holder:v1";

/// The hash domain of the per-claim Agent PERSON a seat child's slip holds
/// for (FIX 10624 step 2): the claim's attempt, lease generation and lease
/// owner follow it, so each claim derives its own holder.
const SEAT_CHILD_HOLDER_DOMAIN: &[u8] = b"oneiron:byoa-seat-child-holder:v1:";

const ERR_SEAT_SECRET_REPO: &str =
    "a seat run's secret manifest is read from its checkout's local repository";

/// One secret a seat run declares for its process environment: the custody
/// `name` the manifest maps and the `variable` the run reads it as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredHostSecret {
    /// The custody name the manifest entry declares.
    pub name: String,
    /// The environment variable the run reads it as.
    pub variable: String,
}

/// The secrets `lease`'s run declares for its environment, in manifest order:
/// each manifest entry that names an environment variable. Empty when the
/// pinned commit carries no manifest.
pub fn declared_host_secrets(
    vault: &Vault,
    lease: &CheckoutLeaseAct,
) -> ByoaResult<Vec<DeclaredHostSecret>> {
    let Some(manifest) = pinned_secret_manifest(vault, lease)? else {
        return Ok(Vec::new());
    };
    Ok(manifest
        .secrets
        .into_iter()
        .filter_map(|entry| {
            entry.env_name.map(|variable| DeclaredHostSecret {
                name: entry.name,
                variable,
            })
        })
        .collect())
}

/// The secret manifest at the commit `lease` pins, or `None` when that commit
/// has none. The checkout materializes this commit, so the manifest read here
/// is the one the run's tree holds.
pub fn pinned_secret_manifest(
    vault: &Vault,
    lease: &CheckoutLeaseAct,
) -> ByoaResult<Option<SecretManifest>> {
    let RepoRef::LocalFolder { path, .. } = &lease.repo_ref else {
        return Err(invalid(ERR_SEAT_SECRET_REPO));
    };
    let wire = GitWire::new(vault)?;
    let repo = wire.open_repo(lease.repo_ref.clone(), Path::new(path))?;
    let commit = repo.pinned_commit()?;
    let Some(bytes) = manifest_bytes(&wire, &repo, &commit)? else {
        return Ok(None);
    };
    let text = String::from_utf8(bytes).map_err(|_| {
        Error::Secret(SecretError::InvalidSecretCustodyBody(
            "secret manifest must be UTF-8",
        ))
    })?;
    Ok(Some(parse_secret_manifest(&text).map_err(Error::from)?))
}

/// The caller a seat run's T1 grants are minted as: the seat-secret holder,
/// bound to `run`.
pub fn seat_secret_caller(vault: &Vault, run: AttemptId) -> ByoaResult<SecretGrantCaller> {
    let holder = ensure_seat_secret_holder(vault)?;
    SecretGrantCaller::of(&vault.memory(holder, EdgeActorClass::Agent), Some(run)).map_err(
        |error| {
            ByoaError::Store(Error::InvalidConfig(format!(
                "the seat-secret holder was refused: {error}"
            )))
        },
    )
}

fn ensure_seat_secret_holder(vault: &Vault) -> ByoaResult<EntityId> {
    let now = vault.now_recorded_at();
    let occurred = TimeRange {
        start: now,
        end: now,
    };
    let actor = vault.try_with_write_txn_grouped(|wtxn| {
        ensure_derived_agent_in_txn(vault, wtxn, SEAT_SECRET_HOLDER_DOMAIN, occurred, now)
    })?;
    Ok(actor.entity_ref())
}

/// The per-claim Agent PERSON the seat child of `attempt`'s run under the
/// claim of `lease_owner` at `attempt_count` holds its slip for (FIX 10624
/// step 2), made when it is not yet. A retried claim derives another, so a
/// grant one claim's helper took never reads as another's.
pub fn seat_child_holder(
    vault: &Vault,
    attempt: AttemptId,
    lease_owner: &str,
    attempt_count: u32,
) -> ByoaResult<EntityId> {
    let mut domain = SEAT_CHILD_HOLDER_DOMAIN.to_vec();
    domain.extend_from_slice(attempt.as_bytes());
    domain.extend_from_slice(&attempt_count.to_be_bytes());
    domain.extend_from_slice(lease_owner.as_bytes());
    let now = vault.now_recorded_at();
    let occurred = TimeRange {
        start: now,
        end: now,
    };
    let actor = vault.try_with_write_txn_grouped(|wtxn| {
        ensure_derived_agent_in_txn(vault, wtxn, &domain, occurred, now)
    })?;
    Ok(actor.entity_ref())
}
