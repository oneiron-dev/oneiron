//! `self.secrets.*` (DOOR-124, e2e SECRETS-03): the typed lifecycle of a
//! secret grant, over the engine's grant seam (FIX 4313). An agent run mints
//! a value-free grant on a secret for one purpose, renews it after the secret
//! rotates, tears it down, and uses it (`self.secrets.use`, the lease-aware
//! twin of `self.use`).
//!
//! The purpose fixes the rung, never the caller: a `self.use` operation or a
//! connector is a door (T0) grant, a destination the run's host registered
//! is a T1 grant, a declared local file is a T2 grant. The owner's binding
//! and the vault's floor cap it. The caller names no tier, owner, generation
//! or clock, and for a door or host purpose no effector: the operation table,
//! the connector route or the run's host names it. The holder is the
//! caller's own verified actor and the run its host attached to this
//! credential ([`SecretGrantCaller::of`]); nothing is synthesized for it.
//!
//! Every answer here is metadata. It never holds the value, a digest of it
//! (a T2 registration's content hash is left out) or a buffer: a T1 value
//! goes only to the run host's destination, a T2 value only to its file.
//! The engine writes no Gate record of its own for a mint, a renewal or a
//! teardown (FIX 4493), so the view names none; a T1/T2 view names the
//! lease's materialization receipt, and every use keeps its own record.
use serde::{Deserialize, Serialize};

use super::secret_use::grant_refusal;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::{Error, SecretError};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::secret_lease::{
    LocalRegistration, SecretCleanup, SecretGrantCaller, SecretGrantStatus, SecretGrantTarget,
    SecretHostDelivery, SecretLease, SecretLeaseGrant,
};
use crate::vault::Vault;

const MATERIALIZE: &str = "self.secrets.materialize";
const RENEW: &str = "self.secrets.renew";
const TEARDOWN: &str = "self.secrets.teardown";

/// `self.secrets.materialize`'s spec: the secret, and what its value is for.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretGrantMintRequest {
    /// The secret's handle, such as `sc12`, as the text or field holds it.
    pub handle: String,
    /// Where the value may go. It fixes the rung.
    pub purpose: SecretGrantPurpose,
    /// How long the grant lives, in seconds. Absent takes the engine's
    /// default; a longer ask is cut to the engine's longest, and the
    /// answer's `expires_at` says so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
}

/// What a grant's value is for. The rung follows from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecretGrantPurpose {
    /// T0: one of `self.use`'s operations, such as `slack.auth_test`. The
    /// value reaches only the operation's provider, inside the door.
    Operation { name: String },
    /// T0: connector calls on one catalogued connector, by its catalog
    /// name. Each send presents the value inside the connector's door.
    Connector { name: String },
    /// T1: a destination the caller's run host registered for the run, by
    /// the host's name for it, such as `env:GH_TOKEN`. The value goes to the
    /// processes the host starts for the run, never into an answer.
    HostDestination { name: String },
    /// T2: a path the secret's record declares, written for one project.
    /// `effector` is the consumer the owner's binding names for the file,
    /// such as `cli:gh`; the binding, not the caller, decides whether the
    /// file rung is allowed.
    LocalFile {
        effector: String,
        path: String,
        project_id: String,
    },
}

impl SecretGrantPurpose {
    fn target(self) -> SecretGrantTarget {
        match self {
            Self::Operation { name } => SecretGrantTarget::Operation { name },
            Self::Connector { name } => SecretGrantTarget::Connector { name },
            Self::HostDestination { name } => SecretGrantTarget::HostDestination { name },
            Self::LocalFile {
                effector,
                path,
                project_id,
            } => SecretGrantTarget::LocalFile {
                effector,
                path,
                project_id,
            },
        }
    }

    fn of(target: &SecretGrantTarget) -> Self {
        match target.clone() {
            SecretGrantTarget::Operation { name } => Self::Operation { name },
            SecretGrantTarget::Connector { name } => Self::Connector { name },
            SecretGrantTarget::HostDestination { name } => Self::HostDestination { name },
            SecretGrantTarget::LocalFile {
                effector,
                path,
                project_id,
            } => Self::LocalFile {
                effector,
                path,
                project_id,
            },
        }
    }
}

/// `self.secrets.renew`'s spec: a fresh grant at the secret's current
/// generation, in the named grant's place.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretGrantRenewRequest {
    /// The grant, as `self.secrets.materialize` answered it.
    pub grant: String,
    /// As [`SecretGrantMintRequest::ttl_secs`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
}

/// `self.secrets.teardown`'s spec.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretGrantTeardownRequest {
    /// The grant, as `self.secrets.materialize` answered it.
    pub grant: String,
}

/// `self.secrets.use`'s spec: `self.use`'s envelope with a grant in place of
/// the handle.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretGrantUseRequest {
    /// The grant, as `self.secrets.materialize` answered it. A door grant
    /// for this operation, or for the connector `connector.call` names.
    pub grant: String,
    /// The operation, such as `slack.auth_test`, or `connector.call`.
    pub operation: String,
    /// The operation's arguments, a JSON object; `{}` for one that takes
    /// none. `connector.call` takes one connector call, as it takes it.
    #[serde(default = "no_arguments")]
    pub arguments: serde_json::Value,
}

fn no_arguments() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

/// A grant's lifecycle, as the engine reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecretGrantViewStatus {
    /// Redeemable within its bindings until it expires. A grant minted
    /// before the secret rotated still reads active and refuses its next
    /// use as stale: renew it.
    Active,
    /// Past `expires_at`.
    Expired,
    /// Torn down, or retired by a failed delivery.
    Revoked,
    /// Retired by its renewal; `replaced_by` names the successor.
    Replaced,
}

impl SecretGrantViewStatus {
    const fn of(status: SecretGrantStatus) -> Self {
        match status {
            SecretGrantStatus::Active => Self::Active,
            SecretGrantStatus::Expired => Self::Expired,
            SecretGrantStatus::Revoked => Self::Revoked,
            SecretGrantStatus::Replaced => Self::Replaced,
        }
    }
}

/// What a teardown found of the copy the grant delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecretGrantCleanup {
    /// The file or destination held the copy, and it is gone.
    Removed,
    /// Nothing was there to clean: a door grant, a copy already gone, or a
    /// destination its replacement now holds.
    Absent,
    /// The copy could not be removed: a T2 file the retry sweep keeps
    /// trying, or a destination the run's host could not reach.
    Kept,
}

impl SecretGrantCleanup {
    const fn of(cleanup: SecretCleanup) -> Self {
        match cleanup {
            SecretCleanup::Removed => Self::Removed,
            SecretCleanup::Absent => Self::Absent,
            SecretCleanup::Kept => Self::Kept,
        }
    }
}

/// A T2 grant's file: where it is and which project it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretGrantRegistration {
    pub path: String,
    pub project_id: String,
}

/// A grant, value-free: what `self.secrets.materialize`, `.renew` and
/// `.teardown` answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretGrantView {
    /// The grant's id, hex: renew, teardown and use name it.
    pub grant: String,
    /// The secret's handle, while its record has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    pub purpose: SecretGrantPurpose,
    /// The effector the owner's binding names for the purpose, such as
    /// `connector:slack`.
    pub effector: String,
    /// The rung, from the purpose: 0 door, 1 leased, 2 local file.
    pub tier: u8,
    /// The secret's rotation generation the grant pins.
    pub generation: u32,
    pub granted_at: u64,
    pub expires_at: u64,
    pub status: SecretGrantViewStatus,
    /// The grant a renewal minted in this one's place.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaced_by: Option<String>,
    /// The lease a T1/T2 grant rides, hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<String>,
    /// The lease's materialization receipt, hex, on the answer of the call
    /// that minted the lease.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub materialization_receipt: Option<String>,
    /// A T2 grant's file, on the answer of the call that wrote it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration: Option<SecretGrantRegistration>,
    /// What a teardown's cleanup found.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup: Option<SecretGrantCleanup>,
}

/// The grant id a spec names.
///
/// # Errors
/// BAD_REQUEST for text that is no grant id.
pub fn secret_grant_id(text: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(text).map_err(|_| {
        MemoryError::bad_request_with(
            "grant is a grant's id, hex",
            &["Name the grant as self.secrets.materialize or self.secrets.renew answered it."],
        )
    })
}

/// `self.secrets.materialize` for the caller `memory` is bound to, acting in
/// `run`, the run its host attached to this credential: one grant on the
/// secret `spec.handle` names, for `spec.purpose`. A T1 grant's bytes go to
/// the run host's destination through `delivery`, and only there.
///
/// # Errors
/// The caller's refusal ([`SecretGrantCaller::of`]), then the engine's:
/// an unknown operation or connector, a destination the run's host did not
/// register, the handle, record, binding, floor, door policy and T2 path
/// refusals.
pub fn mint_secret_grant_as_caller(
    memory: &Memory<'_>,
    run: Option<AttemptId>,
    spec: SecretGrantMintRequest,
    delivery: &mut dyn SecretHostDelivery,
) -> MemoryResult<SecretGrantView> {
    let caller = SecretGrantCaller::of(memory, run)?;
    let vault = memory.vault();
    let minted = vault
        .mint_secret_grant(
            &caller,
            &spec.handle,
            spec.purpose.target(),
            spec.ttl_secs,
            None,
            delivery,
        )
        .map_err(|error| lifecycle_refusal(error, MATERIALIZE))?;
    view(
        vault,
        &minted.grant,
        minted.lease.as_ref(),
        minted.registration.as_ref(),
        None,
    )
}

/// `self.secrets.renew`: a fresh grant at the secret's current generation in
/// the place of `spec.grant`, which the caller holds in `run`. The answer is
/// the new grant; the old one reads `replaced`.
///
/// # Errors
/// As [`mint_secret_grant_as_caller`], and NOT_FOUND for a grant the caller
/// does not hold in this run, INVALID_STATE for one that expired or was
/// retired (mint a fresh one).
pub fn renew_secret_grant_as_caller(
    memory: &Memory<'_>,
    run: Option<AttemptId>,
    spec: SecretGrantRenewRequest,
    delivery: &mut dyn SecretHostDelivery,
) -> MemoryResult<SecretGrantView> {
    let grant = secret_grant_id(&spec.grant)?;
    let caller = SecretGrantCaller::of(memory, run)?;
    let vault = memory.vault();
    let minted = vault
        .renew_secret_grant(&caller, &grant, spec.ttl_secs, None, delivery)
        .map_err(|error| lifecycle_refusal(error, RENEW))?;
    view(
        vault,
        &minted.grant,
        minted.lease.as_ref(),
        minted.registration.as_ref(),
        None,
    )
}

/// `self.secrets.teardown`: revokes `spec.grant`, whatever its state, with
/// the lease it rides, removes its T2 file and clears its T1 destination
/// through `delivery`. The answer says what the cleanup found; bytes a
/// process already copied are beyond any host's reach.
///
/// # Errors
/// NOT_FOUND for a grant the caller does not hold in this run.
pub fn teardown_secret_grant_as_caller(
    memory: &Memory<'_>,
    run: Option<AttemptId>,
    spec: SecretGrantTeardownRequest,
    delivery: &mut dyn SecretHostDelivery,
) -> MemoryResult<SecretGrantView> {
    let grant = secret_grant_id(&spec.grant)?;
    let caller = SecretGrantCaller::of(memory, run)?;
    let vault = memory.vault();
    let torn = vault
        .teardown_secret_grant(&caller, &grant, delivery)
        .map_err(|error| lifecycle_refusal(error, TEARDOWN))?;
    view(
        vault,
        &torn.grant,
        None,
        None,
        Some(SecretGrantCleanup::of(torn.cleanup)),
    )
}

/// The view of `grant`, with what the call that answers it made.
fn view(
    vault: &Vault,
    grant: &SecretLeaseGrant,
    lease: Option<&SecretLease>,
    registration: Option<&LocalRegistration>,
    cleanup: Option<SecretGrantCleanup>,
) -> MemoryResult<SecretGrantView> {
    Ok(SecretGrantView {
        grant: grant.grant_id.to_hex(),
        handle: handle_of(vault, &grant.custody)?,
        purpose: SecretGrantPurpose::of(&grant.target),
        effector: grant.effector.clone(),
        tier: grant.tier.as_u8(),
        generation: grant.generation,
        granted_at: grant.granted_at,
        expires_at: grant.expires_at,
        status: SecretGrantViewStatus::of(grant.status),
        replaced_by: grant.replaced_by.map(|id| id.to_hex()),
        lease: grant.lease.map(|id| id.to_hex()),
        materialization_receipt: lease.map(|lease| lease.materialization_receipt.to_hex()),
        registration: registration.map(|local| SecretGrantRegistration {
            path: local.path.display().to_string(),
            project_id: local.project_id.clone(),
        }),
        cleanup,
    })
}

/// The handle of the custody record `custody`: its short id, while it has
/// one.
fn handle_of(vault: &Vault, custody: &EntityId) -> MemoryResult<Option<String>> {
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    Ok(
        crate::ports::ShortIdStoreRead::port_short_id_reference(&vault.store, &txn, custody)?
            .map(|(short, _)| short),
    )
}

/// A lifecycle refusal in words the holder can act on: a destination the
/// run's host never registered, a rung the binding or the floor caps; the
/// rest reads as a grant's use refusal does.
fn lifecycle_refusal(error: Error, verb: &str) -> MemoryError {
    match error {
        Error::Secret(SecretError::SecretHostDeliveryRefused { .. }) => MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            error.to_string(),
            &[
                "Name a destination this run's host registered for it; a run whose host \
                 registered none takes an operation or connector purpose instead.",
            ],
        ),
        Error::Secret(SecretError::SecretTierDenied { .. }) => MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            error.to_string(),
            &[
                "The owner's binding or the vault's floor caps this secret below the purpose's \
                 rung; an operation or connector purpose is the least exposed.",
            ],
        ),
        other => grant_refusal(other, verb),
    }
}
