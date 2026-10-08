//! The owner's own actions on his vault, shared by the CLI and `/v1/owner`.
//!
//! Every action here takes an open vault and, where the engine asks for one,
//! an [`oneiron::consent::AuthenticatedOwner`]. The CLI gets that proof from
//! holding the vault's writer lease as its embedded owner; the HTTP routes get
//! it from a verified, unattenuated owner slip. Neither adds a prompt: the
//! owner acts once and the engine writes the receipt.

pub(crate) mod backup;
pub(crate) mod imports;
pub(crate) mod location;
pub(crate) mod runs;
pub(crate) mod schedule;
pub(crate) mod stamp;

use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;

/// The local owner: this process holds the vault's writer lease and acts as
/// its embedded owner, the same door `Memory::export` uses for the embedded
/// owner. A vault whose owner was deleted is not given a new one.
pub(crate) fn local_owner(vault: &oneiron::Vault) -> anyhow::Result<AuthenticatedOwner> {
    anyhow::ensure!(
        vault
            .writer_lease()
            .is_some_and(oneiron::VaultWriterLease::held_by_current_process),
        "owner actions need this process to hold the vault's writer lease"
    );
    let actor = vault
        .ensure_embedded_owner_actor()
        .map_err(|error| anyhow::anyhow!("vault owner unavailable: {error}"))?;
    let owner = vault.authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())?;
    anyhow::ensure!(
        vault.is_live_vault_owner(&owner)?,
        "the embedded owner is not this vault's owner"
    );
    Ok(owner)
}

/// Why an owner action did not happen.
#[derive(Debug)]
pub(crate) enum OwnerError {
    /// The request itself is malformed.
    Invalid(String),
    /// What the owner reviewed is no longer what the vault holds.
    Changed(String),
    /// The engine refused or failed.
    Engine(Box<oneiron::Error>),
    /// A host-side failure: files, directories, encoding.
    Host(anyhow::Error),
}

impl std::fmt::Display for OwnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) | Self::Changed(message) => f.write_str(message),
            Self::Engine(error) => write!(f, "{error}"),
            Self::Host(error) => write!(f, "{error:#}"),
        }
    }
}

impl std::error::Error for OwnerError {}

impl From<oneiron::Error> for OwnerError {
    fn from(error: oneiron::Error) -> Self {
        Self::Engine(Box::new(error))
    }
}

impl From<anyhow::Error> for OwnerError {
    fn from(error: anyhow::Error) -> Self {
        Self::Host(error)
    }
}

pub(crate) type OwnerResult<T> = Result<T, OwnerError>;

/// Parses a 32-hex entity id field.
pub(crate) fn entity_id(field: &str, value: &str) -> OwnerResult<oneiron::EntityId> {
    oneiron::EntityId::from_hex(value)
        .map_err(|_| OwnerError::Invalid(format!("{field} must be a 32-hex entity id")))
}
