//! The owner's own actions on his vault, shared by the CLI and `/v1/owner`.
//!
//! Every action here takes an open vault and, where the engine asks for one,
//! an [`oneiron::consent::AuthenticatedOwner`]. The CLI gets that proof from
//! holding the vault's writer lease as its embedded owner; the HTTP routes get
//! it from a verified, unattenuated owner slip. Neither adds a prompt: the
//! owner acts once and the engine writes the receipt.

pub(crate) mod backup;
pub(crate) mod cleanup;
pub(crate) mod cooperative_deletion;
pub(crate) mod embedder;
pub(crate) mod federation_connect;
pub(crate) mod feedback;
pub(crate) mod graph_fs;
pub(crate) mod healer;
pub(crate) mod history;
pub(crate) mod house;
pub(crate) mod imports;
pub(crate) mod location;
pub(crate) mod note_imports;
pub(crate) mod off_record;
pub(crate) mod pack_drift;
pub(crate) mod persona;
pub(crate) mod recovery_kit;
pub(crate) mod runs;
pub(crate) mod schedule;
pub(crate) mod secrets;
pub(crate) mod stamp;
pub(crate) mod vault_key;

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
    /// The engine will not do this yet, whoever asks.
    Refused(String),
    /// The named thing does not exist: `(what, which)`.
    NotFound(&'static str, String),
    /// The engine refused or failed.
    Engine(Box<oneiron::Error>),
    /// A host-side failure: files, directories, encoding.
    Host(anyhow::Error),
}

impl std::fmt::Display for OwnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) | Self::Changed(message) | Self::Refused(message) => {
                f.write_str(message)
            }
            Self::NotFound(what, which) => write!(f, "no {what} {which}"),
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

/// Runs the owner's row `verb` inside its verb hooks (ARCH-0080 §3; FIX
/// 1466, 1752, 1953): the pre chain over `input`'s JSON, `run` on the args
/// every rewrite left, then the post chain over its answer, which is the
/// caller's view. The CLI and `/v1/owner` cross this one boundary per
/// operation, as the owner `actor` in person, after their own owner door
/// admitted the call, so a hook never fires on a call that door refuses. A
/// door's own answer shape reaches the post chain as it is.
pub(crate) fn hooked_row<I, O>(
    vault: &oneiron::Vault,
    actor: oneiron::EntityId,
    verb: &str,
    input: I,
    run: impl FnOnce(I) -> OwnerResult<O>,
) -> OwnerResult<serde_json::Value>
where
    I: serde::Serialize + serde::de::DeserializeOwned,
    O: serde::Serialize,
{
    use oneiron::task_verb::verb_hook_boundary;
    let memory = vault.memory(actor, oneiron::edge::EdgeActorClass::Human);
    let args = hook_json(verb, &input)?;
    let pre = verb_hook_boundary::row_pre(&memory, verb, args.clone()).map_err(memory_refusal)?;
    let input = if pre.args == args {
        input
    } else {
        serde_json::from_value(pre.args.clone()).map_err(|error| {
            OwnerError::Invalid(format!("a verb hook rewrote {verb}'s input: {error}"))
        })?
    };
    let output = hook_json(verb, &run(input)?)?;
    verb_hook_boundary::row_post(vault, pre, output).map_err(memory_refusal)
}

/// A row's value as the JSON its hooks read.
fn hook_json(verb: &str, value: &impl serde::Serialize) -> OwnerResult<serde_json::Value> {
    serde_json::to_value(value).map_err(|error| {
        OwnerError::Host(anyhow::anyhow!(
            "{verb}'s value cannot cross its hooks: {error}"
        ))
    })
}

/// A row's refusal, a verb hook's stop or its ask, as the owner's: the
/// engine's message names the hook and any ask a retry waits on.
pub(crate) fn memory_refusal(error: oneiron::memory::MemoryError) -> OwnerError {
    match error.code.as_str() {
        oneiron::memory::MEMORY_CODE_BAD_REQUEST => OwnerError::Invalid(error.message),
        oneiron::memory::MEMORY_CODE_INTERNAL => {
            OwnerError::Host(anyhow::anyhow!("{}", error.message))
        }
        _ => OwnerError::Refused(error.message),
    }
}
