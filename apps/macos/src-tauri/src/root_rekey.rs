//! The owner's re-key of this Mac's host root (FIX 5571, the re-key half of
//! FIX 5346; owner ruling FIX 5341 = A): two commands and no screen. The
//! button, its confirm panel and the secret field wait for a co-design
//! sitting (RD-18); the launch warning ([`crate::copy::WRONG_ROOT_WARNING`])
//! is unchanged.
//!
//! Re-keying replaces the host root secret this Mac stores with the settled
//! root's, which the owner supplies. It never changes the vault's root, its
//! authority, this install's machine keys, its recovery pin or its standing,
//! and it is never automatic: only [`root_rekey_confirm`] writes, and only
//! this Mac's retained keychain slot. A source the owner configured for the
//! server (its config file or the environment) is never overwritten: the
//! answer names the steps instead. No secret byte is logged or returned.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use oneiron::authority::{LocalHostRootContext, LocalHostRootValidated, RetainedHostRootReplace};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultWriterLease};
use tauri::{AppHandle, Manager};

use crate::{
    DESKTOP_ROOT_SECRET_SOURCE, RootSecretSource, SourceFailure, copy, with_effective_secret,
};

/// The variable `oneiron serve` reads `auth_secret` from, over its config
/// file: set and non-empty, it is where the server-config source's secret
/// came from.
const AUTH_SECRET_ENV: &str = "ONEIRON_AUTH_SECRET";
/// Why the local owner cannot be proved while the recorder opens its vault
/// without the writer lease (`DESKTOP_OPEN_KEEPS_WRITER_LEASE`).
const LEASE_NOT_HELD: &str = "this app does not hold the vault's writer lease, so it cannot \
     prove the local owner; nothing was checked or written";
/// The embedded owner authenticated but owns no part of this vault.
const NOT_THE_OWNER: &str = "the embedded owner is not this vault's owner";
/// After a replace, the next open's search found no secret at all.
const REREAD_NONE: &str = "the slot was replaced, but the next open finds no host root secret";

/// What the re-key commands share: the recorder's vault, where it lives,
/// and one confirm at a time.
pub struct RekeyState {
    vault: Arc<Vault>,
    vault_dir: PathBuf,
    confirming: Mutex<()>,
}

impl RekeyState {
    /// The state over the vault the recorder opened at `vault_dir`.
    #[must_use]
    pub fn new(vault: Arc<Vault>, vault_dir: PathBuf) -> Self {
        Self {
            vault,
            vault_dir,
            confirming: Mutex::new(()),
        }
    }
}

/// Where this Mac's host root secret comes from now: the first source the
/// open reads that holds one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RekeySource {
    /// `auth_secret` in the config file `oneiron serve` reads.
    ServerConfigFile,
    /// `ONEIRON_AUTH_SECRET` in the environment the recorder started with.
    Environment,
    /// This Mac's own retained `HostRoot` keychain slot.
    RetainedSlot,
    /// No source holds one.
    None,
    /// A source failed to read, which stops the search as it stops the open.
    Unreadable,
}

/// [`root_rekey_prepare`]'s answer: public facts only.
#[derive(Debug, serde::Serialize)]
pub struct RekeyPrepared {
    /// The settled root's vault id, lowercase hex; confirm takes it back.
    pub vault_id: String,
    /// This install's machine id, hex; confirm takes it back.
    pub install: String,
    /// Where this Mac's host root secret comes from now.
    pub source: RekeySource,
    /// Whether confirm keeps a secret in that source itself: only this
    /// Mac's retained slot. Any other source answers with setup steps.
    pub replaceable: bool,
    /// Whether this process holds the vault's writer lease, which the local
    /// owner's proof needs. Without it confirm answers `owner_unproven`.
    pub writer_lease_held: bool,
}

/// [`root_rekey_confirm`]'s typed answer. Only `Rekeyed` wrote anything.
#[derive(Debug, serde::Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RekeyConfirmed {
    /// This Mac's retained slot holds the secret, replaced in place, and the
    /// source the next open reads was read again and validates.
    Rekeyed {
        /// The settled root's binding key that source's secret derives, hex.
        root_key: String,
    },
    /// The secret validated, but this Mac reads its host root from the
    /// server's config file or the environment, which the recorder never
    /// overwrites. Nothing was written.
    SetUpElsewhere {
        /// Which of the two.
        source: RekeySource,
        /// The settled root's binding key the secret derives, hex.
        root_key: String,
        /// What the owner does instead.
        steps: &'static [&'static str],
    },
    /// The secret validated, but it is not the 32 bytes a retained slot
    /// holds, so it can only be configured for the server. Nothing was
    /// written.
    SlotCannotHold {
        /// The settled root's binding key the secret derives, hex.
        root_key: String,
        /// What the owner does instead.
        steps: &'static [&'static str],
    },
    /// No source holds a host root secret, so there is nothing to replace.
    /// Nothing was written.
    NothingToReplace,
    /// The local owner could not be proved. Nothing was checked or written.
    OwnerUnproven {
        /// Why, naming no secret.
        reason: String,
    },
    /// The secret, the root or this install did not pass the engine's
    /// check. Nothing was written.
    Refused {
        /// The engine's reason, naming no secret.
        reason: String,
    },
    /// The source the open reads could not be read. Nothing was written.
    SourceUnreadable {
        /// Why, naming no secret.
        reason: String,
    },
    /// This Mac's keystore cannot replace a slot in place, and a replace is
    /// never delete-then-create. Nothing was written.
    KeystoreCannotReplace {
        /// The keystore's reason.
        reason: &'static str,
    },
    /// The slot was replaced, but reading the next open's source again did
    /// not validate, so this is no success: prepare and confirm again.
    Unconfirmed {
        /// Why, naming no secret.
        reason: String,
    },
}

/// The public context a re-key shows before the owner supplies a secret:
/// the settled root's vault id, this install, and where this Mac's host
/// root secret comes from now. Reads only.
#[tauri::command]
pub fn root_rekey_prepare(app: AppHandle) -> Result<RekeyPrepared, String> {
    let state = app.state::<RekeyState>();
    let context = state
        .vault
        .local_host_root_context()
        .map_err(|error| error.to_string())?;
    let source = match winning_source(&state) {
        Ok(Some(source)) => public_source(source),
        Ok(None) => RekeySource::None,
        Err(_) => RekeySource::Unreadable,
    };
    Ok(RekeyPrepared {
        vault_id: hex(&context.vault_id),
        install: context.install.to_hex(),
        source,
        replaceable: source == RekeySource::RetainedSlot,
        writer_lease_held: holds_writer_lease(&state.vault),
    })
}

/// The owner's re-key, bound to the context `vault_id` and `install` that
/// prepare showed. The local owner is proved first, then `secret` is checked
/// by the engine against the settled root and this install, then kept in the
/// source this Mac's open reads, when that is its own retained slot.
/// Success only once that source is read again and validates. Every other
/// outcome writes nothing and says why.
#[tauri::command]
pub fn root_rekey_confirm(
    app: AppHandle,
    vault_id: String,
    install: String,
    secret: String,
) -> Result<RekeyConfirmed, String> {
    let state = app.state::<RekeyState>();
    let _one_at_a_time = state
        .confirming
        .lock()
        .map_err(|_| "the re-key state is unavailable".to_owned())?;
    let shown = LocalHostRootContext {
        vault_id: parse_hex32(&vault_id).ok_or("the vault id is not 64 hex characters")?,
        install: EntityId::from_hex(&install)
            .map_err(|_| "the install id is not a machine id".to_owned())?,
    };
    Ok(confirm(&state, &shown, &secret))
}

fn confirm(state: &RekeyState, shown: &LocalHostRootContext, secret: &str) -> RekeyConfirmed {
    let owner = match local_owner(&state.vault) {
        Ok(owner) => owner,
        Err(reason) => return RekeyConfirmed::OwnerUnproven { reason },
    };
    let (validated, kept) = match validate(&state.vault, &owner, shown, secret) {
        Ok(found) => found,
        Err(reason) => return RekeyConfirmed::Refused { reason },
    };
    let root_key = hex(&validated.root_key);
    match winning_source(state) {
        Err(failure) => RekeyConfirmed::SourceUnreadable {
            reason: failure_reason(failure),
        },
        Ok(None) => RekeyConfirmed::NothingToReplace,
        Ok(Some(RootSecretSource::ServerConfig)) => {
            let source = public_source(RootSecretSource::ServerConfig);
            RekeyConfirmed::SetUpElsewhere {
                source,
                root_key,
                steps: if source == RekeySource::Environment {
                    copy::REKEY_STEPS_ENVIRONMENT
                } else {
                    copy::REKEY_STEPS_SERVER_CONFIG
                },
            }
        }
        Ok(Some(RootSecretSource::RetainedSlot)) => {
            replace_retained(state, &owner, shown, &kept, root_key)
        }
    }
}

/// Writes the validated secret over this Mac's retained slot in place, then
/// reads the next open's source again from the top.
fn replace_retained(
    state: &RekeyState,
    owner: &AuthenticatedOwner,
    shown: &LocalHostRootContext,
    kept: &[u8],
    root_key: String,
) -> RekeyConfirmed {
    let Ok(slot_secret) = <[u8; 32]>::try_from(kept) else {
        return RekeyConfirmed::SlotCannotHold {
            root_key,
            steps: copy::REKEY_STEPS_SERVER_CONFIG,
        };
    };
    match state
        .vault
        .replace_retained_host_root_secret(owner, shown, &slot_secret)
    {
        Ok(RetainedHostRootReplace::Replaced(_)) => {}
        Ok(RetainedHostRootReplace::Empty) => return RekeyConfirmed::NothingToReplace,
        Ok(RetainedHostRootReplace::Unsupported(reason)) => {
            return RekeyConfirmed::KeystoreCannotReplace { reason };
        }
        Err(error) => {
            return RekeyConfirmed::Refused {
                reason: error.to_string(),
            };
        }
    }
    match reread(state, owner, shown) {
        Ok(reread) => RekeyConfirmed::Rekeyed {
            root_key: hex(&reread.root_key),
        },
        Err(reason) => RekeyConfirmed::Unconfirmed { reason },
    }
}

/// The secret as the engine validates it, and the bytes that passed: its
/// text bytes, as `auth_secret` takes it; else, for 64 hex characters, the
/// 32 bytes they spell, as a retained slot holds one. A refusal is the text
/// form's.
fn validate(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    shown: &LocalHostRootContext,
    secret: &str,
) -> Result<(LocalHostRootValidated, Vec<u8>), String> {
    let text = secret.as_bytes();
    let refusal = match vault.validate_local_host_root_replacement(owner, shown, text) {
        Ok(validated) => return Ok((validated, text.to_vec())),
        Err(error) => error.to_string(),
    };
    if let Some(bytes) = parse_hex32(secret)
        && let Ok(validated) = vault.validate_local_host_root_replacement(owner, shown, &bytes)
    {
        return Ok((validated, bytes.to_vec()));
    }
    Err(refusal)
}

/// The source the next open reads, searched again from the top, and its
/// secret checked as a replacement would be.
fn reread(
    state: &RekeyState,
    owner: &AuthenticatedOwner,
    shown: &LocalHostRootContext,
) -> Result<LocalHostRootValidated, String> {
    with_effective_secret(
        &state.vault,
        &state.vault_dir,
        DESKTOP_ROOT_SECRET_SOURCE,
        false,
        |found| match found {
            Some((_, secret)) => state
                .vault
                .validate_local_host_root_replacement(owner, shown, secret)
                .map_err(|error| error.to_string()),
            None => Err(REREAD_NONE.to_owned()),
        },
    )
    .map_err(failure_reason)?
}

/// The source the open reads first that holds a secret, as the open
/// searches: a retained slot is read, never created.
fn winning_source(state: &RekeyState) -> Result<Option<RootSecretSource>, SourceFailure> {
    with_effective_secret(
        &state.vault,
        &state.vault_dir,
        DESKTOP_ROOT_SECRET_SOURCE,
        false,
        |found| found.map(|(source, _)| source),
    )
}

/// `source` as the commands name it; the server config's secret came from
/// the environment when that variable is set, as it stands over the file.
fn public_source(source: RootSecretSource) -> RekeySource {
    match source {
        RootSecretSource::ServerConfig
            if std::env::var_os(AUTH_SECRET_ENV).is_some_and(|value| !value.is_empty()) =>
        {
            RekeySource::Environment
        }
        RootSecretSource::ServerConfig => RekeySource::ServerConfigFile,
        RootSecretSource::RetainedSlot => RekeySource::RetainedSlot,
    }
}

fn failure_reason(failure: SourceFailure) -> String {
    match failure {
        SourceFailure::ServerConfig(reason) => {
            format!("the server config did not resolve: {reason}")
        }
        SourceFailure::RetainedSlot(error) => {
            format!("this Mac's keychain gave no host root secret: {error}")
        }
    }
}

/// The local owner, proved the way the server's own CLI proves him
/// (`oneiron-server` `owner::local_owner`): this process holds the vault's
/// writer lease and acts as its embedded owner, who authenticates and is a
/// live owner of this vault now. The engine checks him again in the
/// snapshot it validates in.
fn local_owner(vault: &Vault) -> Result<AuthenticatedOwner, String> {
    if !holds_writer_lease(vault) {
        return Err(LEASE_NOT_HELD.to_owned());
    }
    let actor = vault
        .ensure_embedded_owner_actor()
        .map_err(|error| format!("the vault's owner is unavailable: {error}"))?;
    let owner = vault
        .authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())
        .map_err(|error| error.to_string())?;
    match vault.is_live_vault_owner(&owner) {
        Ok(true) => Ok(owner),
        Ok(false) => Err(NOT_THE_OWNER.to_owned()),
        Err(error) => Err(error.to_string()),
    }
}

fn holds_writer_lease(vault: &Vault) -> bool {
    vault
        .writer_lease()
        .is_some_and(VaultWriterLease::held_by_current_process)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// 64 hex characters as the 32 bytes they spell; anything else is `None`.
fn parse_hex32(text: &str) -> Option<[u8; 32]> {
    let text = text.as_bytes();
    if text.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (byte, pair) in bytes.iter_mut().zip(text.chunks_exact(2)) {
        *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(bytes)
}

const fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}
