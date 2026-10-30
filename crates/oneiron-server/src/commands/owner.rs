//! The owner's own commands on a stopped vault: doctor, backup, restore,
//! window and clock recovery, export, the secret scan switch, registering and
//! rotating a secret, the vault key's wraps, import consent and agent-run
//! consent.
//!
//! Holding the vault's writer lease is the owner proof here, the same local
//! door the embedded export uses; a running `serve` answers the same actions
//! at `/v1/owner/*`. Output is JSON on stdout.

use std::io::{self, Read, Seek, Write};
use std::path::Path;

use oneiron::claim::CallerLocality;
use oneiron::run_tree::GateConsentBundleAction;
use serde::Serialize;

use super::history_import;
use crate::cli::{
    BackupArgs, DoctorArgs, ExportArgs, HandoffAlarmsCommand, ImportCommand, PackRemoveArgs,
    PacksCommand, RecoverClockArgs, RecoverWindowArgs, RestoreArgs, RunsCommand, SecretClass,
    SecretRegisterArgs, SecretRotateArgs, SecretScanArgs, SecretScanSwitch, SecretsCommand,
    SubscriptionListArgs, SubscriptionPutArgs, SubscriptionRevokeArgs, SubscriptionsCommand,
    WhoamiArgs,
};
use crate::config::{ServeArgs, ServeConfig, resolve_serve_config};
#[cfg(test)]
use crate::owner::backup;
use crate::owner::backup::{BackupPlan, CustodyAnchorCredentials};
use crate::owner::stamp::rfc3339_secs;
use crate::owner::{hooked_row, imports, local_owner, memory_refusal, note_imports};

mod control_commands;
mod doctor;
mod pack_commands;
mod recovery_commands;
mod recovery_kit;
mod secret_commands;
mod secret_input;
mod transfer_commands;
mod vault_key;
pub use self::control_commands::{
    embedding_spaces, guests, handoff_alarms, learning_settings, legal_holds, runs, widen_proposals,
};
use self::doctor::doctor_report;
pub use self::pack_commands::{packs, subscriptions};
pub use self::recovery_commands::{backup, recover_clock, recover_window, restore};
pub use self::recovery_kit::recovery_kit;
#[cfg(test)]
use self::secret_commands::{read_secret_value, register_secret, rotate_secret};
pub use self::secret_commands::{reveal_secret, revoke_secret, secret_scan, secrets};
pub use self::transfer_commands::{export, import};
pub use self::vault_key::vault_key;
pub(super) use self::vault_key::{
    HostUnlock, ensure_page_seal_wrapped, prepare_page_seal, read_secret_file,
    refuse_orphaned_page_seal,
};

pub(super) fn emit(value: &impl Serialize) -> anyhow::Result<()> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, value)?;
    writeln!(stdout)?;
    Ok(())
}

fn backup_plan(config: &ServeConfig) -> BackupPlan {
    BackupPlan::new(
        &config.vault_path,
        config.backup.dir_for(&config.vault_path),
        config.backup.keep,
    )
}

pub(super) fn vault_config(config: &ServeConfig) -> oneiron::VaultConfig {
    let mut vault_config = config.vault_config();
    vault_config.dict_search_paths =
        super::resolve_dict_search_paths(&config.dict_search_paths).paths;
    vault_config
}

/// [`vault_config`] with no page seal and no unlock tried on this device: a
/// restore, rehearsal or activation sets the seal it chose for its path
/// (FIX 2709).
pub(super) fn base_vault_config(config: &ServeConfig) -> oneiron::VaultConfig {
    let mut vault_config = config.base_vault_config();
    vault_config.dict_search_paths =
        super::resolve_dict_search_paths(&config.dict_search_paths).paths;
    vault_config
}

/// Opens the configured, existing vault for one owner command. `route` names
/// the `/v1/owner` route to use instead while a server holds the vault.
fn open_vault(config: &ServeConfig, route: &str) -> anyhow::Result<oneiron::Vault> {
    open_stopped_vault(config, &format!("or ask it: `oneiron api raw {route}`"))
}

/// [`open_vault`] for a command no running server answers: `instead` says
/// what to do while one holds the vault.
fn open_stopped_vault(config: &ServeConfig, instead: &str) -> anyhow::Result<oneiron::Vault> {
    open_stopped_vault_with(config, vault_config(config), instead)
}

/// [`open_stopped_vault`] under a vault config the command adjusted.
pub(super) fn open_stopped_vault_with(
    config: &ServeConfig,
    vault_config: oneiron::VaultConfig,
    instead: &str,
) -> anyhow::Result<oneiron::Vault> {
    let path = &config.vault_path;
    anyhow::ensure!(
        path.join("data.mdb").is_file(),
        "vault {} does not exist; `oneiron init` creates one",
        path.display()
    );
    let vault = oneiron::Vault::open_owned(path, vault_config).map_err(|error| match error {
        oneiron::Error::ConcurrentWrite(oneiron::VAULT_WRITER_LEASE_HELD) => anyhow::anyhow!(
            "vault {} is open in a running `oneiron serve`; stop it first, {instead}",
            path.display()
        ),
        error => anyhow::anyhow!("open vault {}: {error}", path.display()),
    })?;
    // A command that signs (a delete's receipt, a settings edit) needs this
    // install's keys from the keystore.
    config.keystore.install_on(&vault, path);
    // And this install's own machine profile, under the configured host root
    // as `serve` ensures it, to carry the owner's acts (FIX 4648). No root is
    // minted here, and the command goes on without one.
    vault.ensure_serving_install_profile_at_start(
        configured_host_issuer(config, &vault, false).as_ref(),
        "owner command",
    );
    Ok(vault)
}

/// The host root issuer a configured secret admits, as `serve` takes it
/// (`SyncServer::new`): [`host_issuer`]; none for an absent or empty
/// secret, on a relay, or where this install holds no issuer seed.
pub(super) fn configured_host_issuer(
    config: &ServeConfig,
    vault: &oneiron::Vault,
    may_root: bool,
) -> Option<oneiron::authority::HostSlipIssuer> {
    if vault.privacy_posture() == oneiron::HostingPrivacyPosture::Relay {
        return None;
    }
    config
        .sync_server_config()
        .auth_secret
        .filter(|secret| !secret.is_empty())?;
    host_issuer(config, vault, may_root).ok()
}

/// This install's host root issuer for `vault` (FIX-LIST 3018): its own
/// issuer seed for the vault, in the keystore `config` names, installed here
/// as `serve` installs it when the vault has none yet. With `may_root`, a
/// vault no root has reached takes a fresh seed first, for the rooting the
/// caller then does; a rooted vault only loads its seed, never a new one.
/// The configured secret admits the caller; it is not the key.
pub(super) fn host_issuer(
    config: &ServeConfig,
    vault: &oneiron::Vault,
    may_root: bool,
) -> anyhow::Result<oneiron::authority::HostSlipIssuer> {
    if vault.device_keystore_assurance().is_none() {
        config.keystore.install_on(vault, &config.vault_path);
    }
    let issuer = if may_root {
        vault.bootstrap_host_slip_issuer()
    } else {
        vault.load_host_slip_issuer()
    };
    issuer.map_err(|error| {
        anyhow::anyhow!(
            "this install holds no host issuer for vault {}: {error}",
            config.vault_path.display()
        )
    })
}

pub fn doctor(args: DoctorArgs) -> anyhow::Result<()> {
    emit(&doctor_report(args)?)
}

#[derive(Serialize)]
struct Whoami {
    /// The PERSON a credential names to act as this vault's owner.
    owner_principal: String,
    /// The class that credential binds for the owner's read lane.
    actor_class: &'static str,
    /// The authority vault id its slips carry; `null` until the vault is
    /// rooted (its first `serve` or `token bootstrap` with an issuer key).
    vault_id: Option<String>,
    /// This install's sync node id: what another machine's
    /// `[device_sync] home_node_id` names when this one is its home.
    sync_node_id: u64,
}

/// Prints who owns the stopped vault: the principal facade credentials name
/// and the vault id they carry. Read-only apart from the housekeeping every
/// open does; it never roots the vault.
pub fn whoami(args: WhoamiArgs) -> anyhow::Result<()> {
    let config = resolve_serve_config(&ServeArgs {
        config: args.config,
        vault_path: Some(args.path),
        ..ServeArgs::default()
    })?;
    let vault = open_vault(
        &config,
        "POST /v1/core/facade/describe --data '{\"self\":true}'",
    )?;
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(|error| anyhow::anyhow!("vault owner unavailable: {error}"))?;
    let vault_id = vault
        .authority_fold()?
        .vault_id
        .map(|id| id.iter().map(|byte| format!("{byte:02x}")).collect());
    let sync_node_id = oneiron::DreamerRunnerStore::new(&vault)
        .local_home_node_candidate(true, true, false)?
        .node_id;
    emit(&Whoami {
        owner_principal: owner.to_hex(),
        actor_class: "human",
        vault_id,
        sync_node_id,
    })
}

/// Creates `out` (owner-only, never over an existing file) and fills it with
/// `write`. A failed write removes the partial file, so the same `--out` can
/// be retried.
pub(super) fn write_new_file(
    out: &Path,
    write: impl FnOnce(&mut std::fs::File) -> io::Result<()>,
) -> anyhow::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(out)
        .map_err(|error| anyhow::anyhow!("create {}: {error}", out.display()))?;
    if let Err(error) = write(&mut file) {
        drop(file);
        let _ = std::fs::remove_file(out);
        anyhow::bail!("write {}: {error}", out.display());
    }
    Ok(())
}

/// Stdin's own file, unbuffered. `io::Stdin` copies a short read through a
/// process-wide buffer that is never wiped.
fn raw_stdin() -> io::Result<std::fs::File> {
    #[cfg(unix)]
    let owned = std::os::fd::AsFd::as_fd(&io::stdin()).try_clone_to_owned()?;
    #[cfg(windows)]
    let owned = std::os::windows::io::AsHandle::as_handle(&io::stdin()).try_clone_to_owned()?;
    Ok(std::fs::File::from(owned))
}

/// Deciding a Dreamer proposal writes its signed history with the host's
/// machine key (ONE-1634), so the command holds the host root as `serve` does
/// when the config names its secret. Without one, a run the Dreamer proposed
/// stays undecided here; a running server decides it at `/v1/owner/runs`.
fn hold_host_root(config: &ServeConfig, vault: &oneiron::Vault) -> anyhow::Result<()> {
    if config
        .sync_server_config()
        .auth_secret
        .is_none_or(|secret| secret.is_empty())
    {
        return Ok(());
    }
    let issuer = host_issuer(config, vault, true)?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.provision_engine_machine_identities(&issuer)?;
    Ok(())
}

/// One owner row of `embedding-spaces`, run inside its verb hooks.
struct SpaceRow<'a> {
    vault: &'a oneiron::Vault,
    owner: &'a oneiron::consent::AuthenticatedOwner,
    actor: oneiron::EntityId,
    verb: &'a str,
}

impl SpaceRow<'_> {
    /// The row's SDK fn `sdk_fn` on `input`, between its pre and post
    /// chains: the caller's view of its answer.
    fn run<I, O>(
        self,
        input: I,
        sdk_fn: impl FnOnce(
            &oneiron::Vault,
            &oneiron::consent::AuthenticatedOwner,
            I,
        ) -> oneiron::memory::MemoryResult<O>,
    ) -> crate::owner::OwnerResult<serde_json::Value>
    where
        I: Serialize + serde::de::DeserializeOwned,
        O: Serialize,
    {
        hooked_row(self.vault, self.actor, self.verb, input, |input| {
            sdk_fn(self.vault, self.owner, input).map_err(memory_refusal)
        })
    }
}

/// The vault owner's actor, which an owner row's verb hooks run as.
fn owner_actor(vault: &oneiron::Vault) -> anyhow::Result<oneiron::EntityId> {
    vault
        .ensure_embedded_owner_actor()
        .map_err(|error| anyhow::anyhow!("vault owner unavailable: {error}"))
}

/// The CLI's local host actor, for a read that takes no owner proof: the
/// actor a host's own call runs as (`verb_hook_boundary::host_actor`, the
/// vault's embedded owner), when this vault holds it. Unlike `owner_actor`
/// it creates nothing.
fn local_host_actor(vault: &oneiron::Vault) -> anyhow::Result<Option<oneiron::EntityId>> {
    let Ok(actor) = oneiron::task_verb::verb_hook_boundary::host_actor() else {
        return Ok(None);
    };
    Ok(vault.entity_exists(&actor)?.then_some(actor))
}

/// The engine's input kind for a command-line kind.
fn input_kind(kind: crate::cli::EmbeddingKind) -> oneiron::embed::InputKind {
    use crate::cli::EmbeddingKind;
    use oneiron::embed::InputKind;
    match kind {
        EmbeddingKind::Text => InputKind::Text,
        EmbeddingKind::Image => InputKind::Image,
        EmbeddingKind::Audio => InputKind::Audio,
    }
}

/// The space `embedding-spaces declare` names, as the route's body.
fn declared_space(
    args: crate::cli::EmbeddingSpaceDeclareArgs,
) -> oneiron::task_verb::sdk::EmbeddingSpaceDeclareRequest {
    let kinds =
        |kinds: &[crate::cli::EmbeddingKind]| kinds.iter().copied().map(input_kind).collect();
    oneiron::task_verb::sdk::EmbeddingSpaceDeclareRequest(oneiron::embed::EmbeddingSpace {
        id: args.id,
        dimensions: args.width,
        accepts: kinds(&args.accepts),
        query_towers: kinds(&args.query_towers),
        evidence: args
            .floor
            .zip(args.strong)
            .map(|(floor, strong)| oneiron::config::VectorEvidenceFloors { floor, strong }),
    })
}

/// A 32-hex id given on the command line.
fn hold_id_arg(hex: &str) -> anyhow::Result<oneiron::EntityId> {
    oneiron::EntityId::from_hex(hex).map_err(|_| anyhow::anyhow!("{hex} is not a 32-hex id"))
}

/// The engine's hold targets from `--record` and `--gate-partition`.
fn hold_targets(
    args: &crate::cli::LegalHoldTargetArgs,
) -> anyhow::Result<Vec<oneiron::deletion::LegalHoldTarget>> {
    use oneiron::deletion::LegalHoldTarget;
    let mut targets = Vec::with_capacity(args.records.len() + args.gate_partitions.len());
    for record in &args.records {
        targets.push(LegalHoldTarget::Record(hold_id_arg(record)?));
    }
    for partition in &args.gate_partitions {
        targets.push(LegalHoldTarget::GatePartition(match partition.as_str() {
            "none" => None,
            claim => Some(hold_id_arg(claim)?),
        }));
    }
    Ok(targets)
}

#[cfg(test)]
mod tests;
