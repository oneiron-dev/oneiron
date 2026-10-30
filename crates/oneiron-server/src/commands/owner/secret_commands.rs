//! Secret scan, custody, and value commands for a stopped vault.
//! Keeps unbuffered secret input and output with their existing wipe scopes.
//! Shared vault access and the vault-key reader's stdin helper stay in the parent.

use super::secret_input::{TerminalRead, read_stdin_secret};
use super::{
    Read, SecretClass, SecretRegisterArgs, SecretRotateArgs, SecretScanArgs, SecretScanSwitch,
    SecretsCommand, Write, emit, io, local_owner, open_stopped_vault, open_vault,
    resolve_serve_config,
};
use crate::owner::{pending_custody, secret_bindings, secrets};

pub fn secret_scan(args: SecretScanArgs) -> anyhow::Result<()> {
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_vault(&config, "GET /v1/owner/secret-scan")?;
    let Some(switch) = args.mode else {
        return emit(&serde_json::json!({
            "mode": vault.secret_scan_mode()?,
            "changes": vault.secret_scan_change_log()?,
        }));
    };
    let mode = match switch {
        SecretScanSwitch::On => oneiron::policy_model::SecretScanMode::On,
        SecretScanSwitch::Off => oneiron::policy_model::SecretScanMode::Off,
    };
    let owner = local_owner(&vault)?;
    emit(&vault.set_secret_scan_mode(&owner, mode, vault.now_recorded_at())?)
}

/// The largest value read from stdin, as for the route's whole body.
const SECRET_VALUE_LIMIT: usize = 1 << 20;

pub fn secrets(command: SecretsCommand) -> anyhow::Result<()> {
    // Only a door that takes a value reads stdin; revoke and reveal read
    // nothing. A terminal is asked for it with its echo off (FIX 1490).
    let value =
        |what: &str| read_stdin_secret(what, TerminalRead::ToEnd, |input| read_secret_value(input));
    match command {
        SecretsCommand::Register(args) => {
            emit(&register_secret(*args, &value("the secret value")?)?)
        }
        SecretsCommand::Rotate(args) => emit(&rotate_secret(*args, &value("the new value")?)?),
        SecretsCommand::Revoke(args) => revoke_secret(*args),
        SecretsCommand::Reveal(args) => reveal_secret(*args),
        SecretsCommand::Rewrap(args) => emit(&rewrap_secret(*args)?),
        SecretsCommand::AnchorSign(args) => emit(&sign_with_anchor(
            *args,
            &value("your recovery kit, one recovery code per line")?,
        )?),
        SecretsCommand::Bind(args) => emit(&bind_secret(*args)?),
        SecretsCommand::Unbind(args) => emit(&unbind_secret(*args)?),
        SecretsCommand::Pending(args) => pending_custody(*args),
    }
}

/// The value on stdin, exactly as given, in one buffer sized up front: the
/// read never moves it, so no copy is left behind, and it is wiped on drop.
pub(super) fn read_secret_value(input: impl Read) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut value = zeroize::Zeroizing::new(Vec::with_capacity(SECRET_VALUE_LIMIT + 1));
    input
        .take(SECRET_VALUE_LIMIT as u64 + 1)
        .read_to_end(&mut value)?;
    anyhow::ensure!(
        value.len() <= SECRET_VALUE_LIMIT,
        "a secret value is at most 1 MiB"
    );
    anyhow::ensure!(
        !value.is_empty(),
        "the secret value is read from stdin, and stdin was empty"
    );
    Ok(value)
}

/// Registers through the engine door the route uses, as the local owner.
pub(super) fn register_secret(
    args: SecretRegisterArgs,
    value: &[u8],
) -> anyhow::Result<secrets::Registered> {
    use oneiron::secret_custody::{
        CustodyClass, CustodyTier, ManifestSource, OwnerSecretRegistration, RequestedBinding,
    };
    let bindings = args
        .bindings
        .iter()
        .map(|binding| {
            let (effector, scopes) = binding.split_once('=').unwrap_or((binding, ""));
            RequestedBinding {
                effector: effector.to_owned(),
                tier_ceiling: None,
                scopes: scopes
                    .split(',')
                    .filter(|scope| !scope.is_empty())
                    .map(str::to_owned)
                    .collect(),
            }
        })
        .collect();
    let plan = secrets::custody_plan(args.holder, args.recipients)?;
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_vault(&config, "POST /v1/owner/secrets/register --data -")?;
    let owner = local_owner(&vault)?;
    // This command is an in-process call on this machine.
    let registered = vault.register_secret_with_custody(
        &owner,
        oneiron::authority::ActSurface::ThisInstall,
        &OwnerSecretRegistration {
            name: &args.name,
            class: match args.class {
                SecretClass::CustodyPortable => CustodyClass::CustodyPortable,
                SecretClass::CustodyDeviceBound => CustodyClass::CustodyDeviceBound,
                SecretClass::CrossVault => CustodyClass::CrossVault,
            },
            device_only: args.device_only,
            rung: CustodyTier::from_u8(args.rung)
                .ok_or_else(|| anyhow::anyhow!("a rung is 0, 1 or 2"))?,
            bindings,
            manifest: args.repo.map(|repo| ManifestSource {
                repo,
                git_ref: args.git_ref,
            }),
            value,
        },
        &plan,
        vault.now_recorded_at(),
    )?;
    Ok(registered.into())
}

pub(super) fn rotate_secret(
    args: SecretRotateArgs,
    value: &[u8],
) -> anyhow::Result<secrets::CustodyRotated> {
    let plan = secrets::custody_plan(args.holder, args.recipients)?;
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_vault(&config, "POST /v1/owner/secrets/rotate --data -")?;
    let owner = local_owner(&vault)?;
    let rotated = vault.rotate_secret_with_custody(
        &owner,
        oneiron::authority::ActSurface::ThisInstall,
        &args.name,
        value,
        &plan,
        vault.now_recorded_at(),
    )?;
    Ok(secrets::CustodyRotated {
        receipt: rotated.rotation.map(secrets::Rotated::from),
        custody: rotated.custody.into(),
    })
}

/// Seals a portable secret again to the installs named, through the engine
/// door `POST /v1/owner/secrets/rewrap` uses, as the local owner (WILL L04
/// row 04). It reads nothing from stdin.
fn rewrap_secret(args: crate::cli::SecretRewrapArgs) -> anyhow::Result<secrets::CustodyReply> {
    let plan = secrets::custody_plan(args.holder, args.recipients)?;
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_vault(&config, "POST /v1/owner/secrets/rewrap --data -")?;
    let owner = local_owner(&vault)?;
    Ok(secrets::rewrap(
        &vault,
        &owner,
        oneiron::authority::ActSurface::ThisInstall,
        &args.name,
        &plan,
    )?)
}

/// Binds a secret to an effector through the engine door `POST
/// /v1/owner/secrets/bind` uses, as the local owner (FIX 2620). It reads
/// nothing from stdin.
fn bind_secret(args: crate::cli::SecretBindArgs) -> anyhow::Result<secret_bindings::BoundView> {
    let request = oneiron::secret_custody::SecretBindRequest {
        target: secret_bindings::target(args.secret.handle, args.secret.name)?,
        effector: args.effector,
        tier_ceiling: secret_bindings::rung(args.rung)?,
        scopes: if args.scopes.is_empty() {
            oneiron::secret_custody::SecretBindRequest::default_scopes()
        } else {
            args.scopes
        },
    };
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_vault(&config, "POST /v1/owner/secrets/bind --data -")?;
    let owner = local_owner(&vault)?;
    Ok(secret_bindings::bind(
        &vault,
        &owner,
        oneiron::authority::ActSurface::ThisInstall,
        &request,
    )?)
}

/// Withdraws a secret's binding to one effector through the engine door
/// `POST /v1/owner/secrets/unbind` uses, as the local owner (FIX 2620).
/// Every other binding stays. It reads nothing from stdin.
fn unbind_secret(args: crate::cli::SecretUnbindArgs) -> anyhow::Result<secret_bindings::BoundView> {
    let target = secret_bindings::target(args.secret.handle, args.secret.name)?;
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_vault(&config, "POST /v1/owner/secrets/unbind --data -")?;
    let owner = local_owner(&vault)?;
    Ok(secret_bindings::unbind(
        &vault,
        &owner,
        oneiron::authority::ActSurface::ThisInstall,
        &target,
        &args.effector,
    )?)
}

/// A restore's credentials pending on their source's evidence, by batch,
/// with each batch's card, as `GET /v1/owner/secrets/custody/pending` lists
/// them; with `--keep BATCH --confirm keep_without_source`, the owner's
/// election that keeps the batch without its source, and its receipt
/// (FIX 11158). It reads nothing from stdin.
fn pending_custody(args: crate::cli::SecretPendingArgs) -> anyhow::Result<()> {
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_vault(&config, "GET /v1/owner/secrets/custody/pending")?;
    let owner = local_owner(&vault)?;
    match (args.keep, args.confirm) {
        (Some(batch), Some(confirm)) => {
            emit(&pending_custody::keep(&vault, &owner, &batch, &confirm)?)
        }
        _ => emit(&pending_custody::page(&vault, &owner)?),
    }
}

/// Revokes a secret through the engine door `POST /v1/owner/secrets/revoke`
/// uses, as the local owner (OF-422). It reads nothing from stdin.
pub fn revoke_secret(args: crate::cli::SecretRevokeArgs) -> anyhow::Result<()> {
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_vault(&config, "POST /v1/owner/secrets/revoke --data -")?;
    let owner = local_owner(&vault)?;
    emit(&secrets::revoke(
        &vault,
        &owner,
        oneiron::authority::ActSurface::ThisInstall,
        &args.name,
    )?)
}

/// Reads a secret's value through the engine door `POST /v1/owner/secrets/reveal`
/// uses, as the local owner, with the reason its receipt keeps (OF-560). The
/// value goes to stdout exactly as held, unbuffered, and the receipt to
/// stderr. It reads nothing from stdin.
pub fn reveal_secret(args: crate::cli::SecretRevealArgs) -> anyhow::Result<()> {
    use oneiron::secret_custody::RevealTarget;
    let target = match (args.handle, args.name) {
        (Some(handle), None) => RevealTarget::Handle(handle),
        (None, Some(name)) => RevealTarget::Name(name),
        _ => anyhow::bail!("name the secret by exactly one of --handle or --name"),
    };
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_vault(&config, "POST /v1/owner/secrets/reveal --data -")?;
    let owner = local_owner(&vault)?;
    let revealed = vault.reveal_secret_as_owner(&owner, &target, &args.reason)?;
    let receipt = &revealed.receipt;
    let receipt_ref = receipt
        .decision
        .map(|decision| format!("gate:{}", decision.to_hex()))
        .unwrap_or_default();
    eprintln!(
        "revealed {} ({}); reveal {}, receipt {receipt_ref}",
        receipt.handle,
        receipt.class.as_str(),
        receipt.reveal.to_hex(),
    );
    let mut stdout = raw_stdout()?;
    stdout.write_all(&revealed.value)?;
    stdout.flush()?;
    Ok(())
}

/// Stdout's own file, unbuffered, so a value written to it is copied through
/// no process-wide buffer that is never wiped.
fn raw_stdout() -> io::Result<std::fs::File> {
    #[cfg(unix)]
    let owned = std::os::fd::AsFd::as_fd(&io::stdout()).try_clone_to_owned()?;
    #[cfg(windows)]
    let owned = std::os::windows::io::AsHandle::as_handle(&io::stdout()).try_clone_to_owned()?;
    Ok(std::fs::File::from(owned))
}

/// Pushes a portable secret's current custody transition, signed with the
/// owner anchor of the recovery kit read from stdin, to the installs named
/// (OF-422, CALLS CUSTODY_KIT_PUSH), through the engine door
/// `Vault::sign_custody_with_anchor`, as the local owner: the owner's kit is
/// his authority; the install carries no act, so the engine takes it only
/// from an install with no live machine profile. `kit` is one recovery code
/// per line, after the kit passphrase on the first line when
/// `--with-passphrase` says the kit has one. The kit and the seed it rebuilds
/// stay in this process, and every buffer that holds them is wiped on drop;
/// no route takes them.
fn sign_with_anchor(
    args: crate::cli::SecretAnchorSignArgs,
    kit: &[u8],
) -> anyhow::Result<secrets::AnchorSigned> {
    use oneiron::recovery::{KitPassphrase, KitPiece, KitSecretKind};
    let recipients = secrets::custody_plan(None, args.recipients)?.recipients;
    let text = std::str::from_utf8(kit)
        .map_err(|_| anyhow::anyhow!("the recovery kit on stdin is not UTF-8"))?;
    let mut lines = text
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line));
    let passphrase = if args.with_passphrase {
        let line = lines.next().unwrap_or_default();
        Some(KitPassphrase::new(line).map_err(|error| anyhow::anyhow!("kit passphrase: {error}"))?)
    } else {
        None
    };
    let pieces = lines
        .filter(|line| !line.trim().is_empty())
        .map(KitPiece::from_recovery_code)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| anyhow::anyhow!("recovery code: {error}"))?;
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_stopped_vault(
        &config,
        "then run this again to read the kit on this machine alone, or send it in that server's \
         own call: `POST /v1/owner/secrets/anchor-sign`",
    )?;
    let owner = local_owner(&vault)?;
    let vault_id = vault.authority_fold()?.vault_id.ok_or_else(|| {
        anyhow::anyhow!("this vault has no authority root yet, so no recovery kit opens for it")
    })?;
    let held: Vec<&KitPiece> = pieces.iter().collect();
    let restored = vault
        .restore_kit_here(
            vault_id,
            KitSecretKind::RecoveryRoot,
            &held,
            passphrase.as_ref(),
        )
        .map_err(|error| anyhow::anyhow!("the recovery kit did not open: {error}"))?;
    let seed = oneiron::world_keys::RecoveryRootSeed::from_restored_kit(restored)?;
    Ok(secrets::sign_with_anchor(
        &vault,
        &owner,
        &seed,
        &args.name,
        &recipients,
    )?)
}
