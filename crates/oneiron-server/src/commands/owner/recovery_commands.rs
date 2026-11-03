//! Backup, restore, and recovery commands for a stopped vault.
//! Uses the parent's owner proof, configuration, and output helpers.
//! Common support and the vault-key command remain in the parent family.

use super::{
    BackupArgs, CustodyAnchorCredentials, Path, RecoverClockArgs, RecoverWindowArgs, RestoreArgs,
    Serialize, ServeConfig, backup_plan, base_vault_config, emit, local_owner, open_stopped_vault,
    open_vault, resolve_serve_config, rfc3339_secs, vault_key,
};
use crate::owner::backup;

mod open_pads;

pub fn backup(args: BackupArgs) -> anyhow::Result<()> {
    let mut config = resolve_serve_config(&args.serve)?;
    if let Some(dir) = args.dir {
        config.backup.dir = Some(dir);
    }
    if let Some(keep) = args.keep {
        anyhow::ensure!(keep > 0, "--keep must be at least 1");
        config.backup.keep = keep;
    }
    // The custody anchor door's owner credential, on the pipe the owner
    // named, read before the vault opens (FIX 5788).
    let anchor = CustodyAnchorCredentials::handed(args.serve.custody_anchor_credentials_fd)?;
    let plan = backup_plan(&config).anchored_at(&config.backup, anchor);
    if args.list {
        return emit(&backup::list(&plan)?);
    }
    let vault = open_vault(&config, "POST /v1/owner/backups")?;
    emit(&backup::take_publishing(&vault, &plan)?)
}

pub fn restore(args: RestoreArgs) -> anyhow::Result<()> {
    let config = resolve_serve_config(&args.serve)?;
    if args.wrap.wrap_to.is_some() {
        refuse_wrap_elsewhere(&args, &config)?;
    }
    if let Some(previous) = &args.activate {
        // The archive keeps its own tier and opens with its own mirror; the
        // vault that replaced it reads with its own (OF-570).
        let mut archive = base_vault_config(&config);
        archive.page_seal = vault_key::page_seal_at(&config, previous, None)?;
        let live_seal = vault_key::page_seal_at(&config, &config.vault_path, None)?;
        return emit(&backup::activate(
            previous,
            &config.vault_path,
            archive,
            live_seal,
        )?);
    }
    let backup = args
        .backup
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("name the backup file to restore"))?;
    if args.inspect {
        let unlocks = oneiron::recovery::checkpoint::CheckpointKey::unlocks(backup)
            .map_err(|error| anyhow::anyhow!("read backup {}: {error}", backup.display()))?;
        return emit(&crate::owner::vault_key::BackupUnlocks::from(unlocks));
    }
    // A page-seal mirror whose vault's data is missing is refused first, by
    // name (OF-570): a restore never makes a vault under another's custody.
    vault_key::refuse_orphaned_page_seal(&config.vault_path)?;
    // A backup opens with this install's keystore, as configured, unless the
    // owner names another unlock and the signers to trust.
    let keystore = config.keystore.open(&config.vault_path)?;
    // The durable wrap the owner names is read first: reading the unlock
    // may release a registry capsule's recipient (FIX 2558).
    let wrap = vault_key::RestoreWrap::read(&args.wrap)?;
    let unlock = vault_key::HostUnlock::read(&args, backup)?;
    let restored = restore_unlocked(&args, &config, backup, keystore, &unlock, wrap.as_ref());
    // A registry capsule's recipient secret was released into this process,
    // whether or not the restore went through (CROSS-ARCH-0022
    // #ov-custody-backend).
    if let Some(note) = unlock.released_note() {
        eprintln!("{note}");
    }
    restored
}

/// `--wrap-to` adds a wrap to a restore where no vault is yet (FIX 2558): a
/// vault a restore runs over, rehearses or activates keeps its own wraps.
/// Its secret and the unlock's are never both read from stdin.
fn refuse_wrap_elsewhere(args: &RestoreArgs, config: &ServeConfig) -> anyhow::Result<()> {
    anyhow::ensure!(
        args.activate.is_none()
            && !args.inspect
            && !args.rehearse
            && !args.open_pads
            && !config.vault_path.join("data.mdb").exists(),
        "--wrap-to adds a wrap to a restore where no vault is yet; a vault that is there keeps \
         its own wraps (`oneiron vault-key set-password --unlock ...` adds one)"
    );
    vault_key::refuse_two_stdin_secrets(
        &vault_key::UnlockRequest::restore(args),
        vault_key::RestoreWrap::reads_stdin(&args.wrap),
        "the new wrap's secret",
        "--wrap-secret-file",
    )
}

/// The restore once its unlock is read: a new vault where none is, else a
/// rehearsal or a restore over the vault.
fn restore_unlocked(
    args: &RestoreArgs,
    config: &ServeConfig,
    backup: &Path,
    keystore: Option<std::sync::Arc<dyn oneiron_keystore::DeviceKeystore>>,
    unlock: &vault_key::HostUnlock,
    wrap: Option<&vault_key::RestoreWrap>,
) -> anyhow::Result<()> {
    let pins = args
        .trust
        .as_deref()
        .map(vault_key::read_pins)
        .transpose()?;
    // `--open-pads`: the existing vault's Locked worlds, opened from the
    // custody head beside the backup with the kit or an admitted machine
    // (FIX 10470); nothing is restored.
    if args.open_pads {
        return open_pads::open_pads(args, config, backup, keystore, unlock, pins);
    }
    if !args.rehearse && !config.vault_path.join("data.mdb").exists() {
        // Its custody anchor door's owner credential, on the pipe the owner
        // named, read before the new vault is made (FIX 5788).
        let anchor = CustodyAnchorCredentials::handed(args.serve.custody_anchor_credentials_fd)?;
        return emit(&vault_key::restore_fresh(
            backup,
            config,
            keystore,
            unlock,
            wrap,
            pins,
            anchor,
            args.pad_machine.as_deref(),
            args.custody_home.as_deref(),
        )?);
    }
    let key = vault_key::backup_key(backup, &config.vault_path, keystore.as_ref(), unlock, pins)?;
    // A sealed vault (OF-570 maximum tier) opens, or reads beside a `serve`,
    // with its own seal; the restored copy keeps its tier.
    let live_seal = vault_key::page_seal_at(config, &config.vault_path, Some(unlock))?;
    if args.rehearse {
        // Read off the disk, beside a `serve` that may hold the vault.
        let mut source =
            oneiron::recovery::checkpoint::SideRestoreSource::read(&config.vault_path, live_seal)?;
        if let Some(keystore) = keystore {
            source = source.with_keystore(keystore);
        }
        let scratch = args.scratch.as_deref();
        return emit(&match key {
            Some(key) => {
                backup::rehearse_keyed(backup, base_vault_config(config), scratch, &source, key)?
            }
            None => backup::rehearse(backup, base_vault_config(config), scratch, &source)?,
        });
    }
    // `--pad-machine` opens pads on `--open-pads` or a restore where no
    // vault is yet; a restore over the vault reads no machine key.
    if args.pad_machine.is_some() {
        anyhow::bail!("--pad-machine opens pads on --open-pads or a restore where no vault is yet");
    }
    let mut live = base_vault_config(config);
    live.page_seal = live_seal;
    emit(&match key {
        Some(key) => backup::restore_over_keyed(backup, &config.vault_path, live, key)?,
        None => backup::restore_over(backup, &config.vault_path, live, keystore)?,
    })
}

#[derive(Serialize)]
struct RecoveredWindow {
    window: String,
    /// `healthy`, `targeted_chunk_repair` or `full_rebuild`.
    tier: &'static str,
    /// The window's manifest of chunk hashes, kept for the next recovery.
    manifest: std::path::PathBuf,
    /// A bad manifest, renamed intact beside the manifest.
    quarantined: Option<std::path::PathBuf>,
    /// The chunks this recovery rebuilt.
    rebuilt: Vec<String>,
    /// With `--rebootstrap`: the window's CRDT state now holds no history,
    /// and this many of its keys took their rebuilt value.
    #[serde(skip_serializing_if = "Option::is_none")]
    rebootstrap_rewritten_keys: Option<usize>,
}

/// Recovers one window of the stopped vault from a canonical snapshot of its
/// CRDT state (ARCH-0038). Holding the writer lease stops the window's
/// writers; the engine holds the snapshot in memory and writes none to disk.
pub fn recover_window(args: RecoverWindowArgs) -> anyhow::Result<()> {
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_stopped_vault(
        &config,
        "since a window recovers only with its writers stopped",
    )?;
    let owner = local_owner(&vault)?;
    let dir = config.vault_path.join("recovery");
    let budget = oneiron::recovery::RecoveryBudget::default();
    let (report, rewritten) = if args.rebootstrap {
        vault
            .rebootstrap_window_from_canonical_snapshot(&owner, &args.window, &dir, budget)
            .map(|done| (done.recovery, Some(done.rewritten_keys)))
    } else {
        vault
            .recover_window_from_canonical_snapshot(&owner, &args.window, &dir, budget)
            .map(|report| (report, None))
    }
    .map_err(|error| anyhow::anyhow!("recover window {}: {error}", args.window))?;
    emit(&RecoveredWindow {
        window: report.window,
        tier: match report.tier {
            oneiron::recovery::RecoveryTier::Healthy => "healthy",
            oneiron::recovery::RecoveryTier::TargetedChunkRepair => "targeted_chunk_repair",
            oneiron::recovery::RecoveryTier::FullRebuild => "full_rebuild",
        },
        manifest: report.manifest_path,
        quarantined: report.quarantine_path,
        rebuilt: report.obligations,
        rebootstrap_rewritten_keys: rewritten,
    })
}

#[derive(Serialize)]
struct RecoveredClock {
    /// Where the clock holder proofs are judged on stood.
    old_floor: String,
    /// Where it stands now: this host's clock.
    new_floor: String,
    /// How far ahead it was, in seconds.
    gap_secs: u64,
    /// No proof signed before this is admitted again.
    not_before: String,
}

/// Lets agents back in after the host clock ran ahead and was set back:
/// while the vault's proof clock sits ahead, every fresh holder proof gets
/// 401. Holding the writer lease keeps a running `serve` out; the engine
/// refuses when the clock is not ahead, or when lowering it would reopen a
/// proof it no longer remembers.
pub fn recover_clock(args: RecoverClockArgs) -> anyhow::Result<()> {
    use oneiron::authority::ProofClockRecovery;
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_stopped_vault(&config, "then run this again")?;
    let owner = local_owner(&vault)?;
    match vault.recover_proof_clock(&owner)? {
        ProofClockRecovery::Recovered {
            old_floor,
            new_floor,
            not_before,
        } => emit(&RecoveredClock {
            old_floor: rfc3339_secs(old_floor),
            new_floor: rfc3339_secs(new_floor),
            gap_secs: old_floor - new_floor,
            not_before: rfc3339_secs(not_before),
        }),
        ProofClockRecovery::NotAhead { floor, wall } => anyhow::bail!(
            "nothing to recover: the vault's proof clock ({}) is not ahead of this host's \
             clock ({})",
            rfc3339_secs(floor),
            rfc3339_secs(wall)
        ),
        ProofClockRecovery::Forgotten {
            floor,
            forgotten_before,
            wall,
        } => anyhow::bail!(
            "not recovered: agents connected while the host clock was ahead, and the vault \
             no longer remembers every proof it admitted then (up to {}): the clock stayed \
             ahead for over a day, or an older version kept each proof for a minute only. \
             It must keep refusing every proof signed before then, so lowering its clock \
             would not let agents in. Agents get in again once this host's clock ({}) \
             reaches {}",
            rfc3339_secs(forgotten_before),
            rfc3339_secs(wall),
            rfc3339_secs(floor)
        ),
    }
}
