//! The `vault-key recovery-preset` command: read the vault key's recovery
//! preset, or set it, with the kit for a switch to Nobody but me.

use super::*;

/// Shows the recovery preset, or sets it with `--set`. Entering
/// `nobody-but-me` writes the printed sheet's code to the new owner-only file
/// `--sheet-out` names, synced, before the write that removes the old wraps
/// (review of #7766): a failed write leaves the vault as it was. The file is
/// removed again when the vault did not take the sheet. The vault keeps only
/// the sheet's wrap.
pub(super) fn recovery_preset(args: VaultKeyRecoveryPresetArgs) -> anyhow::Result<()> {
    let unlock = UnlockRequest::of(&args.unlock);
    let Some(set) = args.set else {
        anyhow::ensure!(
            args.sheet_out.is_none(),
            "--sheet-out is read only with --set nobody-but-me"
        );
        anyhow::ensure!(
            args.kit.pieces.is_empty() && args.kit.secret_file.is_none(),
            "--piece is read only with --set nobody-but-me"
        );
        let vault = open(&args.serve, &unlock, KeyNeed::Open)?;
        return emit(&view::RecoveryPresetView {
            preset: vault.recovery_preset()?,
        });
    };
    let (preset, need, sheet_out) = match (set, args.sheet_out) {
        (RecoveryPresetArg::NobodyButMe, Some(path)) => {
            (RecoveryPreset::NobodyButMe, KeyNeed::Held, Some(path))
        }
        (RecoveryPresetArg::NobodyButMe, None) => anyhow::bail!(
            "--set nobody-but-me writes the printed sheet's code to a new owner-only file: \
             --sheet-out FILE"
        ),
        (RecoveryPresetArg::NobodyButMeAnyTwo, _) => anyhow::bail!(
            "\"any 2 pieces\" is turned on with the kit its pieces come from: \
             oneiron recovery-kit issue-vault-key --any-two-pieces"
        ),
        (RecoveryPresetArg::Standard, None) => (RecoveryPreset::Standard, KeyNeed::Open, None),
        (RecoveryPresetArg::Standard, Some(_)) => {
            anyhow::bail!("--sheet-out is read only with --set nobody-but-me")
        }
    };
    let wants_kit = !args.kit.pieces.is_empty() || args.kit.secret_file.is_some();
    if preset == RecoveryPreset::Standard && wants_kit {
        anyhow::bail!("--piece is read only with --set nobody-but-me: leaving it takes no kit");
    }
    // Entering with one piece and no file reads the kit passphrase from
    // stdin, coordinated with the unlock as `confirm` coordinates it.
    let config = resolve_serve_config(&args.serve)?;
    let vault = if wants_kit {
        open_with_unlock_for_secret(
            &config,
            &unlock,
            need,
            INSTEAD,
            args.kit.secret_file.is_none() && args.kit.pieces.len() == 1,
            "the kit passphrase",
            "--secret-file",
        )?
    } else {
        open_with_unlock(&config, &unlock, need, INSTEAD)?
    };
    let owner = local_owner(&vault)?;
    let kit = wants_kit.then(|| read_kit_args(&args.kit)).transpose()?;
    let mut kept = None;
    let keep_sheet = |sheet: &world_keys::RecoverySheet| -> oneiron::Result<()> {
        let path = sheet_out
            .as_deref()
            .ok_or_else(|| oneiron::Error::Io(std::io::Error::other("no --sheet-out file")))?;
        credential_file::write_new(path, sheet.code().as_bytes())
            .map_err(|error| oneiron::Error::Io(std::io::Error::other(error.to_string())))?;
        kept = Some(path);
        Ok(())
    };
    let changed = match kit {
        Some((pieces, passphrase)) => {
            let refs: Vec<&oneiron::store::recovery_kit::KitPiece> = pieces.iter().collect();
            let authority = ActAuthority::Owner(owner, ActSurface::ThisInstall);
            vault.set_recovery_preset_with_kit_as(
                &authority,
                preset,
                &refs,
                passphrase.as_ref(),
                keep_sheet,
                &NoRecoveryBox,
            )
        }
        None => vault.set_recovery_preset_as(&owner, preset, keep_sheet, &NoRecoveryBox),
    };
    // A kept sheet the vault did not take opens nothing. One the vault may
    // have taken stays: an error after the commit must not drop it.
    let took_sheet = match &changed {
        Ok(change) => change.previous != change.preset,
        Err(_) => vault.recovery_preset().ok() != Some(RecoveryPreset::Standard),
    };
    if !took_sheet && let Some(path) = kept.take() {
        let _ = std::fs::remove_file(path);
    }
    let change = changed.map_err(|error| match kept {
        Some(path) => anyhow::anyhow!(
            "{error}; the sheet's code stays in {}, as the vault may have taken its wrap",
            path.display()
        ),
        None => error.into(),
    })?;
    let (mut set, _) = view::RecoveryPresetSet::of(&vault.vault_key_vault_id(), change);
    set.sheet_file = kept.map(|path| path.display().to_string());
    emit(&set)
}
