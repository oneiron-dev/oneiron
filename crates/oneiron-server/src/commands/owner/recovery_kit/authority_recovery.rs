//! Explicit recovery-key enrollment before loss; kit issuance is separate.

use oneiron::authority::{ActAuthority, ActSurface};
use oneiron::recovery::{KitPiece, KitSecretKind};
use oneiron::store::recovery_kit::RestoredKitSecret;
use oneiron::world_keys::RecoveryRootSeed;
use oneiron::{EntityId, Vault};
use serde::Serialize;

use super::super::host_issuer;
use super::super::vault_key::{KeyNeed, UnlockRequest, open_with_unlock_for_secret_checked};
use super::{INSTEAD, emit, read_kit_passphrase, read_kit_pieces};
use crate::cli::RecoveryKitAuthorityArgs;
use crate::config::{ServeConfig, resolve_serve_config};
use crate::owner::host_owner;
use crate::owner::vault_key::hex;

#[derive(Serialize)]
struct Enrolled {
    entry: String,
    machine: String,
    public_key: String,
}

pub(super) fn enroll(args: RecoveryKitAuthorityArgs) -> anyhow::Result<()> {
    let config = resolve_serve_config(&args.serve)?;
    let (vault, secret) = open_material(&config, &args)?;
    let named = args
        .machine
        .as_deref()
        .map(EntityId::from_hex)
        .transpose()?;
    let machine = crate::owner::recovery_kit::authority_holding_machine(&vault, named)?
        .ok_or_else(|| anyhow::anyhow!("this install has no machine in the vault"))?;
    let authority = ActAuthority::Owner(host_owner(&vault)?, ActSurface::ThisInstall);
    let seed = RecoveryRootSeed::from_restored_kit(secret)?;
    let issuer = host_issuer(&config, &vault, false)?;
    let receipt =
        vault.enrol_recovery_authority_key_as_host(&authority, machine, &seed, &issuer)?;
    emit(&Enrolled {
        entry: hex(&receipt.entry),
        machine: receipt.machine.to_hex(),
        public_key: hex(&receipt.public_key),
    })
}

fn open_material(
    config: &ServeConfig,
    args: &RecoveryKitAuthorityArgs,
) -> anyhow::Result<(Vault, RestoredKitSecret)> {
    let pieces = read_kit_pieces(&args.kit.pieces)?;
    let vault = open_with_unlock_for_secret_checked(
        config,
        &UnlockRequest::of(&args.unlock),
        KeyNeed::Open,
        INSTEAD,
        |opened| reads_stdin_before_open(config, opened, &pieces, args),
        "the kit passphrase",
        "--secret-file",
    )?;
    let vault_id = vault
        .authority_fold()?
        .vault_id
        .ok_or_else(|| anyhow::anyhow!("the vault has no authority genesis"))?;
    let kept = keeps_piece(&vault, &pieces);
    let passphrase = read_kit_passphrase(args.kit.secret_file.as_deref(), pieces.len(), kept)?;
    let given: Vec<&KitPiece> = pieces.iter().collect();
    let secret = vault.restore_kit_here(
        vault_id,
        KitSecretKind::RecoveryRoot,
        &given,
        passphrase.as_ref(),
    )?;
    Ok((vault, secret))
}

fn keeps_piece(vault: &Vault, pieces: &[KitPiece]) -> bool {
    vault.keeps_kit_piece_for_input(
        KitSecretKind::RecoveryRoot,
        pieces.first().map(KitPiece::kit_id),
    )
}

fn reads_stdin_before_open(
    config: &ServeConfig,
    opened: Option<&Vault>,
    pieces: &[KitPiece],
    args: &RecoveryKitAuthorityArgs,
) -> anyhow::Result<bool> {
    if args.kit.secret_file.is_some() || pieces.len() > 1 {
        return Ok(false);
    }
    let kept = match opened {
        Some(vault) => keeps_piece(vault, pieces),
        None => {
            // With no supplied piece, a successful sealed restore needs a
            // kept piece and its passphrase; no kit can open with neither.
            let Some(piece) = pieces.first() else {
                return Ok(true);
            };
            match config.keystore.open(&config.vault_path)? {
                Some(keystore) => oneiron::world_keys::sealed_keeps_kit_piece(
                    &config.vault_path,
                    &keystore,
                    KitSecretKind::RecoveryRoot,
                    piece.kit_id(),
                )?,
                None => false,
            }
        }
    };
    Ok(pieces.len() + usize::from(kept) == 1)
}
