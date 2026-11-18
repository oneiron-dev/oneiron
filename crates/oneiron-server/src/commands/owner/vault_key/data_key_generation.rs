//! `oneiron vault-key new-generation`: the owner starts a new data-key
//! generation on a stopped vault (DATAKEY-GEN-WHO = C).
//!
//! The WAYS = A flow: `--preview` names, with no secret read, every wrap of
//! the current key that no way the owner keeps covers; the act then presents
//! each kept way (the password from stdin or `--secret-file`, each passkey's
//! PRF output from its owner-only file, each escrow's recipient from its
//! file) and removes each wrap the owner confirmed by id. Only the owner
//! starts the act; an agent proposes it through
//! `vault.data_key.generation.propose`.

use oneiron::authority::{ActAuthority, ActSurface};
use oneiron::world_keys::{
    DataKeyGenerationCause, DataKeyGenerationKeptWays, DataKeyGenerationWays, HybridPublicKey,
};
use zeroize::Zeroizing;

use super::super::emit;
use super::{
    INSTEAD, KeyNeed, UnlockRequest, open, open_with_unlock_for_secret, read_secret,
    read_secret_file,
};
use crate::cli::VaultKeyNewGenerationArgs;
use crate::config::resolve_serve_config;
use crate::owner::local_owner;
use crate::owner::vault_key::{self as view, secret32};

/// Starts a new data-key generation, or, with `--preview`, names the wraps
/// it would remove. The preview reads no secret; the act reads the password
/// only with `--keep-password`.
pub(super) fn new_generation(args: VaultKeyNewGenerationArgs) -> anyhow::Result<()> {
    if args.preview {
        let vault = open(&args.serve, &UnlockRequest::of(&args.unlock), KeyNeed::Open)?;
        let kept = DataKeyGenerationKeptWays {
            password: args.keep_password,
            passkeys: args
                .keep_passkeys
                .iter()
                .map(|kept| kept.name.clone())
                .collect(),
            escrows: args
                .keep_escrows
                .iter()
                .map(|kept| kept.label.clone())
                .collect(),
        };
        return emit(&view::DataKeyGenerationPreviewView::of(
            &vault.vault_key_vault_id(),
            vault.data_key_generation_preview(&kept)?,
        ));
    }
    let unlock = UnlockRequest::of(&args.unlock);
    let config = resolve_serve_config(&args.serve)?;
    // The key held when the vault has one: a vault with none is not given a
    // key only for the act to replace it; the act then refuses.
    let vault = open_with_unlock_for_secret(
        &config,
        &unlock,
        KeyNeed::HeldIfAny,
        INSTEAD,
        args.keep_password && args.secret.secret_file.is_none(),
        "the vault password",
        "--secret-file",
    )?;
    let password = args
        .keep_password
        .then(|| read_secret(&args.secret, "the vault password"))
        .transpose()?;
    let mut prfs = Vec::with_capacity(args.keep_passkeys.len());
    for kept in &args.keep_passkeys {
        let prf = secret32(
            &read_secret_file(&kept.file, "a kept passkey's PRF output")?,
            "a PRF output",
        )?;
        prfs.push(prf);
    }
    let mut recipients = Vec::with_capacity(args.keep_escrows.len());
    for kept in &args.keep_escrows {
        let bytes = std::fs::read(&kept.file)
            .map_err(|error| anyhow::anyhow!("read {}: {error}", kept.file.display()))?;
        let recipient = HybridPublicKey::from_bytes(&bytes)
            .map_err(|_| anyhow::anyhow!("{} is not a hybrid public key", kept.file.display()))?;
        recipients.push(recipient);
    }
    let passkeys: Vec<(&str, &Zeroizing<[u8; 32]>)> = args
        .keep_passkeys
        .iter()
        .zip(&prfs)
        .map(|(kept, prf)| (kept.name.as_str(), prf))
        .collect();
    let escrows: Vec<(&str, &HybridPublicKey)> = args
        .keep_escrows
        .iter()
        .zip(&recipients)
        .map(|(kept, recipient)| (kept.label.as_str(), recipient))
        .collect();
    let ways = DataKeyGenerationWays {
        password: password.as_ref().map(|secret| secret.as_slice()),
        passkeys,
        escrows,
        confirmed_removals: args.confirm_removals.into_iter().collect(),
    };
    let owner = local_owner(&vault)?;
    let authority = ActAuthority::Owner(owner, ActSurface::ThisInstall);
    let outcome = vault.start_data_key_generation_as(
        &authority,
        DataKeyGenerationCause::OwnerRequest,
        &ways,
    )?;
    emit(&view::DataKeyGenerationView::of(
        &vault.vault_key_vault_id(),
        outcome,
    ))
}
