//! `oneiron host recover-shared-owner`: proof-of-control owner recovery
//! (ARCH-0043, OF-163) on a stopped self-host vault, the host operator's act
//! `POST /v1/operator/shared/recover-owner` answers while `serve` runs. The
//! operator has judged, outside the engine, the claimant's proof that they
//! control the organization owning the shared vault; the engine has no check
//! for that proof. It checks what it holds (no live Owner left, `from` still
//! an Owner, the claimant a live person other than `from`), and this host's
//! key, from the config's auth secret `serve` signs with, signs the
//! `OwnerHandover`.
//!
//! The engine keeps the note's BLAKE3 with the signed `OwnerHandover`, never
//! the note. Stdout is the engine's receipt alone; stderr names the same
//! BLAKE3 beside the receipt id, for the operator's own record.

use std::io::{self, Write};

use zeroize::Zeroizing;

use crate::cli::HostRecoverSharedOwnerArgs;
use crate::config::resolve_serve_config;

pub fn host_recover_shared_owner(args: HostRecoverSharedOwnerArgs) -> anyhow::Result<()> {
    anyhow::ensure!(
        !args.serve.managed_by_hypnos,
        "a managed vault's operator recovers an owner through its supervisor, at /v1/operator/shared/recover-owner"
    );
    anyhow::ensure!(
        args.serve.auth_secret.is_none(),
        "set ONEIRON_AUTH_SECRET or a protected config file; never pass the issuer key in argv"
    );
    let person = |flag: &str, hex: &str| {
        oneiron::EntityId::from_hex(hex)
            .map_err(|_| anyhow::anyhow!("{flag} {hex} is not a 32-hex person id"))
    };
    let from = person("--from", &args.from)?;
    let claimant = person("--claimant", &args.claimant)?;
    anyhow::ensure!(
        !args.proof_note.trim().is_empty(),
        "--proof-note names the proof of control you judged"
    );
    // A TOML error renders the line it failed on, and that line may hold a
    // host secret, so only the outermost message leaves this command.
    let config = resolve_serve_config(&args.serve).map_err(|error| {
        anyhow::anyhow!("{error} (detail withheld: the file may hold a secret)")
    })?;
    let secret = Zeroizing::new(
        config
            .sync_server_config()
            .auth_secret
            .filter(|secret| !secret.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "the config names no auth secret, so this host has no key to sign the owner handover"
                )
            })?,
    );
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(secret.as_bytes())?;
    let vault = super::owner::open_stopped_vault_with(
        &config,
        super::owner::vault_config(&config),
        "or ask it under the host's root credential: `oneiron api raw POST /v1/operator/shared/recover-owner --data -`",
    )?;
    // A blank note was refused above, so the handover always keeps a digest.
    let digest = blake3::hash(args.proof_note.as_bytes());
    let receipt = vault.recover_shared_owner_with_proof(
        &issuer,
        args.vault_id,
        from,
        claimant,
        Some(*digest.as_bytes()),
    )?;
    super::owner::emit(&receipt)?;
    writeln!(
        io::stderr().lock(),
        "receipt {}: the signed handover keeps the proof note's BLAKE3 {}, not the note; keep yours with this receipt",
        receipt.id,
        digest.to_hex()
    )?;
    Ok(())
}
