//! The vault data key's public side, shared by `oneiron vault-key`, `oneiron
//! restore` and `/v1/owner/vault-key` (OF-570 E1): the wraps as an owner reads
//! them, a passkey's PRF input, and the checkpoint signer pin a host with no
//! vault trusts a backup by. No secret passes through here.

use base64::Engine as _;
use oneiron::recovery::checkpoint::{ArtifactKind, ArtifactUnlocks, CheckpointSigner};
use oneiron::world_keys::{VaultKeyStatus, VaultKeyWrapInfo, VaultKeyWrapKind};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::stamp::rfc3339_secs;

/// One wrap as the owner reads it.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct WrapView {
    pub(crate) id: String,
    pub(crate) kind: VaultKeyWrapKind,
    pub(crate) created: String,
    /// For a passkey: the PRF input (`prf.eval.first`) to ask it at, base64url.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) prf_input: Option<String>,
}

impl WrapView {
    pub(crate) fn of(vault_id: &[u8; 32], info: VaultKeyWrapInfo) -> Self {
        let prf_input = match &info.kind {
            VaultKeyWrapKind::Passkey { credential } => {
                oneiron::world_keys::passkey_prf_input(vault_id, credential)
                    .ok()
                    .map(|input| b64(&input))
            }
            _ => None,
        };
        Self {
            id: info.id,
            kind: info.kind,
            created: rfc3339_secs(info.created_at),
            prf_input,
        }
    }
}

/// Whether the vault has a data key, whether this handle holds it, and its
/// wraps.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct VaultKeyReport {
    pub(crate) vault_id: String,
    pub(crate) status: VaultKeyStatus,
    pub(crate) wraps: Vec<WrapView>,
}

pub(crate) fn report(vault: &oneiron::Vault) -> oneiron::Result<VaultKeyReport> {
    let vault_id = *vault.vault_id().as_bytes();
    Ok(VaultKeyReport {
        vault_id: hex(&vault_id),
        status: vault.vault_key_status()?,
        wraps: vault
            .vault_key_wraps()?
            .into_iter()
            .map(|info| WrapView::of(&vault_id, info))
            .collect(),
    })
}

/// What a backup's clear head says unlocks it. Unauthenticated until the
/// backup opens: it picks the unlock, never the trust.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct BackupUnlocks {
    pub(crate) kind: &'static str,
    pub(crate) vault_id: String,
    pub(crate) wraps: Vec<WrapView>,
}

impl From<ArtifactUnlocks> for BackupUnlocks {
    fn from(unlocks: ArtifactUnlocks) -> Self {
        Self {
            kind: match unlocks.kind {
                ArtifactKind::Backup => "backup",
                ArtifactKind::Checkpoint => "checkpoint",
            },
            vault_id: hex(&unlocks.vault_id),
            wraps: unlocks
                .wraps
                .into_iter()
                .map(|info| WrapView::of(&unlocks.vault_id, info))
                .collect(),
        }
    }
}

/// A passkey's PRF input, in both spellings a ceremony takes.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct PrfInput {
    pub(crate) credential: String,
    /// base64url, no padding: what a WebAuthn client decodes into
    /// `extensions.prf.eval.first`.
    pub(crate) prf_input: String,
    pub(crate) prf_input_hex: String,
}

pub(crate) fn prf_input(vault: &oneiron::Vault, credential: &str) -> oneiron::Result<PrfInput> {
    let input = vault.vault_key_passkey_prf_input(credential)?;
    Ok(PrfInput {
        credential: credential.to_owned(),
        prf_input: b64(&input),
        prf_input_hex: hex(&input),
    })
}

/// One checkpoint signer as a pin file spells it: what `oneiron vault-key
/// signer` prints and `oneiron restore --trust` reads.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignerPin {
    /// The install's id, hex.
    pub(crate) install: String,
    /// The Ed25519 public key, base64url.
    pub(crate) ed25519: String,
    /// The SLH-DSA-SHA2-256s public key, base64url.
    pub(crate) slhdsa: String,
}

impl From<CheckpointSigner> for SignerPin {
    fn from(signer: CheckpointSigner) -> Self {
        Self {
            install: hex(&signer.install),
            ed25519: b64(&signer.ed25519),
            slhdsa: b64(&signer.slhdsa),
        }
    }
}

impl TryFrom<SignerPin> for CheckpointSigner {
    type Error = anyhow::Error;

    fn try_from(pin: SignerPin) -> anyhow::Result<Self> {
        let install = unhex(&pin.install)
            .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
            .ok_or_else(|| anyhow::anyhow!("a signer pin's install is 32 hex digits"))?;
        let ed25519 = unb64(&pin.ed25519)
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or_else(|| anyhow::anyhow!("a signer pin's ed25519 key is 32 bytes, base64url"))?;
        let slhdsa = unb64(&pin.slhdsa)
            .filter(|bytes| bytes.len() == 64)
            .ok_or_else(|| anyhow::anyhow!("a signer pin's slhdsa key is 64 bytes, base64url"))?;
        Ok(Self {
            install,
            ed25519,
            slhdsa,
        })
    }
}

/// A pin file: one pin, or a list of them.
#[derive(Deserialize)]
#[serde(untagged)]
enum PinFile {
    One(SignerPin),
    Many(Vec<SignerPin>),
}

/// The signers a pin file names.
pub(crate) fn parse_pins(text: &str) -> anyhow::Result<Vec<CheckpointSigner>> {
    let pins = match serde_json::from_str(text)
        .map_err(|error| anyhow::anyhow!("a signer pin file is JSON: {error}"))?
    {
        PinFile::One(pin) => vec![pin],
        PinFile::Many(pins) => pins,
    };
    anyhow::ensure!(!pins.is_empty(), "the signer pin file names no signer");
    pins.into_iter().map(CheckpointSigner::try_from).collect()
}

/// A 32-byte secret as given: 32 raw bytes, 64 hex digits or base64url.
pub(crate) fn secret32(raw: &[u8], what: &str) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    let decoded = match raw.len() {
        32 => Some(Zeroizing::new(raw.to_vec())),
        64 => std::str::from_utf8(raw)
            .ok()
            .and_then(unhex)
            .map(Zeroizing::new),
        _ => std::str::from_utf8(raw)
            .ok()
            .and_then(unb64)
            .map(Zeroizing::new),
    };
    match decoded {
        Some(bytes) if bytes.len() == 32 => out.copy_from_slice(&bytes),
        _ => anyhow::bail!("{what} is 32 bytes: raw, 64 hex digits or base64url"),
    }
    Ok(out)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}

pub(crate) fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(text: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text.trim_end_matches('='))
        .ok()
}
