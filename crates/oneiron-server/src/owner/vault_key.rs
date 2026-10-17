//! The vault data key's public side, shared by `oneiron vault-key`, `oneiron
//! restore` and `/v1/owner/vault-key` (OF-570 E1): the wraps as an owner reads
//! them, whether the pages are sealed, a passkey's PRF input, and the
//! checkpoint signer pin a host with no vault trusts a backup by. No secret
//! passes through here.

use base64::Engine as _;
use oneiron::recovery::checkpoint::{ArtifactKind, ArtifactUnlocks, CheckpointSigner};
use oneiron::world_keys::{HybridSecretKey, VaultKeyStatus, VaultKeyWrapInfo, VaultKeyWrapKind};
use oneiron_vault_contract::escrow::{
    ESCROW_REPORT_SCHEMA_VERSION, ESCROW_REPORT_TYPE, EscrowCapsuleReport,
};
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
    /// What keeps this install's device wrap and signing seeds at rest:
    /// `hardware`, `platform` or `software`; none without a keystore.
    pub(crate) keystore: Option<&'static str>,
    /// `sealed` at the maximum tier (OF-570), else `plain`.
    pub(crate) pages: &'static str,
    /// The maximum tier's warning, while the pages are sealed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) warning: Option<&'static str>,
}

pub(crate) fn report(vault: &oneiron::Vault) -> oneiron::Result<VaultKeyReport> {
    let vault_id = vault.vault_key_vault_id();
    Ok(VaultKeyReport {
        vault_id: hex(&vault_id),
        status: vault.vault_key_status()?,
        wraps: vault
            .vault_key_wraps()?
            .into_iter()
            .map(|info| WrapView::of(&vault_id, info))
            .collect(),
        keystore: vault
            .device_keystore_assurance()
            .map(oneiron_keystore::KeystoreAssurance::label),
        pages: if vault.vault_pages_sealed() {
            "sealed"
        } else {
            "plain"
        },
        warning: vault
            .vault_pages_sealed()
            .then_some(oneiron::PAGE_SEAL_WARNING),
    })
}

/// What a backup's clear head says unlocks it. Unauthenticated until the
/// backup opens: it picks the unlock, never the trust.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct BackupUnlocks {
    pub(crate) kind: &'static str,
    pub(crate) vault_id: String,
    /// The commitment naming the vault key, hex: the registry's escrow
    /// capsule for this key names the same one (`--capsule`).
    pub(crate) key_commitment: String,
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
            key_commitment: hex(&unlocks.commitment),
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
    prf_input_for(&vault.vault_key_vault_id(), credential)
}

/// [`prf_input`] for the vault `vault_id` names, with no vault open: a sealed
/// vault's, from the public id its page-seal mirror names (OF-570).
pub(crate) fn prf_input_for(vault_id: &[u8; 32], credential: &str) -> oneiron::Result<PrfInput> {
    let input = oneiron::world_keys::passkey_prf_input(vault_id, credential)?;
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

/// The roles a registry's escrow capsule is sealed for (CROSS-ARCH-0022
/// #ov-custody): the node's managed recipient and the owner's break-glass one.
const CAPSULE_ROLES: [&str; 2] = ["managed", "break-glass"];

/// One escrow capsule as a registry kept it ([`EscrowCapsuleReport`]),
/// checked and decoded: what `oneiron restore --capsule` opens a backup
/// with. None of it is secret.
pub(crate) struct CapsuleReport {
    pub(crate) vault_id: [u8; 32],
    pub(crate) commitment: [u8; 32],
    pub(crate) role: String,
    pub(crate) label: String,
    /// The E0 `VaultDek` envelope.
    pub(crate) capsule: Vec<u8>,
}

/// The escrow capsule report `text` holds. Refused: an unknown field, another
/// schema version or report type, a role the registry does not seal for, a
/// wrap id other than `escrow:<label>`, and a report id other than the
/// capsule's BLAKE3.
pub(crate) fn parse_capsule_report(text: &str) -> anyhow::Result<CapsuleReport> {
    let report: EscrowCapsuleReport = serde_json::from_str(text)
        .map_err(|error| anyhow::anyhow!("an escrow capsule report is JSON: {error}"))?;
    anyhow::ensure!(
        report.schema_version == ESCROW_REPORT_SCHEMA_VERSION,
        "the escrow capsule report is schema version {}; this host reads {}",
        report.schema_version,
        ESCROW_REPORT_SCHEMA_VERSION
    );
    anyhow::ensure!(
        report.report_type == ESCROW_REPORT_TYPE,
        "the report is not an escrow capsule report (`report_type` is not {ESCROW_REPORT_TYPE:?})"
    );
    let role = CAPSULE_ROLES
        .iter()
        .find(|role| **role == report.role)
        .ok_or_else(|| {
            anyhow::anyhow!("an escrow capsule report's role is managed or break-glass")
        })?;
    anyhow::ensure!(
        report
            .label
            .strip_prefix(role)
            .is_some_and(|rest| rest.starts_with('.')),
        "an escrow capsule report's label is `<role>.<recipient fingerprint>`"
    );
    anyhow::ensure!(
        report.wrap_id == format!("escrow:{}", report.label),
        "an escrow capsule report's wrap_id is `escrow:<label>`"
    );
    let id32 = |text: &str, what: &str| {
        unhex(text)
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or_else(|| anyhow::anyhow!("an escrow capsule report's {what} is 64 hex digits"))
    };
    let vault_id = id32(&report.vault_id, "vault_id")?;
    let commitment = id32(&report.key_commitment, "key_commitment")?;
    let capsule = unhex(&report.capsule)
        .filter(|capsule| !capsule.is_empty())
        .ok_or_else(|| anyhow::anyhow!("an escrow capsule report's capsule is hex"))?;
    anyhow::ensure!(
        blake3::hash(&capsule)
            .to_hex()
            .eq_ignore_ascii_case(&report.report_id),
        "an escrow capsule report's report_id is not its capsule's BLAKE3"
    );
    Ok(CapsuleReport {
        vault_id,
        commitment,
        role: (*role).to_owned(),
        label: report.label,
        capsule,
    })
}

/// An escrow recipient's secret half as given, the one door for the forms
/// `restore --capsule` reads: a 32-byte seed
/// ([`oneiron::world_keys::escrow_recipient`]), as `--unlock escrow` reads
/// it, or the key's own 96 bytes of seeds, ML-KEM-1024's 64 (`d ‖ z`) then
/// X25519's 32 (`HybridSecretKey::from_seeds`). Either is raw, hex or
/// base64url.
pub(crate) fn escrow_secret(raw: &[u8]) -> anyhow::Result<HybridSecretKey> {
    const SEEDS: usize = 96;
    let seeds = match raw.len() {
        SEEDS => Some(Zeroizing::new(raw.to_vec())),
        len if len == 2 * SEEDS => std::str::from_utf8(raw)
            .ok()
            .and_then(unhex)
            .map(Zeroizing::new),
        _ => std::str::from_utf8(raw)
            .ok()
            .and_then(unb64)
            .map(Zeroizing::new),
    };
    if let Some(seeds) = seeds.filter(|seeds| seeds.len() == SEEDS) {
        anyhow::ensure!(
            seeds.iter().any(|byte| *byte != 0),
            "an escrow recipient's seeds are not all zero"
        );
        let mut mlkem = Zeroizing::new([0u8; 64]);
        let mut x25519 = Zeroizing::new([0u8; 32]);
        mlkem.copy_from_slice(&seeds[..64]);
        x25519.copy_from_slice(&seeds[64..]);
        return Ok(HybridSecretKey::from_seeds(&mlkem, &x25519));
    }
    let seed = secret32(
        raw,
        "an escrow recipient's secret (a 32-byte seed, or 96 bytes of seeds)",
    )?;
    Ok(oneiron::world_keys::escrow_recipient(&seed)?)
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
