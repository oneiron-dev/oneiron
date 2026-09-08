//! Sync-gated import receipt codec, key consts, and status types.
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::sync::selector::FederationAdmissionRole;
use crate::sync::types::WindowKey;

pub const VAULT_IMPORT_RECEIPT_KEY_PREFIX: &str = "vault_import_receipt:v1:";

pub(super) const VAULT_IMPORT_CONTENT_KEY_PREFIX: &str = "vault_import_content:v1:";

/// Verdict text `sync::selector::admit_federated_entity_blob` raises when a
/// REMOTE entity blob is too short to carry its metadata header.
///
/// Matching the verdict text — rather than the bare `CorruptedIndex`
/// discriminant — is what keeps this scoped to the foreign artifact. Every
/// LOCAL store fault reachable from `admit_federated_window_update` raises a
/// DIFFERENT text (`authority_fold` uses "entity header", "type index row
/// without entity", "type index row kind mismatch", and the first-seen
/// sidecar constants), so local corruption stays retryable and only the
/// truncated remote blob becomes terminal.
pub(super) const REMOTE_ENTITY_METADATA_CORRUPT: &str = "entity metadata";

pub const VAULT_IMPORT_RECEIPT_SCHEMA_VERSION: u8 = 1;

pub const VAULT_IMPORT_RECEIPT_ID_DOMAIN: &[u8] = b"oneiron/vault-import-receipt/v1\0";

pub const MAX_FOREIGN_PLATFORM_NAME_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForeignVaultImportSource {
    AnotherPerson { peer_ref: EntityId },
    ForeignPlatform { platform: String },
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultImportStageStatus {
    Pending = 1,
    Confirmed = 2,
    Failed = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultImportFailure {
    AdmissionRejected = 1,
    ConfirmationMismatch = 2,
    DurableImportFailed = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultImportStageReceipt {
    pub receipt_id: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub remote_update_digest: [u8; 32],
    pub admitted_update_digest: Option<[u8; 32]>,
    pub window_key: String,
    pub source: ForeignVaultImportSource,
    pub role: FederationAdmissionRole,
    pub status: VaultImportStageStatus,
    pub confirmed_by: Option<EntityId>,
    pub confirmed_at_secs: Option<u64>,
    pub failure: Option<VaultImportFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedVaultImport {
    pub(crate) receipt: VaultImportStageReceipt,
    pub(crate) admitted_update: Vec<u8>,
}

impl StagedVaultImport {
    pub fn receipt(&self) -> &VaultImportStageReceipt {
        &self.receipt
    }
    pub fn receipt_id(&self) -> [u8; 32] {
        self.receipt.receipt_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultImportConfirmation {
    pub receipt_id: [u8; 32],
    pub actor: EntityId,
    pub confirmed_at_secs: u64,
}

pub(super) fn source_bytes(s: &ForeignVaultImportSource) -> Result<Vec<u8>> {
    match s {
        ForeignVaultImportSource::AnotherPerson { peer_ref } => {
            let mut x = vec![1];
            x.extend_from_slice(peer_ref.as_bytes());
            Ok(x)
        }
        ForeignVaultImportSource::ForeignPlatform { platform } => {
            if platform.is_empty()
                || platform != platform.trim()
                || platform.len() > MAX_FOREIGN_PLATFORM_NAME_BYTES
                || platform.chars().any(char::is_control)
            {
                return Err(Error::InvalidConfig("invalid foreign platform".into()));
            }
            let mut x = vec![2];
            x.extend_from_slice(platform.as_bytes());
            Ok(x)
        }
    }
}

pub(super) fn receipt_key(id: &[u8; 32]) -> String {
    format!("{VAULT_IMPORT_RECEIPT_KEY_PREFIX}{}", super::hex_lower(id))
}

pub(super) fn content_key(id: &[u8; 32]) -> String {
    format!("{VAULT_IMPORT_CONTENT_KEY_PREFIX}{}", super::hex_lower(id))
}

pub(super) fn receipt_id(
    manifest: &[u8; 32],
    source: &ForeignVaultImportSource,
    window: &str,
    remote: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut h = blake3::Hasher::new();
    h.update(VAULT_IMPORT_RECEIPT_ID_DOMAIN);
    h.update(manifest);
    h.update(&source_bytes(source)?);
    h.update(window.as_bytes());
    h.update(remote);
    Ok(*h.finalize().as_bytes())
}

fn optional_digest(v: Option<[u8; 32]>) -> rmpv::Value {
    v.map_or(rmpv::Value::Nil, |x| rmpv::Value::Binary(x.to_vec()))
}

pub(crate) fn encode_vault_import_receipt(r: &VaultImportStageReceipt) -> Result<Vec<u8>> {
    // Receipt state is part of the durable protocol, not merely display metadata.
    if WindowKey::try_new(r.window_key.clone()).is_none()
        || r.role != FederationAdmissionRole::Guest
        || r.receipt_id
            != receipt_id(
                &r.manifest_digest,
                &r.source,
                &r.window_key,
                &r.remote_update_digest,
            )?
    {
        return Err(Error::InvalidConfig("invalid receipt identity".into()));
    }
    match r.status {
        VaultImportStageStatus::Pending => {
            if r.admitted_update_digest.is_none()
                || r.confirmed_by.is_some()
                || r.confirmed_at_secs.is_some()
                || r.failure.is_some()
            {
                return Err(Error::InvalidConfig("invalid pending receipt".into()));
            }
        }
        VaultImportStageStatus::Confirmed => {
            if r.admitted_update_digest.is_none()
                || r.confirmed_by.is_none()
                || r.confirmed_at_secs.unwrap_or(0) == 0
                || r.failure.is_some()
            {
                return Err(Error::InvalidConfig("invalid confirmed receipt".into()));
            }
        }
        VaultImportStageStatus::Failed => {
            if r.admitted_update_digest.is_some()
                || r.confirmed_by.is_some()
                || r.confirmed_at_secs.is_some()
                || r.failure.is_none()
            {
                return Err(Error::InvalidConfig("invalid failed receipt".into()));
            }
        }
    }
    let v = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("v"),
            rmpv::Value::from(VAULT_IMPORT_RECEIPT_SCHEMA_VERSION),
        ),
        (
            rmpv::Value::from("id"),
            rmpv::Value::Binary(r.receipt_id.to_vec()),
        ),
        (
            rmpv::Value::from("manifest"),
            rmpv::Value::Binary(r.manifest_digest.to_vec()),
        ),
        (
            rmpv::Value::from("remote"),
            rmpv::Value::Binary(r.remote_update_digest.to_vec()),
        ),
        (
            rmpv::Value::from("admitted"),
            optional_digest(r.admitted_update_digest),
        ),
        (
            rmpv::Value::from("window"),
            rmpv::Value::from(r.window_key.clone()),
        ),
        (
            rmpv::Value::from("source"),
            rmpv::Value::Binary(source_bytes(&r.source)?),
        ),
        (rmpv::Value::from("role"), rmpv::Value::from(2u8)),
        (
            rmpv::Value::from("status"),
            rmpv::Value::from(r.status as u8),
        ),
        (
            rmpv::Value::from("confirmed_by"),
            r.confirmed_by.map_or(rmpv::Value::Nil, |x| {
                rmpv::Value::Binary(x.as_bytes().to_vec())
            }),
        ),
        (
            rmpv::Value::from("confirmed_at_secs"),
            r.confirmed_at_secs
                .map_or(rmpv::Value::Nil, rmpv::Value::from),
        ),
        (
            rmpv::Value::from("failure"),
            r.failure
                .map_or(rmpv::Value::Nil, |x| rmpv::Value::from(x as u8)),
        ),
    ]);
    let mut b = Vec::new();
    rmpv::encode::write_value(&mut b, &v)
        .map_err(|_| Error::InvariantViolation("receipt encode failed"))?;
    Ok(b)
}

pub fn vault_import_stage_receipt(
    vault: &Vault,
    id: &[u8; 32],
) -> Result<Option<VaultImportStageReceipt>> {
    let Some(raw) = vault.sync_state_get(&receipt_key(id))? else {
        return Ok(None);
    };
    let mut c = std::io::Cursor::new(&raw);
    let v = rmpv::decode::read_value(&mut c)
        .map_err(|_| Error::InvalidConfig("invalid receipt".into()))?;
    if c.position() != raw.len() as u64 {
        return Err(Error::InvalidConfig("trailing receipt bytes".into()));
    };
    let rmpv::Value::Map(f) = v else {
        return Err(Error::InvalidConfig("receipt is not map".into()));
    };
    let names = [
        "v",
        "id",
        "manifest",
        "remote",
        "admitted",
        "window",
        "source",
        "role",
        "status",
        "confirmed_by",
        "confirmed_at_secs",
        "failure",
    ];
    if f.len() != names.len() {
        return Err(Error::InvalidConfig("receipt shape".into()));
    };
    let mut seen = std::collections::HashSet::new();
    for (k, _) in &f {
        let Some(n) = k.as_str() else {
            return Err(Error::InvalidConfig("receipt key".into()));
        };
        if !names.contains(&n) || !seen.insert(n) {
            return Err(Error::InvalidConfig("receipt keys".into()));
        }
    }
    let get = |n| {
        f.iter()
            .find(|(k, _)| k.as_str() == Some(n))
            .map(|(_, v)| v)
    };
    let bin = |v: Option<&rmpv::Value>, n| -> Result<Vec<u8>> {
        match v {
            Some(rmpv::Value::Binary(b)) if b.len() == n => Ok(b.clone()),
            _ => Err(Error::InvalidConfig("receipt binary".into())),
        }
    };
    if !matches!(get("v"),Some(rmpv::Value::Integer(i)) if i.as_u64()==Some(1)) {
        return Err(Error::InvalidConfig("receipt version".into()));
    };
    let rid: [u8; 32] = bin(get("id"), 32)?
        .try_into()
        .map_err(|_| Error::InvalidConfig("receipt binary".into()))?;
    if &rid != id {
        return Err(Error::InvalidConfig("receipt id mismatch".into()));
    };
    let manifest: [u8; 32] = bin(get("manifest"), 32)?
        .try_into()
        .map_err(|_| Error::InvalidConfig("receipt binary".into()))?;
    let remote: [u8; 32] = bin(get("remote"), 32)?
        .try_into()
        .map_err(|_| Error::InvalidConfig("receipt binary".into()))?;
    let window = match get("window") {
        Some(rmpv::Value::String(x)) => x
            .as_str()
            .ok_or_else(|| Error::InvalidConfig("window utf8".into()))?
            .to_owned(),
        _ => return Err(Error::InvalidConfig("window type".into())),
    };
    if WindowKey::try_new(window.clone()).is_none() {
        return Err(Error::InvalidConfig("window invalid".into()));
    };
    let source_raw = bin(
        get("source"),
        get("source")
            .and_then(|v| {
                if let rmpv::Value::Binary(b) = v {
                    Some(b.len())
                } else {
                    None
                }
            })
            .unwrap_or(0),
    )?;
    let source = match source_raw.first() {
        Some(1) if source_raw.len() == 17 => ForeignVaultImportSource::AnotherPerson {
            peer_ref: EntityId::from_bytes(
                source_raw[1..]
                    .try_into()
                    .map_err(|_| Error::InvalidConfig("source invalid".into()))?,
            )?,
        },
        Some(2) => ForeignVaultImportSource::ForeignPlatform {
            platform: String::from_utf8(source_raw[1..].to_vec())
                .map_err(|_| Error::InvalidConfig("source utf8".into()))?,
        },
        _ => return Err(Error::InvalidConfig("source invalid".into())),
    };
    if source_bytes(&source)? != source_raw {
        return Err(Error::InvalidConfig("source noncanonical".into()));
    };
    if rid != receipt_id(&manifest, &source, &window, &remote)? {
        return Err(Error::InvalidConfig("receipt derivation".into()));
    };
    if !matches!(get("role"),Some(rmpv::Value::Integer(i))if i.as_u64()==Some(2)) {
        return Err(Error::InvalidConfig("role".into()));
    };
    let status = match get("status") {
        Some(rmpv::Value::Integer(i)) if i.as_u64() == Some(1) => VaultImportStageStatus::Pending,
        Some(rmpv::Value::Integer(i)) if i.as_u64() == Some(2) => VaultImportStageStatus::Confirmed,
        Some(rmpv::Value::Integer(i)) if i.as_u64() == Some(3) => VaultImportStageStatus::Failed,
        _ => return Err(Error::InvalidConfig("status".into())),
    };
    let admitted = match get("admitted") {
        Some(rmpv::Value::Nil) => None,
        Some(rmpv::Value::Binary(b)) if b.len() == 32 => Some(
            b.clone()
                .try_into()
                .map_err(|_| Error::InvalidConfig("admitted".into()))?,
        ),
        _ => return Err(Error::InvalidConfig("admitted".into())),
    };
    let by = match get("confirmed_by") {
        Some(rmpv::Value::Nil) => None,
        Some(rmpv::Value::Binary(b)) if b.len() == 16 => Some(EntityId::from_bytes(
            b.clone()
                .try_into()
                .map_err(|_| Error::InvalidConfig("confirmer".into()))?,
        )?),
        _ => return Err(Error::InvalidConfig("confirmer".into())),
    };
    let at = match get("confirmed_at_secs") {
        Some(rmpv::Value::Nil) => None,
        Some(rmpv::Value::Integer(i)) => Some(
            i.as_u64()
                .ok_or_else(|| Error::InvalidConfig("negative time".into()))?,
        ),
        _ => return Err(Error::InvalidConfig("time".into())),
    };
    let failure = match get("failure") {
        Some(rmpv::Value::Nil) => None,
        Some(rmpv::Value::Integer(i)) if i.as_u64() == Some(1) => {
            Some(VaultImportFailure::AdmissionRejected)
        }
        Some(rmpv::Value::Integer(i)) if i.as_u64() == Some(2) => {
            Some(VaultImportFailure::ConfirmationMismatch)
        }
        Some(rmpv::Value::Integer(i)) if i.as_u64() == Some(3) => {
            Some(VaultImportFailure::DurableImportFailed)
        }
        _ => return Err(Error::InvalidConfig("failure".into())),
    };
    let r = VaultImportStageReceipt {
        receipt_id: rid,
        manifest_digest: manifest,
        remote_update_digest: remote,
        admitted_update_digest: admitted,
        window_key: window,
        source,
        role: FederationAdmissionRole::Guest,
        status,
        confirmed_by: by,
        confirmed_at_secs: at,
        failure,
    };
    if encode_vault_import_receipt(&r)? != raw {
        return Err(Error::InvalidConfig("receipt noncanonical".into()));
    };
    Ok(Some(r))
}
