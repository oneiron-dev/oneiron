//! Sync-gated import receipt codec, key consts, and status types.
use crate::side_table::key::SideKey;
use crate::window_key::WindowKey;
use crate::window_protocol::FederationAdmissionRole;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

pub const VAULT_IMPORT_RECEIPT_KEY_PREFIX: &str = "vault_import_receipt:v1:";

pub const VAULT_IMPORT_CONTENT_KEY_PREFIX: &str = "vault_import_content:v1:";

/// A 32-byte id spelled as 64 lower-case hex characters — this family's key
/// shape, shared by [`RECEIPT`], [`CONTENT`] and [`STAMPS`].
#[derive(Clone, Copy)]
pub struct Hex64(pub [u8; 32]);

impl SideKey for Hex64 {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(
            crate::batch::export::export_authority::hex_lower(&self.0).as_bytes(),
        );
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        if text.len() != 64 {
            return None;
        }
        let mut out = [0_u8; 32];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(text.get(index * 2..index * 2 + 2)?, 16).ok()?;
        }
        Some(Self(out))
    }
}

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
pub const REMOTE_ENTITY_METADATA_CORRUPT: &str = "entity metadata";

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
    /// BLAKE3 of the ordered per-window admitted-content carrier, including
    /// every destination key, its exact update bytes and admitted born-with text.
    pub admitted_update_digest: Option<[u8; 32]>,
    pub window_key: String,
    pub source: ForeignVaultImportSource,
    pub role: FederationAdmissionRole,
    pub status: VaultImportStageStatus,
    pub confirmed_by: Option<EntityId>,
    pub confirmed_at_secs: Option<u64>,
    pub failure: Option<VaultImportFailure>,
    /// The blake3 digest of the ordered per-window records of facet stamps a Pending receipt
    /// keeps (`VAULT_IMPORT_STAMPS`), the empty record included, which its confirmation
    /// checks before it holds them again. `None` on a Failed receipt and on
    /// one staged before the record existed.
    pub staged_stamps_digest: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedVaultImport {
    pub receipt: VaultImportStageReceipt,
    /// The encoded ordered per-window carrier bound by the receipt's digest.
    pub admitted_update: Vec<u8>,
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

pub fn source_bytes(s: &ForeignVaultImportSource) -> Result<Vec<u8>> {
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

pub fn receipt_key(id: &[u8; 32]) -> String {
    format!(
        "{VAULT_IMPORT_RECEIPT_KEY_PREFIX}{}",
        crate::batch::export::export_authority::hex_lower(id)
    )
}

pub fn content_key(id: &[u8; 32]) -> String {
    format!(
        "{VAULT_IMPORT_CONTENT_KEY_PREFIX}{}",
        crate::batch::export::export_authority::hex_lower(id)
    )
}

pub fn receipt_id(
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

pub fn encode_vault_import_receipt(r: &VaultImportStageReceipt) -> Result<Vec<u8>> {
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
                || r.staged_stamps_digest.is_some()
                || r.confirmed_by.is_some()
                || r.confirmed_at_secs.is_some()
                || r.failure.is_none()
            {
                return Err(Error::InvalidConfig("invalid failed receipt".into()));
            }
        }
    }
    let mut fields = vec![
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
    ];
    // Last and only when set, so a receipt staged before the record existed
    // encodes as it always did.
    if let Some(digest) = r.staged_stamps_digest {
        fields.push((
            rmpv::Value::from("stamps"),
            rmpv::Value::Binary(digest.to_vec()),
        ));
    }
    let v = rmpv::Value::Map(fields);
    let mut b = Vec::new();
    rmpv::encode::write_value(&mut b, &v)
        .map_err(|_| Error::InvariantViolation("receipt encode failed"))?;
    Ok(b)
}
