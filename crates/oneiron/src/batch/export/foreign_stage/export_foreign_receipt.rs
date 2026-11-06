//! Core half of `batch::export::foreign_stage::export_foreign_receipt`: its store-layer items live in `oneiron_store::batch::export::foreign_stage::export_foreign_receipt` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::batch::export::foreign_stage::export_foreign_receipt::*;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideKey, SideTable};
use crate::store::window_protocol::FederationAdmissionRole;
use crate::window_key::WindowKey;

/// Admitted foreign-import payload retained only while its receipt is
/// Pending. Key: hex64.
pub(super) const CONTENT: SideTable<Hex64, Vec<u8>, Raw> =
    SideTable::new(&side_table::VAULT_IMPORT_CONTENT);

/// Terminal/pending status receipt for one foreign vault-import artifact.
/// Key: hex64.
pub(super) const RECEIPT: SideTable<Hex64, Vec<u8>, Raw> =
    SideTable::new(&side_table::VAULT_IMPORT_RECEIPT);

/// The facet stamps an artifact staged ahead of their rows, kept exactly as
/// long as [`CONTENT`]. Key: hex64.
pub(super) const STAMPS: SideTable<Hex64, Vec<u8>, Raw> =
    SideTable::new(&side_table::VAULT_IMPORT_STAMPS);

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
    let stamps_named = f.iter().any(|(k, _)| k.as_str() == Some("stamps"));
    if f.len() != names.len() + usize::from(stamps_named) {
        return Err(Error::InvalidConfig("receipt shape".into()));
    };
    let mut seen = std::collections::HashSet::new();
    for (k, _) in &f {
        let Some(n) = k.as_str() else {
            return Err(Error::InvalidConfig("receipt key".into()));
        };
        if !(names.contains(&n) || n == "stamps") || !seen.insert(n) {
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
    let stamps = match get("stamps") {
        None => None,
        Some(rmpv::Value::Binary(b)) if b.len() == 32 => Some(
            b.clone()
                .try_into()
                .map_err(|_| Error::InvalidConfig("stamps".into()))?,
        ),
        _ => return Err(Error::InvalidConfig("stamps".into())),
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
        staged_stamps_digest: stamps,
    };
    if encode_vault_import_receipt(&r)? != raw {
        return Err(Error::InvalidConfig("receipt noncanonical".into()));
    };
    Ok(Some(r))
}
