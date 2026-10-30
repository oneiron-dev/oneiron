//! The owner's import of one export secret supplement on the recipient
//! machine his export named (FIX 11846, 12068): shared by `POST
//! /v1/owner/secrets/export-supplements/import` and `oneiron secrets
//! import-supplement`. It takes the supplement read's `request` and `sealed`
//! as `GET /v1/core/export-secret-supplements/{request}` returns them, opens
//! the sealed copy on this install and restores its secret through the
//! archive import's custody restore. The value never leaves the engine: the
//! answer names only what the import did.

use base64::Engine as _;
use oneiron::authority::{ActSurface, SecretSupplementImport};
use oneiron::consent::AuthenticatedOwner;
use serde::Serialize;

use super::{OwnerError, OwnerResult};

/// What the import of one supplement did.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(crate) struct SupplementImported {
    /// The export secret request, as 64 hex.
    request: String,
    outcome: SecretSupplementImport,
}

/// Opens `sealed`, the holder's copy as standard base64, of the export
/// secret request `request` (64 hex) for `owner`, here, and imports its
/// secret, his act made from `surface` (audit only). A copy sealed to
/// another machine, or not the one its holder's signed result names, opens
/// nowhere but there. An import that restores the secret, or finds it here
/// the same, marks the request imported, so no install relays its copy any
/// more (FIX 12062).
pub(crate) fn import(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    request: &str,
    sealed: &str,
) -> OwnerResult<SupplementImported> {
    let request = blake3::Hash::from_hex(request)
        .map_err(|_| OwnerError::Invalid("request must be a 64-hex authority entry".to_owned()))?;
    let sealed = base64::engine::general_purpose::STANDARD
        .decode(sealed)
        .map_err(|_| {
            OwnerError::Invalid(
                "sealed must be standard base64, as the supplement read returns it".to_owned(),
            )
        })?;
    let opened = vault.open_export_secret_supplement(owner, *request.as_bytes(), &sealed)?;
    let outcome = vault.import_secret_supplement(owner, surface, &opened)?;
    Ok(SupplementImported {
        request: request.to_hex().to_string(),
        outcome,
    })
}
