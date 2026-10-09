//! The owner rotates a secret (ARCH-0069 S6). Rotation is a vault update the
//! owner starts; the next lease materializes the new value, and exhaust built
//! with the old one reads as stale at its next publish or export check.

use base64::Engine as _;
use oneiron::consent::AuthenticatedOwner;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use super::{OwnerError, OwnerResult};

/// One rotation request. The value travels as standard base64 so binary
/// secrets survive JSON; it reaches the vault's custody plane and no receipt,
/// log or reply.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RotateSecret {
    /// The secret's custody name.
    pub(crate) name: String,
    pub(crate) value_base64: String,
}

impl std::fmt::Debug for RotateSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotateSecret")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// What the rotation changed: the generation moved, never the value.
#[derive(Debug, Serialize)]
pub(crate) struct Rotated {
    pub(crate) receipt_id: String,
    pub(crate) name: String,
    pub(crate) from_generation: u32,
    pub(crate) to_generation: u32,
    pub(crate) rotated_at: u64,
}

pub(crate) fn rotate(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    mut request: RotateSecret,
) -> OwnerResult<Rotated> {
    let decoded = base64::engine::general_purpose::STANDARD.decode(request.value_base64.as_bytes());
    request.value_base64.zeroize();
    let value = Zeroizing::new(
        decoded.map_err(|_| OwnerError::Invalid("value_base64 must be standard base64".into()))?,
    );
    if value.is_empty() {
        return Err(OwnerError::Invalid("a rotated secret needs a value".into()));
    }
    let receipt =
        vault.rotate_secret_as_owner(owner, &request.name, &value, vault.now_recorded_at())?;
    Ok(Rotated {
        receipt_id: receipt.receipt_id.to_hex(),
        name: receipt.secret_ref,
        from_generation: receipt.from_generation,
        to_generation: receipt.to_generation,
        rotated_at: receipt.rotated_at,
    })
}
