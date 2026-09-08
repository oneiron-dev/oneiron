//! The one validated dispatch path: runtime stop, validation, then the sealed backend call.

use super::contract::{
    VaultReadAvailability, VaultReadClient, VaultReadRequest, VaultReadResponse,
};
use super::error::{VaultReadError, VaultReadResult};
use super::sealed;
use super::validate::validate_request;

/// Validation runs once, before any adapter code. Runtime peers stop here,
/// before validation, backend, or transport work.
pub(super) fn validate_and_dispatch<B>(
    backend: &B,
    request: VaultReadRequest,
) -> VaultReadResult<VaultReadResponse>
where
    B: sealed::Backend + ?Sized,
{
    let method = request.method();
    if matches!(
        method.availability(),
        VaultReadAvailability::RuntimeDeferred
    ) {
        return Err(VaultReadError::RuntimeUnavailable { method });
    }
    let validated = validate_request(request)?;
    backend.dispatch_validated(validated)
}

impl<T: sealed::Backend + ?Sized> VaultReadClient for T {}
