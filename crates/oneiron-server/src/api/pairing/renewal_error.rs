//! FIX 4651: a credential renewal's named refusal over HTTP (CALLS row
//! "FIX 4651 renewal reason status").
//!
//! `Vault::renew_owner_device_slip` refuses with one of four content-free
//! reasons. [`renewal_refusal`] is the one mapping table from each reason to
//! its status: the credential's standing (K04) or the own-device Grant and
//! enrolled machine is a 403 for the owner-device scope, a stale or
//! unadmitted proof is a 401, and the lifetime is a 400 on `lifetime_secs`.
//! The message is the engine's reason itself. Any other refusal is not a
//! renewal reason and keeps the caller's own mapping.

use oneiron::authority::{
    RENEWAL_GRANT_AND_DEVICE, RENEWAL_K04, RENEWAL_LIFETIME, RENEWAL_PROOF_NOT_FRESH,
};
use oneiron::error::RecordError;

use crate::error::{ApiError, ApiErrorDetails};

/// The scope a renewal's authority refusals name: only an owner's own
/// paired device renews.
const OWNER_DEVICE_SCOPE: &str = "owner-device";

/// Policy hook (FIX 4651): the HTTP refusal for a renewal reason, or `None`
/// when `error` is no renewal refusal.
pub(super) fn renewal_refusal(error: &oneiron::Error) -> Option<ApiError> {
    let oneiron::Error::Record(RecordError::AuthorityRefused(reason)) = error else {
        return None;
    };
    let forbidden = |suggestion: &str| {
        ApiError::new(
            *reason,
            ApiErrorDetails::Forbidden {
                required_scope: Some(OWNER_DEVICE_SCOPE.to_owned()),
            },
            [suggestion],
        )
    };
    let refusal = match *reason {
        RENEWAL_K04 => forbidden(
            "Only an owner's own paired device credential renews; ask the owner for a fresh \
             credential or pair this device again.",
        ),
        RENEWAL_GRANT_AND_DEVICE => forbidden(
            "Renew from the enrolled device that holds this owner's current own-device Grant, \
             with its machine proof on the request.",
        ),
        RENEWAL_PROOF_NOT_FRESH => ApiError::new(
            *reason,
            ApiErrorDetails::Unauthorized,
            ["Retry with a fresh holder and machine proof; an expired or revoked credential \
              pairs again."],
        ),
        RENEWAL_LIFETIME => ApiError::new(
            *reason,
            ApiErrorDetails::BadRequest {
                field: Some("lifetime_secs".to_owned()),
            },
            ["Send a positive lifetime_secs within the original paired duration and the \
              owner's current ceiling, or omit it."],
        ),
        _ => return None,
    };
    Some(refusal)
}
