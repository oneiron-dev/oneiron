//! One best-effort conflict close in the caller's write transaction.

use super::{ClaimApprovalStatus, DreamerRunContext, Error, Value};
use crate::dreamer_consolidation::resources::ConsolidationFence;
use crate::{EntityId, Vault};

/// The run, fence and inputs of one close, with the caller's provenance and
/// the final words of its refusal log. Each landing owns a nested savepoint.
pub(crate) struct CloseMarkerRequest<'a> {
    /// The run that authors the close.
    pub(crate) run: &'a DreamerRunContext,
    /// The caller's fence, including the outputs this close relies on.
    pub(crate) fence: &'a ConsolidationFence,
    /// The open marker the close answers.
    pub(crate) marker: EntityId,
    /// Native's resolution value, wrapped by the close builder.
    pub(crate) resolution: Value,
    /// The outputs' cited evidence.
    pub(crate) evidence: &'a [EntityId],
    /// The caller's provenance for the close.
    pub(crate) provenance: Value,
    /// The same refusal message the caller used before this shared door.
    pub(crate) log_message: &'static str,
}

/// A fatal close error. `release_replacement` preserves the correction
/// caller's explicit fence cleanup on its three pre-existing error exits;
/// errors propagated by `?` keep their original cleanup path.
pub(crate) struct MarkerCloseError {
    pub(crate) error: Error,
    pub(crate) release_replacement: bool,
}

impl From<Error> for MarkerCloseError {
    fn from(error: Error) -> Self {
        Self {
            error,
            release_replacement: false,
        }
    }
}

/// Lands one close. `Some` is the committed approval (Auto answers the marker;
/// Proposed waits in review); `None` leaves it without writing. Domain and
/// gate refusals are logged and skipped. Only a store failure errors.
pub(crate) fn close_marker_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    request: &CloseMarkerRequest<'_>,
) -> std::result::Result<Option<ClaimApprovalStatus>, MarkerCloseError> {
    let marker = request.marker;
    let close = {
        let read_txn: &heed::RoTxn<'_> = txn;
        match crate::dreamer_consolidation::conflict_close_candidate_in_txn(
            vault,
            read_txn,
            request.run,
            marker,
            request.resolution.clone(),
            request.evidence.to_vec(),
        ) {
            Ok(close) => close,
            Err(error @ (Error::Gate(_) | Error::Claim(_) | Error::InvalidClaimBody(_))) => {
                tracing::warn!(reason = "no_close_candidate", error_kind = ?error.kind(), marker = %marker.to_hex(), "{}", request.log_message);
                return Ok(None);
            }
            Err(error) => {
                return Err(MarkerCloseError {
                    error,
                    release_replacement: true,
                });
            }
        }
    };
    // An earlier pass may already have left this close in the owner's
    // review, or the owner may have decided it since. Neither is re-authored.
    {
        let read_txn: &heed::RoTxn<'_> = txn;
        match crate::dreamer_consolidation::reviewed::reviewed_output_in_txn(
            vault, read_txn, &close,
        ) {
            Ok(true) => return Ok(None),
            Ok(false) => {}
            Err(error @ (Error::Gate(_) | Error::Claim(_) | Error::InvalidClaimBody(_))) => {
                tracing::warn!(reason = "reviewed_output_refused", error_kind = ?error.kind(), marker = %marker.to_hex(), "{}", request.log_message);
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        }
    }
    let mut savepoint = vault.store.env.nested_write_txn(txn).map_err(Error::from)?;
    let (prepared, claim_candidate) = {
        let read_txn: &heed::RoTxn<'_> = &savepoint;
        match super::prepare_promotion(
            vault,
            read_txn,
            request.run,
            close,
            None,
            &[],
            Some(request.provenance.clone()),
        ) {
            Ok(prepared) => prepared,
            Err(rejection) => {
                savepoint.abort();
                if rejection.gate.is_some() || rejection.claim_domain {
                    tracing::warn!(reason = "promotion_refused", error_kind = ?rejection.kind, marker = %marker.to_hex(), "{}", request.log_message);
                    return Ok(None);
                }
                return Err(MarkerCloseError {
                    error: Error::Io(std::io::Error::other(format!(
                        "close preparation failed: {:?}",
                        rejection.kind
                    ))),
                    release_replacement: true,
                });
            }
        }
    };
    if let Err(error) = super::land_prepared_promotion_in_txn(
        vault,
        request.run,
        &prepared,
        claim_candidate,
        Some(request.fence),
        false,
        &mut savepoint,
    ) {
        savepoint.abort();
        match error {
            error @ (Error::Gate(_) | Error::Claim(_) | Error::InvalidClaimBody(_)) => {
                tracing::warn!(reason = "promotion_refused", error_kind = ?error.kind(), marker = %marker.to_hex(), "{}", request.log_message);
                return Ok(None);
            }
            error => {
                return Err(MarkerCloseError {
                    error,
                    release_replacement: true,
                });
            }
        }
    }
    let stored = {
        let save_read: &heed::RoTxn<'_> = &savepoint;
        vault.get_claim_in_txn(save_read, &prepared.claim_id)?
    };
    let landed = stored.as_ref().and_then(|stored| {
        super::verify_landed_body(stored, &prepared.predicate, prepared.source).ok()
    });
    match landed {
        Some(approval @ (ClaimApprovalStatus::Auto | ClaimApprovalStatus::Proposed)) => {
            savepoint.commit().map_err(Error::from)?;
            Ok(Some(approval))
        }
        Some(other) => {
            savepoint.abort();
            tracing::warn!(reason = other.as_str(), marker = %marker.to_hex(), "{}", request.log_message);
            Ok(None)
        }
        None => {
            savepoint.abort();
            tracing::warn!(reason = "promotion_refused", marker = %marker.to_hex(), "{}", request.log_message);
            Ok(None)
        }
    }
}
