//! Core half of `store::claim_lineage`: its store-layer items live in `oneiron_store::claim_lineage` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::claim_lineage::*;

use crate::error::{Error, Result};
use crate::write_envelope::claim_body::*;
use crate::write_envelope::claim_predicate::is_reserved_predicate;
use oneiron_contracts::claim::{ClaimLifecycleStatus, ClaimSource};
use rmpv::Value;

/// The ClaimOf weight a claim is born with: the initial-weight entry in its
/// scope map, else the ClaimOf default. `None` for an edge subject, which has
/// no ClaimOf edge. The candidate materializer and both machine-history fold
/// entry points read this one value, so the stored edge and signed replay
/// agree. An absent entry, or a scope that is not a map, is the default; a
/// duplicate entry, a value that is not a finite weight in 0..1, or an entry
/// on an edge subject is a fail-closed [`Error::InvalidClaimBody`].
pub(crate) fn claim_initial_claim_of_weight(body: &ClaimBody) -> Result<Option<f32>> {
    let entry = match &body.scope {
        Some(Value::Map(entries)) => {
            match single_map_value(entries, CLAIM_SCOPE_INITIAL_CLAIM_OF_WEIGHT_KEY) {
                MapValue::Missing => None,
                MapValue::Duplicate => {
                    return Err(Error::InvalidClaimBody("duplicate initial ClaimOf weight"));
                }
                MapValue::Present(value) => Some(
                    unit_interval_f32(value)
                        .ok_or(Error::InvalidClaimBody("malformed initial ClaimOf weight"))?,
                ),
            }
        }
        _ => None,
    };
    match (body.subject, entry) {
        (ClaimSubject::Entity(_), weight) => Ok(Some(
            weight.unwrap_or(crate::vault::CLAIM_OF_DEFAULT_WEIGHT),
        )),
        (ClaimSubject::Edge { .. }, None) => Ok(None),
        (ClaimSubject::Edge { .. }, Some(_)) => Err(Error::InvalidClaimBody(
            "initial ClaimOf weight requires an entity subject",
        )),
    }
}
