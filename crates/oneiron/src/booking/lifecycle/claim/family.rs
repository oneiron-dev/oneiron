//! The `booking.*` claim family door, and the claim-class descriptor rows
//! the family ships.

use super::*;

/// Whether `predicate` belongs to the `booking.*` claim family.
///
/// The family is the UNION of its per-layer exact tables — the host
/// configuration predicate ONE-1823 owns, plus the four lifecycle predicates
/// this layer owns. It is deliberately a table union and never a `booking.`
/// prefix test: a prefix would silently adopt every future booking predicate
/// into whichever validator happened to be checked first.
///
/// It lives here rather than in `booking/mod.rs` because ONE-1816 asserts
/// mechanically that `mod.rs` defines nothing at all; `mod.rs` re-exports this.
#[must_use]
pub fn is_booking_family_claim_predicate(predicate: &str) -> bool {
    crate::booking::config::is_booking_claim_predicate(predicate)
        || is_booking_lifecycle_claim_predicate(predicate)
}

/// Validates one `booking.*` claim body against its own layer's validator.
///
/// This is the booking-family door: it routes on the exact predicate tables, so
/// a body whose predicate is not an exact member of ANY layer's table is
/// rejected here rather than accepted unvalidated.
///
/// # Errors
///
/// [`crate::Error::InvalidClaimBody`] naming the defect.
pub fn validate_booking_family_claim(body: &ClaimBody) -> crate::Result<()> {
    if crate::booking::config::is_booking_claim_predicate(&body.predicate) {
        return crate::booking::config::validate_event_type_claim(body);
    }
    if is_booking_lifecycle_claim_predicate(&body.predicate) {
        return validate_lifecycle_claim(body);
    }
    Err(crate::Error::InvalidClaimBody(
        "unknown booking claim predicate",
    ))
}

/// Every pure-data claim-class descriptor row the `booking.*` family ships.
///
/// The per-layer tables concatenated in family order: host configuration first,
/// then the lifecycle rows.
#[must_use]
pub fn booking_claim_class_descriptors() -> Vec<ClaimClassDescriptorRow> {
    let mut rows = crate::booking::config::claim_class_descriptors();
    rows.extend(claim_class_descriptors());
    rows
}

/// Descriptor rows for the lifecycle family, one per exact predicate.
///
/// All four are `recorded` and `projector_only`: the engine writes them from the
/// home-node transition as facts about a transaction that happened, and no human
/// or agent authors them by hand. No descriptor runtime or registry exists —
/// this is pure data, ready to register when one lands.
#[must_use]
pub fn claim_class_descriptors() -> Vec<ClaimClassDescriptorRow> {
    BOOKING_LIFECYCLE_PREDICATES
        .into_iter()
        .map(|predicate| ClaimClassDescriptorRow {
            predicate,
            write_class: "recorded",
            enforcement: false,
            restrictive: false,
            projector_only: true,
        })
        .collect()
}
