//! CRM pack engine-side registration home.
//!
//! This module owns exactly three things: the CRM pack's stable id, the
//! CAMPAIGN short-id namespace, and the bootstrap helper that hands a
//! runtime-assigned type byte to the existing dynamic-registration API.
//!
//! It deliberately owns NO type byte. Byte-space v3 assigns CAMPAIGN's byte at
//! registration time from the `Crm` band; a static constant here (or a
//! `registry.rs` row) would re-introduce the compile-time allocation this pack
//! exists to avoid. `companion.rs` is the module-layout precedent only — its
//! `ENTITY_TYPE_COMPANION_REGISTER` static-byte style is explicitly not copied.
//!
//! Ratified separation law: CAMPAIGN is an entity, the cohort is claims, and a
//! campaign never stores or owns a member list. This module mints the
//! structural kind and stops there.

use crate::Vault;
use crate::error::Result;
use crate::registry::{StructuralKindRegistration, TypeByteBand};

/// The CRM pack's claim families: `campaign.member`, `crm.fit`, `crm.stage`,
/// and the CA-owned `comm.do_not_contact` / `comm.bounce` /
/// `comm.jurisdiction` predicates.
pub mod claims;

/// Stable short-id namespace for CAMPAIGN entities.
///
/// Two lowercase ASCII letters per the short-id convention; it names CAMPAIGN,
/// not the CRM pack as a whole, and is collision-vetted by the registration API
/// against both static and already-registered runtime prefixes. This is a
/// namespace token, not an entity-type byte.
pub const CAMPAIGN_SHORT_ID_PREFIX: &str = "ca";

/// Pack provenance persisted in the vault-scoped structural-kind registration.
pub const CRM_PACK_ID: &str = "oneiron-crm";

/// Registers the CAMPAIGN structural kind for a NEW vault.
///
/// `assigned_type_byte` comes from the byte-space-v3 registration flow run by
/// the vault/pack initializer; this module never chooses, infers, or hard-codes
/// a byte. The underlying `register_structural_kind` is intentionally strict and
/// non-idempotent for duplicate bytes, so the contract is "register once while
/// initializing a new vault, read the persisted registration on reopen" — never
/// "register on every open". A reopened vault recovers the row through
/// [`Vault::structural_kind_registration`].
///
/// # Errors
///
/// Propagates the existing registration errors unchanged: a byte outside the
/// `Crm` band yields `StructuralKindBandViolation`, and a taken byte or prefix
/// yields `StructuralKindTypeByteCollision` / `StructuralKindPrefixCollision`.
/// CAMPAIGN adds no registration failure mode of its own.
pub fn register_campaign_kind(
    vault: &Vault,
    assigned_type_byte: u8,
) -> Result<StructuralKindRegistration> {
    vault.register_structural_kind(
        assigned_type_byte,
        CAMPAIGN_SHORT_ID_PREFIX,
        TypeByteBand::Crm,
        CRM_PACK_ID,
    )
}

#[cfg(test)]
mod tests;
