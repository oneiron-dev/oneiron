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
use crate::error::{Error, Result};
use crate::registry::{
    StructuralKindRegistration, TYPE_BYTE_BAND_CRM_END, TYPE_BYTE_BAND_CRM_START, TypeByteBand,
};

/// The CRM pack's claim families: `campaign.member`, `crm.fit`, `crm.stage`,
/// and the CA-owned `comm.do_not_contact` / `comm.bounce` /
/// `comm.jurisdiction` predicates.
pub mod claims;

/// CA-03's leader-only enrollment consequence writer: home-node designation,
/// the `campaign.enrollment.macro` attempt kind, and the membership/outbound
/// legs that turn a detected SAVED_QUERY transition into durable effects.
pub mod enrollment;

/// CA-06's compliance pack: the versioned, vault-resident legal rule rows, the
/// hydrated-evidence dispatch evaluator the external-effect gate enforces, and
/// the tighten-auto / loosen-owner-stamp amendment transaction. Law lives in
/// `compliance/seed_v1.json` as data; this module never spells a jurisdiction's
/// rule in Rust.
pub mod compliance;

/// CA-05's send hygiene: the one-transaction bounce/unsubscribe suppression
/// door, the deterministic RFC 8058 `List-Unsubscribe` headers folded into the
/// frozen outbound payload, and the sticky-sender binding. Sender health itself
/// stays in `identity_reputation.rs`; this module wires the campaign webhook
/// into it rather than growing a second reputation model.
pub mod send_hygiene;

/// CA-04's stage-ladder machinery: the pure ladder schema, coded-reply routing,
/// warm/cold lane selection, the single projector that writes `crm.stage`
/// through CA-01's transition door, read-side calendar-outcome consumption, and
/// snooze-with-wake re-entry. Mechanism only — ONE-1779 supplies the preset
/// content that instantiates a ladder, and no stage name is spelled here.
pub mod stage;

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

/// Every structural kind the CRM pack mints, in registration order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrmPackRegistration {
    /// CAMPAIGN's vault-scoped registration.
    pub campaign: StructuralKindRegistration,
    /// SAVED_QUERY's vault-scoped registration.
    pub saved_query: StructuralKindRegistration,
}

/// Registers the whole CRM pack against one vault.
///
/// The pack's kinds are registered from ONE entry point so a host cannot be
/// left with half a pack: a vault carrying CAMPAIGN but not SAVED_QUERY would
/// let a cohort exist with no way to name the query that derived it. Both bytes
/// are caller-assigned from the `Crm` band — this module still owns no byte.
///
/// Two properties make the guarantee real, because
/// [`Vault::register_structural_kind`] commits per call and cannot be composed
/// into one transaction from here:
///
/// * **Both slots are vetted before either is written.** A bad SAVED_QUERY byte
///   is rejected before CAMPAIGN becomes durable, so the ordinary
///   misconfiguration never half-installs anything.
/// * **The call is resumable.** A slot already registered to exactly this
///   pack's kind is reused instead of colliding with itself, so re-running the
///   same whole-pack call after any partial failure converges instead of
///   failing forever on the registration it already made.
///
/// # Errors
///
/// Propagates [`Vault::register_structural_kind`] errors unchanged: band
/// violations, byte collisions, and prefix collisions all keep their existing
/// identities. Two equal bytes are a byte collision.
pub fn register_crm_pack(
    vault: &Vault,
    campaign_type_byte: u8,
    saved_query_type_byte: u8,
) -> Result<CrmPackRegistration> {
    if campaign_type_byte == saved_query_type_byte {
        return Err(Error::StructuralKindTypeByteCollision(campaign_type_byte));
    }
    vet_pack_slot(vault, campaign_type_byte, CAMPAIGN_SHORT_ID_PREFIX)?;
    vet_pack_slot(
        vault,
        saved_query_type_byte,
        crate::saved_query::SAVED_QUERY_SHORT_ID_PREFIX,
    )?;
    Ok(CrmPackRegistration {
        campaign: register_pack_slot(
            vault,
            campaign_type_byte,
            CAMPAIGN_SHORT_ID_PREFIX,
            |byte| register_campaign_kind(vault, byte),
        )?,
        saved_query: register_pack_slot(
            vault,
            saved_query_type_byte,
            crate::saved_query::SAVED_QUERY_SHORT_ID_PREFIX,
            |byte| crate::saved_query::register_saved_query_kind(vault, byte),
        )?,
    })
}

/// Rejects a slot that cannot possibly register, BEFORE any slot is written.
///
/// Deliberately narrow: it checks the band this pack is confined to and a byte
/// already held by something that is not this slot. Every other rejection stays
/// where it belongs — inside the registrar.
fn vet_pack_slot(vault: &Vault, type_byte: u8, prefix: &str) -> Result<()> {
    if !(TYPE_BYTE_BAND_CRM_START..=TYPE_BYTE_BAND_CRM_END).contains(&type_byte) {
        return Err(Error::StructuralKindBandViolation {
            type_byte,
            declared_band: TypeByteBand::Crm,
            actual_band: crate::registry::band_of(type_byte),
            reason: "type byte is outside the declared band",
        });
    }
    match vault.structural_kind_registration(type_byte) {
        Some(existing) if !slot_matches(&existing, type_byte, prefix) => {
            Err(Error::StructuralKindTypeByteCollision(type_byte))
        }
        _ => Ok(()),
    }
}

/// Registers a slot, or returns the identical registration already present.
fn register_pack_slot(
    vault: &Vault,
    type_byte: u8,
    prefix: &str,
    register: impl FnOnce(u8) -> Result<StructuralKindRegistration>,
) -> Result<StructuralKindRegistration> {
    match vault.structural_kind_registration(type_byte) {
        Some(existing) if slot_matches(&existing, type_byte, prefix) => Ok(existing),
        _ => register(type_byte),
    }
}

fn slot_matches(existing: &StructuralKindRegistration, type_byte: u8, prefix: &str) -> bool {
    existing.type_byte == type_byte
        && existing.short_id_prefix == prefix
        && existing.band == TypeByteBand::Crm
        && existing.pack == CRM_PACK_ID
}

#[cfg(test)]
mod tests;
