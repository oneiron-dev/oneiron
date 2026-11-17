//! The legal-hold vocabulary (OF-470, design B; ARCH-0038 #legal-hold,
//! BIZ-LEGAL-0004 §12, owner ruling 2026-10-17). Every field is an id, a
//! time or a typed code: the hold log holds no memory content and no free
//! text (C3).

use crate::entity_id::EntityId;

#[doc(hidden)]
pub use oneiron_verb_wire::deletion::legal_hold::types::{
    HoldCloneCapture, LegalHold, LegalHoldActorKind, LegalHoldEvent, LegalHoldEventKind,
    LegalHoldKind, LegalHoldReason, LegalHoldTarget,
};

/// How long a hold's log rows outlive the hold, in calendar months (C3: the
/// hold's life, then 24 months).
pub const LEGAL_HOLD_LOG_RETENTION_MONTHS: u32 = 24;

/// The owner's production of a standing customer hold's sealed copy
/// (`vault.legal_holds.produce`, PRODUCE = A): each capture's sealed frames
/// byte for byte, plus the hold's 32-byte seed sealed to the recipient's
/// public key. No plaintext leaves the engine, and nothing is re-encrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegalHoldProduction {
    /// The hold produced.
    pub hold_id: EntityId,
    /// This production's own id, bound into its sealed key.
    pub production_id: EntityId,
    /// The blake3 of the recipient public key's bytes.
    pub recipient_fingerprint: [u8; 32],
    /// The hold's seed, sealed to the recipient's public key.
    pub sealed_hold_key: Vec<u8>,
    /// The hold's captures, oldest first.
    pub captures: Vec<ProducedHoldCapture>,
}

/// One produced capture: its sealed frames byte for byte, so its
/// fingerprint equals the one the hold row and its `Placed` / `ScopeChanged`
/// event logged. The recipient opens the frames with the hold's key pair,
/// rebuilt from the production's sealed seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducedHoldCapture {
    /// The capture's id.
    pub capture: EntityId,
    /// The capture's fingerprint, as the hold row names it.
    pub fingerprint: [u8; 32],
    /// The capture file's bytes.
    pub frames: Vec<u8>,
}

/// A host order to hold records (C1). Placed only where Oneiron hosts the
/// bytes, through the host-only door.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostOrderHold {
    pub targets: Vec<LegalHoldTarget>,
    /// Opaque order reference; it stays in the host-only log.
    pub order_ref: String,
    /// The order's period end, as the host computed it (for example
    /// §2703(f) 90 days, an EU preservation order 60 days, 刑訴 197(3) 30).
    pub ends_at: u64,
    /// The end of any silence the order imposes (§2705(b), 刑訴 218(3),
    /// e-evidence Art. 5(7)); `None` tells the owner as usual.
    pub secret_until: Option<u64>,
    /// Opaque ref of the host operator placing it.
    pub placed_by: String,
    /// The law the order is made under, as an opaque ref (a statute or
    /// provision id). Its refusals name it.
    pub legal_basis_ref: Option<String>,
    /// Where that law binds, as an opaque code.
    pub jurisdiction: Option<String>,
    /// Who issued the order, as an opaque ref.
    pub issuing_authority_ref: Option<String>,
    /// The order's own terms also forbid using what it keeps (C6), recorded
    /// as the order's data; no vault path reads it; never set on a customer
    /// hold.
    pub requires_non_use: bool,
}

/// One legal-hold maintenance pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LegalHoldMaintenance {
    /// Host orders whose end date passed, now lifted.
    pub lapsed: u64,
    /// Log rows and released holds past their retention.
    pub expired: u64,
}
