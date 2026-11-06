//! Counterparty contact body keys and disclosure field profiles.

/// Pinned on-disk MessagePack key set for CounterpartyContactRecord bodies.
pub const COUNTERPARTY_CONTACT_BODY_KEYS: [&str; 11] = [
    "schema_version",
    "identity_ref",
    "counterparty",
    "first_touch",
    "status",
    "created_at",
    "updated_at",
    "revoked_at",
    "opt_out",
    "promo_consent",
    "notes",
];

pub const COUNTERPARTY_CONTACT_FIELDS_MINIMAL: &[&str] = &[
    "identity_ref",
    "counterparty",
    "first_touch",
    "status",
    "opt_out",
];

pub const COUNTERPARTY_CONTACT_FIELDS_STANDARD: &[&str] = &[
    "identity_ref",
    "counterparty",
    "first_touch",
    "status",
    "updated_at",
    "opt_out",
    "promo_consent",
];

pub const COUNTERPARTY_CONTACT_FIELDS_FULL: &[&str] = &COUNTERPARTY_CONTACT_BODY_KEYS;
