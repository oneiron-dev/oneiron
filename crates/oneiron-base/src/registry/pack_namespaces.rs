//! Stable pack provenance and structural-kind short-id namespaces.

/// Stable short-id namespace for CAMPAIGN entities.
///
/// Two lowercase ASCII letters per the short-id convention; it names CAMPAIGN,
/// not the CRM pack as a whole, and is collision-vetted by the registration API
/// against both static and already-registered runtime prefixes. This is a
/// namespace token, not an entity-type byte.
pub const CAMPAIGN_SHORT_ID_PREFIX: &str = "ca";

/// Pack provenance persisted in the vault-scoped structural-kind registration.
pub const CRM_PACK_ID: &str = "oneiron-crm";

/// Stable short-id namespace for SAVED_QUERY entities. Two lowercase ASCII
/// letters per the short-id convention; a namespace token, never a type byte.
pub const SAVED_QUERY_SHORT_ID_PREFIX: &str = "sq";
