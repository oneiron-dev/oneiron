/// Same-origin prefix every advertised booking path is relative to.
pub(crate) const BOOKING_ROUTE_PREFIX: &str = "/api/booking";

/// Lease owner recorded on the attempt row while this node drains one booking
/// verb. Named for the surface so a queue inspection says which door enqueued.
pub(super) const BOOKING_LIFECYCLE_LEASE_OWNER: &str = "oneiron-server-booking-agent-api";

/// Domain tag for the page token digest. Domain separation is what stops a
/// page token from ever colliding with a lifecycle token digest computed over
/// the same bytes.
pub(super) const PAGE_TOKEN_DOMAIN: &[u8] = b"oneiron.booking.agent_api.page_token.v1\0";

/// Domain tag for the visitor session key material.
pub(super) const SESSION_KEY_DOMAIN: &[u8] = b"oneiron.booking.agent_api.session.v1\0";

/// Domain tag for the canonical selected-slot hash carried in admission facts.
pub(super) const SELECTED_SLOT_DOMAIN: &[u8] = b"oneiron.booking.agent_api.selected_slot.v1\0";

/// Domain tag for the canonical intake hash carried in admission facts.
pub(super) const INTAKE_DOMAIN: &[u8] = b"oneiron.booking.agent_api.intake.v1\0";

/// Domain tag for the deterministic booker-contact subject derived from a
/// confirmed email address.
pub(super) const BOOKER_CONTACT_DOMAIN: &[u8] = b"oneiron.booking.agent_api.booker_contact.v1\0";

/// A page token is the lowercase hex of this many digest bytes.
pub(super) const PAGE_TOKEN_BYTES: usize = 16;

/// Prefix every page token carries.
///
/// Load-bearing, not decoration: without it a 32-character hex token would be
/// SHAPED like an entity id, and a reviewer — or a future handler — could
/// mistake one for the other. With it, a page token cannot be parsed as an
/// `EntityId` and an `EntityId` cannot be presented as a page token.
pub(super) const PAGE_TOKEN_PREFIX: &str = "bkp_";

/// Bound on the opaque per-session reference a caller may supply. It matches
/// the bound ONE-1816's front applies to the same field, so a reference this
/// surface admits is one the constraint front could also carry.
pub(super) const MAX_SESSION_REF_BYTES: usize = 120;

/// Bound on the booker email a confirm may carry.
pub(super) const MAX_BOOKER_EMAIL_BYTES: usize = 254;

/// Bound on one intake answer's field key.
pub(super) const MAX_INTAKE_FIELD_KEY_BYTES: usize = 64;

/// Bound on one intake answer's value.
pub(super) const MAX_INTAKE_VALUE_BYTES: usize = 4096;

/// Bound on how many intake answers one confirm may carry.
pub(super) const MAX_INTAKE_ANSWERS: usize = 32;

/// Bound on a caller-supplied idempotency key. The lifecycle applies its own
/// bound too; this one fails the request before a verb is ever built.
pub(super) const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
