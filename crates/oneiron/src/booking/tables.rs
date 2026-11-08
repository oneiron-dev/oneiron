//! The side tables `booking` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Event-type configuration shortcut. Key: hash32.
    BOOKING_EVENT_TYPE_CONFIG_SHORTCUT: VaultMeta b"booking.event_type.v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Session soft-hold on a slot. Key: hash32.
    BOOKING_HOLD: VaultMeta b"booking.hold.v1:" VersionedNamed
        [restore: content] [family: unclassified] [tier: canonical];
    /// Booking lifecycle transition receipt. Key: hash32.
    BOOKING_LIFECYCLE_RECEIPT: VaultMeta b"booking.lifecycle.receipt.v1:" VersionedNamed
        [restore: content] [family: unclassified] [tier: canonical];
    /// Public booking page protected claim marker. Key: id16.
    BOOKING_PUBLIC_PAGE_PROTECTED_CLAIM: VaultMeta b"booking.public_page.protected_claim/" Raw
        [restore: refuse "public booking pages"] [family: unclassified] [tier: canonical];
    /// Public booking page token index. Key: string.
    BOOKING_PUBLIC_PAGE_TOKEN_INDEX: VaultMeta b"booking.public_page.token/" Raw
        [restore: refuse "public booking pages"] [family: unclassified] [tier: canonical];
    /// Booking token and checkout lease rows (digest domains keep them apart). Key: hash32.
    BOOKING_TOKEN: VaultMeta b"booking.token.v1:" VersionedNamed
        [restore: content] [family: unclassified] [tier: canonical];
    /// Booking anti-abuse rule proposals, rate counters, slot-list caches and quarantined
    /// submissions. Key: tag NUL + hash32 or id16 (proposal, rate, cache, submission).
    BOOKING_ANTI_ABUSE: VaultMeta b"booking:anti_abuse:v1:" Raw
        [restore: live]
        [family: unclassified]
        [tier: canonical, runtime for b"rate\0", runtime for b"cache\0"];
    /// Companion shortlist proposal. Key: bytes32.
    BOOKING_COMPANION_PROPOSAL: VaultMeta b"booking:companion_proposal:v1:" VersionedNamed
        [restore: content] [family: unclassified] [tier: canonical];
    /// Emergency effect attempt to checkpoint. Key: id16.
    EMERGENCY_EFFECT_LOOKUP: VaultMeta b"booking:emergency_effect:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Emergency reschedule instruction. Key: hex64.
    EMERGENCY_INSTRUCTION: VaultMeta b"booking:emergency_instruction:v1:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Emergency-affected booking checkpoint. Key: hex64.
    EMERGENCY_ITEM: VaultMeta b"booking:emergency_item:v1:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// EVENT to pending emergency checkpoint. Key: id16.
    EMERGENCY_PENDING_EVENT_LOOKUP: VaultMeta b"booking:emergency_pending_event:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Emergency reschedule plan. Key: hex64.
    EMERGENCY_PLAN: VaultMeta b"booking:emergency_plan:v1:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Plans under one instruction. Key: hash32 + id16.
    EMERGENCY_REQUEST_PLAN_INDEX: VaultMeta b"booking:emergency_request_plan:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
}
