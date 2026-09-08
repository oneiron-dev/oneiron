//! Shared test fixtures for booking anti-abuse guard tests.

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::booking::EventTypeKey;
use oneiron::booking::anti_abuse::{
    BookingAntiAbuseOwnerConfig, BookingRequestFacts, apply_rule_amendment, booking_email_hash,
    booking_ip_hash, booking_session_hash, default_booking_anti_abuse_rows,
};
use oneiron::booking::config::{
    BOOKING_EVENT_TYPE_PREDICATE, BOOKING_EVENT_TYPE_SCHEMA_VERSION, BookingEventTypeClaimValue,
    DEFAULT_INTRO_DURATION_MIN, DEFAULT_MIN_NOTICE_SECS, EventTypeConfig, HostAvailabilityConfig,
    RoutingMode, WeeklyWallWindow, encode_event_type_claim_value,
};
use oneiron::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};

use crate::server::SyncServer;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const PAGE_BYTE: u8 = 0x61;

    pub(crate) const OTHER_PAGE_BYTE: u8 = 0x62;

    pub(crate) fn test_server() -> (tempfile::TempDir, Arc<SyncServer>) {
        let dir = tempfile::tempdir().expect("temp vault dir");
        let vault = Arc::new(
            oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).expect("open vault"),
        );
        let server = Arc::new(
            SyncServer::new(vault, crate::config::SyncServerConfig::default())
                .expect("sync server"),
        );
        (dir, server)
    }

    pub(crate) fn page() -> EntityId {
        EntityId::from_bytes([PAGE_BYTE; 16]).expect("page id")
    }

    pub(crate) fn other_page() -> EntityId {
        EntityId::from_bytes([OTHER_PAGE_BYTE; 16]).expect("other page id")
    }

    pub(crate) fn event() -> EventTypeKey {
        EventTypeKey("intro-call".to_owned())
    }

    pub(crate) fn nz16(value: u16) -> NonZeroU16 {
        match NonZeroU16::new(value) {
            Some(nz) => nz,
            None => panic!("fixture must be non-zero"),
        }
    }

    pub(crate) fn nz32(value: u32) -> NonZeroU32 {
        match NonZeroU32::new(value) {
            Some(nz) => nz,
            None => panic!("fixture must be non-zero"),
        }
    }

    pub(crate) fn nz64(value: u64) -> NonZeroU64 {
        match NonZeroU64::new(value) {
            Some(nz) => nz,
            None => panic!("fixture must be non-zero"),
        }
    }

    /// The ratified owner-supplied stack, mirroring the engine fixtures.
    pub(crate) fn owner_config() -> BookingAntiAbuseOwnerConfig {
        BookingAntiAbuseOwnerConfig {
            min_intake_chars: nz16(10),
            normal_notice_secs: nz64(86_400),
            high_value_notice_secs: nz64(172_800),
            min_submit_millis: nz64(1_500),
            slot_list_per_minute_per_ip: nz32(120),
            slot_list_cache_ttl_secs: nz64(45),
            book_per_minute_per_ip: nz32(10),
            max_active_future_per_email: 1,
            max_active_holds_per_session: 1,
            hold_per_minute_per_ip: nz32(30),
            tentative_confirm_ttl_secs: nz64(900),
        }
    }

    pub(crate) fn install_defaults(server: &SyncServer) {
        install_defaults_scoped(server, Some(event()));
    }

    pub(crate) fn install_live_booking_config(server: &SyncServer, event_type: EventTypeKey) {
        let config = BookingEventTypeClaimValue {
            schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION,
            page_ref: page(),
            config: EventTypeConfig {
                key: event_type,
                duration_min: DEFAULT_INTRO_DURATION_MIN,
                slot_step_min: 30,
                pre_buffer_min: 0,
                post_buffer_min: 0,
                min_notice_secs: DEFAULT_MIN_NOTICE_SECS,
                booking_window_secs: 86_400,
                daily_cap: None,
                weekly_cap: None,
                routing: RoutingMode::Either,
                hosts: vec![HostAvailabilityConfig {
                    host_ref: EntityId::from_bytes([0x63; 16]).expect("host fixture id"),
                    calendar_refs: vec![
                        EntityId::from_bytes([0x64; 16]).expect("calendar fixture id"),
                    ],
                    host_tz: "UTC".to_owned(),
                    working_hours: vec![WeeklyWallWindow {
                        weekday: 0,
                        start_minute: 0,
                        end_minute: 60,
                    }],
                    preferred_hours: Vec::new(),
                }],
                flex_windows: Vec::new(),
            },
        };
        let body = ClaimBody::new(
            BOOKING_EVENT_TYPE_PREDICATE,
            ClaimSubject::Entity(page()),
            encode_event_type_claim_value(&config).expect("config value"),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        server
            .vault
            .put_claim(
                &EntityId::from_bytes([0x65; 16]).expect("config fixture id"),
                &body,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
            )
            .expect("live booking config");
    }

    pub(crate) fn install_defaults_scoped(server: &SyncServer, event_type: Option<EventTypeKey>) {
        // The quarantine path mints its pending-review claim with the page
        // as the subject through the ordinary claim door, so the fixture
        // page exists the way a published booking page does.
        server
            .vault
            .put_entity(
                &page(),
                oneiron::registry::ENTITY_TYPE_EVENT,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"booking page fixture",
            )
            .expect("page entity");
        install_live_booking_config(server, event_type.clone().unwrap_or_else(event));
        let rows = default_booking_anti_abuse_rows(page(), event_type, &owner_config())
            .expect("seed rows");
        for row in rows {
            apply_rule_amendment(&server.vault, 0, row, None).expect("install row");
        }
    }

    pub(crate) fn facts() -> BookingRequestFacts {
        BookingRequestFacts {
            page_ref: page(),
            event_type: Some(event()),
            ip_hash: booking_ip_hash("198.51.100.23"),
            email_hash: Some(booking_email_hash("ada@example.org")),
            session_hash: Some(booking_session_hash("sess-fixture")),
            started_at_millis: 4_000_000,
            submitted_at_millis: 4_000_000 + 4_000,
            submission_fingerprint: [0xA5; 32],
            selected_slot_hash: [0xB1; 32],
            intake_content_hash: [0xC2; 32],
            honeypot_nonempty: false,
            intake_chars: 32,
            active_future_bookings_for_email: 0,
            active_holds_for_session: 0,
            email: None,
        }
    }
}
