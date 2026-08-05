//! Calendar module home (CAL-00).
//!
//! Owns the `calendar.*` claim family and the single calendar error home. The
//! family is claims-on-EVENT: this layer allocates no entity type byte, no
//! `EdgeKind`, and no serialization profile change. Series, exception,
//! successor, passport, and outcome relations are all claim values.
//!
//! CAL-09 adds the read side on top of that family — [`query`] projects EVENTs
//! and [`freebusy`] projects busy-only occupancy — plus the optional inbound
//! [`safeguard`] hook CAL-02 calls before imported-claim admission.

pub mod claims;
pub mod freebusy;
pub mod query;
pub mod safeguard;

/// Single calendar error home. Uninhabited at CAL-00; later stack layers append variants.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CalendarError {}

pub use claims::{
    CALENDAR_CLAIM_PREDICATES, CalendarBusyTransparency, CalendarOrigin, CalendarPassportDirection,
    CalendarPassportPresence, CalendarPassportValue, CalendarSeriesExceptionValue,
    CalendarSeriesMasterValue, CalendarStatus, CalendarStatusBasis, CalendarStatusValue,
    CalendarSuccessorValue, CalendarTimeKind, CalendarTimeKindValue, ClaimClassDescriptorRow,
    claim_class_descriptors, is_calendar_claim_predicate,
};
pub use freebusy::{BusyInterval, BusyUnion, freebusy, freebusy_scoped};
pub use query::{
    CalendarEventView, CalendarRangeDto, CalendarRead, CalendarReadRequest, CalendarSearchRequest,
    CalendarSel, MAX_CALENDAR_SEARCH_LIMIT, read_event, read_event_scoped, search_events,
    search_events_scoped,
};
pub use safeguard::{
    CALENDAR_SAFEGUARD_CONFIG_KEY, CALENDAR_SAFEGUARD_REASON_NO_SCREENER, CalendarAdmissionRequest,
    CalendarBodyScreener, CalendarInboundBody, CalendarScreenVerdict, Screened, screen_then_claim,
};

#[cfg(test)]
pub(crate) mod test_support {
    //! Calendar EVENT fixtures shared by the CAL-09 unit tests.
    //!
    //! One builder, so every test writes its EVENTs through the same public
    //! doors (`put_entity` + `put_claim`) the real ingest path uses and no test
    //! grows a private notion of what a calendar EVENT is.

    use rmpv::Value;

    use super::claims::{
        CalendarBusyTransparency, PREDICATE_CALENDAR_ORIGIN, PREDICATE_CALENDAR_STATUS,
        PREDICATE_CALENDAR_TIME_KIND,
    };
    use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
    use crate::config::VaultConfig;
    use crate::entity_id::EntityId;
    use crate::registry::ENTITY_TYPE_EVENT;
    use crate::temporal::TimeRange;
    use crate::vault::Vault;

    /// Opens a temporary vault for calendar fixtures.
    pub(crate) fn open_calendar_vault() -> (tempfile::TempDir, Vault) {
        crate::test_util::open_test_vault_with(VaultConfig::default())
    }

    /// Encodes an EVENT body carrying the `name` field the EVENT profile pins.
    pub(crate) fn event_name_body(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        rmpv::encode::write_value(
            &mut out,
            &Value::Map(vec![(Value::from("name"), Value::from(name))]),
        )
        .expect("encode event body");
        out
    }

    /// One calendar EVENT fixture: an EVENT entity plus its `calendar.*` claims.
    pub(crate) struct CalendarEventFixture {
        seed: u8,
        name: String,
        occurred: TimeRange,
        transparency: CalendarBusyTransparency,
        cancelled: bool,
        approval: ClaimApprovalStatus,
    }

    impl CalendarEventFixture {
        pub(crate) fn new(seed: u8, name: &str, start: u64, end: u64) -> Self {
            Self {
                seed,
                name: name.to_owned(),
                occurred: TimeRange { start, end },
                transparency: CalendarBusyTransparency::Busy,
                cancelled: false,
                approval: ClaimApprovalStatus::Approved,
            }
        }

        pub(crate) fn transparency(mut self, transparency: CalendarBusyTransparency) -> Self {
            self.transparency = transparency;
            self
        }

        pub(crate) fn cancelled(mut self) -> Self {
            self.cancelled = true;
            self
        }

        /// Stores the family claims as `proposed` instead of `approved`, so the
        /// EVENT's calendar facts are present on disk but not surfaceable.
        pub(crate) fn proposed(mut self) -> Self {
            self.approval = ClaimApprovalStatus::Proposed;
            self
        }

        pub(crate) fn store(self, vault: &Vault) -> EntityId {
            let id = crate::test_util::entity(self.seed);
            vault
                .put_entity(
                    &id,
                    ENTITY_TYPE_EVENT,
                    self.occurred,
                    1,
                    &event_name_body(&self.name),
                )
                .expect("put calendar event");

            self.put_claim(vault, id, 0, PREDICATE_CALENDAR_ORIGIN, Value::from("imported"));
            self.put_claim(
                vault,
                id,
                1,
                PREDICATE_CALENDAR_TIME_KIND,
                Value::Map(vec![
                    (Value::from("kind"), Value::from("absolute")),
                    (
                        Value::from("busy_transparency"),
                        Value::from(self.transparency.as_str()),
                    ),
                ]),
            );
            if self.cancelled {
                self.put_claim(
                    vault,
                    id,
                    2,
                    PREDICATE_CALENDAR_STATUS,
                    Value::Map(vec![
                        (Value::from("status"), Value::from("cancelled")),
                        (Value::from("basis"), Value::from("imported_cancel")),
                        (Value::from("recorded_at"), Value::from(1_754_400_000_u64)),
                    ]),
                );
            }
            id
        }

        fn put_claim(
            &self,
            vault: &Vault,
            subject: EntityId,
            index: u8,
            predicate: &str,
            value: Value,
        ) {
            // `(0xC0, event seed, claim index)` keys every fixture claim
            // uniquely without colliding with any generic `entity(seed)` id.
            let mut bytes = [0xC0_u8; 16];
            bytes[1] = self.seed;
            bytes[2] = index;
            let claim_id = EntityId::from_bytes(bytes).expect("claim fixture id");
            vault
                .put_claim(
                    &claim_id,
                    &ClaimBody::new(
                        predicate,
                        ClaimSubject::Entity(subject),
                        value,
                        1.0,
                        self.approval,
                        ClaimLifecycleStatus::Active,
                    ),
                    TimeRange { start: 1, end: 1 },
                    1,
                )
                .expect("put calendar claim");
        }
    }
}
