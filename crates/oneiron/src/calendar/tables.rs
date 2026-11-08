//! The side tables `calendar` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Calendar connector write-outbox rows and remote object cursors. Key: `row:` or `obj:` +
    /// bytes32.
    /// Owner-installed CalDAV seats, cursors and kill switches. Key: seat name.
    CALENDAR_CONNECTOR_SEAT: VaultMeta b"calendar.connector-seat.v1:" Named;
    CALENDAR_CONNECTOR_WRITE: VaultMeta b"calendar.connector-write.v1:" LegacyJson Authored [accepts: crate::calendar::calendar_connector_write_accepts_masked];
    /// Owner-installed ICS feed configuration and last public completion. Key: system name.
    CALENDAR_ICS_FEED_CONFIG: VaultMeta b"calendar.ics-feed-config.v1:" Named;
    /// Per-feed poll cursor. Key: bytes32.
    CALENDAR_ICS_FEED_CURSOR: VaultMeta b"calendar.ics-feed.v1:" LegacyJson Authored [accepts: crate::calendar::calendar_ics_feed_cursor_accepts_masked];
    /// UID-to-EVENT lookup cache. Key: bytes32.
    /// Host-installed iMIP submission endpoint and custody name. Key: ().
    CALENDAR_IMIP_TRANSPORT: VaultMeta b"calendar.imip-transport.v1" Named;
    /// FIX 12004: one meeting card delivered to the owners' INBOX, a prep pack or a check-in with
    /// its one morning re-ask, holding the lens as delivered. Key: id16(EVENT) + string (kind).
    CALENDAR_INBOX_CARD: VaultMeta b"calendar.inbox-card.v1:" Named Admitted;
    CALENDAR_PASSPORT_UID_INDEX: VaultMeta b"calendar.passport.v1:" Raw;
    /// Marker that a derived EVENT's source was erased. Key: id16.
    CALENDAR_INVALIDATED_EVENT: VaultMeta b"calendar_invalid:v1:" Raw;
}
