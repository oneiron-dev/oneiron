//! Purposes of the calendar (`crates/oneiron/src/calendar`).

purposes! {}

legacy_purposes! {
    /// The digest of a calendar connector literal (`calendar::connectors::literal::digest`):
    /// plain BLAKE3 of the value's JSON encoding, no tag. A seat's literal scope and an
    /// outbox row's or a remote cursor's digest are sealed in the connector's custody
    /// envelope, and opening it refuses an envelope whose digests differ from the row's now.
    CONNECTOR_LITERAL = (Blake3, NotHashed, "oneiron.calendar.connector_literal.v1");
}
