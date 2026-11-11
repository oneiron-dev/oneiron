//! [SESSION-OVERLAY-ROUTE-OVERLAY-PUBLIC]: `SessionWriteRoute::overlay` is
//! `pub` in the store, but the engine hands no route and no overlay to another
//! crate: both session accessors stay crate-private in core.

fn main() {
    let _ = oneiron::off_record::OffRecordSession::write_route;
    let _ = oneiron::off_record::OffRecordSession::overlay;
}
