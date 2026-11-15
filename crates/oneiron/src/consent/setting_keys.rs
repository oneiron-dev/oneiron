//! The setting keys `consent` declares (Setting stage 1): the crate's build script lists each row
//! in the setting catalogue.

use super::DisclosureOfferMode;
use crate::setting::Kind;

crate::setting::setting_keys! {
    /// The owner's disclosure-mode knob (OF-365): `always_ask` (the companion never offers a
    /// contact clearance on its own; the owner starts each), `auto` (it may offer one when it
    /// reads the room) or `always_yes` (the owner clears named trusted sets in advance; offers
    /// stay allowed). Auto unless the owner sets it. No mode moves the confirm surface: a new
    /// clearance lands only on the owner's own confirm or pre-clearance.
    pub(crate) OFFER_MODE: DisclosureOfferMode = "disclosure.offer_mode" {
        kind: Kind::new(DisclosureOfferMode::default),
    };
}
