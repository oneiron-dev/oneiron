//! The setting keys `consent` declares (Setting stage 1): the crate's build script lists each row
//! in the setting catalogue.

use super::DisclosureOfferMode;
use super::widen::WidenOpenSecs;
use crate::setting::{Kind, lower_is_tighter};

/// Member proposals stay off unless the owner turns them on.
const fn member_proposals_off() -> bool {
    false
}

crate::setting::setting_keys! {
    /// The owner's disclosure-mode knob (OF-365): `always_ask` (the companion never offers a
    /// contact clearance on its own; the owner starts each), `auto` (it may offer one when it
    /// reads the room) or `always_yes` (the owner clears named trusted sets in advance; offers
    /// stay allowed). Auto unless the owner sets it. No mode moves the confirm surface: a new
    /// clearance lands only on the owner's own confirm or pre-clearance.
    pub(crate) OFFER_MODE: DisclosureOfferMode = "disclosure.offer_mode" {
        kind: Kind::new(DisclosureOfferMode::default),
    };
    /// How long, in seconds, a widen proposal may stay open for the owner's answer: an action,
    /// disclosure or auto-confirm widening, a contact-disclosure offer, and two filings that stay
    /// open this long: the engine's own offer for a person's first entry into a room, and a grant
    /// a non-owner's `vault.shape.apply` files for the owner. One hour unless
    /// the owner sets it, at most thirty days; a filing with a later expiry is refused. A shorter
    /// window leaves every open proposal its own expiry. Only the owner's answer settles a
    /// proposal, however long it stays open.
    pub(crate) WIDEN_MAX_OPEN_SECS: WidenOpenSecs = "consent.widen.max_open_secs" {
        kind: Kind::new(WidenOpenSecs::one_hour).tighter(lower_is_tighter::<WidenOpenSecs>),
    };
    /// Whether a member may file a widen proposal: a live human credential in its holder's own
    /// hands that lists the proposal's verb (`propose_action_widen`, `propose_disclosure_widen`
    /// or `propose_auto_confirm_widen`) files one of those three widenings as an agent's does.
    /// The typed contact-disclosure offer (`vault.disclosure.offer`) stays an agent's. Off unless
    /// the owner turns it on. A proposal confers nothing: only the owner's own answer settles it,
    /// and the credential it was filed under never does.
    pub(crate) WIDEN_MEMBER_PROPOSALS: bool = "consent.widen.member_proposals" {
        kind: Kind::new(member_proposals_off)
            .strictest(member_proposals_off)
            .tighter(lower_is_tighter::<bool>),
    };
}
