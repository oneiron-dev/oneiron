//! The persona snapshot's owner Setting key (owner principle, 16 Nov 00:44: a restriction that is
//! not a correctness fix ships as a good default plus an owner opt-out). The default is today's
//! clamp. The owner changes the value; an agent's change, either way, waits on the owner's
//! approval.
//!
//! Direction: the key decides how much of the owner's own data a card may carry, so letting
//! more in is looser. A row that does not decode reads as false, today's clamp.

use crate::setting::{Kind, lower_is_tighter};

/// Restricted-band claims stay out: today's clamp, and the strictest value.
fn kept_out() -> bool {
    false
}

crate::setting::setting_keys! {
    /// Whether a restricted-band claim (sensitivity band 3 or higher) about a live owner of the
    /// vault may enter a persona snapshot compile whose subject is that owner (default false: it
    /// never enters). True is looser. A card about anyone else keeps the clamp, and a claim whose
    /// band does not read, or that is Tier A by an off-record stretch, its type, its predicate or
    /// the owner's own mark, never enters whatever this says. The audience's scoped read and the
    /// preview's strike list still decide each row (compile_persona_snapshot).
    pub(crate) PERSONA_SNAPSHOT_INCLUDE_RESTRICTED_BAND: bool =
        "persona_snapshot.compile.include_restricted_band" {
        kind: Kind::new(kept_out)
            .strictest(kept_out)
            .tighter(lower_is_tighter::<bool>),
    };
}
