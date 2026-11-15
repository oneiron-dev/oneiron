//! The connector slate drafter's owner Setting keys (DESIGN 15-setting-primitive; restriction
//! census C46, Engine RULING RESTRICTION-WAVE-6-CANON-ROWS 16 Nov 03:35, C46 = A): rows the
//! setting catalogue reads from this file.

use crate::setting::{Kind, lower_is_tighter};

/// Off: drafts pre-fill `always ask` or `never allow` only, as ARCH-0072 says.
fn drafts_never_offer() -> bool {
    false
}

crate::setting::setting_keys! {
    /// Whether a connector's admission and drift drafts may pre-fill `always allow` (off by
    /// default). On, the drafter pre-fills it on a tool row only where the owner's past rulings
    /// show he chose `always allow` for every kind of call the tool makes, on at least two
    /// connectors and on more than half of those he ruled; tighter evidence still wins, and the
    /// elicitation row still starts at `auto`. A draft grants nothing: the slate is shown before
    /// anything is granted, and only the owner's stamp accepts the row (ARCH-0072). Turning the
    /// key off stops new such drafts; it does not change a slate already drafted. On is the
    /// looser value: only the owner sets it, and an agent's change waits on the owner's answer.
    pub(crate) DRAFTS_OFFER_ALWAYS_ALLOW: bool = "connectors.slate.drafts_offer_always_allow" {
        kind: Kind::new(drafts_never_offer)
            .strictest(drafts_never_offer)
            .tighter(lower_is_tighter::<bool>),
    };
}
