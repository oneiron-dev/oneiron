//! The federation module's owner Setting keys (DESIGN 15-setting-primitive): rows the setting
//! catalogue reads from this file.

use super::{MAX_DELEGATE_TTL_SECS, SHARED_INVITATION_TTL_SECS};
use crate::setting::{Kind, lower_is_tighter};

/// Fourteen days: an invitation's lifetime until the owner sets another.
fn fourteen_days() -> u64 {
    SHARED_INVITATION_TTL_SECS
}

/// Ninety days: the Delegate cap until the owner sets another.
fn ninety_days() -> u64 {
    MAX_DELEGATE_TTL_SECS
}

crate::setting::setting_keys! {
    /// How long a shared vault invitation stays open, in seconds on the store clock from its
    /// issue. The `add_member` effect reads it in its own writer; an invitation already issued
    /// keeps the expiry it was given. Fourteen days until the owner sets another; a value
    /// under one second reads as one second, and a row that does not decode reads as fourteen
    /// days. A longer lifetime is the looser value, so only the owner raises it; an agent's
    /// change waits on the owner's answer.
    pub(crate) SHARED_INVITATION_TTL: u64 = "federation.invitation.ttl_secs" {
        kind: Kind::new(fourteen_days).strictest(fourteen_days).tighter(lower_is_tighter::<u64>),
    };
    /// The longest lifetime a one-hop Delegate grant takes, in seconds past its mint. The
    /// delegate doors read it in their own writer and refuse a later expiry; a Delegate
    /// already minted keeps its expiry. Ninety days until the owner sets another; a value
    /// under one second reads as one second, and a row that does not decode reads as ninety
    /// days. A longer cap is the looser value, so only the owner raises it; an agent's change
    /// waits on the owner's answer.
    pub(crate) DELEGATE_MAX_TTL: u64 = "federation.delegate.max_ttl_secs" {
        kind: Kind::new(ninety_days).strictest(ninety_days).tighter(lower_is_tighter::<u64>),
    };
}
