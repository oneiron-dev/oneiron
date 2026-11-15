//! The resident ledger's catalogue key (DESIGN 15-setting-primitive, stage 4): the owner's share
//! of the host-paid allocation for each resident. What the residents' calls spent stays the
//! ledger's (`BUDGET_RESIDENT_USAGE`).

use super::resident::{announce_share_change, record_share_change};
use crate::check_in::ActClass;
use crate::llm::run_admission::ResidentShare;
use crate::setting::{Kind, ScopeKind};

crate::setting::setting_keys! {
    /// One resident's share of the host-paid allocation (FIX 7767): `units` in the allocation's
    /// unit, or none for the default split, what the residents with no share in units split
    /// equally once the shares in units are taken from the allocation; `pinned`, past it the
    /// resident's new paid work is refused, while a soft share lets the spend past it write an
    /// overdraft receipt. A resident's row is its share; the vault's row is the share of every
    /// resident with no row of its own. The owner sets both; raising a share is spend above a
    /// cap. A change wakes the resident's steps parked on a spent share that it frees.
    pub(crate) RESIDENT_SHARE: ResidentShare = "budget.resident_share" {
        kind: Kind::new(ResidentShare::default),
        scopes: &[ScopeKind::Vault, ScopeKind::Agent],
        act: ActClass::SpendOverCap,
        on_change: Some(record_share_change),
        after_commit: Some(announce_share_change),
    };
}
