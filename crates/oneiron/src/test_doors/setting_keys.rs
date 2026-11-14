//! The catalogue keys the Setting primitive's tests set (DESIGN 15-setting-primitive, stage 0.1).
//! They exist only under `--cfg oneiron_test_support`; no engine code reads them.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::check_in::ActClass;
use crate::error::Result;
use crate::federation::EngineControlClass;
use crate::setting::{
    ItemDomain, Kind, ReadBy, ScopeKind, SetBy, SettingChange, higher_is_tighter, lower_is_tighter,
};

/// How many changes `test.hooked` has seen.
static HOOKED_CHANGES: AtomicU64 = AtomicU64::new(0);

fn seven() -> u64 {
    7
}

fn ten() -> u64 {
    10
}

fn zero() -> u64 {
    0
}

fn quiet_default() -> bool {
    false
}

fn quietest() -> bool {
    true
}

fn empty_banner() -> String {
    String::new()
}

fn channel(item: &str) -> bool {
    matches!(item, "mail" | "chat")
}

fn count_change(
    _vault: &crate::Vault,
    _txn: &mut heed::RwTxn<'_>,
    _change: &SettingChange,
) -> Result<()> {
    HOOKED_CHANGES.fetch_add(1, Ordering::SeqCst);
    Ok(())
}

/// How many changes `test.hooked`'s hook has run for.
#[must_use]
pub fn hooked_changes() -> u64 {
    HOOKED_CHANGES.load(Ordering::SeqCst)
}

crate::setting::setting_keys! {
    /// A number only the owner sets, at the vault, a world or a project.
    pub TEST_OWNER_NUMBER: u64 = "test.owner_number" {
        kind: Kind::new(seven).strictest(zero),
        scopes: &[ScopeKind::Vault, ScopeKind::World, ScopeKind::Project],
    };
    /// A work budget a holder of the work-budget class tunes inside the owner's cap.
    pub TEST_WORK_BUDGET: u64 = "test.work_budget" {
        kind: Kind::new(ten).strictest(zero).tighter(lower_is_tighter::<u64>),
        scopes: &[ScopeKind::Vault, ScopeKind::Project],
        set_by: SetBy::Class(EngineControlClass::WorkBudget),
    };
    /// Whether an agent keeps quiet: the agent tightens its own row; loosening asks.
    pub TEST_AGENT_QUIET: bool = "test.agent_quiet" {
        kind: Kind::new(quiet_default).strictest(quietest).tighter(higher_is_tighter::<bool>),
        scopes: &[ScopeKind::Vault, ScopeKind::Agent],
        set_by: SetBy::Subject,
    };
    /// A wait per outbound channel: a family key.
    pub TEST_CHANNEL_WAIT: u64 = "test.channel_wait" {
        kind: Kind::new(zero),
        item: Some(ItemDomain { name: "outbound channels", admits: channel }),
    };
    /// A banner every member of the vault reads.
    pub TEST_MEMBER_BANNER: String = "test.member_banner" {
        kind: Kind::new(empty_banner),
        read_by: ReadBy::Members,
        act: ActClass::ReversibleWork,
    };
    /// A key whose hook counts its changes.
    pub TEST_HOOKED: u64 = "test.hooked" {
        kind: Kind::new(zero),
        on_change: Some(count_change),
    };
}
