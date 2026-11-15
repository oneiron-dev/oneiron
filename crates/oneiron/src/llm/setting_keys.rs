//! The model layer's owner Setting keys (DESIGN 15-setting-primitive): rows the setting
//! catalogue reads from this file.

use crate::check_in::ActClass;
use crate::setting::{ItemDomain, Kind, ScopeKind, lower_is_tighter};

/// Off: only the owner answers a quota question.
fn owner_answers() -> bool {
    false
}

/// The answers a quota question offers, by their wire names (`POST /v1/ai/quota/{id}`).
fn quota_choice(item: &str) -> bool {
    matches!(
        item,
        "wait" | "add_account" | "use_fallback" | "top_up" | "pay_as_you_go"
    )
}

crate::setting::setting_keys! {
    /// Let this agent give this answer to a spent-quota question. Off by default for every
    /// answer: only the owner answers at `POST /v1/ai/quota/{id}`, as before. One item per
    /// answer (`wait`, `add_account`, `use_fallback`, `top_up`, `pay_as_you_go`), so the owner
    /// lets an agent wait out a window without letting it put a paid offer back. `top_up` and
    /// `pay_as_you_go` put the offer back at once and its calls spend on the provider's account,
    /// so the key is declared with the billing act class: turning any answer on is a payment
    /// loosening (RESTRICTION-WAVE-11-OWNER-ROWS Q1 = A; ARCH-0082 #payment). The engine never
    /// pays; the provider's own payment authentication stays where it is. An agent's row names
    /// one agent; the vault row opens every agent, and an agent's own row wins over it. A member
    /// is never let in by this key. Only the owner turns it on; an agent's change waits on the
    /// owner's answer (restriction wave 11, census C17).
    pub MODELS_QUOTA_AGENT_MAY_ANSWER: bool = "models.quota.agent_may_answer" {
        kind: Kind::new(owner_answers)
            .strictest(owner_answers)
            .tighter(lower_is_tighter::<bool>),
        scopes: &[ScopeKind::Vault, ScopeKind::Agent],
        item: Some(ItemDomain { name: "quota answers", admits: quota_choice }),
        act: ActClass::Billing,
    };
}
