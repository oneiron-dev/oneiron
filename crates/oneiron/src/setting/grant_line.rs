//! The Grant lines of the setting keys: the per-key verbs a Grant lists to let an agent set,
//! read or widen a key.

use super::SettingScope;

/// The Grant line that makes an agent a holder of one key (DESIGN 1.2 step 3): it sets the key's
/// value rows inside the owner's, and its widening asks the user (AUTH-1 = A). A Grant lists it
/// as a verb, matched exactly.
#[must_use]
pub fn set_line(key: &str) -> String {
    format!("settings.set:{key}")
}

/// The Grant line that lets an agent read one key whole.
#[must_use]
pub fn get_line(key: &str) -> String {
    format!("settings.get:{key}")
}

/// The Grant line of the owner's standing approval for one key (owner principle, 16 Nov 00:44):
/// the key's holder line with a widening allowance. An agent whose live owner Grant lists it
/// holds the key at every scope, and its widening lands without asking
/// ([`super::Setter::Standing`]). It never pins, and never sets a row under the owner's pin. A
/// Grant lists it as a verb, matched exactly; revoking the Grant ends it.
#[must_use]
pub fn widen_line(key: &str) -> String {
    format!("settings.widen:{key}")
}

/// [`widen_line`] at one scope only: the rows of `key` at exactly `scope`. `None` for a pack
/// scope, which only the pack door writes.
#[must_use]
pub fn widen_line_at(key: &str, scope: &SettingScope) -> Option<String> {
    scope_line_text(scope).map(|scope| format!("settings.widen:{key}@{scope}"))
}

/// The owner's standing approval for every key at one scope: the rows of each key at exactly
/// `scope`. `None` for a pack scope.
#[must_use]
pub fn widen_scope_line(scope: &SettingScope) -> Option<String> {
    scope_line_text(scope).map(|scope| format!("settings.widen:*@{scope}"))
}

/// A scope as a Grant line names it: `vault`, `task_type:<node>`, or `<kind>:<32 hex>` for a
/// scope that names an entity; `None` for a pack scope.
fn scope_line_text(scope: &SettingScope) -> Option<String> {
    match scope {
        SettingScope::Vault => Some("vault".to_owned()),
        SettingScope::Pack(_) => None,
        SettingScope::TaskType(node) => Some(format!("task_type:{node}")),
        other => other
            .entity()
            .map(|id| format!("{}:{}", other.kind().as_str(), id.to_hex())),
    }
}
