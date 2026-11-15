//! Door for `tests/slack_install_sweep.rs` (UC-12 PR 1): the states the pending Slack install
//! table holds, expired rows included, which no public read shows.

/// Every state the pending Slack install table holds, in key order.
///
/// # Errors
///
/// Storage errors, or a key that is not a state.
pub fn pending_slack_install_states(vault: &crate::Vault) -> crate::error::Result<Vec<String>> {
    vault.slack_install_states_for_test()
}
