//! Delegated custody scope strings: the custody effector per channel and the
//! subject and granted scopes a delegated row's read binding names.
//! Entry: `delegated_custody_scopes`. Defines its own items; the custody proof stays in `custody`.

use super::*;

/// The effector whose read binding is what "custody" MEANS for a delegated
/// row on a given channel.
///
/// One entry today: a delegated `email` row is a member-held Gmail/Workspace
/// mailbox, and the only thing that makes the row true is a live
/// `connector:gmail` read binding on the named custody record. A channel with
/// no entry admits no delegated row at all, so an unknown channel fails closed
/// rather than defaulting to "any binding will do".
const DELEGATED_CUSTODY_EFFECTORS: [(&str, &str); 1] = [("email", "connector:gmail")];

/// The effector binding a delegated `channel` row's custody record must carry.
///
/// `None` means the channel admits no delegated rows. The lookup takes the
/// channel through [`ChannelKey::normalize`] for the same reason
/// [`delegated_custody_subject_scope`] does: a table keyed on lowercase nouns
/// answers a raw spelling honestly or not at all.
#[must_use]
pub fn delegated_custody_effector(channel: &str) -> Option<&'static str> {
    let channel = ChannelKey::normalize(channel);
    DELEGATED_CUSTODY_EFFECTORS
        .iter()
        .find_map(|(candidate, effector)| (*candidate == channel.as_str()).then_some(*effector))
}

/// The scope string a custody record must declare to name `(channel, address)`
/// as its SUBJECT.
///
/// Scope-string form, not a codec change: `SecretBinding.scopes` is already a
/// free-form `Vec<String>` whose documented job is naming what a binding is
/// FOR, so the subject rides there with no on-disk migration.
///
/// The host registers it at OAuth completion — it has the account email from
/// the token exchange, which the engine does not and must not.
///
/// BOTH halves of the subject are normalized here, and the channel half is what
/// ONE-1825 closes. Every writer that consumes this scope —
/// `verify_delegated_custody_in_txn`, reached through
/// [`Vault::provision_delegated_identity`](crate::Vault::provision_delegated_identity)
/// and [`Vault::verify_delegated_custody`](crate::Vault::verify_delegated_custody) —
/// runs the request channel through [`ChannelKey::normalize`] FIRST and then
/// looks for `subject:email:…`. A helper that interpolated the caller's raw
/// spelling would put the registration side and the admission side of the same
/// tie out of step on any channel spelling that normalizes:
/// [`delegated_custody_scopes`]`("Email", addr)` would emit `subject:Email:…`,
/// the engine would look for `subject:email:…`, and a binding a host registered
/// in good faith would be refused forever for a mailbox the engine otherwise
/// accepts. Normalizing once, here, is what keeps the two halves from drifting;
/// already-normalized inputs are byte-for-byte unaffected.
#[must_use]
pub fn delegated_custody_subject_scope(channel: &str, address: &str) -> String {
    let channel = ChannelKey::normalize(channel);
    format!(
        "subject:{}:{}",
        channel.as_str(),
        AssignmentAddress::normalize(channel.as_str(), address).as_str()
    )
}

/// The read + subject scope pair a delegated custody binding must declare.
///
/// The registration-side twin of `verify_delegated_custody_in_txn`, so a host
/// registering a grant and the engine admitting it cannot drift. `"Email"`,
/// `"EMAIL"` and `" email "` all register the one scope the engine looks for.
#[must_use]
pub fn delegated_custody_scopes(channel: &str, address: &str) -> Vec<String> {
    vec![
        SECRET_SCOPE_READ.to_owned(),
        delegated_custody_subject_scope(channel, address),
    ]
}

/// The scope string a custody binding declares when the PROVIDER granted
/// `scope` to the token it holds.
///
/// The host registers it at OAuth completion, and only from the provider's own
/// token response (Google's granted `scope` list), never from what the consent
/// request asked for: an incremental-consent screen can come back narrower than
/// it was requested. A row naming a send scope is admitted only over a binding
/// carrying this evidence, so a caller-built config cannot manufacture send.
#[must_use]
pub fn delegated_custody_granted_scope(scope: DelegatedGrantScope) -> String {
    format!("granted:{}", scope.as_str())
}

/// [`delegated_custody_scopes`] plus the granted-scope evidence every
/// send-capable scope in `grant_scopes` needs.
#[must_use]
pub fn delegated_custody_scopes_for_grant(
    channel: &str,
    address: &str,
    grant_scopes: &[DelegatedGrantScope],
) -> Vec<String> {
    let mut scopes = delegated_custody_scopes(channel, address);
    for scope in grant_scopes {
        if matches!(scope, DelegatedGrantScope::MailSend) {
            scopes.push(delegated_custody_granted_scope(*scope));
        }
    }
    scopes
}
