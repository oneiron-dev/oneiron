//! Canonical outbound verb classes and class membership.
//!
//! A grant stores a verb class name, never the verbs in it (DEC-0006
//! invariant 3): membership resolves here when an effect arrives. A class
//! name also covers its own literal spelling, so a grant minted for one verb
//! keeps covering exactly that verb.

use super::scope::SEND_VERB_CLASS;

/// Each registered class and its member verbs, as the outbound capability
/// manifests name them. A verb outside the class a grant names matches
/// nothing, so the Gate raises its consent ask for it: the owner widens a
/// class for a grant by answering that ask or a proposed action widen
/// ([`crate::Vault::propose_action_widen`]), never through reuse.
const OUTBOUND_VERB_CLASSES: [(&str, &[&str]); 1] = [
    // A message delivered to a counterparty in its conversation. A cold
    // first contact, a broadcast, an edit or a retraction is not one.
    (SEND_VERB_CLASS, &["send", "send_media", "send_dm", "reply"]),
];

/// Whether `verb` is a member of the class `class` names: its own literal
/// spelling, or a member the registry lists for that class. Both sides are
/// trimmed; spelling is otherwise exact.
pub(super) fn verb_in_class(class: &str, verb: &str) -> bool {
    let (class, verb) = (class.trim(), verb.trim());
    class == verb
        || OUTBOUND_VERB_CLASSES
            .iter()
            .any(|(name, members)| *name == class && members.contains(&verb))
}
