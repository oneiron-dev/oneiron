//! Stored actor-class wire tokens.

use oneiron_base::edge::EdgeActorClass;

/// The pinned wire token for an actor class.
///
/// Deliberately NOT `EdgeActorClass::gate_actor_class`: that key belongs to
/// Gate's `actor_ceilings` policy rows and is free to change with policy. This
/// mapping is a storage ABI. The exhaustive match makes a new class a compile
/// error here, which is the point.
pub const fn actor_class_token(class: EdgeActorClass) -> &'static str {
    match class {
        EdgeActorClass::Human => "human",
        EdgeActorClass::Agent => "agent",
        EdgeActorClass::System => "system",
    }
}

/// Inverse of [`actor_class_token`]; `None` for an unknown token.
pub fn actor_class_from_token(token: &str) -> Option<EdgeActorClass> {
    [
        EdgeActorClass::Human,
        EdgeActorClass::Agent,
        EdgeActorClass::System,
    ]
    .into_iter()
    .find(|class| actor_class_token(*class) == token)
}
