//! The role a human decision ask goes to, and the serde form of an answer's
//! actor. The decision ladder (`llm::decision`) builds and resolves asks;
//! the store-layer e-sign escalation and import audience read the role.

#[doc(hidden)]
pub use oneiron_verb_wire::store::decision_ask_role::AskRole;
#[doc(hidden)]
pub(crate) use oneiron_verb_wire::store::decision_ask_role::answer_actor;
