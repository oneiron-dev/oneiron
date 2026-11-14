//! OF-493's role-holder doors (Q3 by role): the wire shapes a person or a
//! bound agent uses to answer a decision ask put to its role and to pass one
//! up its chain. Its list of the open asks at its roles takes no input.
//!
//! The engine's `DecisionAnswer` rides inside unchanged, decoded through its
//! own serde and shown to a schema as any JSON value. No holder, role, kind
//! or clock is a field here: the server's door takes the actor and its class
//! from the credential, and the vault reads the role's holders again.

#[doc(hidden)]
pub use oneiron_verb_wire::receipt::decision_asks::{
    DecisionAskAnswerRequest, DecisionAskClimbRequest, DecisionAskConfirmGrantRequest,
};
