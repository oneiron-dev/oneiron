//! A Connect guest's proposals and the owner's review of them (FIX 3684).
use serde::{Deserialize, Serialize};

use crate::EntityId;

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::connect_proposal::{
    ConnectProposal, ConnectProposalDecision, ConnectProposalLanded, ConnectProposalRef,
    ConnectProposeRequest,
};
