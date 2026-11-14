//! Context-bearing text replies through the host's configured inference door.
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::reply::{
    AiReply, AiReplyCompanion, AiReplyL2Base, AiReplyReader, AiReplyRequest, AiReplyStanding,
};
