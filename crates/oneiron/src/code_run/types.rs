//! Call vocabulary from guest requests to host admission and recorded answers.
//! Entry type: `SelfCall`.
//! The call, effect, request, host_door and outcome children own the forwarded definitions.

mod call;
mod effect;
mod host_door;
mod outcome;
mod request;
mod session_hooks;
mod session_write;

pub use self::call::*;
pub use self::effect::*;
pub use self::host_door::*;
pub use self::outcome::*;
pub use self::request::*;
pub use self::session_hooks::{
    SessionHookDisposition, SessionHookNotKept, SessionHookPhase, SessionHookReceipt,
    SessionHookState,
};
pub use self::session_write::{SessionWriteAdmission, SessionWriteCeiling};

// Referenced only by an intra-doc link on `SelfCall::MemoryWriteFixture`;
// gated so the name is in scope for rustdoc without being an unused import.
#[cfg(doc)]
use crate::Vault;
use crate::context_projection::ContextSpec;
use crate::off_record::ExecutorUtterance;
use crate::{ClaimCandidate, EdgeKind, EntityId, Result, ScoredEntity, TimeRange};

use super::{TeamSubmitAnswer, TeamSubmitInput, blocked, reader, repo_calls};
