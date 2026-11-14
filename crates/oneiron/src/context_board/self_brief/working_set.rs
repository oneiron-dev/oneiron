//! WORKING SET (Engine ruling 21:47): this run's admitted board selection as
//! typed handles. Each family is resolved on its own, so a known scratchpad
//! says nothing of the pins or the replay bindings. A handle grants nothing
//! by itself.

use crate::entity_id::EntityId;
use crate::vault::RevisionRef;

#[doc(hidden)]
pub use oneiron_records::context_board::self_brief::working_set::{
    BriefWorkingHandle, BriefWorkingSet,
};
