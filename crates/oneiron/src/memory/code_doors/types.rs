//! Code symbol lease, proposal and mutation-log request and view records.
//! `CodeSymbolsDeclareRequest` is the first of its records.
//! These are local definitions; `memory::code_doors` re-exports them.

use serde::{Deserialize, Serialize};

use crate::EntityId;

#[doc(hidden)]
pub use oneiron_verb_wire::memory::code_doors::types::{
    CodeProposalRereviewRequest, CodeProposalSubmitRequest, CodeProposalSubmitted, CodeRepoRequest,
    CodeSymbolsDeclareRequest, CodeSymbolsTaskRequest,
};

#[doc(hidden)]
pub use oneiron_records::memory::code_doors::types::{
    CodeMutationEntry, CodeMutationLog, CodeMutationState, CodeSymbolLeaseView,
    CodeSymbolsDeclared, CodeSymbolsReleased,
};
