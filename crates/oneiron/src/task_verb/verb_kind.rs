//! TASK vocabulary: kind, assignee, and absolute expiry shared by every verb.
//! Entry [`TaskTtl`]; deadlines are absolute so replicas agree on one wall time.
//! Owned by `task_verb`; kinds originate in `context_board::task_kind`, assignees in `gate`.
pub use crate::context_board::task_kind::TaskKind;

pub use crate::gate::task_assignee::TaskAssignee;

#[doc(hidden)]
pub use oneiron_verb_wire::task_verb::verb_kind::TaskTtl;
