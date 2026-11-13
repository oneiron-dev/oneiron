//! READ SHAPE (census L9-37, ARCH-0051 #decision-r9-bench): the shape a
//! pumped run reads memory through, as its host picked it when the run woke.
//! Both shapes stay reachable under the run's grants (Engine RULING
//! L9-37-SHAPE-REACH = A): the brief names the one the policy picked for
//! the run's model, and narrows nothing.

use crate::store::ReadShape;

/// What identity states for a run that reads through the typed verbs.
const READ_THROUGH_VERBS: &str =
    "read memory through the typed memory verbs; the graph_fs mount stays open too";

/// What identity states for a run that reads through the mount.
const READ_THROUGH_MOUNT: &str = "read memory through the graph_fs mount at / with graph_fs.ls, \
     graph_fs.find, graph_fs.grep, graph_fs.cat, graph_fs.head and graph_fs.wc; the typed memory \
     verbs stay open too";

/// The read shape a run woke under, with the line identity states for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct BriefReadShape {
    pub shape: ReadShape,
    read_through: &'static str,
}

impl BriefReadShape {
    /// The brief's value for a run stamped with `shape`.
    #[must_use]
    pub const fn new(shape: ReadShape) -> Self {
        let read_through = match shape {
            ReadShape::Verbs => READ_THROUGH_VERBS,
            ReadShape::Mount => READ_THROUGH_MOUNT,
        };
        Self {
            shape,
            read_through,
        }
    }
}
