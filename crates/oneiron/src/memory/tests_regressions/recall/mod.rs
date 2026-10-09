//! BRIDGE-02 retrieval surface regressions: BM25, neighbors, recall packs, scope honesty, limits.

use super::*;
use crate::memory::tests::short_id_part;

include!("query_neighbors.rs");
include!("pack_scope.rs");
include!("ranking_hydration.rs");
include!("bounds_execution.rs");
include!("temporal.rs");
include!("control_kinds.rs");
include!("read_grants.rs");
include!("turn_fold.rs");
include!("clock_consistency.rs");
