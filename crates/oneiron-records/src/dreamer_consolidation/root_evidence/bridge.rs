//! Moved from `crates/oneiron/src/dreamer_consolidation/root_evidence/bridge.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::consolidation_scope::DreamerConsolidationScope;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// The bridge attempt type. Queued on the existing Micro kind
/// (`DreamerConsolidationScope::Micro.attempt_kind()`), so wake preparation
/// skips its non-partition input by decode failure and the partition window
/// excludes it by attempt type; the inner executor arm runs it.
pub const ATTEMPT: &str = "dreamer.consolidation.root_bridge";

/// Domain of the per-payload dedupe-children digest (dedupe key segment).
pub const DEDUPE_DOMAIN: &[u8] = b"oneiron:root-bridge-dedupe:v1";
