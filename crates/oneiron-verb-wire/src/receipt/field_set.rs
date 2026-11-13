//! Moved from `crates/oneiron/src/receipt/field_set.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

pub const FIELD_MANIFEST_ENTRIES: &str = "manifest.entries";

/// FIX 6934: the complete set of rows the attempt read its inputs from.
pub const FIELD_MANIFEST_SOURCE_ROWS: &str = "manifest.source_rows";

/// OF-578: the functional role the attempt's executor ran as, frozen with
/// `model` and `executor_seat`; its value is the role's serde token.
pub const FIELD_EXECUTOR_ROLE: &str = "executor_role";

/// FIX 8259: the lease generation (`AttemptRecord.attempt_count`) the attempt
/// settled under, frozen at the terminal seal. Absent on receipts sealed
/// before the stamp existed.
pub const FIELD_LEASE_GENERATION: &str = "lease_generation";

/// FIX 12306: the calling principal of an agent-dispatch or turn-program
/// attempt, frozen on its pack receipt as canonical 32-lowercase-hex.
pub const FIELD_ATTEMPT_CALLER: &str = "attempt.caller";

/// BUDGET-TRAP-UNTYPED-NO-SENDER: the typed refusal a spend scope gave a try
/// it refused for good, as the refusal's own serde JSON (tag `reason`),
/// stamped by the engine from the failed row or its runner's settle. Absent on
/// every other receipt; [`ReceiptRecord::budget_refusal`] reads it typed.
pub const FIELD_BUDGET_REFUSAL: &str = "budget_refusal";

/// The run's project, frozen beside its typeRef: the scope its learning
/// cells key on (FIX 6038). Absent, the vault's.
pub const FIELD_TYPE_REF_PROJECT: &str = "type_ref.project";

pub const BOARD_STATE_REF_PREFIX: &str = "board:";

pub const ACTIVATED_MEMORY_IDS_SEPARATOR: char = ',';
