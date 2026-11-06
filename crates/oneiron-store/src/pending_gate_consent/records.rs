//! Pending gate-consent record and index-state types, ABI-pinned versions, msgpack codecs, and validation.

use serde::{Deserialize, Serialize};

use oneiron_base::error::Error;
use oneiron_base::error::Result;

/// Body version of one pending gate-consent tray row.
///
/// Pinned to the same numeric value the decision ledger happens to carry
/// today, because that is the value already on disk — this names it rather
/// than changing it. The two families are stored, indexed and swept
/// separately, so borrowing [`GATE_DECISION_LEDGER_VERSION`] here would make
/// the NEXT decision-ledger bump decode every stored pending row as corrupt.
///
/// Receipt-family ABI-pin rule: changing this requires a
/// [`STORAGE_ABI_VERSION`] bump.
pub const PENDING_GATE_CONSENT_VERSION: u8 = 0;

/// Receipt-family ABI-pin rule: changing this requires a
/// [`STORAGE_ABI_VERSION`] bump.
pub const PENDING_GATE_CONSENT_INDEX_STATE_VERSION: u8 = 1;

pub const OWNER_ANSWER_OBLIGATION_VERSION: u8 = 0;
