//! Moved from `crates/oneiron/src/secret_custody/found_keys.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use heed::RwTxn;
pub(crate) use oneiron_store::file_secret_marks::HANDLE_TEXT_OPEN;
pub(crate) use oneiron_store::file_secret_marks::unmask_value;
pub use oneiron_store::secret_record::write_records::FoundKeyAction;
pub use oneiron_store::secret_record::write_records::FoundKeySettled;
pub(crate) use oneiron_store::secret_record::write_records::FoundNote;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use zeroize::Zeroizing;

/// The scan's reason codes share this prefix; a key's kind is what follows.
pub const REASON_PREFIX: &str = "gate.secret_scan.";
