//! Moved from `crates/oneiron/src/origin/residence.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::receipt_identity::ERASED_CALL_IDENTITY;
pub use oneiron_verb_wire::origin::residence::OriginAuthority;
pub use oneiron_verb_wire::origin::residence::OriginResidence;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

/// The writer an erased host leaves in the authority row, its admission
/// stamps and its intents (FIX 3877; a call, L02's ruling): one fixed marker,
/// never Nil and never a dropped field, so it can never read as an
/// unconfigured origin. The repository and epoch stay; no host holds the
/// repository until the owner's explicit cutover, and nothing fails over.
pub const ORIGIN_ERASED_WRITER: &str = ERASED_CALL_IDENTITY;
