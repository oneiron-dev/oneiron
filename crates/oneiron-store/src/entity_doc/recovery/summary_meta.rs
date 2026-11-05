//! The scope-summary meta a canonical EntityDoc row carries beside its
//! editable metadata (FIX 756): a SUMMARY document's purpose and derivation,
//! the typed values its meta map keeps as encoded bytes. Neither is an
//! editable field (`ports::document_fields` names neither), so they ride a
//! field of their own and are written back as they were captured.

use std::collections::BTreeMap;

use loro::LoroDoc;

use oneiron_base::error::Result;

/// The meta keys a summary document keeps its typed values under.
pub const SUMMARY_META: [&str; 2] = ["purpose", "derivation"];
