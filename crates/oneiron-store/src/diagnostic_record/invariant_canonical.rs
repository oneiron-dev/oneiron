//! Canonicalization of invariant field values for stable comparison.

use std::collections::BTreeMap;

use rmpv::{Integer, Value};

use crate::diagnostic_record::untrusted_text::is_forbidden_text_scalar;
use oneiron_base::error::Result;

/// Longest string leaf the grammar before the owner ruling of 2026-10-14
/// accepted inside `expected` / `actual` / `delta`.
pub const EARLIER_INVARIANT_STRING_LEN: usize = 1024;

// ── invariant-value canonicalization ────────────────────────────────────────

/// Node and depth budget for one `expected` / `actual` / `delta` value, and
/// the grammar the walk reads.
#[derive(Default)]
pub struct InvariantBudget {
    pub depth: usize,
    pub nodes: usize,
    /// Also read the strings and string-keyed maps the grammar before the
    /// owner ruling of 2026-10-14 allowed. Only a stored body is read so.
    pub earlier_grammar: bool,
    /// The walk met a string or a map, even an empty one: a value only that
    /// grammar allows.
    pub earlier_only: bool,
}
