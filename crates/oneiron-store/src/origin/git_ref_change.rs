//! One ref a checkout push moves and the paths that move changes, as the
//! smart-HTTP door reads them back and the intent writer judges them.
//! `federation::git_push` re-exports [`GitPushRefChange`] at its old path.

use std::collections::BTreeSet;

/// One ref a checkout push moves and every path that move changes, the old
/// and new name of a rename and the path of a delete among them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitPushRefChange {
    pub git_ref: String,
    pub paths: BTreeSet<String>,
}
