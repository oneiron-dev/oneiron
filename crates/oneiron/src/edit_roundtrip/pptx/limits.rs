//! Policy-manifest budgets for the modern-comment writer.
//!
//! These are operational budgets, not OOXML invariants. The stored policy
//! narrows the shipped row; optional holder limits may narrow it further.
//! How many comments one edit carries is no budget here: the vault door
//! measures it against `limits.pptx_comment_patches` and serves it whole.

use oneiron_docedit::pptx_comments::PptxCommentLimits;
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[doc(hidden)]
pub use oneiron_records::edit_roundtrip::pptx::limits::PptxOperationalLimits;
#[doc(hidden)]
use oneiron_records::edit_roundtrip::pptx::limits::min;
