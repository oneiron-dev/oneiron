//! Indexed claim grep with search and final-hydration narrowing receipts.
use crate::ports::point_read::PointRead;
use crate::write_envelope::claim_body::decode_claim_body;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_CLAIM;
use oneiron_contracts::claim::ScopedReadReceipt;
use rmpv::Value;

use crate::graph_fs::coreutils_text::LinePosition;

pub struct ClaimGrepPage {
    pub bytes: Vec<u8>,
    pub next_cursor: Option<String>,
    pub total: usize,
    pub receipt: ScopedReadReceipt,
}

pub fn claim_value_text(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| format!("{value:?}"), str::to_owned)
}

pub fn sanitize_coreutils_field(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            '\t' | '\n' | '\r' => ' ',
            _ => ch,
        })
        .collect()
}
