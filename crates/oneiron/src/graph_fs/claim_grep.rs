//! Indexed claim grep with search and final-hydration narrowing receipts.
use crate::claim::{PointRead, ReadRow, ScopedReadReceipt, decode_claim_body};
use crate::error::Result;
use crate::registry::ENTITY_TYPE_CLAIM;
use rmpv::Value;

use super::model::GraphFsResolver;
use super::paging::CommandOutputBuilder;

pub(super) struct ClaimGrepPage {
    pub(super) bytes: Vec<u8>,
    pub(super) next_cursor: Option<String>,
    pub(super) total: usize,
    pub(super) receipt: ScopedReadReceipt,
}

impl GraphFsResolver<'_, '_> {
    pub(super) fn grep_claims_pushdown(
        &self,
        pattern: &str,
        cursor: Option<&str>,
    ) -> Result<ClaimGrepPage> {
        let hits = self
            .scoped_read
            .search_text(pattern, self.coreutils_result_cap(), None)?;
        let ids: Vec<_> = hits.value.iter().map(|hit| hit.id).collect();
        let reads: Vec<_> = ids.iter().copied().map(PointRead::id).collect();
        let projection = self
            .scoped_read
            .read(&reads, Some(&hits.receipt.applied.as_filter()))?;
        let mut receipt = hits.receipt;
        receipt.restrict_with(&projection.receipt);
        let mut out = CommandOutputBuilder::new(self.options);
        let mut last_emitted = cursor.map(str::to_owned);
        let mut skipping = cursor.is_some();
        let mut total = 0;
        for (id, row) in ids.into_iter().zip(projection.value) {
            let id_hex = id.to_hex();
            if skipping {
                if cursor == Some(id_hex.as_str()) {
                    skipping = false;
                }
                continue;
            }
            let Some(ReadRow {
                entity_type: ENTITY_TYPE_CLAIM,
                body: Some(body),
                ..
            }) = row
            else {
                continue;
            };
            let body = decode_claim_body(&body, true)?;
            let line = format!(
                "/claims/{id_hex}:id={id_hex}\tpredicate={}\tvalue={}\n",
                sanitize_coreutils_field(&body.predicate),
                sanitize_coreutils_field(&claim_value_text(&body.value))
            );
            if !out.try_push(line.as_bytes()) {
                return Ok(ClaimGrepPage {
                    bytes: out.into_bytes(),
                    next_cursor: last_emitted,
                    total,
                    receipt,
                });
            }
            total += 1;
            last_emitted = Some(id_hex);
        }
        Ok(ClaimGrepPage {
            bytes: out.into_bytes(),
            next_cursor: None,
            total,
            receipt,
        })
    }
}

fn claim_value_text(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| format!("{value:?}"), str::to_owned)
}

fn sanitize_coreutils_field(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            '\t' | '\n' | '\r' => ' ',
            _ => ch,
        })
        .collect()
}
