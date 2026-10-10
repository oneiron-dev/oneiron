//! Indexed claim grep with search and final-hydration narrowing receipts.
use crate::claim::{PointRead, ReadRow, ScopedReadReceipt, decode_claim_body};
use crate::error::Result;
use crate::registry::ENTITY_TYPE_CLAIM;
use rmpv::Value;

use super::coreutils_text::LinePosition;
use super::model::GraphFsResolver;
use super::paging::CommandOutputBuilder;

pub(super) struct ClaimGrepPage {
    pub(super) bytes: Vec<u8>,
    pub(super) next_cursor: Option<String>,
    pub(super) total: usize,
    pub(super) receipt: ScopedReadReceipt,
}

impl GraphFsResolver<'_, '_> {
    /// The claims the text index ranks for `pattern`, a page at a time: each
    /// page reads up to the result cap of ranked hits from where the page
    /// before stopped, and hands out the rank to resume at, sealed, while
    /// hits remain.
    pub(super) fn grep_claims_pushdown(
        &self,
        pattern: &str,
        path: &str,
        cursor: Option<&str>,
    ) -> Result<ClaimGrepPage> {
        let scope = self.cursor_scope(&format!("grep -r {}:{pattern} {path}", pattern.len()));
        let at: LinePosition = scope.open(cursor)?.unwrap_or_default();
        let (from, mut printed) = (at.line, at.printed);
        let cap = self.coreutils_result_cap();
        let hits = self.scoped_read.search_text(
            pattern,
            from.saturating_add(cap).saturating_add(1),
            None,
        )?;
        let more = hits.value.len() > from.saturating_add(cap);
        let ids: Vec<_> = hits
            .value
            .iter()
            .skip(from)
            .take(cap)
            .map(|hit| hit.id)
            .collect();
        let reads: Vec<_> = ids.iter().copied().map(PointRead::id).collect();
        let projection = self
            .scoped_read
            .read(&reads, Some(&hits.receipt.applied.as_filter()))?;
        let mut receipt = hits.receipt;
        receipt.restrict_with(&projection.receipt);
        let mut out = CommandOutputBuilder::new(self.options);
        let mut total = 0;
        let read = ids.len();
        for (rank, (id, row)) in (from..).zip(ids.into_iter().zip(projection.value)) {
            // Only the page's first line may be partly printed already.
            let line_printed = std::mem::take(&mut printed);
            let id_hex = id.to_hex();
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
            if let Some(printed) = out.push_line(&line, line_printed) {
                let at = LinePosition {
                    line: rank,
                    printed,
                };
                return Ok(ClaimGrepPage {
                    bytes: out.into_bytes(),
                    next_cursor: Some(scope.seal(&at)),
                    total,
                    receipt,
                });
            }
            total += 1;
        }
        let next = LinePosition {
            line: from + read,
            printed: 0,
        };
        Ok(ClaimGrepPage {
            bytes: out.into_bytes(),
            next_cursor: more.then(|| scope.seal(&next)),
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
