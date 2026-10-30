//! The keys a file's leaf holds (OF-560, owner ruling G04 binary = C2): what
//! the door's text rules and its field reading place, and each value custody
//! already holds, at its span in the file's own bytes or in one member's.

use std::ops::Range;

use zeroize::Zeroizing;

use super::super::container::{MAX_FILE_KEYS, REASON_OVER_BUDGET};
use super::super::secret_scan_error;
use super::{FileKey, Masker, REASON_KNOWN_VALUE, escaped_span, file_spans, merged, occurrences};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::secret_custody::MemberStep;

impl Masker {
    /// The keys the door's text and field rules place in `leaf` (a file's
    /// own bytes, or one member's), each at `path`.
    pub(super) fn place(
        &mut self,
        path: &[MemberStep],
        leaf: &[u8],
        keys: &mut Vec<FileKey>,
    ) -> Result<()> {
        // A value custody already holds is marked with its own record
        // (OF-560 C); the file's bytes stay as stored, and a read masks it
        // through the same mark.
        let known: Vec<(Range<usize>, EntityId)> = match &self.known {
            Some(known) => known
                .spans(leaf)
                .into_iter()
                .filter(|hit| !self.is_kept(&leaf[hit.span.clone()]))
                .map(|hit| (hit.span, hit.custody))
                .collect(),
            None => Vec::new(),
        };
        let mut placed = Vec::new();
        // The switch is off: no shape span and no structured-field value are
        // discovered, and nothing is minted (FIX 8644).
        let mut spans = Vec::new();
        if !self.known_only {
            spans = file_spans(leaf);
            // A value a structured reading places (a credential field), wherever
            // its bytes sit in the leaf.
            let mut fields = Masker {
                mints: true,
                at: self.at.clone(),
                ..Masker::default()
            };
            fields.mask_body(leaf)?;
            for found in fields.found {
                let mut hits: Vec<Range<usize>> = occurrences(leaf, &found.value).collect();
                // A value the leaf holds escaped (a PEM block's `\n`) is
                // placed at its escaped form (FIX 1369).
                if hits.is_empty() {
                    hits = escaped_span::escaped_occurrences(leaf, &found.value);
                }
                spans.extend(hits.into_iter().map(|span| (span, found.reason)));
            }
        }
        for (span, reason) in merged(spans) {
            if known
                .iter()
                .any(|(held, _)| held.start < span.end && span.start < held.end)
            {
                continue;
            }
            // A value the owner ruled no secret in the record is left as
            // written, whatever rule placed its span (FIX 8646).
            if self.is_kept(&leaf[span.clone()]) {
                continue;
            }
            let value = Zeroizing::new(
                leaf.get(span.clone())
                    .ok_or(Error::InvariantViolation(
                        "a file's key span left its bytes",
                    ))?
                    .to_vec(),
            );
            self.handle(&value, reason)?;
            placed.push(FileKey {
                path: path.to_vec(),
                span,
                reason,
                value,
                custody: None,
            });
        }
        for (span, custody) in known {
            let value = Zeroizing::new(
                leaf.get(span.clone())
                    .ok_or(Error::InvariantViolation(
                        "a file's known span left its bytes",
                    ))?
                    .to_vec(),
            );
            self.placed_known = true;
            placed.push(FileKey {
                path: path.to_vec(),
                span,
                reason: REASON_KNOWN_VALUE,
                value,
                custody: Some(custody),
            });
        }
        placed.sort_by_key(|key| key.span.start);
        keys.extend(placed);
        if keys.len() > MAX_FILE_KEYS {
            return Err(secret_scan_error(REASON_OVER_BUDGET));
        }
        Ok(())
    }
}
