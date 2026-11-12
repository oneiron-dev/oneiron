//! The keys a file's leaf holds (OF-560, owner ruling G04 binary = C2): what
//! the door's text rules and its field reading place, a recovery phrase split
//! over the leaf's parts word by word (LABEL-04), and each value custody
//! already holds, at its span in the file's own bytes or in one member's.

use std::ops::Range;

use zeroize::Zeroizing;

use super::super::container::{MAX_FILE_KEYS, REASON_OVER_BUDGET};
use super::super::{REASON_MNEMONIC, secret_scan_error, write_payload_hit};
use super::body::reads_as_text;
use super::split_phrase;
use super::text_log::{TextLog, TextSpans};
use super::{FileKey, Masker, REASON_KNOWN_VALUE, escaped_span, file_spans, merged, occurrences};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::file_secret_marks::MemberStep;

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
                .spans_except(leaf, |value| self.is_kept(value))
                .into_iter()
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
            // A leaf no decoder takes is read as one text, whose spans are
            // the ones just found: they are not found again (speed).
            if reads_as_text(leaf) {
                let leaf_spans = TextSpans {
                    known: Vec::new(),
                    shapes: spans.clone(),
                };
                fields.text_log = TextLog::seeded(leaf, leaf_spans);
            }
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
            // A value the owner ruled no secret or kept as text in the record is left
            // as written, whatever rule placed its span (FIX 8646).
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
        // A clean scan read every part of the leaf too: no phrase split over
        // them is sought again (speed). The switch off places a phrase
        // custody already holds, and no other (FIX 8644). Only the batch
        // door's plan places one; a carrier's text stays unplaced.
        if self.places_split_phrases && !self.shapes_read {
            self.place_split_phrases(path, leaf, &known, &mut placed)?;
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

    /// Each recovery phrase split over `leaf`'s parts (LABEL-04): one
    /// custody record holds the phrase (the record that holds it already,
    /// if one does; with the switch off, only such a phrase is placed), and
    /// each of its words no span covers yet is marked with it. The file's
    /// bytes stay as stored. A hit the leaf's parts still hold once every
    /// mark is filled leaves its phrases unplaced: the door's refusal stands
    /// (REVIEW-7059 P1).
    fn place_split_phrases(
        &mut self,
        path: &[MemberStep],
        leaf: &[u8],
        known: &[(Range<usize>, EntityId)],
        placed: &mut Vec<FileKey>,
    ) -> Result<()> {
        let mut phrases: Vec<PhrasePlace> = Vec::new();
        for phrase in split_phrase::split_phrases(leaf) {
            // A word two readings find is placed once.
            let words: Vec<Range<usize>> = phrase
                .words
                .iter()
                .filter(|word| {
                    !known
                        .iter()
                        .map(|(held, _)| held)
                        .chain(placed.iter().map(|key| &key.span))
                        .chain(phrases.iter().flat_map(|place| &place.words))
                        .any(|held| held.start < word.end && word.start < held.end)
                })
                .cloned()
                .collect();
            if words.is_empty() || self.is_kept(&phrase.value) {
                continue;
            }
            let held =
                self.known
                    .as_ref()
                    .and_then(|index| match index.spans(&phrase.value).as_slice() {
                        [hit] if hit.span == (0..phrase.value.len()) => Some(hit.custody),
                        _ => None,
                    });
            if held.is_none() && self.known_only {
                continue;
            }
            phrases.push(PhrasePlace {
                value: phrase.value,
                words,
                held,
            });
        }
        if phrases.is_empty() {
            return Ok(());
        }
        let marks: Vec<Range<usize>> = known
            .iter()
            .map(|(span, _)| span.clone())
            .chain(placed.iter().map(|key| key.span.clone()))
            .chain(phrases.iter().flat_map(|place| place.words.iter().cloned()))
            .collect();
        if !self.filled_parts_read_clean(leaf, &marks) {
            return Ok(());
        }
        for place in phrases {
            let (reason, custody) = match place.held {
                Some(custody) => {
                    self.placed_known = true;
                    (REASON_KNOWN_VALUE, Some(custody))
                }
                None => {
                    self.handle(&place.value, REASON_MNEMONIC)?;
                    (REASON_MNEMONIC, None)
                }
            };
            for span in place.words {
                placed.push(FileKey {
                    path: path.to_vec(),
                    span,
                    reason,
                    value: place.value.clone(),
                    custody,
                });
            }
        }
        Ok(())
    }

    /// Whether the door's rules read no hit in `leaf` with each of `marks`
    /// filled where its decoder still reads the leaf as it read it
    /// (`split_phrase::filled_in_place`). A word's span in an array of byte
    /// values holds the separators between its numbers, so the plan's copy,
    /// filled over them, may decode no more: the door's second read would
    /// then take it as text alone, blind to a key in another of its parts
    /// that no span places (REVIEW-7059 P1). A value the owner kept in the
    /// record is screened as the door's read screens it. With the switch off
    /// the door refuses nothing, so there is no refusal to keep.
    fn filled_parts_read_clean(&self, leaf: &[u8], marks: &[Range<usize>]) -> bool {
        if self.known_only {
            return true;
        }
        let Some(copy) = split_phrase::filled_in_place(leaf, marks) else {
            return true;
        };
        let screened = self
            .at
            .as_ref()
            .and_then(|(record, _)| self.kept.screened(record, &copy))
            .map(Zeroizing::new);
        let read = match &screened {
            Some(screened) => screened.as_slice(),
            None => copy.as_slice(),
        };
        write_payload_hit(read).is_none()
    }
}

/// A recovery phrase split over a leaf that the plan places: its value, its
/// words no span covers yet, and the custody record that holds it already.
struct PhrasePlace {
    value: Zeroizing<Vec<u8>>,
    words: Vec<Range<usize>>,
    held: Option<EntityId>,
}
