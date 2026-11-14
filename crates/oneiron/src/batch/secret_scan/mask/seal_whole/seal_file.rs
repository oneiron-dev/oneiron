//! A file's seal (ARCH-0069 #binary-secrets, owner ruling G04 binary = C2;
//! ARCH-0038 #secret-scan-target): a file whose bytes still read as a hit
//! once the plan has marked each key a span places is stored, never refused,
//! and its bytes stay as written. When the door decodes the file (JSON, or
//! one whole MessagePack value), the smallest value that reads as the hit
//! alone is marked as one key: custody holds that value as it holds a
//! body's sealed value, and the mark covers its bytes in the file, outside
//! each key marked before. The plan reads the file again with each mark
//! filled where its decoder still reads it (`split_phrase::filled_in_place`),
//! so a hit in another of its values is still seen (REVIEW-7059 P1), and
//! seals until the door reads it clean.
//!
//! Sealed whole: a file no decoder reads, one whose hit only its whole tree
//! holds, one with a key in a member, and one whose masked copy the door
//! still reads as a hit. Its mark says so, no copy of it goes into custody,
//! and a masked reader is served none of it ("a sealed file that no mark
//! covers is withheld").

use std::ops::Range;

use zeroize::Zeroizing;

use super::super::split_phrase;
use super::super::wipe::replace_wiped;
use super::super::{FileKey, FoundFile, Masker, masked_copy, part_at, united_places};
use super::{MAX_SEALS_PER_OP, hit, smallest_hit, value_bytes};
use crate::batch::BatchOp;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::file_secret_marks::KeyPlaces;
use crate::secret_custody::KeptValues;

impl Masker {
    /// Seals `op`, the plan's copy of a file put whose bytes as written are
    /// `written`, which the door still reads as a hit (`clean` reads a copy
    /// as the door does): each value that reads as the hit alone is marked
    /// as one key, or the file is sealed whole, for `reason`, the door's
    /// reason. The file is stored as written either way. Bytes whose seal
    /// the owner ruled no secret are sealed no more
    /// (L6-03-SEALED-FILE-NO-NOTICE).
    pub(super) fn seal_file(
        &mut self,
        kept: &KeptValues,
        op: &mut BatchOp,
        written: &[u8],
        clean: &dyn Fn(&BatchOp) -> bool,
        reason: &'static str,
    ) -> Result<()> {
        let BatchOp::Put { id, .. } = op else {
            return Err(Error::InvariantViolation("a file seal read no put"));
        };
        let record = *id;
        let hash = *blake3::hash(written).as_bytes();
        if self.ruled_seals.contains(&hash) {
            return Ok(());
        }
        let places = self.marked.get(&hash).cloned().unwrap_or_default();
        let (keys, sealed) = self.value_seals(kept, record, written, &places, op, clean)?;
        if keys.is_empty() && !sealed {
            return Ok(());
        }
        let sealed = sealed.then_some(reason);
        if !keys.is_empty() {
            let united = united_places(places, &keys)?;
            self.marked.insert(hash, united);
        }
        match self
            .files
            .iter_mut()
            .find(|file| file.hash == hash && file.record == record)
        {
            Some(file) => {
                file.keys.extend(keys);
                file.sealed = file.sealed.or(sealed);
            }
            None => self.files.push(FoundFile {
                hash,
                keys,
                record,
                sealed,
            }),
        }
        if !self.file_ids.contains(&record) {
            self.file_ids.push(record);
        }
        Ok(())
    }

    /// The keys that seal each value of `written` that reads as the hit
    /// alone, beside `places` (the keys the plan marked before), and whether
    /// the file is sealed whole as well. `op`'s copy is left as the door
    /// read it last.
    fn value_seals(
        &mut self,
        kept: &KeptValues,
        record: EntityId,
        written: &[u8],
        places: &KeyPlaces,
        op: &mut BatchOp,
        clean: &dyn Fn(&BatchOp) -> bool,
    ) -> Result<(Vec<FileKey>, bool)> {
        let mut keys = Vec::new();
        // A key in a member: the hit may sit in a member, whose values are
        // no values of the file's own tree.
        if places.iter().any(|(path, _)| !path.is_empty()) {
            return Ok((keys, true));
        }
        let mut marks = Vec::new();
        for (_, spans) in places {
            for &(start, end) in spans {
                marks.push(byte_at(start)?..byte_at(end)?);
            }
        }
        let read = |bytes: &[u8]| hit(kept, &record, bytes);
        let mut seals = 0;
        loop {
            let Some(mut filled) = split_phrase::filled_in_place(written, &marks) else {
                return Ok((keys, true));
            };
            put_copy(op, std::mem::take(&mut *filled));
            if clean(op) {
                break;
            }
            if seals == MAX_SEALS_PER_OP {
                return Ok((keys, true));
            }
            let Some((mut tree, node, form)) = split_phrase::decoded(copy_of(op)) else {
                return Ok((keys, true));
            };
            let Some((path, reason)) = smallest_hit(&tree.0, form, &read)? else {
                return Ok((keys, true));
            };
            if path.is_empty() {
                return Ok((keys, true));
            }
            let Some(span) = split_phrase::part_span(&node, &path) else {
                return Ok((keys, true));
            };
            let gaps = outside(span, &marks);
            if gaps.is_empty() {
                return Ok((keys, true));
            }
            let part = part_at(&mut tree.0, &path).ok_or(Error::InvariantViolation(
                "a file seal's path names no value in its tree",
            ))?;
            // A file keeps its bytes as written: its key is a span of them,
            // which a ruling unmarks and never writes back, so it is held
            // as read.
            let (value, _) = value_bytes(part, form)?;
            self.at = Some((record, "file".to_owned()));
            self.handle(&value, reason)?;
            for gap in gaps {
                marks.push(gap.clone());
                keys.push(FileKey {
                    path: Vec::new(),
                    span: gap,
                    reason,
                    value: value.clone(),
                    custody: None,
                });
            }
            seals += 1;
        }
        // The copy a serving door would rebuild is read again: one the door
        // still reads as a hit leaves the file sealed whole.
        let served = united_places(places.clone(), &keys)?;
        put_copy(op, masked_copy(written, &served)?);
        let sealed = !clean(op);
        Ok((keys, sealed))
    }
}

/// The parts of `span` no span of `marks` covers, in byte order.
fn outside(span: Range<usize>, marks: &[Range<usize>]) -> Vec<Range<usize>> {
    let mut held: Vec<&Range<usize>> = marks
        .iter()
        .filter(|mark| mark.start < span.end && span.start < mark.end)
        .collect();
    held.sort_by_key(|mark| mark.start);
    let mut gaps = Vec::new();
    let mut at = span.start;
    for mark in held {
        if mark.start > at {
            gaps.push(at..mark.start);
        }
        at = at.max(mark.end);
    }
    if at < span.end {
        gaps.push(at..span.end);
    }
    gaps
}

/// The plan's copy of the file put `op`, now `bytes`; the copy it held is
/// wiped.
fn put_copy(op: &mut BatchOp, bytes: Vec<u8>) {
    if let BatchOp::Put { data, .. } = op {
        replace_wiped(data, bytes);
    }
}

/// The bytes the file put `op` holds.
fn copy_of(op: &BatchOp) -> &[u8] {
    match op {
        BatchOp::Put { data, .. } => data,
        _ => &[],
    }
}

fn byte_at(at: u64) -> Result<usize> {
    usize::try_from(at).map_err(|_| Error::ArithmeticOverflow("masked file key span"))
}
