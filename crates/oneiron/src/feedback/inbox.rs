//! The open inbox's notes (ARCH-0056 #open-inbox): what anyone sent us, kept
//! for the triage sweep.
//!
//! A note arrives with no key and no moderation, so it is kept apart from the
//! vault's content: a side table that no recall, view or Dreamer job reads,
//! read back only through [`Vault::feedback_inbox`], which the host serves to
//! the owner. Notes are numbered in arrival order, from 1; a sweep keeps the
//! last number it read and asks for the notes after it. Bounding what one
//! note may carry and how many arrive is the host's (its body row and flood
//! cap); nothing here reads a note's text, except a body that declares itself
//! an issue signature, which lands only once it reads back as one (FIX 7684).
use std::ops::Bound;

use serde::{Deserialize, Serialize};

use super::report::{REPORT_SIGNATURE_SCHEMA, received_issue_signature};
use super::{FeedbackBundle, FeedbackCategory, FeedbackEncoding, decode_feedback_bundle_as};
use crate::side_table::{self, Named, SideTable};
use crate::{Error, Result, Vault};

/// Every note, keyed by its arrival number.
const NOTES: SideTable<u64, FeedbackInboxNote, Named> = SideTable::new(&side_table::FEEDBACK_INBOX);

/// How a note reached the inbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackInboxVia {
    /// A plain GET link carrying the text in its query.
    Link,
    /// A POST carrying the text as its body.
    Post,
    /// A POST carrying a v1 feedback bundle a vault sent.
    Bundle,
    /// A POST carrying a content-free issue signature a vault's Coach sent
    /// (`oneiron.issue_signature.v1`), read back typed; its text is the exact
    /// canonical body.
    Signature,
}

/// Whether `body` declares itself an issue signature: a JSON object whose
/// `schema` is `oneiron.issue_signature.v1`. Such a body lands only through
/// [`Vault::take_feedback_signature`], once it [`reads_as_issue_signature`].
#[must_use]
pub fn declares_issue_signature(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body).is_ok_and(|value| {
        value.get("schema").and_then(serde_json::Value::as_str) == Some(REPORT_SIGNATURE_SCHEMA)
    })
}

/// One note in the inbox.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackInboxNote {
    /// Arrival number, from 1.
    pub seq: u64,
    /// Vault clock seconds when the note landed.
    pub received_at: u64,
    pub via: FeedbackInboxVia,
    /// The text as sent; a bundle's note, or empty when it carries none.
    pub text: String,
    /// The kind the sender named, if any.
    pub category: Option<FeedbackCategory>,
    /// The bundle a vault sent, decoded; `None` for a plain note.
    pub bundle: Option<FeedbackBundle>,
}

/// Whether `body` reads back as an issue signature, byte for byte: what
/// [`Vault::take_feedback_signature`] lands.
#[must_use]
pub fn reads_as_issue_signature(body: &str) -> bool {
    received_issue_signature(body).is_some()
}

impl Vault {
    /// Lands one plain note and returns its arrival number.
    pub fn take_feedback_note(
        &self,
        via: FeedbackInboxVia,
        text: String,
        category: Option<FeedbackCategory>,
    ) -> Result<u64> {
        match via {
            FeedbackInboxVia::Bundle => {
                return Err(Error::InvalidConfig(
                    "a feedback bundle lands through take_feedback_bundle".into(),
                ));
            }
            FeedbackInboxVia::Signature => {
                return Err(Error::InvalidConfig(
                    "an issue signature lands through take_feedback_signature".into(),
                ));
            }
            FeedbackInboxVia::Link | FeedbackInboxVia::Post => {}
        }
        self.land_feedback_note(via, text, category, None)
    }

    /// Lands one content-free issue signature a vault's Coach sent and
    /// returns its arrival number. A body that does not read back as one,
    /// byte for byte, is refused and nothing lands, so its sender never
    /// records it delivered (FIX 7684).
    pub fn take_feedback_signature(&self, body: &str) -> Result<u64> {
        if !reads_as_issue_signature(body) {
            return Err(Error::InvalidConfig("invalid issue signature".into()));
        }
        self.land_feedback_note(FeedbackInboxVia::Signature, body.to_owned(), None, None)
    }

    /// Lands one v1 feedback bundle a vault sent and returns its arrival
    /// number. Bytes that are not a bundle are refused and nothing lands.
    pub fn take_feedback_bundle(&self, bytes: &[u8]) -> Result<u64> {
        self.take_feedback_bundle_as(FeedbackEncoding::V1, bytes)
    }

    /// Lands one feedback bundle sent under `encoding`; a v2 bundle keeps its
    /// proposal on the stored row.
    pub fn take_feedback_bundle_as(&self, encoding: FeedbackEncoding, bytes: &[u8]) -> Result<u64> {
        let bundle = decode_feedback_bundle_as(encoding, bytes)
            .map_err(|_| Error::InvalidConfig("invalid feedback bundle".into()))?;
        let text = bundle.user_note.clone().unwrap_or_default();
        let category = Some(bundle.category);
        self.land_feedback_note(FeedbackInboxVia::Bundle, text, category, Some(bundle))
    }

    fn land_feedback_note(
        &self,
        via: FeedbackInboxVia,
        text: String,
        category: Option<FeedbackCategory>,
        bundle: Option<FeedbackBundle>,
    ) -> Result<u64> {
        let received_at = self.store.clock.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
            let seq = match NOTES.iter_rev_from(&self.store, txn, &[])?.next() {
                None => 1,
                Some(row) => row?
                    .0
                    .checked_add(1)
                    .ok_or(Error::IndexOverflow("feedback inbox sequence"))?,
            };
            let note = FeedbackInboxNote {
                seq,
                received_at,
                via,
                text,
                category,
                bundle,
            };
            NOTES.put(&self.store, txn, &seq, &note)?;
            Ok(seq)
        })
    }

    /// Up to `limit` notes after arrival number `after` (from the first when
    /// `None`), oldest first.
    pub fn feedback_inbox(
        &self,
        after: Option<u64>,
        limit: usize,
    ) -> Result<Vec<FeedbackInboxNote>> {
        let txn = self.store.env.read_txn()?;
        let start = after.map_or(Bound::Unbounded, Bound::Excluded);
        let mut notes = Vec::new();
        for row in NOTES
            .iter_range(&self.store, &txn, start.as_ref(), Bound::Unbounded)?
            .take(limit)
        {
            let (seq, note) = row?;
            if note.seq != seq {
                return Err(Error::CorruptedIndex("feedback inbox identity"));
            }
            notes.push(note);
        }
        Ok(notes)
    }
}
