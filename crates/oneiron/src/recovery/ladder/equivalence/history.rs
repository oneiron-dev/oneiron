//! Equality of one frozen EntityDoc history, in native field order.

use crate::error::Result;
use crate::recovery::canonical::{
    CanonicalDocumentFork, CanonicalDocumentPin, CanonicalDocumentReceipt,
    CanonicalDocumentVersion, CanonicalEntityDocumentHistory,
};

use super::metadata::MetadataComparison;
use super::{compare_bytes, compare_optional_text, compare_rows, compare_value};

#[derive(Default)]
pub(super) struct HistoryComparison {
    group: Group,
    next: usize,
    member: usize,
    byte: usize,
    part: Part,
    metadata: MetadataComparison,
}

#[derive(Default)]
enum Group {
    #[default]
    Versions,
    Shallow,
    Pins,
    Receipts,
    Forks,
    Purges,
    Complete,
}

#[derive(Default, PartialEq, Eq)]
enum Part {
    #[default]
    First,
    Second,
    Third,
    Fourth,
    Fifth,
}

impl HistoryComparison {
    pub(super) fn advance(
        &mut self,
        actual: &mut Option<CanonicalEntityDocumentHistory>,
        wanted: &Option<CanonicalEntityDocumentHistory>,
    ) -> Result<bool> {
        let (Some(actual), Some(wanted)) = (actual.as_mut(), wanted.as_ref()) else {
            compare_value(&actual.is_some(), &wanted.is_some())?;
            return Ok(true);
        };
        let CanonicalEntityDocumentHistory {
            versions,
            shallow,
            pins,
            receipts,
            forks,
            purges,
        } = actual;
        let (done, next_group) = match self.group {
            Group::Versions => (self.versions(versions, &wanted.versions)?, Group::Shallow),
            Group::Shallow => {
                compare_value(shallow, &wanted.shallow)?;
                (true, Group::Pins)
            }
            Group::Pins => (self.pins(pins, &wanted.pins)?, Group::Receipts),
            Group::Receipts => (self.receipts(receipts, &wanted.receipts)?, Group::Forks),
            Group::Forks => (self.forks(forks, &wanted.forks)?, Group::Purges),
            Group::Purges => (
                compare_rows(purges, &wanted.purges, &mut self.next)?,
                Group::Complete,
            ),
            Group::Complete => return Ok(true),
        };
        if done {
            *self = Self {
                group: next_group,
                ..Self::default()
            };
        }
        Ok(matches!(self.group, Group::Complete))
    }

    fn finish_row(&mut self) {
        self.next += 1;
        self.member = 0;
        self.byte = 0;
        self.part = Part::First;
        self.metadata = MetadataComparison::default();
    }

    fn versions(
        &mut self,
        actual: &mut [CanonicalDocumentVersion],
        wanted: &[CanonicalDocumentVersion],
    ) -> Result<bool> {
        compare_value(&actual.len(), &wanted.len())?;
        let Some(CanonicalDocumentVersion {
            parents,
            prefix,
            suffix,
            middle,
            metadata,
            summary_meta,
        }) = actual.get_mut(self.next)
        else {
            return Ok(true);
        };
        let expected = &wanted[self.next];
        if self.part == Part::First {
            if compare_rows(parents, &expected.parents, &mut self.member)? {
                compare_value(prefix, &expected.prefix)?;
                compare_value(suffix, &expected.suffix)?;
                self.part = Part::Second;
                self.member = 0;
            }
            return Ok(false);
        }
        if self.part == Part::Second {
            if compare_bytes(
                middle.as_bytes(),
                expected.middle.as_bytes(),
                &mut self.byte,
            )? {
                self.part = Part::Third;
                self.byte = 0;
            }
            return Ok(false);
        }
        if self.part == Part::Third {
            if self.metadata.advance(metadata, &expected.metadata)? {
                self.part = Part::Fourth;
            }
            return Ok(false);
        }
        if self
            .metadata
            .advance(summary_meta, &expected.summary_meta)?
        {
            self.finish_row();
        }
        Ok(false)
    }

    fn pins(
        &mut self,
        actual: &[CanonicalDocumentPin],
        wanted: &[CanonicalDocumentPin],
    ) -> Result<bool> {
        compare_value(&actual.len(), &wanted.len())?;
        let Some(CanonicalDocumentPin {
            citation,
            document,
            actor,
            version,
            start,
            end,
            quote,
            hash,
        }) = actual.get(self.next)
        else {
            return Ok(true);
        };
        let expected = &wanted[self.next];
        if self.byte == 0 {
            compare_value(citation, &expected.citation)?;
            compare_value(document, &expected.document)?;
            compare_value(actor, &expected.actor)?;
            compare_value(version, &expected.version)?;
            compare_value(start, &expected.start)?;
            compare_value(end, &expected.end)?;
        }
        if compare_bytes(quote.as_bytes(), expected.quote.as_bytes(), &mut self.byte)? {
            compare_value(hash, &expected.hash)?;
            self.finish_row();
        }
        Ok(false)
    }

    fn receipts(
        &mut self,
        actual: &[CanonicalDocumentReceipt],
        wanted: &[CanonicalDocumentReceipt],
    ) -> Result<bool> {
        compare_value(&actual.len(), &wanted.len())?;
        let Some(CanonicalDocumentReceipt {
            receipt,
            proposal,
            fork,
            actor,
            verb,
            at,
            before,
            after,
            read_refs,
        }) = actual.get(self.next)
        else {
            return Ok(true);
        };
        let expected = &wanted[self.next];
        if self.member == 0 {
            compare_value(receipt, &expected.receipt)?;
            compare_value(proposal, &expected.proposal)?;
            compare_value(fork, &expected.fork)?;
            compare_value(actor, &expected.actor)?;
            compare_value(verb, &expected.verb)?;
            compare_value(at, &expected.at)?;
            compare_value(before, &expected.before)?;
            compare_value(after, &expected.after)?;
        }
        if compare_rows(read_refs, &expected.read_refs, &mut self.member)? {
            self.finish_row();
        }
        Ok(false)
    }

    fn forks(
        &mut self,
        actual: &mut [CanonicalDocumentFork],
        wanted: &[CanonicalDocumentFork],
    ) -> Result<bool> {
        compare_value(&actual.len(), &wanted.len())?;
        let Some(CanonicalDocumentFork {
            fork,
            proposal,
            parent_document,
            actor,
            opened_at,
            rewrite,
            status,
            base,
            output,
            output_metadata,
            proposal_index,
            proposal_len,
            proposal_settled,
            proposal_opener_lineage,
            read_refs,
            keep,
        }) = actual.get_mut(self.next)
        else {
            return Ok(true);
        };
        let expected = &wanted[self.next];
        match self.part {
            Part::First => {
                if self.byte == 0 {
                    compare_value(fork, &expected.fork)?;
                    compare_value(proposal, &expected.proposal)?;
                    compare_value(parent_document, &expected.parent_document)?;
                    compare_value(actor, &expected.actor)?;
                    compare_value(opened_at, &expected.opened_at)?;
                    compare_value(rewrite, &expected.rewrite)?;
                    compare_value(status, &expected.status)?;
                    compare_value(base, &expected.base)?;
                }
                if compare_optional_text(output, &expected.output, &mut self.byte)? {
                    self.part = Part::Second;
                    self.byte = 0;
                }
            }
            Part::Second => {
                if self
                    .metadata
                    .advance_optional(output_metadata, &expected.output_metadata)?
                {
                    self.part = Part::Third;
                }
            }
            Part::Third => {
                if self.member == 0 {
                    compare_value(proposal_index, &expected.proposal_index)?;
                    compare_value(proposal_len, &expected.proposal_len)?;
                    compare_value(proposal_settled, &expected.proposal_settled)?;
                }
                if compare_rows(
                    proposal_opener_lineage,
                    &expected.proposal_opener_lineage,
                    &mut self.member,
                )? {
                    self.part = Part::Fourth;
                    self.member = 0;
                }
            }
            Part::Fourth => {
                if compare_rows(read_refs, &expected.read_refs, &mut self.member)? {
                    self.part = Part::Fifth;
                    self.member = 0;
                }
            }
            Part::Fifth => {
                if compare_optional_text(keep, &expected.keep, &mut self.byte)? {
                    self.finish_row();
                }
            }
        }
        Ok(false)
    }
}
