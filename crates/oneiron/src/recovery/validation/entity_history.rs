//! Ordered row history checks over the same frozen canonical document.

use super::{id, invalid, strict, validate_document_metadata_field, validate_summary_meta_field};
use crate::error::Result;
use crate::recovery::canonical::{CanonicalEntityDocument, CanonicalForkStatus};
use crate::store::canonical_document::CanonicalDocumentTexts;
use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Unbounded};

#[derive(Default)]
pub(super) struct HistoryValidation {
    stage: Stage,
    next: usize,
    texts: Vec<String>,
    text_builder: Option<CanonicalDocumentTexts>,
    reached: Vec<bool>,
    metadata: MetadataRows,
    parent_next: usize,
    pin_quote: PinQuote,
}

#[derive(Default)]
enum Stage {
    #[default]
    Header,
    HeaderMetadata,
    HeaderSummary,
    HistoryHeader,
    Texts,
    Head,
    Versions,
    VersionSummary,
    VersionParents,
    VersionParentOrder,
    PinOrder,
    Pins,
    PinQuote,
    ReceiptOrder,
    Receipts,
    ForkOrder,
    Forks,
    ForkMetadata,
    ForkState,
    PurgeOrder,
    Purges,
    Complete,
}

impl HistoryValidation {
    pub(super) fn advance_row(&mut self, row: &CanonicalEntityDocument) -> Result<bool> {
        let history = || {
            row.history
                .as_ref()
                .expect("history cursor stays on its immutable row")
        };
        loop {
            match self.stage {
                Stage::Header => {
                    strict(row.record_fields.iter())?;
                    if row.record_fields.iter().any(|field| {
                        !crate::ports::is_metadata_field(field)
                            || row.field.as_deref() == Some(field.as_str())
                    }) || (row.field.is_none() && !row.record_fields.is_empty())
                    {
                        return Err(invalid("document native record fields"));
                    }
                    self.stage = Stage::HeaderMetadata;
                    continue;
                }
                Stage::HeaderMetadata => {
                    if !self.metadata.advance(&row.metadata, |field, bytes| {
                        validate_document_metadata_field(field, bytes, row.field.as_deref())
                    })? {
                        return Ok(false);
                    }
                    self.stage = Stage::HeaderSummary;
                    continue;
                }
                Stage::HeaderSummary => {
                    if !self
                        .metadata
                        .advance(&row.summary_meta, validate_summary_meta_field)?
                    {
                        return Ok(false);
                    }
                    self.stage = Stage::HistoryHeader;
                    continue;
                }
                Stage::HistoryHeader => {
                    let Some(history) = &row.history else {
                        self.stage = Stage::Complete;
                        return Ok(true);
                    };
                    if !history.shallow
                        && history.pins.is_empty()
                        && history.receipts.is_empty()
                        && history.forks.is_empty()
                        && history.purges.is_empty()
                    {
                        return Err(invalid("entity document history without causal state"));
                    }
                    if !history.purges.is_empty() && !history.shallow {
                        return Err(invalid("entity document purge without a purge floor"));
                    }
                    self.text_builder = Some(CanonicalDocumentTexts::new(history));
                    self.stage = Stage::Texts;
                    return Ok(false);
                }
                Stage::Texts => {
                    let history = history();
                    let builder = self
                        .text_builder
                        .as_mut()
                        .expect("text reconstruction was started");
                    if !builder.advance_row(history)? {
                        return Ok(false);
                    }
                    self.texts = self
                        .text_builder
                        .take()
                        .expect("completed text reconstruction")
                        .into_texts();
                    self.stage = Stage::Head;
                    continue;
                }
                Stage::Head => {
                    let history = history();
                    let head = self
                        .texts
                        .len()
                        .checked_sub(1)
                        .ok_or(invalid("entity document history has no head"))?;
                    if self.texts[head] != row.text
                        || history.versions[head].metadata != row.metadata
                    {
                        return Err(invalid("entity document head version"));
                    }
                    self.reached = vec![false; self.texts.len()];
                    self.reached[head] = true;

                    self.next = history.versions.len();
                    self.stage = Stage::Versions;
                    return Ok(false);
                }
                Stage::Versions => {
                    let history = history();
                    let Some(index) = self.next.checked_sub(1) else {
                        self.start(Stage::PinOrder);
                        continue;
                    };
                    let version = &history.versions[index];
                    if !self.metadata.advance(&version.metadata, |field, bytes| {
                        validate_document_metadata_field(field, bytes, row.field.as_deref())
                    })? {
                        return Ok(false);
                    }
                    self.stage = Stage::VersionSummary;
                    continue;
                }
                Stage::VersionSummary => {
                    let history = history();
                    let index = self.next - 1;
                    let version = &history.versions[index];
                    if !self
                        .metadata
                        .advance(&version.summary_meta, validate_summary_meta_field)?
                    {
                        return Ok(false);
                    }
                    if !self.reached[index] {
                        return Err(invalid("entity document version is not before its head"));
                    }
                    if history.shallow && index > 0 && version.parents.is_empty() {
                        return Err(invalid("entity document version precedes its purge floor"));
                    }
                    self.parent_next = 0;
                    self.stage = Stage::VersionParentOrder;
                    continue;
                }
                Stage::VersionParentOrder => {
                    let version = &history().versions[self.next - 1];
                    if self.parent_next == version.parents.len() {
                        self.parent_next = 0;
                        self.stage = Stage::VersionParents;
                        continue;
                    }
                    strict(
                        version.parents[self.parent_next.saturating_sub(1)..=self.parent_next]
                            .iter()
                            .copied(),
                    )?;
                    self.parent_next += 1;
                    return Ok(false);
                }
                Stage::VersionParents => {
                    let index = self.next - 1;
                    let version = &history().versions[index];
                    let Some(&parent) = version.parents.get(self.parent_next) else {
                        self.next = index;
                        self.stage = Stage::Versions;
                        continue;
                    };
                    let parent = parent as usize;
                    if parent >= index {
                        return Err(invalid("entity document version parent"));
                    }
                    self.reached[parent] = true;
                    self.parent_next += 1;
                    return Ok(false);
                }
                Stage::PinOrder => {
                    let history = history();
                    if self.next == history.pins.len() {
                        self.start(Stage::Pins);
                        continue;
                    }
                    strict(
                        history.pins[self.next.saturating_sub(1)..=self.next]
                            .iter()
                            .map(|pin| pin.citation),
                    )?;
                }
                Stage::Pins => {
                    let history = history();
                    let Some(pin) = history.pins.get(self.next) else {
                        self.start(Stage::ReceiptOrder);
                        continue;
                    };
                    for value in [pin.citation, pin.document].into_iter().chain(pin.actor) {
                        id(value)?;
                    }
                    self.texts
                        .get(pin.version as usize)
                        .ok_or(invalid("entity document pin version"))?;
                    self.pin_quote = PinQuote::default();
                    self.stage = Stage::PinQuote;
                    return Ok(false);
                }
                Stage::PinQuote => {
                    let pin = &history().pins[self.next];
                    let text = &self.texts[pin.version as usize];
                    let (start, end) = (pin.start as usize, pin.end as usize);
                    if !self.pin_quote.advance(text, start, end) {
                        return Ok(false);
                    }
                    if start > end
                        || end > self.pin_quote.chars
                        || self.pin_quote.quote != pin.quote
                        || blake3::hash(self.pin_quote.quote.as_bytes()).as_bytes() != &pin.hash
                    {
                        return Err(invalid("entity document pin quote"));
                    }
                    self.pin_quote = PinQuote::default();
                    self.stage = Stage::Pins;
                }
                Stage::ReceiptOrder => {
                    let history = history();
                    if self.next == history.receipts.len() {
                        self.start(Stage::Receipts);
                        continue;
                    }
                    strict(
                        history.receipts[self.next.saturating_sub(1)..=self.next]
                            .iter()
                            .map(|receipt| receipt.receipt),
                    )?;
                }
                Stage::Receipts => {
                    let history = history();
                    let Some(receipt) = history.receipts.get(self.next) else {
                        self.start(Stage::ForkOrder);
                        continue;
                    };
                    let version = |index: u32| (index as usize) < self.texts.len();
                    for value in [receipt.receipt, receipt.proposal, receipt.fork]
                        .into_iter()
                        .chain(receipt.actor)
                    {
                        id(value)?;
                    }
                    if !version(receipt.before) || !version(receipt.after) {
                        return Err(invalid("entity document receipt version"));
                    }
                }
                Stage::ForkOrder => {
                    let history = history();
                    if self.next == history.forks.len() {
                        self.start(Stage::Forks);
                        continue;
                    }
                    strict(
                        history.forks[self.next.saturating_sub(1)..=self.next]
                            .iter()
                            .map(|fork| fork.fork),
                    )?;
                }
                Stage::Forks => {
                    let history = history();
                    let Some(fork) = history.forks.get(self.next) else {
                        self.start(Stage::PurgeOrder);
                        continue;
                    };
                    let version = |index: u32| (index as usize) < self.texts.len();
                    for value in [fork.fork, fork.proposal, fork.parent_document]
                        .into_iter()
                        .chain(fork.actor)
                    {
                        id(value)?;
                    }
                    let pending = fork.status == CanonicalForkStatus::Pending;
                    match fork.base {
                        Some(base) if version(base) => {}
                        None if history.shallow && !pending => {}
                        _ => return Err(invalid("entity document fork base")),
                    }
                    self.stage = Stage::ForkMetadata;
                    continue;
                }
                Stage::ForkMetadata => {
                    let fork = &history().forks[self.next];
                    if let Some(metadata) = &fork.output_metadata
                        && !self.metadata.advance(metadata, |field, bytes| {
                            validate_document_metadata_field(field, bytes, row.field.as_deref())
                        })?
                    {
                        return Ok(false);
                    }
                    self.stage = Stage::ForkState;
                    continue;
                }
                Stage::ForkState => {
                    let fork = &history().forks[self.next];
                    let pending = fork.status == CanonicalForkStatus::Pending;
                    if fork.output_metadata.is_some() != pending
                        || fork.output.is_some() != pending
                        || fork.proposal_index >= fork.proposal_len
                    {
                        return Err(invalid("entity document fork state"));
                    }
                    self.stage = Stage::Forks;
                }
                Stage::PurgeOrder => {
                    let history = history();
                    if self.next == history.purges.len() {
                        self.start(Stage::Purges);
                        continue;
                    }
                    strict(
                        history.purges[self.next.saturating_sub(1)..=self.next]
                            .iter()
                            .map(|purge| purge.receipt),
                    )?;
                }
                Stage::Purges => {
                    let history = history();
                    let Some(purge) = history.purges.get(self.next) else {
                        self.start(Stage::Complete);
                        continue;
                    };
                    let version = |index: u32| (index as usize) < self.texts.len();
                    for value in [purge.receipt, purge.document]
                        .into_iter()
                        .chain(purge.actor)
                    {
                        id(value)?;
                    }
                    if !version(purge.requested) || !version(purge.applied) {
                        return Err(invalid("entity document purge version"));
                    }
                }

                Stage::Complete => return Ok(true),
            }
            self.next += 1;
            return Ok(false);
        }
    }

    fn start(&mut self, stage: Stage) {
        self.stage = stage;
        self.next = 0;
    }
}

/// A single sorted resume key; values stay in the frozen source map.
#[derive(Default)]
struct MetadataRows {
    after: Option<String>,
}

impl MetadataRows {
    fn advance(
        &mut self,
        fields: &BTreeMap<String, Vec<u8>>,
        validate: impl FnOnce(&str, &[u8]) -> Result<()>,
    ) -> Result<bool> {
        let bounds = (self.after.as_deref().map_or(Unbounded, Excluded), Unbounded);
        let Some((field, bytes)) = fields.range::<str, _>(bounds).next() else {
            self.after = None;
            return Ok(true);
        };
        validate(field, bytes)?;
        self.after = Some(field.clone());
        Ok(false)
    }
}

#[derive(Default)]
struct PinQuote {
    byte: usize,
    chars: usize,
    quote: String,
}

impl PinQuote {
    fn advance(&mut self, text: &str, start: usize, end: usize) -> bool {
        let Some(ch) = text[self.byte..].chars().next() else {
            return true;
        };
        if self.chars >= start && self.chars < end {
            self.quote.push(ch);
        }
        self.byte += ch.len_utf8();
        self.chars += 1;
        false
    }
}
