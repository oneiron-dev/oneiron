//! Ordered row history checks over the same frozen canonical document.

use super::{id, invalid, strict, validate_document_metadata, validate_summary_meta};
use crate::error::Result;
use crate::recovery::canonical::{CanonicalEntityDocument, CanonicalForkStatus};
use crate::store::canonical_document::CanonicalDocumentTexts;

#[derive(Default)]
pub(super) struct HistoryValidation {
    stage: Stage,
    next: usize,
    texts: Vec<String>,
    text_builder: Option<CanonicalDocumentTexts>,
    reached: Vec<bool>,
}

#[derive(Default)]
enum Stage {
    #[default]
    Header,
    Texts,
    Head,
    Versions,
    PinOrder,
    Pins,
    ReceiptOrder,
    Receipts,
    ForkOrder,
    Forks,
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
                    validate_document_metadata(&row.metadata, row.field.as_deref())?;
                    validate_summary_meta(&row.summary_meta)?;
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
                    validate_document_metadata(&version.metadata, row.field.as_deref())?;
                    validate_summary_meta(&version.summary_meta)?;
                    if !self.reached[index] {
                        return Err(invalid("entity document version is not before its head"));
                    }
                    if history.shallow && index > 0 && version.parents.is_empty() {
                        return Err(invalid("entity document version precedes its purge floor"));
                    }
                    strict(version.parents.iter().copied())?;
                    for &parent in &version.parents {
                        let parent = parent as usize;
                        if parent >= index {
                            return Err(invalid("entity document version parent"));
                        }
                        self.reached[parent] = true;
                    }

                    self.next = index;
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
                    let text = self
                        .texts
                        .get(pin.version as usize)
                        .ok_or(invalid("entity document pin version"))?;
                    let (start, end) = (pin.start as usize, pin.end as usize);
                    let quote: String = text
                        .chars()
                        .skip(start)
                        .take(end.saturating_sub(start))
                        .collect();
                    if start > end
                        || end > text.chars().count()
                        || quote != pin.quote
                        || blake3::hash(quote.as_bytes()).as_bytes() != &pin.hash
                    {
                        return Err(invalid("entity document pin quote"));
                    }
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
                    if let Some(metadata) = &fork.output_metadata {
                        validate_document_metadata(metadata, row.field.as_deref())?;
                    }
                    if fork.output_metadata.is_some() != pending
                        || fork.output.is_some() != pending
                        || fork.proposal_index >= fork.proposal_len
                    {
                        return Err(invalid("entity document fork state"));
                    }
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
