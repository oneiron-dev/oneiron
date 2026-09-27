//! Revision-pinned quote pointers derived from engine-issued span selections.

use serde::Serialize;

use crate::EntityId;
#[cfg(feature = "sync")]
use crate::claim::ScopedRead;
#[cfg(feature = "sync")]
use crate::error::{Error, Result};
#[cfg(feature = "sync")]
use crate::lens::generated_ui::GeneratedUiRender;
#[cfg(feature = "sync")]
use crate::ports::EntityStoreRead;
#[cfg(feature = "sync")]
use crate::registry::ENTITY_TYPE_MESSAGE;

use super::LensReadHandle;
#[cfg(feature = "sync")]
use super::{LensRenderFrame, LensSpanSelectionRequest};

/// Half-open offsets in Unicode scalar values, not UTF-8 bytes or UTF-16 units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LensQuoteRange {
    pub start: usize,
    pub end: usize,
}

/// An engine-issued quote pointer. It carries no copy of the selected text.
/// The private selection is used to re-prove the pointer at the render boundary;
/// only the canonical message/revision/range triple is serialized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LensQuoteHandle {
    reply_to_message_id: EntityId,
    reply_to_revision_id: String,
    reply_to_range: LensQuoteRange,
    #[serde(skip)]
    selection: LensReadHandle,
}

impl LensQuoteHandle {
    #[must_use]
    pub fn reply_to_message_id(&self) -> EntityId {
        self.reply_to_message_id
    }

    #[must_use]
    pub fn reply_to_revision_id(&self) -> &str {
        &self.reply_to_revision_id
    }

    #[must_use]
    pub fn reply_to_range(&self) -> LensQuoteRange {
        self.reply_to_range
    }
}

#[cfg(feature = "sync")]
impl LensRenderFrame {
    /// Select a MESSAGE span and issue its revision-pinned quote triple.
    /// The client supplies only a rendered atom, handle name and scalar offsets.
    pub fn select_quote(
        &self,
        read: &ScopedRead<'_>,
        render: &GeneratedUiRender,
        request: &LensSpanSelectionRequest,
    ) -> Result<LensQuoteHandle> {
        let selected = self.select_span(read, render, request)?;
        self.quote_from_span(read, render, &selected)
    }

    /// Convert an issued span selection to a quote, re-proving its render,
    /// disclosure scope, MESSAGE identity and pinned frontier at the boundary.
    pub fn quote_from_span(
        &self,
        read: &ScopedRead<'_>,
        render: &GeneratedUiRender,
        selected: &LensReadHandle,
    ) -> Result<LensQuoteHandle> {
        let row = self.resolve_read_handle(read, render, selected)?;
        let span = selected
            .span()
            .ok_or_else(|| Error::InvalidConfig("quote requires a selected span".into()))?;
        let (start, end) = span.range();
        if start == end {
            return Err(Error::InvalidConfig(
                "quote requires a nonempty span".into(),
            ));
        }
        let id = *row.target().entity_id();
        let txn = read.vault().store.env.read_txn()?;
        let record = read.vault().store.port_entity_record(&txn, &id)?;
        if record.is_none_or(|record| record.entity_type != ENTITY_TYPE_MESSAGE) {
            return Err(Error::InvalidConfig("quote requires a MESSAGE".into()));
        }
        Ok(LensQuoteHandle {
            reply_to_message_id: id,
            reply_to_revision_id: span
                .frontier()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            reply_to_range: LensQuoteRange { start, end },
            selection: selected.clone(),
        })
    }

    /// Refuse an old selection after its render, scope or source revision changes.
    pub fn prove_quote(
        &self,
        read: &ScopedRead<'_>,
        render: &GeneratedUiRender,
        quote: &LensQuoteHandle,
    ) -> Result<()> {
        let current = self.quote_from_span(read, render, &quote.selection)?;
        if current != *quote {
            return Err(Error::InvalidConfig(
                "quote no longer matches its selection".into(),
            ));
        }
        Ok(())
    }
}
