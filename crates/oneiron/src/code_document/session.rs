//! Private Loro forks and persistent cursor-anchored symbol spans.

use super::codec::{frontier, hash, invalid};
use super::types::{CodeDocumentFrontier, CodeSpanAnchor, CodeSpanResolution};
use crate::entity_id::EntityId;
use crate::error::Result;
use loro::LoroDoc;
use loro::cursor::{Cursor, Side};

/// One editor's observed file state. Refresh explicitly to observe another
/// session. An edit is never silently re-diffed against an unseen newer body.
pub struct CodeDocumentSession {
    pub(super) doc: LoroDoc,
    pub(super) repo: String,
    pub(super) document_id: [u8; 32],
    pub(super) session_id: EntityId,
    pub(super) initial_hash: [u8; 32],
}

impl CodeDocumentSession {
    pub fn document_id(&self) -> [u8; 32] {
        self.document_id
    }
    pub fn session_id(&self) -> EntityId {
        self.session_id
    }
    pub fn text(&self) -> String {
        self.doc.get_text("body").to_string()
    }
    pub fn path(&self) -> Result<String> {
        Ok(self.frontier()?.path)
    }
    pub fn frontier(&self) -> Result<CodeDocumentFrontier> {
        frontier(&self.doc, &self.repo, self.document_id)
    }
    pub fn anchor_span(&self, start: usize, end: usize) -> Result<CodeSpanAnchor> {
        let text = self.text();
        if start > end || end > text.chars().count() {
            return Err(invalid());
        }
        let body = self.doc.get_text("body");
        let content: String = text.chars().skip(start).take(end - start).collect();
        Ok(CodeSpanAnchor {
            document_id: self.document_id,
            start: body
                .get_cursor(start, Side::Middle)
                .ok_or_else(invalid)?
                .encode(),
            end: body
                .get_cursor(end, Side::Middle)
                .ok_or_else(invalid)?
                .encode(),
            content_hash: hash(content.as_bytes()),
        })
    }
    pub fn resolve_span(&self, span: &CodeSpanAnchor) -> Result<CodeSpanResolution> {
        if span.document_id != self.document_id {
            return Err(invalid());
        }
        let start = Cursor::decode(&span.start).map_err(|_| invalid())?;
        let end = Cursor::decode(&span.end).map_err(|_| invalid())?;
        let (Ok(start), Ok(end)) = (
            self.doc.get_cursor_pos(&start),
            self.doc.get_cursor_pos(&end),
        ) else {
            return Ok(CodeSpanResolution::Drifted);
        };
        let (start, end) = (start.current.pos, end.current.pos);
        let text = self.text();
        if start > end || end > text.chars().count() {
            return Ok(CodeSpanResolution::Drifted);
        }
        let content: String = text.chars().skip(start).take(end - start).collect();
        if hash(content.as_bytes()) != span.content_hash {
            return Ok(CodeSpanResolution::Drifted);
        }
        Ok(CodeSpanResolution::Mapped { start, end })
    }
}
