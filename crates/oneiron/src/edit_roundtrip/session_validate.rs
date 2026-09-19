//! Engine adapter for the storage-independent edit session seam.
use super::{AppliedEdit, EditPlan, OfficeDoc};
use crate::Result;
pub trait EditSession {
    /// Identity of the writer/recalculator used by this session.
    fn engine_id(&self) -> oneiron_docedit::calc::EngineId {
        oneiron_docedit::calc::EngineId {
            engine: "external-session".to_owned(),
            version: "unattested".to_owned(),
        }
    }
    /// Stage 2: apply the plan to a copy and return the edited bytes.
    fn apply_edits(&self, doc: &OfficeDoc, plan: &EditPlan) -> Result<AppliedEdit>;

    /// Stage 3: refresh cached formula values in the edited bytes. Must
    /// preserve unknown parts; the corruption gate re-checks regardless.
    fn recalc(&self, doc: &OfficeDoc) -> Result<Vec<u8>>;

    /// Whether this session image can recalc (LibreOffice present).
    fn supports_recalc(&self) -> bool {
        true
    }
}

/// Adapts an organ session (including an in-process recalculator) to the vault
/// API without making the organ or calculator depend on storage errors.
pub struct DocumentSession<S> {
    session: S,
}

impl<S> DocumentSession<S> {
    #[must_use]
    pub fn new(session: S) -> Self {
        Self { session }
    }
}

impl<S: oneiron_docedit::roundtrip::EditSession> EditSession for DocumentSession<S> {
    fn engine_id(&self) -> oneiron_docedit::calc::EngineId {
        self.session.engine_id()
    }
    fn apply_edits(&self, doc: &OfficeDoc, plan: &EditPlan) -> Result<AppliedEdit> {
        self.session.apply_edits(doc, plan).map_err(Into::into)
    }
    fn recalc(&self, doc: &OfficeDoc) -> Result<Vec<u8>> {
        self.session.recalc(doc).map_err(Into::into)
    }
    fn supports_recalc(&self) -> bool {
        self.session.supports_recalc()
    }
}
