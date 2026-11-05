//! Owned per-put data. Only the later builder continuation produces final inputs.

use super::admission::FixedPut;

mod pending;
mod record_put;
pub(in crate::batch) use pending::PendingNativeSkillPut;
pub(crate) use record_put::AdmittedRecordDocumentPut;
