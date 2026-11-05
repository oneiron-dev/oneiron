//! Content-address and occurrence binding shared by local and replicated puts.

pub(crate) use crate::store::diagnostic_record::admission::{
    reject_off_record_diagnostic_sources, validate_diagnostic_event_admission,
};
pub(super) use crate::store::diagnostic_record::admission::{
    stored_diagnostic_event, validate_detector_id,
};
