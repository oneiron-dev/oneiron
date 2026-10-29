//! A witnessed reply's typed record assertions (OF-063, FIX 10261), as a
//! napi object, and its one lowering onto the engine's `WitnessAssertions`.

use napi_derive::napi;

use super::NapiRecordRef;

/// The records one witnessed reply names as cited or created. Both lists
/// name records that already exist; the engine judges each by its `id`
/// through the writer's own read, and records a `created` record whose
/// birth does not prove the writer made it as `creation_not_proven`. A
/// supplied assertion is the engine's input, never proof of creation.
#[napi(object)]
pub struct NapiWitnessAssertions {
    /// Records the reply cites.
    pub cited: Vec<NapiRecordRef>,
    /// Records the reply reports it created.
    pub created: Vec<NapiRecordRef>,
}

impl NapiWitnessAssertions {
    /// The engine's assertions, field for field.
    pub(in crate::facade) fn to_engine(&self) -> oneiron::memory::WitnessAssertions {
        oneiron::memory::WitnessAssertions {
            cited: self.cited.iter().map(record_ref_to_engine).collect(),
            created: self.created.iter().map(record_ref_to_engine).collect(),
        }
    }
}

/// One typed record ref as the engine names it; `kind`, `short_id` and
/// `label` stay display data.
fn record_ref_to_engine(record: &NapiRecordRef) -> oneiron::lens::RecordRef {
    oneiron::lens::RecordRef {
        kind: record.kind.clone(),
        id: record.id.clone(),
        short_id: record.short_id.clone(),
        label: record.label.clone(),
    }
}
