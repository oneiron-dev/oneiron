//! A witnessed reply's typed record assertions as UniFFI crosses them
//! (OF-063, FIX 10261), and their one lowering onto the engine's
//! `WitnessAssertions`.

use oneiron::memory as engine;

use crate::codec::Lower;
use crate::error::OneironError;

/// The records one witnessed reply names as cited or created, as the
/// generated facade [`crate::RecordRef`]. Both lists name records that
/// already exist; the engine judges each by its `id` through the writer's
/// own read, and records a `created` record whose birth does not prove the
/// writer made it as `creation_not_proven`. A supplied assertion is the
/// engine's input, never proof of creation.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct WitnessAssertions {
    /// Records the reply cites.
    pub cited: Vec<crate::RecordRef>,
    /// Records the reply reports it created.
    pub created: Vec<crate::RecordRef>,
}

impl Lower<engine::WitnessAssertions> for WitnessAssertions {
    fn lower(self) -> Result<engine::WitnessAssertions, OneironError> {
        Ok(engine::WitnessAssertions {
            cited: self.cited.into_iter().map(record_ref).collect(),
            created: self.created.into_iter().map(record_ref).collect(),
        })
    }
}

/// One typed record ref as the engine names it; `kind`, `short_id` and
/// `label` stay display data.
fn record_ref(record: crate::RecordRef) -> oneiron::lens::RecordRef {
    oneiron::lens::RecordRef {
        kind: record.kind,
        id: record.id,
        short_id: record.short_id,
        label: record.label,
    }
}
