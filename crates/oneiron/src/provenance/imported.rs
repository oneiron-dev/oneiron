//! Internal imported-edge admission. No permit is created by this door.

use super::*;
use crate::claim::ClaimSource;

/// Provider identity belongs to the imported relationship's scope. The canonical
/// provenance wrapper leaves `evid` absent: any value there conflicts with the
/// record's `actor_class` under the pinned parser. This scope is data, never actor
/// or permit authority.
const IMPORTED_EVIDENCE_SCOPE_KEY: &str = "imported_evidence";

fn imported_evidence_scope(evidence: Value) -> Value {
    Value::Map(vec![(Value::from(IMPORTED_EVIDENCE_SCOPE_KEY), evidence)])
}

pub(super) fn stamp_imported_source(body: &mut ClaimBody, evidence: Value) {
    body.source = Some(ClaimSource::Imported);
    body.scope = Some(imported_evidence_scope(evidence));
}

#[cfg(test)]
mod tests;
