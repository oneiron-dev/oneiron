//! Storage-independent document editing, integrity checks and retained proposals.
//!
//! `ArtifactStorage` keeps vault access outside this crate. A host supplies its
//! own storage, error mapping, and atomic settle transaction; this crate never
//! imports the host engine or opens an LMDB environment.

pub mod anchored_annotation;
pub mod blob_artifact;
pub mod edit_roundtrip;
pub mod edit_settle;
pub mod error;

use edit_roundtrip::{EditOutcome, EditPlan, EditSession, OfficeFormat, run_edit_roundtrip};

/// A consistent artifact snapshot for one edit. Implementations must read the
/// head and its bytes together, not mix versions from separate reads.
#[derive(Debug, Clone)]
pub struct ArtifactSnapshot {
    pub version: u64,
    pub media_type: String,
    pub bytes: Vec<u8>,
}

/// Host storage boundary for the read-only retained-proposal stage.
/// A host owns atomic version writes, annotation replay, and consent checks.
pub trait ArtifactStorage {
    type Id;
    type Error: From<error::Error>;

    fn snapshot(
        &self,
        artifact: &Self::Id,
    ) -> std::result::Result<Option<ArtifactSnapshot>, Self::Error>;
    fn missing_artifact(&self) -> Self::Error;
}

/// Inspect and edit a stored artifact copy without modifying the store.
/// The base version is bound to the snapshot used for validation; settle must
/// recheck the head within its own write transaction.
pub fn propose_artifact_edit<T: ArtifactStorage, S: EditSession>(
    storage: &T,
    artifact: &T::Id,
    session: &S,
    plan: &EditPlan,
    run_ref: &str,
) -> std::result::Result<EditOutcome, T::Error> {
    let snapshot = storage
        .snapshot(artifact)?
        .ok_or_else(|| storage.missing_artifact())?;
    let format = OfficeFormat::from_media_type(&snapshot.media_type)?;
    let mut outcome = run_edit_roundtrip(session, &snapshot.bytes, format, plan, run_ref)?;
    if let EditOutcome::Proposed(proposal) = &mut outcome {
        proposal.base_version = Some(snapshot.version);
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    struct Missing;
    impl ArtifactStorage for Missing {
        type Id = u64;
        type Error = Error;
        fn snapshot(&self, _: &u64) -> Result<Option<ArtifactSnapshot>, Error> {
            Ok(None)
        }
        fn missing_artifact(&self) -> Error {
            Error::EditRoundtripFailed("artifact absent")
        }
    }

    struct Uncalled;
    impl EditSession for Uncalled {
        fn apply_edits(
            &self,
            _: &edit_roundtrip::OfficeDoc,
            _: &EditPlan,
        ) -> Result<edit_roundtrip::AppliedEdit, Error> {
            panic!("must not edit")
        }
        fn recalc(&self, _: &edit_roundtrip::OfficeDoc) -> Result<Vec<u8>, Error> {
            panic!("must not recalc")
        }
    }

    #[test]
    fn missing_artifact_never_invokes_session() {
        assert!(matches!(
            propose_artifact_edit(&Missing, &1, &Uncalled, &EditPlan::new(vec![]), "run"),
            Err(Error::EditRoundtripFailed("artifact absent"))
        ));
    }
}
