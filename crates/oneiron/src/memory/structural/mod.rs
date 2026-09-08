//! Structural puts (habit checkins, companion records, imported-claim
//! admission, blob artifacts) and `author_take`.
//! Split from the flat `facade.rs`; surface re-exported by [`super`].

mod affiliated;
mod codec;
mod guards;
mod puts;
mod types;

pub use self::types::{
    AdmitImportedClaimInput, BlobArtifactInput, BlobVersionView, CompanionRecordInput,
    EntityRefReceipt, EntityView, HabitCheckinInput, StructuralEdgeSpec, StructuralPutInput,
    TextIndexField,
};

pub(super) use self::codec::{
    edge_kind_from_str, kind_string_for_type, registered_edge_weight, type_byte_for_kind,
};
pub(super) use self::guards::ensure_structural_create_in_txn;
