//! Exact read bindings for activated SKILL state changes.

#[cfg(feature = "sync")]
mod admission;
mod canonical;
mod checkpoint;
mod codec;
mod inherited;
mod inspect;
#[cfg(feature = "sync")]
mod prepare;
mod project;
mod register;
mod request;
mod settlement;

#[cfg(feature = "sync")]
pub(super) use admission::LocalSkillStateAdmission;
pub(super) use canonical::{CanonicalRebuiltDocument, CanonicalSkillState, has_witness};
pub(super) use checkpoint::{
    check_checkpoint_insert, check_checkpoint_op, is_checkpoint_root, validate_checkpoint_history,
    validate_image_history,
};
pub(super) use codec::recipient::{
    SkillStateContentSourceView, SkillStateDoorView, SkillStateFactView, SkillStateOperationView,
    SkillStateSharedSuccessView, SkillStateWriterView,
};
pub(super) use inherited::reconcile_for_persist;
pub(super) use inspect::{
    NativeMapFloorView, NativeMapInventory, NativeMapMutationView, NativeMapReplay,
    NativeMapWriteView, inspect as inspect_inventory,
};
pub(super) use project::project_state;
pub(super) use register::current_witness_bytes;
#[cfg(feature = "sync")]
pub(crate) use request::SkillStateSnapshot;
pub(super) use settlement::reconcile_settlement;

/// The local native publisher records no invented caller when none exists.
pub(super) const ANONYMOUS_COMMIT: &str = "native_skill_state";

/// A source comparison only. This does not make a received document an
/// admitted read or a native persistence owner.
#[cfg(feature = "sync")]
pub(super) fn project_source_state(
    document: &super::EntityDoc,
    body: &mut rmpv::Value,
) -> crate::error::Result<()> {
    project::project_state(document, body)
}
