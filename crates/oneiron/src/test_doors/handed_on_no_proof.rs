//! Door for `tests/handed_on_person_sweep.rs` (COMMIT 5 F1/F2/F5): a no-proof handle
//! whose host origin carries the handed-on mark when asked.

use crate::memory::{HostWriteOrigin, Memory};
use crate::{ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, Vault, WriteActor};
use crate::{WriteEnvelope, WriteProvenance};

/// `vault.memory(owner, Human)` bound to a host origin whose envelope carries
/// `handed_on`'s mark: marked no-proof when true, unmarked no-proof when
/// false. No read proof is bound.
///
/// At the head `with_host_origin` copies the envelope's mark to the handle;
/// at `de21ae6c` it ignores it, so the same call is unmarked there. Uses
/// only `de21ae6c` APIs.
///
/// # Errors
///
/// A provenance payload that does not encode (never for the fixed test
/// string).
pub fn memory_with_host_origin_for_test(
    vault: &Vault,
    owner: EntityId,
    handed_on: bool,
) -> crate::error::Result<Memory<'_>> {
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    let actor = if handed_on {
        actor.with_handed_on_credential()
    } else {
        actor
    };
    let provenance = WriteProvenance::new(rmpv::Value::from("handed-on-no-proof"))?;
    let envelope = WriteEnvelope::new(
        actor,
        ClaimSource::Generated,
        provenance,
        ClaimApprovalStatus::Auto,
    );
    let origin = HostWriteOrigin::new(envelope);
    Ok(vault
        .memory(owner, EdgeActorClass::Human)
        .with_host_origin(origin))
}
