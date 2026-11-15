//! Door for `oneiron-server/tests/code_mode_host_verb_refusals.rs` (through
//! its `test_doors::code_mode_verbs`): a host write origin for a door-built
//! code-mode verb call, stamped from the credential's actor, as the code-run
//! dispatcher stamps one host-side for a guest's call.

use crate::memory::HostWriteOrigin;
use crate::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, WriteActor, WriteEnvelope,
    WriteProvenance,
};

/// A host write origin naming `actor` as a human holder: a `Generated`
/// envelope with empty provenance, proposed, as a test's refused call
/// carries it. The envelope's fields are never read short of the guest: the
/// binding admission, the credential gate and the guest admission judge the
/// caller, the verb and the vault only.
///
/// # Errors
///
/// The provenance payload's construction (never on this fixed value).
pub fn host_write_origin(actor: EntityId) -> crate::Result<HostWriteOrigin> {
    Ok(HostWriteOrigin::new(WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Human),
        ClaimSource::Generated,
        WriteProvenance::new(rmpv::Value::Map(Vec::new()))?,
        ClaimApprovalStatus::Proposed,
    )))
}
