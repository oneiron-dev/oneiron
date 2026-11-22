//! Door for `tests/handed_on_session_run.rs`: the write actor a request
//! presenting a verified slip writes as ([`crate::auth::CoreAuth::write_actor`]),
//! which `self.off_record.execute` binds its session run to. No test server
//! runs a code-mode host, so the run itself is not reachable from a test.

use oneiron::authority::VerifiedSlip;
use oneiron::{EdgeActorClass, EntityId, WriteActor};

use crate::auth::CoreAuth;

/// The write actor `(actor, class)` of a request presenting `slip`;
/// `unattenuated` says the slip carries no caveat, as the bearer door reads
/// it. `None` when the slip admits no request.
pub fn write_actor_for(
    slip: VerifiedSlip,
    unattenuated: bool,
    actor: EntityId,
    class: EdgeActorClass,
) -> Option<WriteActor> {
    CoreAuth::from_verified(slip, unattenuated)
        .ok()
        .map(|auth| auth.write_actor(actor, class))
}
