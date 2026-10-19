//! Consult settlement on every housekeeping pass (DOOR-063), on every
//! substrate. The engine expires each consult whose deadline has passed as an
//! engine-caused lapse that takes no actor, then digests each expiry to its
//! own asker. The host's part is the route: the human-task follow-up resolver,
//! bound to the asker as its own sender, so no host or operator identity is
//! ever lent to a send. Runs on a blocking worker, off the request path.

use std::sync::Arc;

use oneiron::human_task::{HumanTaskError, resolve_native_human_route_for_actor};
use oneiron::memory::MemoryResult;
use oneiron::task_verb::ConsultDigestRoute;
use oneiron::{EntityId, Vault};

/// The registered outbound verb a digest travels as.
const DIGEST_VERB: &str = "send";

/// Expires every overdue consult in `vault` and schedules each asker's
/// digest, on the tick's pass and the owner's run-now pass alike. A failure
/// is logged by its code and the pass goes on.
pub(super) async fn settle_consults(vault: Arc<Vault>) {
    let settled = tokio::task::spawn_blocking(move || {
        // The asker is both the person addressed and the sender: the
        // engine schedules the digest as the task's own create owner.
        let resolve = |asker: EntityId| -> MemoryResult<Option<ConsultDigestRoute>> {
            match resolve_native_human_route_for_actor(&vault, asker, asker) {
                Ok(route) => Ok(Some(ConsultDigestRoute {
                    verb: DIGEST_VERB.to_owned(),
                    channel: route.channel,
                    target: route.target,
                })),
                Err(HumanTaskError::Engine(error)) => Err(error.into()),
                // An asker the vault cannot reach natively has no route;
                // the consult has expired all the same.
                Err(
                    HumanTaskError::NotAPerson
                    | HumanTaskError::NotNativelyReachable
                    | HumanTaskError::UnboundResponse,
                ) => Ok(None),
            }
        };
        vault.settle_due_consults(vault.now_recorded_at(), &resolve)
    })
    .await;
    match settled {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => tracing::warn!(code = %error.code, "consult settlement failed"),
        Err(error) => {
            tracing::warn!(
                panicked = error.is_panic(),
                "consult settlement task failed"
            );
        }
    }
}
