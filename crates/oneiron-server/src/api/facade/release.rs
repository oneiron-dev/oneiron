//! A facade answer's destination release, once its call has nothing left to wait on (FIX 8170),
//! and again for each request that waited on the same claimed invocation (FIX 7914, FIX 8212).
//! `released_reply`, `replayed_value` and `rows_still_admitted` are its call surface.
//! `oneiron::runtime_hooks::verb::InvocationRelease` is the record a claimed call keeps.

use super::*;
use oneiron::authority::PeerMachine;
use oneiron::runtime_hooks::verb::InvocationRelease;
use oneiron::settings::{ReadDestination, ReleaseHold};

/// The verb whose owner export reads its prose as no ref (FIX 5522), as the
/// MCP release reads it.
const OWNER_EXPORT_VERB: &str = "vault.agents.export_pack";

/// What [`released_reply`] kept of an answer, for the invocation claim
/// around its route ([`finish_door_claim`]): the machine its caller's
/// connection proved, the rows its producers listed, and the answer before
/// the release when the reply sent is not it. It rides the reply as a
/// response extension and never reaches the wire.
#[derive(Clone)]
pub(crate) struct FacadeReleased {
    peer: PeerMachine,
    rows: Option<Vec<EntityId>>,
    withheld: Option<serde_json::Value>,
}

impl FacadeReleased {
    /// The record the claim keeps beside `sent`, the reply that went out.
    pub(crate) fn kept(self, sent: &serde_json::Value) -> InvocationRelease {
        InvocationRelease {
            peer: self.peer,
            value: self.withheld.unwrap_or_else(|| sent.clone()),
            rows: self.rows,
        }
    }
}

/// The facade route's one release after its call returns (FIX 8170): the
/// answer `output` carries, judged for the destination `auth`'s connection
/// proved by the rows its producers listed and the rows it names. An answer
/// derived from or naming a row a world withheld from that destination keeps
/// becomes the content-free word that the call ran
/// ([`ActAnswer::DetailsOnDevice`](oneiron::task_verb::sdk::ActAnswer)); its
/// effect stays committed. An answer whose rows are unknown, and every answer
/// on this device, goes out as it was.
pub(super) fn released_reply(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
    output: FacadeCallOutput,
) -> (axum::Extension<FacadeReleased>, Json<serde_json::Value>) {
    let FacadeCallOutput { value, rows } = output;
    let owner_export = verb == OWNER_EXPORT_VERB && auth.is_owner_grade();
    let held = known_denied(
        server.vault(),
        &auth.destination(),
        rows.as_deref(),
        &value,
        owner_export,
    );
    let (sent, withheld) = if held {
        (details_on_device(), Some(value))
    } else {
        (value, None)
    };
    let kept = FacadeReleased {
        peer: auth.peer(),
        rows,
        withheld,
    };
    (axum::Extension(kept), Json(sent))
}

/// The answer a request that waited on another's run of the same call gets
/// (FIX 8212): `release`, the first call's answer before its release, judged
/// again for this waiter. A row its producers listed that this waiter's
/// credential no longer reads, or that was erased since, keeps the details
/// here; so does a row a world withheld from this waiter's destination. A
/// waiter toward another machine than the first call's is answered for its
/// own, never refused for the difference. Unknown rows keep the answer.
pub(crate) fn replayed_value(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    verb: &str,
    release: InvocationRelease,
) -> serde_json::Value {
    if release.peer != auth.peer() {
        tracing::debug!(
            verb,
            "invocation answer reprojected for the waiter's machine"
        );
    }
    if let Some(rows) = release.rows.as_deref()
        && !rows_still_admitted(vault, auth, rows)
    {
        return details_on_device();
    }
    let owner_export = verb == OWNER_EXPORT_VERB && auth.is_owner_grade();
    if known_denied(
        vault,
        &auth.destination(),
        release.rows.as_deref(),
        &release.value,
        owner_export,
    ) {
        details_on_device()
    } else {
        release.value
    }
}

/// Whether `auth`'s credential still reads every one of `rows` now, and none
/// was erased since (FIX 7914, FIX 8212): the waiter's current source
/// admission. A check that cannot be read passes: unknown never withholds.
pub(crate) fn rows_still_admitted(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    rows: &[EntityId],
) -> bool {
    rows.iter().all(|row| {
        let erased =
            oneiron::sync::bridge::local_deletion_is_materialized(vault, row).unwrap_or(false);
        !erased && auth.can_read_entity(vault, row).unwrap_or(true)
    })
}

/// [`known_denied`] for one item of a listing, `value`, derived from `rows`
/// (FIX 8164): whether it holds a detail exactly known to be withheld from
/// `destination`.
pub(super) fn known_denied_rows(
    vault: &oneiron::Vault,
    destination: &ReadDestination,
    rows: &[EntityId],
    value: &serde_json::Value,
) -> bool {
    known_denied(vault, destination, Some(rows), value, false)
}

/// Whether an answer `value` derived from `rows` holds a detail exactly known
/// to be withheld from `destination` (F1): a listed row, or a row it names by
/// whole id or short ref, that a world withheld from there keeps. Unknown
/// rows, a check that cannot be read and a conflicted root judge nothing, so
/// they withhold nothing. An owner's own agent-pack export is judged by its
/// listed rows and short refs alone (FIX 5522).
fn known_denied(
    vault: &oneiron::Vault,
    destination: &ReadDestination,
    rows: Option<&[EntityId]>,
    value: &serde_json::Value,
    owner_export: bool,
) -> bool {
    let Some(rows) = rows else {
        return false;
    };
    if !destination.is_off_device() {
        return false;
    }
    let mut named = rows.to_vec();
    if !owner_export {
        named.extend(crate::device_local::short_refs_named(vault, value).unwrap_or_default());
    }
    let payload = if owner_export {
        Vec::new()
    } else {
        serde_json::to_vec(value).unwrap_or_default()
    };
    matches!(
        crate::device_local::retained_hold(vault, destination, &named, &payload),
        Ok(Some(ReleaseHold::Recipient(_) | ReleaseHold::Placement))
    )
}

/// The content-free word that the call ran and its details stay on this
/// device: `{"details_on_device": true}`, nothing else.
pub(crate) fn details_on_device() -> serde_json::Value {
    serde_json::to_value(oneiron::task_verb::sdk::ActAnswer::<()>::details_on_device())
        .unwrap_or_else(|_| serde_json::json!({ "details_on_device": true }))
}
