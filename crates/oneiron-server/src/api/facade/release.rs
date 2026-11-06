//! A facade answer's destination release, once its call has nothing left to wait on (FIX 8170),
//! and again for each request that waited on the same claimed invocation (FIX 7914, FIX 8212).
//! `released_reply`, `replayed_value` and `rows_still_admitted` are its call surface.
//! `oneiron::runtime_hooks::verb::InvocationRelease` is the record a claimed call keeps.

use super::*;
use crate::api::type_feedback_release::{
    FeedbackScan, put_program_step, release_step_feedback, take_program_steps,
};
use oneiron::authority::PeerMachine;
use oneiron::code_run::{ProgramStepFeedback, ProgramStepFeedbackRelease};
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
    /// A reply sent as-is, with known rows retained for replay admission.
    pub(crate) fn sent_with_rows(peer: PeerMachine, rows: Vec<EntityId>) -> Self {
        Self {
            peer,
            rows: Some(rows),
            withheld: None,
        }
    }

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
/// on this device, goes out as it was. The step feedback an answer carries
/// is judged apart from it, after it (FIX 10389): a hold on one withholds
/// only that feedback's text, never the answer. The owner's own whole-vault
/// export, as its route and his fresh proof name it, keeps every integrity
/// hold and no recipient choice (owner ruling 1-EXPORT = B).
pub(super) fn released_reply(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
    output: FacadeCallOutput,
) -> (axum::Extension<FacadeReleased>, Json<serde_json::Value>) {
    let FacadeCallOutput { value, rows } = output;
    let owner_export = verb == OWNER_EXPORT_VERB && auth.is_owner_grade();
    let owner_whole_vault_export =
        super::export_transfer::owner_whole_vault_export_admitted(server, auth, verb);
    let destination = auth.destination();
    let carried = take_program_steps(verb, &value);
    let held = known_denied(
        server.vault(),
        &destination,
        rows.as_deref(),
        carried.as_ref().map_or(&value, |(base, _)| base),
        owner_export,
        owner_whole_vault_export,
    );
    let released = carried.filter(|_| !held).and_then(|(_, feedback)| {
        let rows = rows.as_deref();
        released_feedback(server.vault(), &destination, rows, value.clone(), feedback)
    });
    let (sent, withheld) = match released {
        _ if held => {
            // A transfer-delivered export no caller learns of leaves no
            // spool behind (FIX 11178).
            if verb == "vault.export" {
                server.export_transfers.drop_withheld(&value);
            }
            (details_on_device(), Some(value))
        }
        Some(sent) => (sent, Some(value)),
        None => (value, None),
    };
    let kept = FacadeReleased {
        peer: auth.peer(),
        rows,
        withheld,
    };
    (axum::Extension(kept), Json(sent))
}

/// The reply of a call no credential binds, whose answer derives from no row
/// (the owner's clock repair judged in its own writer, FIX 11190): it goes
/// out as it is.
pub(super) fn unbound_reply(
    value: serde_json::Value,
) -> (axum::Extension<FacadeReleased>, Json<serde_json::Value>) {
    let kept = FacadeReleased {
        peer: PeerMachine::Unknown,
        rows: Some(Vec::new()),
        withheld: None,
    };
    (axum::Extension(kept), Json(value))
}

/// The answer a request that waited on another's run of the same call gets
/// (FIX 8212): `release`, the first call's answer before its release, judged
/// again for this waiter. A row its producers listed that this waiter's
/// credential no longer reads, or that was erased since, keeps the details
/// here; so does a row a world withheld from this waiter's destination. A
/// waiter toward another machine than the first call's is answered for its
/// own, never refused for the difference. Unknown rows keep the answer.
/// `owner_whole_vault_export`: the owner's own whole-vault export, its waiter
/// admitted again now as its owner
/// ([`super::export_transfer::owner_whole_vault_export_admitted`]), released
/// as its first call's answer was.
pub(crate) fn replayed_value(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    verb: &str,
    release: InvocationRelease,
    owner_whole_vault_export: bool,
) -> serde_json::Value {
    if release.peer != auth.peer() {
        tracing::debug!(
            verb,
            "invocation answer reprojected for the waiter's machine"
        );
    }
    if let Some(rows) = release.rows.as_deref()
        && !rows_still_admitted(vault, auth, rows, owner_whole_vault_export)
    {
        return details_on_device();
    }
    let owner_export = verb == OWNER_EXPORT_VERB && auth.is_owner_grade();
    let destination = auth.destination();
    let carried = take_program_steps(verb, &release.value);
    if known_denied(
        vault,
        &destination,
        release.rows.as_deref(),
        carried.as_ref().map_or(&release.value, |(base, _)| base),
        owner_export,
        owner_whole_vault_export,
    ) {
        return details_on_device();
    }
    let Some((_, feedback)) = carried else {
        return release.value;
    };
    let rows = release.rows.as_deref();
    released_feedback(vault, &destination, rows, release.value.clone(), feedback)
        .unwrap_or(release.value)
}

/// `value`, an answer released as it stands, with the step feedback it
/// carries judged apart for `destination` (FIX 10389): `None` when every
/// item leaves whole, else the answer with each item its own release check
/// holds withheld, with none of its text. Nothing else in it changes.
fn released_feedback(
    vault: &oneiron::Vault,
    destination: &ReadDestination,
    rows: Option<&[EntityId]>,
    mut value: serde_json::Value,
    feedback: Vec<(usize, ProgramStepFeedback)>,
) -> Option<serde_json::Value> {
    let mut withheld = false;
    for (slot, feedback) in feedback {
        let released =
            release_step_feedback(vault, destination, rows, feedback, FeedbackScan::Named);
        if matches!(released, ProgramStepFeedbackRelease::Withheld { .. }) {
            withheld = true;
            let released = serde_json::to_value(&released).unwrap_or(serde_json::Value::Null);
            put_program_step(&mut value, slot, released);
        }
    }
    withheld.then_some(value)
}

/// Whether `auth`'s credential still reads every one of `rows` now, and none
/// was erased since (FIX 7914, FIX 8212): the waiter's current source
/// admission. A check that cannot be read passes: unknown never withholds.
/// The owner's own whole-vault export (`owner_whole_vault_export`, its owner
/// admitted again by its door) reads each row as his credential reads it on
/// this device: his recipient choice keeps none of them (owner ruling
/// 1-EXPORT = B); the release judges where they go after.
pub(crate) fn rows_still_admitted(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    rows: &[EntityId],
    owner_whole_vault_export: bool,
) -> bool {
    let destination = if owner_whole_vault_export {
        ReadDestination::on_device()
    } else {
        auth.destination()
    };
    rows.iter().all(|row| {
        let erased =
            oneiron::sync::bridge::local_deletion_is_materialized(vault, row).unwrap_or(false);
        !erased
            && auth
                .can_read_entity_at(vault, row, &destination)
                .unwrap_or(true)
    })
}

/// [`known_denied`] for one item of a listing, `value`, derived from `rows`
/// (FIX 8164): whether it holds a detail exactly known to be withheld from
/// `destination`, for the owner's own whole-vault export
/// (`owner_whole_vault_export`) by an integrity hold alone.
pub(super) fn known_denied_rows(
    vault: &oneiron::Vault,
    destination: &ReadDestination,
    rows: &[EntityId],
    value: &serde_json::Value,
    owner_whole_vault_export: bool,
) -> bool {
    known_denied(
        vault,
        destination,
        Some(rows),
        value,
        false,
        owner_whole_vault_export,
    )
}

/// Whether an answer `value` derived from `rows` holds a detail exactly known
/// to be withheld from `destination` (F1): a listed row, or a row it names by
/// whole id or short ref, that a world withheld from there keeps. Unknown
/// rows, a check that cannot be read and a conflicted root judge nothing, so
/// they withhold nothing. An owner's own agent-pack export
/// (`owner_pack_export`) is judged by its listed rows alone (FIX 5522). The
/// owner's own whole-vault export (`owner_whole_vault_export`) is judged by
/// the same rows, refs and ids, its notices' world names read as no ref, and
/// only an integrity hold withholds it: his recipient choice keeps none of
/// its rows (owner ruling 1-EXPORT = B).
fn known_denied(
    vault: &oneiron::Vault,
    destination: &ReadDestination,
    rows: Option<&[EntityId]>,
    value: &serde_json::Value,
    owner_pack_export: bool,
    owner_whole_vault_export: bool,
) -> bool {
    let Some(rows) = rows else {
        return false;
    };
    if !destination.is_off_device() {
        return false;
    }
    let mut named = rows.to_vec();
    if !owner_pack_export {
        let cleared = owner_whole_vault_export
            .then(|| notice_names_cleared(value))
            .flatten();
        let scanned = cleared.as_ref().unwrap_or(value);
        named.extend(crate::device_local::short_refs_named(vault, scanned).unwrap_or_default());
    }
    let payload = if owner_pack_export {
        Vec::new()
    } else {
        serde_json::to_vec(value).unwrap_or_default()
    };
    let hold = if owner_whole_vault_export {
        crate::device_local::owner_export_retained_hold(vault, destination, &named, &payload)
    } else {
        crate::device_local::retained_hold(vault, destination, &named, &payload)
    };
    matches!(
        hold,
        Ok(Some(ReleaseHold::Recipient(_) | ReleaseHold::Placement))
    )
}

/// The copy of an owner's whole-vault export answer `value` its short-ref
/// scan reads: each notice's world name, his own words for his world, read
/// as none, as MCP reads an owner export's (FIX 5522). `None` when no notice
/// names one: the answer is scanned as it is.
fn notice_names_cleared(value: &serde_json::Value) -> Option<serde_json::Value> {
    let names_world = |notice: &serde_json::Value| {
        notice
            .get("world_name")
            .is_some_and(serde_json::Value::is_string)
    };
    let notices = value.get("notices")?.as_array()?;
    if !notices.iter().any(names_world) {
        return None;
    }
    let mut scan = value.clone();
    for notice in scan
        .get_mut("notices")
        .and_then(serde_json::Value::as_array_mut)
        .into_iter()
        .flatten()
    {
        if let Some(name) = notice.get_mut("world_name") {
            *name = serde_json::Value::Null;
        }
    }
    Some(scan)
}

/// The content-free word that the call ran and its details stay on this
/// device: `{"details_on_device": true}`, nothing else.
pub(crate) fn details_on_device() -> serde_json::Value {
    serde_json::to_value(oneiron::task_verb::sdk::ActAnswer::<()>::details_on_device())
        .unwrap_or_else(|_| serde_json::json!({ "details_on_device": true }))
}
