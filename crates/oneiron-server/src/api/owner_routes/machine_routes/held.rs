//! `/machines/held` is the owner's list of the carried answers that wait for
//! his confirm (row CARRIER-OWNER-PROOF): each needed an owner key's proof
//! and carried none. He confirms the ones he names on an install that holds
//! his key, and dismisses an ask on this install alone. The list shows each
//! machine's revision, and a confirm presents it back as that entry's
//! `seen`, as the answer routes do.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use oneiron::authority::HeldAnswerListing;
use serde::{Deserialize, Serialize};

use super::super::{OwnerReply, blocking, owner};
use super::{act_surface_admitted, parse_revision, revision_hex, revoke_removed_mesh, role_name};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

/// The held answers a confirm names, and the machine revisions the owner's
/// surface presents back.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ConfirmHeldEntries {
    /// The held answers' log entries as `GET /machines/held` listed them,
    /// each as 64 hex.
    entries: Vec<String>,
    /// For any named entry (the key, as 64 hex), the `revision` the list
    /// showed beside it, as 64 hex. An entry with none takes its machine's
    /// current revision; a key that names no entry of `entries` is refused.
    #[serde(default)]
    seen: BTreeMap<String, String>,
}

impl ConfirmHeldEntries {
    /// The entries as the log names them.
    fn parsed(&self) -> OwnerResult<Vec<[u8; 32]>> {
        self.entries
            .iter()
            .map(|entry| parse_revision("entries", entry))
            .collect()
    }

    /// The presented revisions, by the entry each is for. A key that names
    /// no entry of `entries` is a malformed request: the confirm door
    /// refuses it too, and this answers it as one (400).
    fn seen(&self) -> OwnerResult<BTreeMap<[u8; 32], [u8; 32]>> {
        self.seen
            .iter()
            .map(|(entry, seen)| {
                if !self.entries.contains(entry) {
                    return Err(OwnerError::Invalid(
                        "seen must name entries of this confirm".to_owned(),
                    ));
                }
                Ok((
                    parse_revision("seen", entry)?,
                    parse_revision("seen", seen)?,
                ))
            })
            .collect()
    }
}

/// The held answers a dismissal names.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct HeldEntries {
    /// The held answers' log entries as `GET /machines/held` listed them,
    /// each as 64 hex.
    entries: Vec<String>,
}

impl HeldEntries {
    /// The entries as the log names them.
    fn parsed(&self) -> OwnerResult<Vec<[u8; 32]>> {
        self.entries
            .iter()
            .map(|entry| parse_revision("entries", entry))
            .collect()
    }
}

/// The owner's acts that wait for his proof, as this install lists them.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(super) struct HeldAnswers {
    /// Each carried machine answer that still asks the owner. It stands for
    /// nothing until he confirms it.
    answers: Vec<ListedHeldAnswer>,
    /// Each owner choice that waits for his proof and still asks, by its
    /// log entry as 64 hex. He confirms one by making the choice again on an
    /// owner device. A person's own waiting choice (their opt back in to
    /// conversation training) is listed too, and only that person makes it
    /// again.
    waiting_choices: Vec<String>,
    /// Whether this install holds an owner key, so a confirm here is proven.
    /// Where it is false, the confirm route refuses: confirm on an owner
    /// device.
    can_confirm: bool,
}

/// One held machine answer in the owner's list.
#[derive(Debug, Serialize, schemars::JsonSchema)]
struct ListedHeldAnswer {
    /// The held answer's log entry, as 64 hex: what a confirm or a dismissal
    /// names.
    entry: String,
    /// The MACHINE row the answer is about, as hex.
    machine: String,
    /// The role it asks for, as `role` names them on `/machines/answer`.
    role: &'static str,
    /// The class the machine declares: `phone` or `computer`.
    device_class: &'static str,
    /// The machine key the answer names, 64 lower hex: the key the owner
    /// checks against the one the machine itself shows. The machine's proof
    /// binds its encryption key to this key.
    machine_key: String,
    /// Whether the answer names other keys than the machine stands under.
    /// The confirm route refuses such an answer: no route writes one, so
    /// its keys are its carrier's word alone. Dismiss it.
    replaces_keys: bool,
    /// The role the machine stands in now; none when no revision names it.
    standing: Option<&'static str>,
    /// The machine's revision as this list read it, as 64 hex (all zero
    /// when no revision names the machine): a confirm presents it back as
    /// this entry's `seen`.
    revision: String,
    /// The machine whose install key carried the answer, as hex.
    carrier: Option<String>,
    /// The role this install's records give the key that signed the answer
    /// on that machine; none when they tie the two to no profile, and the
    /// machine id is then the answer's word alone.
    carrier_role: Option<&'static str>,
    /// Whether this install trusts the key that signed the answer as one of
    /// the owner's machines.
    carrier_is_yours: bool,
    /// Whether the owner dismissed this ask on this install.
    dismissed: bool,
    /// The question a surface asks about this answer before the owner
    /// confirms or dismisses it, composed by the engine: what the answer
    /// asks for, then on the last line who carried it by this install's
    /// reading of the key that signed it
    /// ([`oneiron::authority::held_answer_prompt`]). Its lines are
    /// separated by a line feed.
    prompt: String,
    /// `machine_key` as a code, 26 symbols, in the form of a recovery kit's
    /// code ([`oneiron::authority::machine_key_code`]): what the owner
    /// compares with the code that machine shows. `machine_key` in full
    /// stays the detail.
    machine_code: String,
    /// What a surface shows under the question: "Code shown on that
    /// phone: " (or computer) and `machine_code`
    /// ([`oneiron::authority::machine_code_line`]).
    machine_code_text: String,
    /// What a surface shows, quiet, under `machine_code_text`: that the code
    /// should match the one the device shows, and to dismiss this answer
    /// when the two differ
    /// ([`oneiron::authority::machine_code_check_line`]).
    machine_code_check_text: String,
}

/// The list as the wire spells it.
fn held_answers_of(listing: &HeldAnswerListing) -> HeldAnswers {
    HeldAnswers {
        answers: listing
            .answers
            .iter()
            .map(|listed| ListedHeldAnswer {
                entry: revision_hex(&listed.entry),
                machine: listed.answer.profile.machine.to_hex(),
                role: role_name(listed.answer.profile.role),
                device_class: listed.answer.profile.device_class.wire(),
                machine_key: revision_hex(&listed.answer.profile.machine_key),
                replaces_keys: listed.replaces_keys,
                standing: listed.standing.map(role_name),
                revision: revision_hex(&listed.revision),
                carrier: listed.answer.carrier().map(|carrier| carrier.to_hex()),
                carrier_role: listed.carrier_role.map(role_name),
                carrier_is_yours: listed.carrier_is_mine,
                dismissed: listed.dismissed,
                prompt: listed.prompt(),
                machine_code: oneiron::authority::machine_key_code(
                    &listed.answer.profile.machine_key,
                ),
                machine_code_text: oneiron::authority::machine_code_line(
                    &listed.answer.profile.machine_key,
                    listed.answer.profile.device_class,
                    oneiron::authority::PromptDeviceName::NotHeld,
                ),
                machine_code_check_text: oneiron::authority::machine_code_check_line(
                    listed.answer.profile.device_class,
                    oneiron::authority::PromptDeviceName::NotHeld,
                ),
            })
            .collect(),
        waiting_choices: listing.waiting_choices.iter().map(revision_hex).collect(),
        can_confirm: listing.can_confirm,
    }
}

/// The OpenAPI schema of the held confirm body: [`ConfirmHeldEntries`].
pub(super) fn held_confirm_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ConfirmHeldEntries>()
}

/// The OpenAPI schema of the held dismiss body: [`HeldEntries`].
pub(super) fn held_entries_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<HeldEntries>()
}

/// The OpenAPI schema of the held confirm and dismiss answers: [`HeldAnswers`].
pub(super) fn held_answers_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<HeldAnswers>()
}

/// `GET /v1/owner/machines/held`: the carried machine answers that wait for
/// the owner's confirm, and the owner choices that wait.
pub(super) async fn get_held(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<HeldAnswers> {
    let owner = owner(&auth, &server)?;
    let held = blocking(move || -> OwnerResult<HeldAnswers> {
        let listing = server.vault().held_machine_answers(&owner)?;
        Ok(held_answers_of(&listing))
    })
    .await?;
    Ok(Json(held))
}

/// `POST /v1/owner/machines/held/confirm`: the owner confirms the held
/// answers he names. Each becomes his own proven answer about its machine,
/// in one transaction. On an install that holds no owner key it refuses
/// before it writes (409, state `owner_key_required`): a confirm promises a
/// proven answer. An entry that names other keys than its machine stands
/// under is refused: a confirm never replaces a machine's keys. A `seen`
/// that is no longer its machine's revision is a conflict (409): an answer
/// about the machine landed after the list was read, and the confirm never
/// writes over it unseen. A confirmed removal revokes the machine's mesh
/// pairing and grants, as `/machines/remove` does.
pub(super) async fn confirm_held(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<ConfirmHeldEntries>,
) -> OwnerReply<HeldAnswers> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let request = payload.read(&server).await?;
    let held = blocking(move || -> OwnerResult<HeldAnswers> {
        let confirmed = server.vault().confirm_held_machine_answers(
            &owner,
            surface,
            &request.parsed()?,
            &request.seen()?,
        )?;
        for machine in &confirmed.removed {
            revoke_removed_mesh(&server, *machine);
        }
        Ok(held_answers_of(&confirmed.listing))
    })
    .await?;
    Ok(Json(held))
}

/// `POST /v1/owner/machines/held/dismiss`: the owner dismisses the ask of
/// the held answers he names, on this install alone. Nothing is written to
/// the log: each answer stays held, and his other devices still ask. A named
/// entry that no longer asks is a conflict.
pub(super) async fn dismiss_held(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<HeldEntries>,
) -> OwnerReply<HeldAnswers> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let held = blocking(move || -> OwnerResult<HeldAnswers> {
        let listing = server
            .vault()
            .dismiss_held_machine_answers(&owner, &request.parsed()?)?;
        Ok(held_answers_of(&listing))
    })
    .await?;
    Ok(Json(held))
}
