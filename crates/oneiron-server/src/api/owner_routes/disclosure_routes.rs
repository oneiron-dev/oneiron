//! `/v1/owner/disclosure`: the owner's doors to contact disclosure (OF-365,
//! the ILDF2 consent channel). An agent or the companion only OFFERS a
//! contact clearance (`vault.disclosure.offer`); here the owner reads the
//! frozen offer with the exact canonical delta it was shown, and answers it
//! once, standing or deny. The owner also narrows or revokes a standing
//! clearance, pre-clears a named trusted set, turns the disclosure-mode knob,
//! and answers the unknown-attendee "who is this?" ask. At a person's or
//! speaker's first entry into a chat or room (ILDF2 P5), the owner reads the
//! entry and answers it once: a standing clearance with the history the
//! entry sees, or no. Each act is the
//! engine's own under the proof `owner` hands it, and the engine writes every
//! receipt. A contact clearance's registry row is
//! `contact_clearance:<contact hex>`, revoked by
//! `consent.revoke_contact_disclosure`, never by the generic grant revoke.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::consent::{
    CONTACT_CLEARANCE_REVOKE_COMMAND, ContactClearanceAct, ContactDisclosureOutcome,
    DisclosureConfirmationReceipt, DisclosureOfferMode, contact_clearance_ref,
};
use oneiron::conversation::{ContainerAttendee, HistoryChoice};
use oneiron::disclosure::AttendeeIdentityChoice;
use oneiron::federation::Scope;
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::params::hex_bytes;
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/disclosure/offer", get(offer))
        .route("/disclosure/confirm", post(confirm))
        .route("/disclosure/narrow", post(narrow))
        .route("/disclosure/revoke", post(revoke))
        .route("/disclosure/preclear", post(preclear))
        .route("/disclosure/mode", get(mode).put(set_mode))
        .route("/disclosure/attendee", post(attendee))
        .route("/disclosure/entry", get(entry))
        .route("/disclosure/entry/confirm", post(confirm_entry))
        .route("/disclosure/entry/decline", post(decline_entry))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OfferQuery {
    /// The offer's 64-hex widen-proposal ref.
    proposal_ref: String,
}

/// One frozen offer as the owner is asked it.
#[derive(Debug, Serialize)]
struct OfferView {
    proposal_ref: String,
    /// Lowercase hex of the offer's frozen canonical delta; a confirm sends
    /// exactly this back as `expected_delta`.
    canonical_delta: String,
    proposer: String,
    owner_ref: String,
    created_at: u64,
    expires_at: u64,
    contact: String,
    scope: Scope,
    purpose: String,
    channel: String,
    beneficiary: String,
    ask: Option<String>,
    /// The contact's clearance digest the offer was filed against; all zero
    /// when it had none. A clearance changed since makes the offer stale.
    prior_clearance_digest: String,
    /// The registry row a standing answer writes, and its one-tap revoke.
    grant_ref: String,
    revoke_command: &'static str,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Answer {
    Once,
    Standing,
    Deny,
}

impl From<Answer> for ContactDisclosureOutcome {
    fn from(answer: Answer) -> Self {
        match answer {
            Answer::Once => Self::Once,
            Answer::Standing => Self::Standing,
            Answer::Deny => Self::Deny,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmOffer {
    proposal_ref: String,
    /// Lowercase hex of the canonical delta the owner was shown.
    expected_delta: String,
    /// `once`, `standing` or `deny`.
    outcome: Answer,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NarrowClearance {
    /// The contact, as 32 hex.
    contact: String,
    /// The narrower Scope; it must sit inside the current clearance.
    scope: Scope,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeClearance {
    /// The contact, as 32 hex.
    contact: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreclearSet {
    /// The trusted set's name; each receipt names it.
    set_name: String,
    /// 1..=256 distinct contacts, as 32 hex each.
    contacts: Vec<String>,
    scope: Scope,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ModeSetting {
    /// `always_ask`, `auto` or `always_yes`.
    mode: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttendeeAnswer {
    /// The `disclosure.attendee_ask` CLAIM answered, as 32 hex.
    ask_ref: String,
    /// The roster revision the ask was raised on.
    roster_revision: u64,
    /// One of the ask's candidate contacts as 32 hex, or `unknown`.
    choice: String,
}

#[derive(Debug, Serialize)]
struct AttendeeResolved {
    ask_ref: String,
    roster_revision: u64,
    /// The chosen contact as 32 hex, or `unknown`.
    choice: String,
    /// The private `disclosure.attendee_identity` CLAIM that records it.
    identity_ref: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryQuery {
    /// The chat or room, as 32 hex.
    container: String,
    /// The PERSON who entered, as 32 hex; else the unplaced speaker's keys.
    #[serde(default)]
    person: Option<String>,
    #[serde(default)]
    session_key: Option<String>,
    #[serde(default)]
    speaker_key: Option<String>,
}

#[derive(Debug, Serialize)]
struct EntryView {
    entry_ref: String,
    container: String,
    attendee: ContainerAttendee,
    roster_revision: u64,
    /// Engine time of the first entry: the attendee's history cut.
    entered_at: u64,
    /// Who the owner said an unplaced speaker is, as 32 hex or `unknown`;
    /// absent while unanswered and for a person.
    identity: Option<String>,
    /// The owner already answered this entry.
    decided: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmEntry {
    /// The entry fact, as 32 hex.
    entry_ref: String,
    /// The frozen offer for the entry's contact.
    proposal_ref: String,
    /// Lowercase hex of the canonical delta the owner was shown.
    expected_delta: String,
    /// `inherit` (the room's rule, from now when it sets none), `share` or
    /// `none`.
    #[serde(default)]
    history: HistoryChoice,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclineEntry {
    entry_ref: String,
    proposal_ref: String,
    expected_delta: String,
}

/// One clearance act's receipt, as the Gate receipt family records it.
#[derive(Debug, Serialize)]
struct ClearanceReceipt {
    receipt_ref: String,
    /// `once`, `standing`, `deny`, `narrowed`, `revoked` or `precleared`.
    act: &'static str,
    contact: String,
    grant_ref: String,
    revoke_command: &'static str,
    proposal_ref: Option<String>,
    ask_ref: Option<String>,
    /// The clearance digest before the act: its revert reference.
    before_digest: String,
    after_digest: String,
    /// The approve-once digest a `once` answer minted.
    once_digest: Option<String>,
}

impl From<DisclosureConfirmationReceipt> for ClearanceReceipt {
    fn from(receipt: DisclosureConfirmationReceipt) -> Self {
        let act = match receipt.act {
            ContactClearanceAct::Settled(outcome) => outcome.as_str(),
            ContactClearanceAct::Narrowed => "narrowed",
            ContactClearanceAct::Revoked => "revoked",
            ContactClearanceAct::Precleared => "precleared",
            ContactClearanceAct::Used => "used",
        };
        Self {
            receipt_ref: format!("gate:{}", receipt.decision_id.to_hex()),
            act,
            contact: receipt.contact_ref.to_hex(),
            grant_ref: contact_clearance_ref(&receipt.contact_ref),
            revoke_command: CONTACT_CLEARANCE_REVOKE_COMMAND,
            proposal_ref: receipt.proposal_ref,
            ask_ref: receipt.ask_ref,
            before_digest: hex_bytes(&receipt.before_digest),
            after_digest: hex_bytes(&receipt.after_digest),
            once_digest: receipt.once_digest.map(|digest| digest.to_hex()),
        }
    }
}

/// Lowercase hex to bytes; anything else is refused whole.
fn delta_bytes(value: &str) -> OwnerResult<Vec<u8>> {
    let invalid = || OwnerError::Invalid("expected_delta must be lowercase hex".to_owned());
    if value.is_empty() || value.len() % 2 != 0 {
        return Err(invalid());
    }
    (0..value.len())
        .step_by(2)
        .map(|at| {
            value
                .get(at..at + 2)
                .filter(|pair| {
                    pair.bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(invalid)
        })
        .collect()
}

/// `GET /v1/owner/disclosure/offer?proposal_ref=<64 hex>`: one frozen
/// contact-disclosure offer, the private ask the owner answers.
async fn offer(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<OfferQuery>, QueryRejection>,
) -> OwnerReply<OfferView> {
    owner(&auth, &server)?;
    let query = query_params(query)?;
    let view = blocking(move || -> OwnerResult<OfferView> {
        let vault = server.vault();
        let not_found = || OwnerError::NotFound("disclosure offer", query.proposal_ref.clone());
        let proposal = vault
            .contact_disclosure_offer(&query.proposal_ref)?
            .ok_or_else(not_found)?;
        let widen = vault
            .widen_proposal(&query.proposal_ref)?
            .ok_or_else(not_found)?;
        let offer = proposal.offer;
        Ok(OfferView {
            canonical_delta: hex_bytes(&widen.canonical_delta),
            proposal_ref: widen.proposal_ref,
            proposer: widen.proposer,
            owner_ref: widen.owner_ref,
            created_at: widen.created_at,
            expires_at: widen.expires_at,
            contact: offer.contact_ref.to_hex(),
            grant_ref: contact_clearance_ref(&offer.contact_ref),
            revoke_command: CONTACT_CLEARANCE_REVOKE_COMMAND,
            scope: offer.scope,
            purpose: offer.purpose,
            channel: offer.channel,
            beneficiary: offer.beneficiary_ref,
            ask: offer.ask_ref,
            prior_clearance_digest: hex_bytes(&proposal.prior_clearance_digest),
        })
    })
    .await?;
    Ok(Json(view))
}

/// `POST /v1/owner/disclosure/confirm`: the owner's answer to one frozen
/// offer, against the exact delta it was shown. Every answer settles the
/// offer once; the lineage that opened it cannot settle it.
async fn confirm(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ConfirmOffer>, JsonRejection>,
) -> OwnerReply<ClearanceReceipt> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let receipt = blocking(move || -> OwnerResult<ClearanceReceipt> {
        let delta = delta_bytes(&request.expected_delta)?;
        Ok(server
            .vault()
            .confirm_contact_disclosure(
                &owner,
                &request.proposal_ref,
                &delta,
                request.outcome.into(),
            )?
            .into())
    })
    .await?;
    Ok(Json(receipt))
}

/// `POST /v1/owner/disclosure/narrow`: narrows a contact's standing
/// clearance to a Scope inside the current one.
async fn narrow(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<NarrowClearance>, JsonRejection>,
) -> OwnerReply<ClearanceReceipt> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let receipt = blocking(move || -> OwnerResult<ClearanceReceipt> {
        let contact = entity_id("contact", &request.contact)?;
        Ok(server
            .vault()
            .narrow_contact_disclosure(&owner, &contact, request.scope)?
            .into())
    })
    .await?;
    Ok(Json(receipt))
}

/// `POST /v1/owner/disclosure/revoke`: `consent.revoke_contact_disclosure`,
/// the one-tap revoke of a contact's standing clearance. The row stays,
/// Revoked, and admits nothing.
async fn revoke(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<RevokeClearance>, JsonRejection>,
) -> OwnerReply<ClearanceReceipt> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let receipt = blocking(move || -> OwnerResult<ClearanceReceipt> {
        let contact = entity_id("contact", &request.contact)?;
        Ok(server
            .vault()
            .revoke_contact_disclosure(&owner, &contact)?
            .into())
    })
    .await?;
    Ok(Json(receipt))
}

/// `POST /v1/owner/disclosure/preclear`: the owner clears a named trusted set
/// for one Scope in advance, each contact with its own receipt.
async fn preclear(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<PreclearSet>, JsonRejection>,
) -> OwnerReply<Vec<ClearanceReceipt>> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let receipts = blocking(move || -> OwnerResult<Vec<ClearanceReceipt>> {
        let contacts = request
            .contacts
            .iter()
            .map(|contact| entity_id("contacts", contact))
            .collect::<OwnerResult<Vec<_>>>()?;
        Ok(server
            .vault()
            .preclear_contact_disclosure(&owner, &request.set_name, &contacts, request.scope)?
            .into_iter()
            .map(ClearanceReceipt::from)
            .collect())
    })
    .await?;
    Ok(Json(receipts))
}

/// `GET /v1/owner/disclosure/mode`: the disclosure-mode knob, `auto` when
/// never set.
async fn mode(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<ModeSetting> {
    owner(&auth, &server)?;
    let mode = blocking(move || -> OwnerResult<ModeSetting> {
        Ok(ModeSetting {
            mode: server.vault().disclosure_offer_mode()?.as_str().to_owned(),
        })
    })
    .await?;
    Ok(Json(mode))
}

/// `PUT /v1/owner/disclosure/mode`: turns the knob. No mode moves the
/// confirm surface: a new clearance still lands only on the owner's own act.
async fn set_mode(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ModeSetting>, JsonRejection>,
) -> OwnerReply<ModeSetting> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let mode = blocking(move || -> OwnerResult<ModeSetting> {
        let mode = DisclosureOfferMode::parse(&request.mode).ok_or_else(|| {
            OwnerError::Invalid("mode is always_ask, auto or always_yes".to_owned())
        })?;
        server.vault().set_disclosure_offer_mode(&owner, mode)?;
        Ok(ModeSetting {
            mode: mode.as_str().to_owned(),
        })
    })
    .await?;
    Ok(Json(mode))
}

/// `POST /v1/owner/disclosure/attendee`: the owner's answer to one
/// unknown-attendee ask, once. It binds at most the chosen candidate to this
/// speaker on this revision; it mints no clearance and enrolls no voice.
async fn attendee(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<AttendeeAnswer>, JsonRejection>,
) -> OwnerReply<AttendeeResolved> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let resolved = blocking(move || -> OwnerResult<AttendeeResolved> {
        let ask_ref = entity_id("ask_ref", &request.ask_ref)?;
        let choice = match request.choice.as_str() {
            oneiron::disclosure::ATTENDEE_UNKNOWN_OPTION => AttendeeIdentityChoice::Unknown,
            contact => AttendeeIdentityChoice::Contact(entity_id("choice", contact)?),
        };
        let resolution = server.vault().resolve_attendee_identity(
            &owner,
            &ask_ref,
            request.roster_revision,
            choice,
        )?;
        Ok(AttendeeResolved {
            ask_ref: resolution.ask_ref.to_hex(),
            roster_revision: resolution.roster_revision,
            choice: match resolution.choice {
                AttendeeIdentityChoice::Contact(contact) => contact.to_hex(),
                AttendeeIdentityChoice::Unknown => {
                    oneiron::disclosure::ATTENDEE_UNKNOWN_OPTION.to_owned()
                }
            },
            identity_ref: resolution.identity_ref.to_hex(),
        })
    })
    .await?;
    Ok(Json(resolved))
}

/// `GET /v1/owner/disclosure/entry?container=..&person=..` (or
/// `&session_key=..&speaker_key=..`): one attendee's first entry into a chat
/// or room, the P5 question the owner answers once.
async fn entry(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<EntryQuery>, QueryRejection>,
) -> OwnerReply<EntryView> {
    owner(&auth, &server)?;
    let query = query_params(query)?;
    let view = blocking(move || -> OwnerResult<EntryView> {
        let container = entity_id("container", &query.container)?;
        let attendee = match (&query.person, query.session_key, query.speaker_key) {
            (Some(person), None, None) => ContainerAttendee::Person(entity_id("person", person)?),
            (None, Some(session_key), Some(speaker_key)) => ContainerAttendee::Speaker {
                session_key,
                speaker_key,
            },
            _ => {
                return Err(OwnerError::Invalid(
                    "name either person or both session_key and speaker_key".to_owned(),
                ));
            }
        };
        let entry = server
            .vault()
            .container_attendee_entry(container, &attendee)?
            .ok_or_else(|| OwnerError::NotFound("attendee entry", query.container.clone()))?;
        Ok(EntryView {
            entry_ref: entry.entry_ref.to_hex(),
            container: entry.container.to_hex(),
            attendee: entry.attendee,
            roster_revision: entry.roster_revision,
            entered_at: entry.entered_at,
            identity: entry.identity.map(|choice| match choice {
                AttendeeIdentityChoice::Contact(contact) => contact.to_hex(),
                AttendeeIdentityChoice::Unknown => {
                    oneiron::disclosure::ATTENDEE_UNKNOWN_OPTION.to_owned()
                }
            }),
            decided: entry.decided,
        })
    })
    .await?;
    Ok(Json(view))
}

/// `POST /v1/owner/disclosure/entry/confirm`: the owner's yes to one entry's
/// P5 question: the entry's contact is cleared standing under the frozen
/// offer, the entry sees the history chosen, and the entry is decided once.
async fn confirm_entry(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ConfirmEntry>, JsonRejection>,
) -> OwnerReply<ClearanceReceipt> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let receipt = blocking(move || -> OwnerResult<ClearanceReceipt> {
        let entry_ref = entity_id("entry_ref", &request.entry_ref)?;
        let delta = delta_bytes(&request.expected_delta)?;
        Ok(server
            .vault()
            .confirm_container_attendee(
                &owner,
                &entry_ref,
                &request.proposal_ref,
                &delta,
                request.history,
            )?
            .into())
    })
    .await?;
    Ok(Json(receipt))
}

/// `POST /v1/owner/disclosure/entry/decline`: the owner's no to one entry's
/// P5 question: the offer settles denied, nothing widens, and the entry is
/// decided once.
async fn decline_entry(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<DeclineEntry>, JsonRejection>,
) -> OwnerReply<ClearanceReceipt> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let receipt = blocking(move || -> OwnerResult<ClearanceReceipt> {
        let entry_ref = entity_id("entry_ref", &request.entry_ref)?;
        let delta = delta_bytes(&request.expected_delta)?;
        Ok(server
            .vault()
            .deny_container_attendee(&owner, &entry_ref, &request.proposal_ref, &delta)?
            .into())
    })
    .await?;
    Ok(Json(receipt))
}
