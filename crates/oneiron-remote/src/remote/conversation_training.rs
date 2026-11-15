//! A person's own conversation-training choice over `GET` and `PUT
//! /v1/owner/conversation-learning/me` (row
//! PERSON-TRAINING-CHOICE-PERSON-KEY-PROOF).
//!
//! A transport helper, not a verb: the route sits outside the facade nest,
//! as the checkpoint fetch does. The client's surface reads the person's
//! own opt-out and, to let their messages back in through a carrier that is
//! not the owner's, proves it with the slip key: the `GET` names `vault_id`
//! and `slip` (ruling PERSONKEY-PR2-STATEMENT-SOURCE = A), the client signs
//! them with `leave_out` and the revision as `seen` under that slip's
//! binding key, and the `PUT` carries the proof as `person_proof`.
//!
//! Like the rest of this crate, it never reads the slip's claims: it signs
//! the fields the server named, and a server naming a wrong one gets a
//! signature the fold refuses.

use ed25519_dalek::Signer;

use super::*;
use crate::{Backend, OneironClient};

/// The person's own opt-out route, beside the vault setting's.
const OWN_TRAINING_PATH: &str = "v1/owner/conversation-learning/me";

/// The person's own opt-out, as `GET /v1/owner/conversation-learning/me`
/// answers it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OwnConversationTraining {
    /// The person whose opt-out this is, as 32 hex: the proof's own.
    pub person: String,
    /// Whether they asked to leave their own messages out.
    pub leave_out: bool,
    /// Whether the vault lets people opt out now; while it does not,
    /// `leave_out` is kept and ignored.
    pub allowed: bool,
    /// Present back as `seen`, 64 hex; zero while no choice is live.
    pub revision: String,
    /// The person's live choices conflict: it reads as left out until a
    /// choice that saw them all supersedes them.
    pub conflicted: bool,
    /// The authority entry of the choice in force, 64 hex; null while none
    /// counts or the choices conflict.
    pub act: Option<String>,
    /// This vault's id as a person proof names it, 64 hex; null when this
    /// caller's door takes no person proof (the vault owner proves with an
    /// owner key; a Connect guest acts on no person slip).
    #[serde(default)]
    pub vault_id: Option<String>,
    /// The caller's own slip their proof presented, as a person proof names
    /// it, 64 hex; null with `vault_id`.
    #[serde(default)]
    pub slip: Option<String>,
}

impl RemoteClient {
    /// `GET /v1/owner/conversation-learning/me` under this handle's
    /// credential: the person's own opt-out the proof names.
    fn own_conversation_training(&self) -> Result<OwnConversationTraining, MemoryError> {
        let url = self.base_url.join(OWN_TRAINING_PATH).map_err(|error| {
            transport_error(format!(
                "could not build the conversation training URL: {error}"
            ))
        })?;
        let mut headers = self.credential_headers()?;
        accept_json(&mut headers);
        let reply = self.send(Method::GET, url, headers, None, false)?;
        let status = reply.status;
        if !status.is_success() {
            return Err(read_error_envelope(reply.body, status));
        }
        read_json(reply.body, status, "a person's own conversation training")
    }

    /// The `GET` above, then `PUT` of the person's choice on what it
    /// showed: `{"leave_out", "seen"}` with `seen` always the `GET`'s
    /// revision, plus `person_proof` when the server named a slip to prove
    /// with. Answers the choice as the server holds it.
    fn set_own_conversation_training(
        &self,
        leave_out: bool,
    ) -> Result<OwnConversationTraining, MemoryError> {
        let current = self.own_conversation_training()?;
        let proof = match self.holder.as_deref().map(|(_, key)| key) {
            Some(key) => person_proof(&current, leave_out, key)?,
            None => None,
        };
        let mut body = serde_json::json!({
            "leave_out": leave_out,
            "seen": current.revision,
        });
        if let Some(proof) = proof {
            body["person_proof"] = proof;
        }
        let body = serialize_request(&body)?;
        let url = self.base_url.join(OWN_TRAINING_PATH).map_err(|error| {
            transport_error(format!(
                "could not build the conversation training URL: {error}"
            ))
        })?;
        let mut headers = self.credential_headers()?;
        let body = encode_request(body, &mut headers);
        accept_json(&mut headers);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let reply = self.send(Method::PUT, url, headers, Some(body.into()), false)?;
        let status = reply.status;
        if !status.is_success() {
            return Err(read_error_envelope(reply.body, status));
        }
        read_json(reply.body, status, "a person's own conversation training")
    }
}

/// The person's own slip-key proof of an opt back in, as the `PUT` carries
/// it: `None` for an opt-out, which needs no proof, and when the server
/// named no slip to prove with. Otherwise the statement over the fields the
/// server named, signed with the connection key, which is that slip's
/// binding key.
fn person_proof(
    reply: &OwnConversationTraining,
    leave_out: bool,
    key: &SigningKey,
) -> Result<Option<serde_json::Value>, MemoryError> {
    if leave_out {
        return Ok(None);
    }
    let (Some(vault_id), Some(slip)) = (reply.vault_id.as_deref(), reply.slip.as_deref()) else {
        return Ok(None);
    };
    let vault_id = field_bytes("vault_id", vault_id)?;
    let slip_id = field_bytes("slip", slip)?;
    let seen = field_bytes("revision", &reply.revision)?;
    let person = oneiron::EntityId::from_hex(&reply.person)
        .map_err(|_| transport_error("the server named a malformed person for the person proof"))?;
    let statement = oneiron::authority::conversation_training_statement(
        &vault_id, person, leave_out, seen, slip_id,
    )
    .map_err(|error| {
        transport_error(format!(
            "the person proof statement could not be built: {error}"
        ))
    })?;
    let signature = key.sign(&statement).to_bytes();
    Ok(Some(serde_json::json!({
        "slip": reply.slip,
        "signature": super::pairing::lower_hex(&signature),
    })))
}

/// The 32 bytes a 64 lower-case hex field names; a malformed one is the
/// server's, naming the field, since the client signs what it named.
fn field_bytes(field: &str, value: &str) -> Result<[u8; 32], MemoryError> {
    let malformed = || {
        transport_error(format!(
            "the server named a malformed {field} for the person proof"
        ))
    };
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(malformed());
    }
    let mut out = [0; 32];
    for (slot, pair) in out.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| malformed())?;
        *slot = u8::from_str_radix(pair, 16).map_err(|_| malformed())?;
    }
    Ok(out)
}

/// An embedded handle's answer: a person's own choice is set over a served
/// connection, as the paired credential's holder.
fn embedded_refusal() -> MemoryError {
    bad_request(
        "a person's own training choice is set over a served connection",
        &["Connect with the person's own paired credential."],
    )
}

impl OneironClient {
    /// The person's own conversation-training opt-out this handle's
    /// credential names, over `GET /v1/owner/conversation-learning/me`.
    /// The call is blocking: run it off an async loop. An embedded handle
    /// refuses: a person's own choice is set over a served connection.
    pub fn own_conversation_training(&self) -> Result<OwnConversationTraining, MemoryError> {
        match &self.backend {
            Backend::Remote(remote) => remote.own_conversation_training(),
            Backend::Embedded(_) | Backend::DreamerAttempt(_) => Err(embedded_refusal()),
        }
    }

    /// Leaves the person's own messages out of training, or lets them back
    /// in, over `PUT /v1/owner/conversation-learning/me`, proved with the
    /// credential's own key where the server named a slip. The call is
    /// blocking: run it off an async loop. An opt back in is refused (409,
    /// state `owner_key_required`) when the server names no slip and the
    /// carrier is not the owner's. An embedded handle refuses: a person's
    /// own choice is set over a served connection.
    pub fn set_own_conversation_training(
        &self,
        leave_out: bool,
    ) -> Result<OwnConversationTraining, MemoryError> {
        match &self.backend {
            Backend::Remote(remote) => remote.set_own_conversation_training(leave_out),
            Backend::Embedded(_) | Backend::DreamerAttempt(_) => Err(embedded_refusal()),
        }
    }
}
