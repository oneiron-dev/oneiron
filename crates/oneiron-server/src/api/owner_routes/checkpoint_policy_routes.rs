//! `/v1/owner/checkpoint-policy`: the owner selects which roots attest his
//! authority checkpoint images, and how many of them must (mesh PR2c, §A 06,
//! K06), from any surface where he is authenticated, on any host, the hosted
//! console included (the owner's ruling, 10-19: "it doesn't matter where you
//! said yes, if you said so"). This server's install carries his choice under
//! its own live profile; a hosted operator's root acts as nobody (FIX 2222),
//! and `owner()` refuses it before anything is written.
//!
//! `GET` reads the policy in force, the live choices and any conflict among
//! them; a conflict never stops checkpointing (the last choice they agreed on
//! stays in force). `POST` selects roots and a quorum, and `POST .../clear`
//! hands the vault back to the policy its hosting posture fixes. Each names
//! the revision the surface showed the owner (`seen`, from `GET`); a stale
//! one is a conflict, never a silent overwrite. Existing pins never change:
//! a device paired on an older policy pairs again with a link from the
//! owner.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::HeaderMap;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::authority::{
    ActAuthority, AuthorityKey, AuthoritySignatureSuite, CheckpointPolicyHead,
    CheckpointPolicyView, CheckpointPosture, CheckpointRootChoice, CheckpointRootPolicy,
};
use oneiron::error::RecordError;
use serde::{Deserialize, Serialize};

use super::machine_routes::{act_surface, parse_revision, revision_hex};
use super::{OwnerReply, blocking, owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/checkpoint-policy", get(view).post(select))
        .route("/checkpoint-policy/clear", post(clear))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectPolicy {
    /// The roots, each `<suite>:<hex key>` (`ed25519:` or `p256:`), each
    /// once, in any order.
    roots: Vec<String>,
    /// Distinct chosen roots that must attest.
    quorum: u8,
    /// One attesting root must be hardware-backed.
    #[serde(default)]
    hardware: bool,
    /// The policy revision the surface showed the owner, as 64 hex; none
    /// takes the current one.
    #[serde(default)]
    seen: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClearPolicy {
    /// As for a selection.
    #[serde(default)]
    seen: Option<String>,
}

#[derive(Debug, Serialize)]
struct RootReply {
    key: String,
    tier: &'static str,
    /// The managed host root.
    host: bool,
}

#[derive(Debug, Serialize)]
struct PolicyReply {
    posture: &'static str,
    roots: Vec<RootReply>,
    quorum: u8,
    hardware: bool,
    /// The owner selected it; else the hosting posture fixes it.
    owner_selected: bool,
}

#[derive(Debug, Serialize)]
struct ChoiceReply {
    roots: Vec<String>,
    quorum: u8,
    hardware: bool,
}

#[derive(Debug, Serialize)]
struct HeadReply {
    /// The choice's authority entry, as 64 hex.
    act: String,
    /// The machine that carried it, as 32 hex.
    machine: String,
    /// The roots and quorum chosen; null for a clear.
    choice: Option<ChoiceReply>,
    /// When it was made, advisory unix seconds.
    at: u64,
}

#[derive(Debug, Serialize)]
struct PolicyViewReply {
    /// Present back as `seen`.
    revision: String,
    /// The policy in force; null when the roster cannot fix it.
    policy: Option<PolicyReply>,
    /// Why the roster cannot fix it, when it cannot.
    refusal: Option<String>,
    /// The owner's choice in force; null while the posture fixes the policy.
    selected: Option<HeadReply>,
    heads: Vec<HeadReply>,
    /// The live choices in conflict; empty when none.
    conflict: Vec<HeadReply>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn key_text(key: &AuthorityKey) -> String {
    let bytes: &[u8] = match key {
        AuthorityKey::Ed25519(bytes) => bytes,
        AuthorityKey::P256(bytes) => bytes,
    };
    format!("{}:{}", key.suite().as_str(), hex(bytes))
}

fn parse_key(text: &str) -> OwnerResult<AuthorityKey> {
    let refused =
        || OwnerError::Invalid("each root must be `ed25519:<hex>` or `p256:<hex>`".to_owned());
    let (suite, digits) = text.split_once(':').ok_or_else(refused)?;
    if digits.len() % 2 != 0 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(refused());
    }
    let bytes = (0..digits.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&digits[at..at + 2], 16).map_err(|_| refused()))
        .collect::<OwnerResult<Vec<u8>>>()?;
    match AuthoritySignatureSuite::parse(suite).ok_or_else(refused)? {
        AuthoritySignatureSuite::Ed25519 => Ok(AuthorityKey::Ed25519(
            bytes.try_into().map_err(|_| refused())?,
        )),
        AuthoritySignatureSuite::P256 => Ok(AuthorityKey::P256(bytes)),
    }
}

fn posture_name(posture: CheckpointPosture) -> &'static str {
    match posture {
        CheckpointPosture::Managed => "managed",
        CheckpointPosture::Relay => "relay",
        CheckpointPosture::SelfHost => "self_host",
    }
}

fn policy_reply(policy: &CheckpointRootPolicy) -> PolicyReply {
    PolicyReply {
        posture: posture_name(policy.posture),
        roots: policy
            .roots
            .iter()
            .map(|root| RootReply {
                key: key_text(&root.key),
                tier: root.tier.as_str(),
                host: root.host,
            })
            .collect(),
        quorum: policy.quorum,
        hardware: policy.hardware,
        owner_selected: policy.owner_selected,
    }
}

fn head_reply(head: &CheckpointPolicyHead) -> HeadReply {
    HeadReply {
        act: revision_hex(&head.act),
        machine: head.machine.to_hex(),
        choice: head.choice.as_ref().map(|choice| ChoiceReply {
            roots: choice.roots.iter().map(key_text).collect(),
            quorum: choice.quorum,
            hardware: choice.hardware,
        }),
        at: head.at,
    }
}

fn view_reply(view: &CheckpointPolicyView) -> PolicyViewReply {
    PolicyViewReply {
        revision: revision_hex(&view.revision),
        policy: view.policy.as_ref().map(policy_reply),
        refusal: view.refusal.clone(),
        selected: view.selected.as_ref().map(head_reply),
        heads: view.heads.iter().map(head_reply).collect(),
        conflict: view.conflict.iter().map(head_reply).collect(),
    }
}

/// The engine's typed refusals as the owner's: a stale revision is a change
/// since his review; a choice that cannot stand, or an act no rule admits,
/// is a refusal naming its rule. Anything else stays the engine's.
fn refusal(error: oneiron::Error) -> OwnerError {
    match &error {
        oneiron::Error::Record(RecordError::CheckpointPolicyRevisionStale { .. }) => {
            OwnerError::Changed(error.to_string())
        }
        oneiron::Error::Record(
            RecordError::CheckpointPolicyRefused(_) | RecordError::AuthorityRefused(_),
        ) => OwnerError::Refused(error.to_string()),
        _ => OwnerError::Engine(Box::new(error)),
    }
}

fn seen_of(seen: Option<&str>) -> OwnerResult<Option<[u8; 32]>> {
    seen.map(|seen| parse_revision("seen", seen)).transpose()
}

/// `GET /v1/owner/checkpoint-policy`: the policy in force, the revision to
/// present back as `seen`, the owner's choice in force, every live choice and
/// any conflict among them.
async fn view(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<PolicyViewReply> {
    owner(&auth, &server)?;
    let reply = blocking(move || -> OwnerResult<PolicyViewReply> {
        let view = server.vault().checkpoint_policy_view().map_err(refusal)?;
        Ok(view_reply(&view))
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/checkpoint-policy`: the owner selects the roots and quorum
/// on any host. Eligibility, the multi-root quorum, the configured floor and
/// hardware-when-eligible stay; only the host-voter rule goes.
async fn select(
    auth: CoreAuth,
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<SelectPolicy>, JsonRejection>,
) -> OwnerReply<PolicyViewReply> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface(&server, &auth, &headers);
    let body = json_payload(payload)?;
    let reply = blocking(move || -> OwnerResult<PolicyViewReply> {
        let mut roots = body
            .roots
            .iter()
            .map(|root| parse_key(root))
            .collect::<OwnerResult<Vec<_>>>()?;
        roots.sort();
        if roots.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(OwnerError::Invalid(
                "each root may be named once".to_owned(),
            ));
        }
        let choice = CheckpointRootChoice {
            roots,
            quorum: body.quorum,
            hardware: body.hardware,
        };
        let seen = seen_of(body.seen.as_deref())?;
        let authority = ActAuthority::Owner(owner, surface);
        let view = server
            .vault()
            .set_checkpoint_policy_as(&authority, Some(choice), seen)
            .map_err(refusal)?;
        Ok(view_reply(&view))
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/checkpoint-policy/clear`: the owner clears his choice;
/// the policy the vault's hosting posture fixes holds again.
async fn clear(
    auth: CoreAuth,
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ClearPolicy>, JsonRejection>,
) -> OwnerReply<PolicyViewReply> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface(&server, &auth, &headers);
    let body = json_payload(payload)?;
    let reply = blocking(move || -> OwnerResult<PolicyViewReply> {
        let seen = seen_of(body.seen.as_deref())?;
        let authority = ActAuthority::Owner(owner, surface);
        let view = server
            .vault()
            .set_checkpoint_policy_as(&authority, None, seen)
            .map_err(refusal)?;
        Ok(view_reply(&view))
    })
    .await?;
    Ok(Json(reply))
}
