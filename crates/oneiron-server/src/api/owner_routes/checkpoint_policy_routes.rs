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
//!
//! `GET .../roots` answers which roots this host's checkpoint head awaits
//! under the policy in force (FIX 5108): each root accepted, signed but not
//! counted, or pending, with the quorum, the hardware rule and what the
//! accepted roots still lack.
//!
//! `GET .../roots/deliveries` answers, for each root held here, where each
//! home's checkpoint head it signed stands (FIX 5196): signed but not
//! uploaded, delivered to the home's intake, or accepted, with the home's
//! machine (null for a home that proved none on its socket).

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::authority::{
    ActAuthority, AuthorityCheckpointRoots, AuthorityKey, AuthoritySignatureSuite,
    CheckpointPolicyHead, CheckpointPolicyView, CheckpointPosture, CheckpointRootChoice,
    CheckpointRootDelivery, CheckpointRootPolicy, RootAttestationDelivery,
    RootAttestationDeliveryState,
};
use oneiron::error::RecordError;
use serde::{Deserialize, Serialize};

use super::machine_routes::{act_surface_admitted, parse_revision, revision_hex};
use super::{OwnerReply, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/checkpoint-policy", get(view).post(select))
        .route("/checkpoint-policy/clear", post(clear))
        .route("/checkpoint-policy/roots", get(roots))
        .route("/checkpoint-policy/roots/deliveries", get(deliveries))
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

#[derive(Debug, Serialize)]
struct RootStateReply {
    key: String,
    tier: &'static str,
    /// The managed host root.
    host: bool,
    /// `accepted` (counts toward the quorum), `signed_not_counted` (made
    /// with another key binding than the one kept now) or `pending` (no
    /// install delivered it here).
    delivery: &'static str,
}

#[derive(Debug, Serialize)]
struct HeadRootsReply {
    /// The head image's id, as 64 hex.
    image: String,
    /// The digest of the root policy the vault counts now, as 64 hex.
    policy: String,
    /// Whether the head was built under that policy.
    current: bool,
    quorum: u8,
    /// Whether one attesting root must be hardware-backed.
    hardware: bool,
    /// Every root of the policy, ascending by key.
    roots: Vec<RootStateReply>,
    /// The roots the head still awaits, each `<suite>:<hex key>`.
    awaited: Vec<String>,
    /// What the accepted roots lack of the policy, named; null once the head
    /// reached it.
    shortfall: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct RootsReply {
    /// This host's checkpoint head and where each root stands on it; null
    /// when no head is kept here.
    head: Option<HeadRootsReply>,
}

/// One home head a root held here signed, and where it stands.
#[derive(Debug, Serialize)]
struct HomeDeliveryReply {
    /// The home's machine, as 32 hex; null for a home that proved none on
    /// its socket.
    machine: Option<String>,
    /// The home's head image the root signed, as 64 hex.
    image: String,
    /// `signed_not_uploaded` (signed here, the home's intake has not taken
    /// it), `delivered` (taken, not yet reported accepted) or `accepted`
    /// (the home's head no longer awaits the root).
    state: RootAttestationDeliveryState,
}

/// One root held here and every home head it signed.
#[derive(Debug, Serialize)]
struct RootDeliveriesReply {
    /// `<suite>:<hex key>`.
    root: String,
    /// In machine order, a home that proved none first.
    homes: Vec<HomeDeliveryReply>,
}

#[derive(Debug, Serialize)]
struct DeliveriesReply {
    /// Each root held here that signed a home's head, ascending by key;
    /// empty when none did.
    roots: Vec<RootDeliveriesReply>,
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

fn delivery_name(delivery: CheckpointRootDelivery) -> &'static str {
    match delivery {
        CheckpointRootDelivery::Accepted => "accepted",
        CheckpointRootDelivery::SignedNotCounted => "signed_not_counted",
        CheckpointRootDelivery::Pending => "pending",
    }
}

fn roots_reply(head: &AuthorityCheckpointRoots) -> HeadRootsReply {
    HeadRootsReply {
        image: hex(&head.image),
        policy: hex(&head.policy),
        current: head.current,
        quorum: head.quorum,
        hardware: head.hardware,
        roots: head
            .roots
            .iter()
            .map(|root| RootStateReply {
                key: key_text(&root.key),
                tier: root.tier.as_str(),
                host: root.host,
                delivery: delivery_name(root.delivery),
            })
            .collect(),
        awaited: head.awaited().map(key_text).collect(),
        shortfall: head.shortfall,
    }
}

fn deliveries_reply(kept: Vec<RootAttestationDelivery>) -> DeliveriesReply {
    let mut roots = std::collections::BTreeMap::<String, Vec<HomeDeliveryReply>>::new();
    for delivery in kept {
        roots
            .entry(key_text(&delivery.root))
            .or_default()
            .push(HomeDeliveryReply {
                machine: delivery.home.map(|machine| machine.to_hex()),
                image: hex(&delivery.image),
                state: delivery.state,
            });
    }
    DeliveriesReply {
        roots: roots
            .into_iter()
            .map(|(root, mut homes)| {
                homes.sort_by(|a, b| a.machine.cmp(&b.machine).then(a.image.cmp(&b.image)));
                RootDeliveriesReply { root, homes }
            })
            .collect(),
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
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<SelectPolicy>,
) -> OwnerReply<PolicyViewReply> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let body = payload.read(&server).await?;
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
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<ClearPolicy>,
) -> OwnerReply<PolicyViewReply> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let body = payload.read(&server).await?;
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

/// `GET /v1/owner/checkpoint-policy/roots`: which roots this host's
/// checkpoint head awaits under the policy in force, and what it lacks. A
/// policy the roster cannot fix is a refusal naming its rule.
async fn roots(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<RootsReply> {
    owner(&auth, &server)?;
    let reply = blocking(move || -> OwnerResult<RootsReply> {
        let head = server
            .vault()
            .authority_checkpoint_roots()
            .map_err(refusal)?;
        Ok(RootsReply {
            head: head.as_ref().map(roots_reply),
        })
    })
    .await?;
    Ok(Json(reply))
}

/// `GET /v1/owner/checkpoint-policy/roots/deliveries`: for each root held
/// here, each home's checkpoint head it signed, as signed but not uploaded,
/// delivered or accepted (FIX 5196). Read-only.
async fn deliveries(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<DeliveriesReply> {
    owner(&auth, &server)?;
    let reply = blocking(move || -> OwnerResult<DeliveriesReply> {
        let kept = server
            .vault()
            .checkpoint_root_deliveries()
            .map_err(refusal)?;
        Ok(deliveries_reply(kept))
    })
    .await?;
    Ok(Json(reply))
}
