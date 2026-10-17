//! The host door of one critic review (`vault.critic.review`, OF-352): the
//! caller binds a target, a session, a lens catalog and each lens's stored
//! skill and actor; the host reads the target under the caller's own scope,
//! asks every lens's verdict, severity, scope and hard check through its
//! decision ladder, and writes the verdict as the caller. It returns the
//! verdict, each lens's artifact and the receipts. Nothing is applied to the
//! target. `host_doors` re-exports it, so the generated HTTP facade handler
//! and the MCP dispatcher call it by the name every host door has. Beside
//! the outcome it lists the rows the review was derived from: those its
//! target read listed, and the rows the review itself reads raw.
use std::sync::Arc;

use oneiron::critic::review::{CriticReviewOutcome, CriticReviewSubmit, review_artifact};
use oneiron::memory::{EntityView, MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult, ProducerRows};
use oneiron::{EdgeActorClass, EntityId, Error, WriteActor};
use serde_json::{Value, json};

use super::host_doors::{Listed, internal, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

const VERB: &str = "vault.critic.review";

/// `vault.critic.review`: reviews one artifact through the host's decision
/// ladder as the authenticated principal, on a blocking thread, one pack of
/// questions per lens.
pub(crate) async fn vault_critic_review(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CriticReviewSubmit,
) -> Listed<CriticReviewOutcome> {
    let (actor, class) = match super::facade_actor(auth) {
        Ok(caller) => caller,
        Err(_) => {
            return refused(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "a critic review writes its verdict as an authenticated principal",
                &["Present a slip paired from a link created with --principal-ref."],
            ));
        }
    };
    let server = Arc::clone(server);
    let auth = auth.clone();
    tokio::task::spawn_blocking(move || {
        let producers = ProducerRows::default();
        let mut read = Vec::new();
        let answer = review(&server, &auth, actor, class, &input, &producers, &mut read);
        read.extend(producers.take());
        (answer, read)
    })
    .await
    .unwrap_or_else(|_| refused(internal(VERB)))
}

/// The review, listing in `producers` what its target read lists and in
/// `read` the rows `review_artifact` reads raw: the target, the session,
/// every lens's skill and critic, and the verdict it stands on.
fn review(
    server: &SyncServer,
    auth: &CoreAuth,
    actor: EntityId,
    class: EdgeActorClass,
    input: &CriticReviewSubmit,
    producers: &ProducerRows,
    read: &mut Vec<EntityId>,
) -> MemoryResult<CriticReviewOutcome> {
    let vault = server.vault();
    let (request, catalog) = input.bind(WriteActor::new(actor, class), vault.now_recorded_at())?;
    // The session, every lens's skill and every critic are the caller's to
    // read; one it cannot read is absent to it.
    let named = std::iter::once(request.session).chain(
        request
            .critics
            .iter()
            .flat_map(|critic| [critic.lens_ref, critic.actor.entity_ref()]),
    );
    for id in named {
        if !auth.can_read_entity(vault, &id)? {
            return Err(Error::EntityNotFound.into());
        }
    }
    let target = crate::api::credential_memory(vault, Some(auth), actor, class)
        .at(auth.locality())
        .listing_producers(producers)
        .get_entity(&input.target_ref)?
        .value
        .ok_or(Error::EntityNotFound)?;
    read.extend([request.target, request.session]);
    read.extend(
        request
            .critics
            .iter()
            .flat_map(|critic| [critic.lens_ref, critic.actor.entity_ref()]),
    );
    let state = target_state(&input.kind, &target);
    let decisions = server.decision_host().review_decisions(actor, &state);
    let result = review_artifact(vault, &request, &catalog, &decisions)?;
    read.push(result.verdict_claim);
    Ok(result.into())
}

/// The target as every lens's questions read it: the caller's view of it,
/// its body cut shorter, halving, until the state fits the ladder's bound;
/// `cut_at_bytes` says where, so a provider knows it reads a cut text.
fn target_state(kind: &str, target: &EntityView) -> Value {
    let whole = state_of(kind, target, target.body.clone(), None);
    if fits(&whole) {
        return whole;
    }
    let text = target
        .body
        .as_ref()
        .map(Value::to_string)
        .unwrap_or_default();
    let mut cut = text.len();
    loop {
        cut /= 2;
        let mut end = cut;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        let state = state_of(kind, target, Some(Value::from(&text[..end])), Some(end));
        // Nothing left to cut: the ladder refuses the state.
        if fits(&state) || end == 0 {
            return state;
        }
    }
}

fn state_of(kind: &str, target: &EntityView, body: Option<Value>, cut: Option<usize>) -> Value {
    json!({
        "kind": kind,
        "target": {
            "id": target.id_hex,
            "kind": target.kind,
            "occurred_start": target.occurred_start,
            "occurred_end": target.occurred_end,
            "learned_at": target.learned_at,
            "body": body,
        },
        "cut_at_bytes": cut,
    })
}

fn fits(state: &Value) -> bool {
    serde_json::to_vec(state)
        .is_ok_and(|bytes| bytes.len() <= oneiron::llm::decision::MAX_DECISION_STATE_BYTES)
}
