//! The host door of one critic review (`vault.critic.review`, OF-352): the
//! caller binds a target, a session, a lens catalog and each lens's stored
//! skill and actor; the host reads the target under the caller's own scope,
//! asks every lens's verdict, severity, scope and hard check through its
//! decision ladder, and writes the verdict as the caller. It returns the
//! verdict, each lens's artifact and the receipts. Nothing is applied to the
//! target. `host_doors` re-exports it, so the generated HTTP facade handler
//! and the MCP dispatcher call it by the name every host door has.
use std::sync::Arc;

use oneiron::critic::review::{CriticReviewOutcome, CriticReviewSubmit, review_artifact};
use oneiron::memory::{EntityView, MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::{EdgeActorClass, EntityId, Error, WriteActor};
use serde_json::{Value, json};

use super::host_doors::internal;
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
) -> MemoryResult<CriticReviewOutcome> {
    let (actor, class) = super::facade_actor(auth).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "a critic review writes its verdict as an authenticated principal",
            &["Present a slip paired from a link created with --principal-ref."],
        )
    })?;
    let server = Arc::clone(server);
    let auth = auth.clone();
    tokio::task::spawn_blocking(move || review(&server, &auth, actor, class, &input))
        .await
        .map_err(|_| internal(VERB))?
}

fn review(
    server: &SyncServer,
    auth: &CoreAuth,
    actor: EntityId,
    class: EdgeActorClass,
    input: &CriticReviewSubmit,
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
        .get_entity(&input.target_ref)?
        .value
        .ok_or(Error::EntityNotFound)?;
    let state = target_state(&input.kind, &target);
    let decisions = server.decision_host().review_decisions(actor, &state);
    Ok(review_artifact(vault, &request, &catalog, &decisions)?.into())
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
