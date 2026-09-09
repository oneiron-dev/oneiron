//! Deterministic conversation, turn and message ids derived from a run's identity.

use sha2::{Digest, Sha256};

use crate::memory::WitnessReceipt;
use crate::off_record::ExecutorUtterance;
use crate::{EntityId, Error, Result, Vault, WriteActor};

/// Domain tags for a canonical run's speech identities (ONE-1686).
///
/// Executor-owned transcript identity is DERIVED, never minted. A durable
/// executor passes both the host-bound run ref and `EngineExecutorConfig.run_id`,
/// so two replay records cannot share transcript rows merely because their
/// dispatchers reused a ref. The optional run id preserves the original
/// run-ref-only identity for standalone dispatcher and witness APIs that have no
/// durable executor config.
const EXECUTOR_SPEECH_CONVERSATION_DOMAIN: &[u8] = b"oneiron:executor-speech-conversation:v1";

const EXECUTOR_SPEECH_TURN_DOMAIN: &[u8] = b"oneiron:executor-speech-turn:v1";

const EXECUTOR_SPEECH_MESSAGE_DOMAIN: &[u8] = b"oneiron:executor-speech-message:v1";

/// Derives one deterministic entity id from a domain tag and length-prefixed
/// material, re-salting past a reserved sentinel rather than truncating into
/// one.
fn derived_executor_id(domain: &[u8], parts: &[&[u8]]) -> Result<EntityId> {
    for salt in 0..=u8::MAX {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update([salt]);
        for part in parts {
            let len = u64::try_from(part.len())
                .map_err(|_| Error::ArithmeticOverflow("executor speech id material"))?;
            hasher.update(len.to_le_bytes());
            hasher.update(part);
        }
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        if let Ok(id) = EntityId::from_bytes(bytes) {
            return Ok(id);
        }
    }
    Err(Error::InvariantViolation(
        "executor speech id derivation failed",
    ))
}

/// The legacy standalone conversation identity. Runtime executor paths use
/// [`canonical_speech_conversation_id_for_run`] with their durable run id.
#[cfg(test)]
pub(in crate::code_run) fn canonical_speech_conversation_id(run_ref: &str) -> Result<EntityId> {
    canonical_speech_conversation_id_for_run(run_ref, None)
}

/// The conversation a CANONICAL run's speech lands in: one shell per durable
/// run, create-or-get through the ordinary witness door.
pub(crate) fn canonical_speech_conversation_id_for_run(
    run_ref: &str,
    run_id: Option<EntityId>,
) -> Result<EntityId> {
    match run_id {
        Some(run_id) => derived_executor_id(
            EXECUTOR_SPEECH_CONVERSATION_DOMAIN,
            &[run_ref.as_bytes(), run_id.as_bytes()],
        ),
        None => derived_executor_id(EXECUTOR_SPEECH_CONVERSATION_DOMAIN, &[run_ref.as_bytes()]),
    }
}

/// The turn one run's speech appends to.
///
/// ONE turn per run, not one per utterance: a TURN is the maximal consecutive
/// run of ONE speaker, and every bubble a run emits is the same Companion. The
/// bubbles' own `order` values carry the interleaving.
pub(super) fn executor_speech_turn_id(run_ref: &str, run_id: Option<EntityId>) -> Result<EntityId> {
    match run_id {
        Some(run_id) => derived_executor_id(
            EXECUTOR_SPEECH_TURN_DOMAIN,
            &[run_ref.as_bytes(), run_id.as_bytes()],
        ),
        None => derived_executor_id(EXECUTOR_SPEECH_TURN_DOMAIN, &[run_ref.as_bytes()]),
    }
}

/// The legacy standalone MESSAGE identity. Runtime executor paths also fold in
/// their durable run id through [`executor_speech_message_id_for_run`].
#[cfg(test)]
pub(crate) fn executor_speech_message_id(run_ref: &str, order: u32) -> Result<EntityId> {
    executor_speech_message_id_for_run(run_ref, None, order)
}

/// The MESSAGE id for one executor bubble: the run identity plus the bubble's
/// host-owned position.
///
/// `order` is the bridge ordering the host stamped (or, for the trailing
/// fallback, the run's next bridge position), so it is unique within the run
/// and reproducible from the persisted replay state. That is what makes a
/// re-emission a re-PUT of the same row rather than a second bubble.
pub(super) fn executor_speech_message_id_for_run(
    run_ref: &str,
    run_id: Option<EntityId>,
    order: u32,
) -> Result<EntityId> {
    let order_bytes = order.to_le_bytes();
    match run_id {
        Some(run_id) => derived_executor_id(
            EXECUTOR_SPEECH_MESSAGE_DOMAIN,
            &[run_ref.as_bytes(), run_id.as_bytes(), &order_bytes],
        ),
        None => derived_executor_id(
            EXECUTOR_SPEECH_MESSAGE_DOMAIN,
            &[run_ref.as_bytes(), &order_bytes],
        ),
    }
}

/// Records ONE canonical-run executor turn through ONE-1728's facade witness
/// door (ONE-1686).
///
/// A CALL SITE, not a transcript surface — the same standing the session arm
/// has. Conversation identity, container resolution, role tags, the approval
/// ceiling, the `AuthoredBy` edge and the BM25 posting are all the door's; what
/// this adds is the run-scoped shell and turn a canonical run has no session to
/// hand it, both derived from the durable run identity so they are the same on
/// every attempt but distinct from another run that reused the dispatcher ref.
///
/// `turn_ref` IS supplied here, unlike on the session arm. The typed refusal
/// there guards GUEST-named turns inside a room; this id is host-derived from
/// the run identity, and naming it is exactly what makes a retried step append
/// to the turn it already opened instead of opening another.
///
/// # Errors
///
/// Propagates the witness door's refusals, including the ONE-1686 approval
/// ceiling — preserved as the typed gate denial so the dispatcher records a
/// `Denied` bridge row rather than an opaque failure.
#[expect(
    clippy::too_many_arguments,
    reason = "every parameter is a distinct axis the witness envelope binds; folding them into a \
              struct would hide which ones the host owns"
)]
pub(super) fn canonical_witness_executor_turn(
    vault: &Vault,
    run_ref: &str,
    run_id: Option<EntityId>,
    kind: ExecutorUtterance,
    text: &str,
    occurred_at: u64,
    order: u32,
    message_id: EntityId,
    actor: WriteActor,
) -> Result<WitnessReceipt> {
    let conversation_id = canonical_speech_conversation_id_for_run(run_ref, run_id)?;
    let turn_id = executor_speech_turn_id(run_ref, run_id)?;
    vault
        .memory(actor.entity_ref(), actor.actor_class())
        .witness(&crate::memory::WitnessTurn {
            conversation_ref: conversation_id.to_hex(),
            turn_ref: Some(turn_id.to_hex()),
            messages: vec![crate::memory::WitnessMessage {
                id: Some(message_id.to_hex()),
                author: crate::memory::WitnessAuthor::Companion,
                message_type: kind.as_message_type().to_owned(),
                content: text.to_owned(),
                metadata: None,
                is_visible: kind.is_visible(),
                order,
            }],
            occurred_at,
        })
        .map_err(|error| {
            error
                .gate_denial_error()
                .unwrap_or(Error::InvariantViolation(
                    "executor witness door rejected the canonical turn",
                ))
        })
}
