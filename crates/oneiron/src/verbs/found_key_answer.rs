//! The two answers to a found key that the person who wrote its value may
//! give, as the owner may (Engine RULING 08:35 C, 14 Nov;
//! L6-03-WRITER-MARK-MANAGED-MEMBER): `vault.secrets.found.not_a_secret`
//! and `vault.secrets.found.keep_as_text`. Each runs the engine door its
//! `/v1/owner/secrets/found/*` route runs, with the same request and reply
//! fields, under a live person's own proof: the owner's, or that of the
//! person who wrote the key's value into its record. The engine door admits
//! only those two people, in its own transaction; a handle that names
//! another writer's key is refused as a non-owner is. No agent Grant reaches
//! either answer: an agent's write records no writer, and an agent's handle
//! is refused before the door. A host passes its own reading of where the
//! request came from as the act's surface, for audit only. An embedded
//! handle acts as this install.

use serde::{Deserialize, Serialize};

use crate::authority::ActSurface;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::secret_custody::FoundKeySettled;
use crate::store::GateDecisionId;
use crate::{EntityId, Vault};

/// The verb that rules a found key no secret.
const NOT_A_SECRET_VERB: &str = "vault.secrets.found.not_a_secret";

/// The verb that keeps a found key's value as text.
const KEEP_AS_TEXT_VERB: &str = "vault.secrets.found.keep_as_text";

/// The input of both answers: the key's handle, the body `POST
/// /v1/owner/secrets/found/not-a-secret` and `/keep-as-text` take.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoundKeyAnswerRequest {
    /// The key's handle, such as `sc12`, as the masked record reads it.
    pub handle: String,
}

/// What an answer settled about a found key, as the owner's routes write
/// it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoundKeySettledReply {
    /// `not_a_secret` or `kept_as_text`.
    pub action: String,
    /// The person who answered: the owner, or the person who wrote the
    /// value.
    pub by: Option<EntityId>,
    /// When the answer was settled, on the vault's clock.
    pub at: u64,
    /// The answer's receipt: `rotation:<hex>`, `redaction:<hex>` or
    /// `gate:<hex>`.
    pub receipt_ref: String,
    /// The standing grant a `grant` wrote; neither answer here writes one.
    pub grant_ref: Option<String>,
}

impl From<FoundKeySettled> for FoundKeySettledReply {
    fn from(settled: FoundKeySettled) -> Self {
        Self {
            action: settled.action.as_str().to_owned(),
            by: settled.by,
            at: settled.at,
            receipt_ref: settled.receipt,
            grant_ref: settled.grant_ref,
        }
    }
}

/// `vault.secrets.found.not_a_secret` under `person`'s proof: the door
/// `POST /v1/owner/secrets/found/not-a-secret` runs. The value goes back
/// into its record as text, and later scans pass it by.
///
/// # Errors
/// Every refusal of [`Vault::rule_found_key_not_a_secret`].
pub fn rule_found_key_not_a_secret_as(
    vault: &Vault,
    person: &AuthenticatedOwner,
    surface: ActSurface,
    input: FoundKeyAnswerRequest,
) -> MemoryResult<FoundKeySettledReply> {
    Ok(vault
        .rule_found_key_not_a_secret(person, surface, &input.handle)?
        .into())
}

/// `vault.secrets.found.keep_as_text` under `person`'s proof: the door
/// `POST /v1/owner/secrets/found/keep-as-text` runs. The value stays a
/// secret by its answerer's choice, goes back into its record as text, and
/// later scans pass it by.
///
/// # Errors
/// Every refusal of [`Vault::keep_found_key_as_text`].
pub fn keep_found_key_as_text_as(
    vault: &Vault,
    person: &AuthenticatedOwner,
    surface: ActSurface,
    input: FoundKeyAnswerRequest,
) -> MemoryResult<FoundKeySettledReply> {
    Ok(vault
        .keep_found_key_as_text(person, surface, &input.handle)?
        .into())
}

/// `vault.secrets.found.not_a_secret` on an embedded handle
/// ([`answerer_proof`]), as this install.
///
/// # Errors
/// A handle that is neither the owner's nor a person's own, and as
/// [`rule_found_key_not_a_secret_as`].
pub fn rule_found_key_not_a_secret_embedded(
    memory: &Memory<'_>,
    input: FoundKeyAnswerRequest,
) -> MemoryResult<FoundKeySettledReply> {
    rule_found_key_not_a_secret_as(
        memory.vault(),
        &answerer_proof(memory, NOT_A_SECRET_VERB)?,
        ActSurface::ThisInstall,
        input,
    )
}

/// `vault.secrets.found.keep_as_text` on an embedded handle
/// ([`answerer_proof`]), as this install.
///
/// # Errors
/// A handle that is neither the owner's nor a person's own, and as
/// [`keep_found_key_as_text_as`].
pub fn keep_found_key_as_text_embedded(
    memory: &Memory<'_>,
    input: FoundKeyAnswerRequest,
) -> MemoryResult<FoundKeySettledReply> {
    keep_found_key_as_text_as(
        memory.vault(),
        &answerer_proof(memory, KEEP_AS_TEXT_VERB)?,
        ActSurface::ThisInstall,
        input,
    )
}

/// The proof an embedded answer runs under: the embedded owner's, or a
/// person's own on a handle bound as that person (their presented slip, or
/// a native call), as `vault.outbound.undo_send` takes it. An agent's handle
/// is refused. The engine door then judges whether that person wrote the
/// key.
fn answerer_proof(memory: &Memory<'_>, verb: &str) -> MemoryResult<AuthenticatedOwner> {
    if let Ok(owner) = memory.embedded_owner(verb) {
        return Ok(owner);
    }
    let refused = || {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} is the vault owner's, or a person's own"),
            &[
                "Call it as the vault's owner, or as the person who wrote the value, on their own verified human credential.",
            ],
        )
    };
    if memory.actor_class() != EdgeActorClass::Human {
        return Err(refused());
    }
    let vault = memory.vault();
    let actor = memory.actor();
    let person = vault
        .authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())
        .map_err(|_| refused())?;
    match memory.presented_credential() {
        Some(slip) => Ok(vault.bind_person_credential(person, slip.clone())?),
        None if memory.native_invocation() => Ok(person),
        None => Err(refused()),
    }
}
