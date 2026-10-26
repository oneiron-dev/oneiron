//! `self.grants.answer` (FIX 1379): an access request answered by the vault
//! owner, or by the person or agent it asks, each on their own proof. A
//! person gets their own person proof (`shared_act_doors::person`), the
//! owner's when they own the vault; an agent carries its own verified
//! credential and the actor it binds, never an owner's proof. The engine
//! revalidates either in the answering write.

use std::sync::Arc;

use oneiron::access_grant::AccessRequestResponder;
use oneiron::authority::VerifiedSlip;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{self, GrantAnswerRequest, GrantAnswered};

use super::host_doors::support::MaybeListed;
use super::shared_act_doors::as_person_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The proof an answer is made on, with the credential that carries what
/// the answerer may delegate.
enum ResponderProof {
    Person {
        proof: AuthenticatedOwner,
        credential: Option<VerifiedSlip>,
    },
    Agent {
        actor: oneiron::EntityId,
        credential: VerifiedSlip,
    },
}

impl ResponderProof {
    fn responder(&self) -> AccessRequestResponder<'_> {
        match self {
            Self::Person { proof, credential } => AccessRequestResponder::Person {
                proof,
                credential: credential.as_ref(),
            },
            Self::Agent { actor, credential } => AccessRequestResponder::Agent {
                actor: *actor,
                credential,
            },
        }
    }
}

/// The answering caller's own proof: an agent's verified credential and the
/// actor it binds, or a person's proof.
fn responder_proof(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<ResponderProof> {
    if auth.actor_class() != Some("agent") {
        let proof = super::shared_act_doors::person(server, auth, verb)?;
        return Ok(ResponderProof::Person {
            proof,
            credential: auth.verified_slip().cloned(),
        });
    }
    let refused = || {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} is answered on the answering agent's own credential"),
            &["Present the agent's own verified credential."],
        )
    };
    super::owner_binding::host_preflight(server, auth)?;
    let credential = auth.verified_slip().ok_or_else(refused)?.clone();
    let (actor, _) = super::facade_actor(server, auth).map_err(|_| refused())?;
    Ok(ResponderProof::Agent { actor, credential })
}

/// The admission `door_admits` runs for `self.grants.answer`.
pub(super) fn answer_admits(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<()> {
    responder_proof(server, auth, verb).map(drop)
}

pub(crate) async fn self_grants_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GrantAnswerRequest,
) -> MaybeListed<GrantAnswered> {
    const VERB: &str = "self.grants.answer";
    as_person_naming(
        server,
        VERB,
        responder_proof(server, auth, VERB),
        move |server, proof| sdk::answer_grant_request_as(server.vault(), proof.responder(), input),
        |answer| Some(answer.grant_ref.into_iter().collect()),
    )
    .await
}
