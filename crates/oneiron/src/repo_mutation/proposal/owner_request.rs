//! An owner's direct code proposal, attributed by the engine (NO-DOOR
//! CODE-PROPOSAL-ATTRIBUTION; Engine CODECUSTODY-ATTRIB Q1 = A, Q2 = A).
//!
//! The owner doors take no session or provenance claim from the caller. In
//! the owner proposal's writer, once the base pin and the bytes to stage are
//! final (a re-review's content is the engine's projection by then), the
//! engine reuses or opens the owner's canonical sitting on this install and
//! records one reserved `repo.provenance` CLAIM on it in the closed
//! `owner_request` form. Every field is the host's: the revalidated owner,
//! the sitting, the BLAKE3 of the door's verb and typed input, the staged
//! bytes' BLAKE3, the repository, the path and the pinned base commit. No
//! model is named, because no model call is witnessed here; a run's model
//! form stays the run host's. The claim attributes the candidate; it
//! approves, queues and lands nothing.

use rmpv::Value;
use serde::Serialize;

use super::{RepoMutationOperation, RepoMutationRequest, invalid};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::repo_mutation::trailer::{
    OWNER_REQUEST_VERSION, REPO_PROVENANCE_OWNER_REQUEST, REPO_PROVENANCE_PREDICATE,
    REPO_PROVENANCE_SOURCE_KIND_KEY,
};
use crate::session_lifecycle::SessionMintOutcome;
use crate::{TimeRange, Vault};

/// The owner door a proposal came through and its typed input as the door
/// decoded it: the request the claim's request hash is taken over. It
/// carries no attribution of its own.
#[derive(Debug, Clone)]
pub(crate) struct OwnerRequestAttribution {
    verb: &'static str,
    input: serde_json::Value,
}

impl OwnerRequestAttribution {
    /// The request of the owner door `verb` with its typed `input`.
    ///
    /// # Errors
    /// An input that does not serialize.
    pub(crate) fn new<T: Serialize>(verb: &'static str, input: &T) -> Result<Self> {
        let input = serde_json::to_value(input)
            .map_err(|_| invalid("an owner proposal's input does not serialize"))?;
        Ok(Self { verb, input })
    }
}

impl Vault {
    /// Binds the session and provenance claim of the owner's proposal
    /// `request` on `repository`: the owner's canonical sitting on this
    /// install, and a reserved `owner_request` claim on it naming the owner,
    /// the request hash, the staged bytes' BLAKE3, the repository, the path
    /// and the commit the stored pointer pins. The owner proof is judged
    /// again in the claim's writer. A request that already names either
    /// source is refused: an owner proposal's sources are the engine's.
    ///
    /// # Errors
    /// A request with sources, no owner, an operation that is not one file
    /// change or a pointer with no commit; a stale owner proof; or a store
    /// failure.
    pub(super) fn attribute_owner_request(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        attribution: &OwnerRequestAttribution,
        repository: EntityId,
        request: &mut RepoMutationRequest,
    ) -> Result<()> {
        if request.session_id.is_some() || request.provenance_claim_id.is_some() {
            return Err(invalid(
                "an owner proposal's session and provenance claim are the engine's",
            ));
        }
        let actor = request
            .actor_id
            .ok_or_else(|| invalid("an owner proposal names its owner"))?;
        let (path, content_hash) = match &request.operation {
            RepoMutationOperation::CommitFile { path, content, .. }
            | RepoMutationOperation::ResolveConflictFile { path, content, .. } => {
                (path.clone(), blake3::hash(content).to_hex().to_string())
            }
            _ => {
                return Err(invalid(
                    "an owner request's provenance binds one file change",
                ));
            }
        };
        let base_commit = request
            .repo_ref
            .commit_hash()
            .ok_or_else(|| invalid("an owner proposal's repository pointer names its commit"))?
            .to_owned();
        let session =
            match self.mint_session(self.local_session_key(actor)?, self.now_recorded_at())? {
                SessionMintOutcome::Minted(session) | SessionMintOutcome::AlreadyOpen(session) => {
                    session
                }
            };
        let preimage = serde_json::json!({
            "version": OWNER_REQUEST_VERSION,
            "verb": attribution.verb,
            "actor": actor.to_hex(),
            "session": session.to_hex(),
            "input": attribution.input,
            "repo_ref": request.repo_ref.canonical(),
            "base_commit": base_commit,
            "effective_content_hash": content_hash,
        });
        let preimage = crate::llm::canonical_json_bytes(&preimage)
            .map_err(|_| invalid("an owner request's hash input does not serialize"))?;
        let request_hash = blake3::hash(&preimage).to_hex().to_string();
        let mut body = ClaimBody::new(
            REPO_PROVENANCE_PREDICATE,
            ClaimSubject::Entity(session),
            Value::Map(vec![
                (
                    Value::from(REPO_PROVENANCE_SOURCE_KIND_KEY),
                    Value::from(REPO_PROVENANCE_OWNER_REQUEST),
                ),
                (Value::from("actor"), Value::from(actor.to_hex())),
                (Value::from("session"), Value::from(session.to_hex())),
                (Value::from("request_hash"), Value::from(request_hash)),
                (
                    Value::from("derivation_envelope"),
                    Value::Map(vec![
                        (Value::from("content_hash"), Value::from(content_hash)),
                        (Value::from("version"), Value::from(OWNER_REQUEST_VERSION)),
                    ]),
                ),
                (
                    Value::from("diff_lineage_receipt"),
                    Value::Map(vec![
                        (Value::from("repo"), Value::from(repository.to_hex())),
                        (Value::from("path"), Value::from(path)),
                        (Value::from("base_commit"), Value::from(base_commit)),
                    ]),
                ),
            ]),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )?;
        // The host observed this request; it is attribution, not approval.
        body.source = Some(ClaimSource::Observed);
        let claim = EntityId::now();
        self.with_write_txn_grouped(|txn| {
            if owner.revalidate_in_txn(self, txn)? != actor {
                return Err(invalid("proposal actor is not the authenticated owner"));
            }
            // The claim is about the sitting, a SESSION, which has no
            // substrate facet (only a PERSON's put mints one), and a CLAIM's
            // birth needs a live FACET (#4389): it is born in the vault
            // default facet.
            body.scope_facet = self.default_facet_in_txn(&*txn)?;
            let now = self.now_recorded_at();
            self.put_reserved_claim_in_txn(
                txn,
                &claim,
                &body,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )
        })?;
        request.session_id = Some(session);
        request.provenance_claim_id = Some(claim);
        Ok(())
    }
}
