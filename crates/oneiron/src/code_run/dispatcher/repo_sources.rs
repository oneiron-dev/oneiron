//! The attribution a run's proposal records (FIX 6867, G1 PR2b; CALL "FIX
//! 6867 review policy and provenance"), minted by the host, never named by
//! the guest: the actor's canonical session on this install, and an
//! ordinary gated `repo.provenance` claim naming the real actor, the model
//! and request the run's executor bound before the call, and the exact work
//! and change. A run whose host holds no such witness answers
//! `repo_provenance_required`: no author is made up. A session is
//! attribution, not work isolation; one already open is the one used.

use rmpv::Value;

use super::HostSelfDispatcher;
use crate::code_document::CodeOpProvenance;
use crate::code_run::types::SelfEffect;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Result;
use crate::memory::repo_doors::{REPO_PROVENANCE_REQUIRED, RepoRunSources, RepoRunStamp};
use crate::memory::{MemoryError, MemoryResult};
use crate::repo_mutation::REPO_PROVENANCE_PREDICATE;
use crate::session_lifecycle::SessionMintOutcome;
use crate::temporal::TimeRange;
use crate::write_envelope::ClaimCandidate;
use crate::{ClaimSubject, EntityId, Vault};

/// The derivation a run's provenance names: the proposal door's own.
const REPO_PROVENANCE_DERIVATION_VERSION: &str = "self.code.proposal_submit.v1";

/// The one file change a run's proposal makes, as its provenance names it.
pub(super) struct RepoChange {
    pub(super) path: String,
    /// The BLAKE3 hash of the new bytes.
    pub(super) content_hash: [u8; 32],
}

/// The model request the run is serving, as its executor bound it.
struct RequestWitness {
    /// The request's canonical hash as sent.
    digest: [u8; 32],
    model: String,
    /// The BLAKE3 hash of the request's sampling params and provider
    /// options.
    params_hash: String,
}

impl HostSelfDispatcher<'_> {
    /// The run's attribution for its change `change` in the work `stamp`
    /// binds: its session, and the provenance claim, gated as any claim the
    /// run writes. The inner answer is `repo_provenance_required` when the
    /// host holds no witness of the request; the outer error is a store or
    /// gate failure, which ends the call as any memory write's does.
    ///
    /// # Errors
    /// A store failure, or the gate's rejection of the provenance claim.
    pub(super) fn repo_run_sources(
        &self,
        vault: &Vault,
        stamp: &RepoRunStamp,
        change: &RepoChange,
    ) -> Result<MemoryResult<RepoRunSources>> {
        let Some(witness) = self.request_witness() else {
            return Ok(Err(MemoryError::new(
                REPO_PROVENANCE_REQUIRED,
                "this run's host holds no witness of the model request it serves",
                &["A run's proposal needs the request its executor bound; the work is kept."],
            )));
        };
        let actor = self.actor.entity_ref();
        let key = vault.local_session_key(actor)?;
        let session = match vault.mint_session(key, vault.now_recorded_at())? {
            SessionMintOutcome::Minted(session) | SessionMintOutcome::AlreadyOpen(session) => {
                session
            }
        };
        let provenance_claim =
            self.repo_provenance_claim(vault, stamp, change, session, &witness)?;
        Ok(Ok(RepoRunSources {
            session,
            provenance_claim,
            op_provenance: CodeOpProvenance {
                activity: Some(stamp.task),
                ..CodeOpProvenance::default()
            },
        }))
    }

    /// The request the run's executor bound before its latest call, with
    /// the model it names; `None` when none reached this engine.
    fn request_witness(&self) -> Option<RequestWitness> {
        let bound = self.run_request.borrow();
        let sent = bound.as_ref()?.sent.as_ref()?;
        let request = &sent.kept.as_ref()?.request;
        let params = serde_json::to_vec(&(&request.params, &request.provider_options)).ok()?;
        Some(RequestWitness {
            digest: sent.digest,
            model: request.model.as_str().to_owned(),
            params_hash: blake3::hash(&params).to_hex().to_string(),
        })
    }

    /// Mints the gated `repo.provenance` claim of one run change, about the
    /// actor's session, under the run's own envelope.
    fn repo_provenance_claim(
        &self,
        vault: &Vault,
        stamp: &RepoRunStamp,
        change: &RepoChange,
        session: EntityId,
        witness: &RequestWitness,
    ) -> Result<EntityId> {
        let text = |value: String| Value::from(value);
        let value = Value::Map(vec![
            (Value::from("actor"), text(self.actor.entity_ref().to_hex())),
            (Value::from("model"), text(witness.model.clone())),
            (
                Value::from("prompt_hash"),
                text(bytes_to_hex_lower(&witness.digest)),
            ),
            (
                Value::from("derivation_envelope"),
                Value::Map(vec![
                    (
                        Value::from("content_hash"),
                        text(bytes_to_hex_lower(&change.content_hash)),
                    ),
                    (Value::from("model_id"), text(witness.model.clone())),
                    (
                        Value::from("version"),
                        Value::from(REPO_PROVENANCE_DERIVATION_VERSION),
                    ),
                    (
                        Value::from("params_hash"),
                        text(witness.params_hash.clone()),
                    ),
                ]),
            ),
            (
                Value::from("diff_lineage_receipt"),
                Value::Map(vec![
                    (Value::from("work"), text(stamp.work.to_hex())),
                    (Value::from("path"), text(change.path.clone())),
                    (Value::from("base_green"), text(stamp.base_green.clone())),
                    (
                        Value::from("base_snapshot"),
                        text(bytes_to_hex_lower(&stamp.base_snapshot)),
                    ),
                    (
                        Value::from("executor_run"),
                        text(stamp.executor_run.to_hex()),
                    ),
                    (Value::from("task"), text(stamp.task.to_hex())),
                ]),
            ),
        ]);
        let id = vault.store.clock.entity_id()?;
        let admission = self.code_emission_admission()?;
        let candidate = ClaimCandidate::new(
            REPO_PROVENANCE_PREDICATE,
            ClaimSubject::Entity(session),
            value,
            1.0,
        );
        let candidate = match admission
            .as_ref()
            .and_then(|admission| admission.candidate_evidence.clone())
        {
            Some(evidence) => candidate.with_evidence(evidence),
            None => candidate,
        };
        let envelope = self.write_envelope(SelfEffect::RepoProposalSubmit, admission.as_ref())?;
        let gate_body = candidate.clone().into_claim_body(
            &envelope,
            crate::claim::substrate_facet_id(envelope.actor().entity_ref())?,
        )?;
        self.check_write_gate(id, &gate_body, &envelope, false)?;
        let at = vault.now_recorded_at();
        vault.put_claim_candidate_with_landing(
            &id,
            candidate,
            &envelope,
            TimeRange { start: at, end: at },
            at,
            |_| Ok(()),
        )?;
        Ok(id)
    }
}
