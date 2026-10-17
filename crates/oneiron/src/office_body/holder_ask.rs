//! Holder asks for office proposals (DEC-0006: "The rest wait together as one
//! review bundle, offered to every holder whose power covers them"). When a
//! settlement leaves members waiting, one ask TASK goes to every holder of
//! the artifact's office edits, or to the vault's owners when no standing
//! grant names one. The ask is a notice: a holder answers by settling the
//! proposal at its own door, and neither the ask's answer nor its silence
//! lands anything (ARCH-0040: "Only a ledger record from a holder surface
//! satisfies approval").

use crate::entity_id::EntityId;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::task_verb::{
    AskAuthorityScope, ConsultPayloadRef, TaskAskDefault, TaskAskQuestion, TaskAskSpec,
    TaskAskTarget,
};

use super::consent::office_scope;
use super::{MemberVerdict, ProposalAsk};

/// The intent prefix of an office proposal's holder ask; with the proposal
/// and the waiting set's revision it keys one ask, so a repeat replays it.
const ASK_INTENT: &str = "office.proposal.holders";
const REVISION_DOMAIN: &[u8] = b"oneiron.office.proposal_ask.v1";

impl Memory<'_> {
    /// Ask the holders of `artifact`'s office edits about the members of
    /// `proposal` that wait, once per waiting set. An ask admission refuses
    /// only the ask: the settlement stands, and the refusal is logged.
    pub(super) fn ask_office_holders(&self, artifact: &EntityId, proposal: &EntityId) {
        if let Err(error) = self.raise_office_holder_ask(artifact, proposal) {
            tracing::warn!(
                proposal = %proposal.to_hex(),
                %error,
                "office proposal holder ask refused"
            );
        }
    }

    fn raise_office_holder_ask(
        &self,
        artifact: &EntityId,
        proposal: &EntityId,
    ) -> MemoryResult<()> {
        let vault = self.vault();
        let Some(record) = vault.office_body_proposal(artifact, proposal)? else {
            return Ok(());
        };
        let forks: Vec<EntityId> = record
            .members
            .iter()
            .filter(|member| member.verdict == MemberVerdict::Waiting)
            .map(|member| member.fork)
            .collect();
        if record.settlement.is_some() || forks.is_empty() {
            return Ok(());
        }
        let (class, envelope) = office_scope(artifact)?;
        let who = {
            let txn = vault
                .store
                .env
                .read_txn()
                .map_err(crate::error::Error::from)?;
            if vault
                .ask_authority_holders_in_txn(&txn, &class, &envelope)?
                .is_empty()
            {
                let owners = crate::policy_model::owners_in_txn(vault, &txn)?;
                if owners.is_empty() {
                    return Err(MemoryError::bad_request(
                        "an office proposal ask has no holder and no vault owner",
                    ));
                }
                TaskAskTarget::People(owners.into_iter().collect())
            } else {
                TaskAskTarget::Authority(AskAuthorityScope { class, envelope })
            }
        };
        let version = vault
            .blob_artifact_head(artifact)?
            .ok_or_else(|| MemoryError::not_found("the office artifact has no version"))?;
        let revision = waiting_revision(proposal, &forks);
        let mut question = TaskAskQuestion::new(ConsultPayloadRef::Claim(version.claim_id));
        question.revision = revision;
        question.label = Some(format!(
            "Office proposal {} on artifact {}: {} fork(s) wait for a holder whose authority covers them. Read each with vault.artifacts.body.fork.diff, then answer with vault.artifacts.body.proposal.settle; answering this ask lands nothing.",
            proposal.to_hex(),
            artifact.to_hex(),
            forks.len()
        ));
        let mut spec = TaskAskSpec::shorthand(Some(who), question, None, TaskAskDefault::Hold);
        spec.intent_key = format!("{ASK_INTENT}/{}/{revision}", proposal.to_hex());
        let receipt = self.tasks_ask(&spec)?;
        vault.record_office_proposal_ask(
            artifact,
            proposal,
            ProposalAsk {
                ask: receipt.handle.group_ref,
                forks,
                at: vault.now_recorded_at(),
            },
        )?;
        Ok(())
    }
}

/// One waiting set's revision: the same forks waiting in a proposal ask once;
/// a fork joining or landing makes a new set, asked anew.
fn waiting_revision(proposal: &EntityId, forks: &[EntityId]) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REVISION_DOMAIN);
    hasher.update(proposal.as_bytes());
    for fork in forks {
        hasher.update(fork.as_bytes());
    }
    let mut head = [0; 8];
    head.copy_from_slice(&hasher.finalize().as_bytes()[..8]);
    u64::from_be_bytes(head).max(1)
}
