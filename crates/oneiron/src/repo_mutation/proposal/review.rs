//! The shared authenticated critic writer for engine and public owner doors.
use super::*;

impl Vault {
    /// Records one authenticated host critic identity. A critic cannot rewrite its vote.
    pub fn review_repo_proposal(
        &self,
        id: EntityId,
        critic: EntityId,
        critique: CritiqueArtifact,
    ) -> Result<RepoProposal> {
        self.review_repo_proposal_checked(id, critic, critique, |_, _| Ok(()))
    }

    pub(crate) fn review_repo_proposal_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        id: EntityId,
        critique: CritiqueArtifact,
    ) -> Result<RepoProposal> {
        let critic = owner.revalidate(self)?;
        let sources = critique.evidence_refs.iter().map(|reference| EntityId::from_hex(reference))
            .collect::<Result<Vec<_>>>()?;
        let calibration_subject = critique.calibration.subject;
        self.review_repo_proposal_checked(id, critic, critique, |txn, row| {
            if owner.revalidate_in_txn(self, txn)? != critic {
                return Err(invalid("reviewer identity changed"));
            }
            for source in sources.into_iter().chain([calibration_subject, id]) {
                if !crate::ports::EntityStoreRead::port_entity_present(&self.store, txn, &source)? {
                    return Err(Error::EntityNotFound);
                }
            }
            settlement::require_independent(self, txn, row, critic)
        })
    }

    fn review_repo_proposal_checked(
        &self,
        id: EntityId,
        critic: EntityId,
        critique: CritiqueArtifact,
        check: impl FnOnce(&heed::RoTxn<'_>, &RepoProposal) -> Result<()>,
    ) -> Result<RepoProposal> {
        let mut txn = self.store.env.write_txn()?;
        let mut row = PROPOSAL
            .get(&self.store, &txn, &id)?
            .ok_or(Error::EntityNotFound)?;
        check(&txn, &row)?;
        if row.status != RepoProposalStatus::Proposed
            || row.actor.is(critic)
            || critique.provenance.critic_ref != critic.to_hex()
            || critique.candidate_ref != id.to_hex()
            || critique.out_of_scope
            || row.critiques.len() >= 64
            || !crate::ports::EntityStoreRead::port_entity_present(&self.store, &txn, &critic)?
        {
            return Err(invalid(
                "critic is unbound, self-reviewing, or proposal is closed",
            ));
        }
        if let Some(existing) = row.critiques.iter().find(|c| {
            c.provenance.critic_ref == critique.provenance.critic_ref
                && c.lens_id == critique.lens_id
                && c.domain == critique.domain
        }) {
            return if existing == &critique {
                Ok(row)
            } else {
                Err(invalid("critic vote is immutable"))
            };
        }
        row.critiques.push(critique);
        row.triage()?;
        store(self, &mut txn, &row)?;
        txn.commit()?;
        Ok(row)
    }
}
