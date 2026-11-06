//! Physical discovery-proposal rows from the original eager scanner.

use crate::store::attempt_sources::SkillEditProposalSource;
use crate::{Result, Vault};

use super::codec::EDIT_PROPOSAL;
use super::types::{SkillEditProposal, SkillEditProposalReadPosition};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalSkillEditProposal {
    sequence: u64,
    key: Vec<u8>,
    body: Vec<u8>,
    proposal: SkillEditProposal,
}

impl CanonicalSkillEditProposal {
    pub(crate) fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(crate) fn key(&self) -> &[u8] {
        &self.key
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) fn proposal(&self) -> &SkillEditProposal {
        &self.proposal
    }

    pub(crate) fn read_position(&self) -> Option<&SkillEditProposalReadPosition> {
        self.proposal.read_position.as_ref()
    }

    pub(crate) fn into_proposal(self) -> SkillEditProposal {
        self.proposal
    }

    pub(crate) fn source(&self) -> SkillEditProposalSource {
        SkillEditProposalSource {
            sequence: self.sequence,
            id: self.proposal.row_id,
            key: self.key.clone(),
            body_hash: *blake3::hash(&self.body).as_bytes(),
        }
    }
}

pub(crate) fn canonical_skill_edit_proposal_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    sequence: u64,
) -> Result<Option<CanonicalSkillEditProposal>> {
    let Some(body) = EDIT_PROPOSAL.get_bytes(&vault.store, txn, &sequence)? else {
        return Ok(None);
    };
    let proposal = EDIT_PROPOSAL.decode_value(&body)?;
    Ok(Some(CanonicalSkillEditProposal {
        sequence,
        key: EDIT_PROPOSAL.key_bytes(&sequence),
        body,
        proposal,
    }))
}

/// No auxiliary marker tables: the ordinary decoder consults only these rows.
pub(crate) fn canonical_skill_edit_proposals_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<(Vec<CanonicalSkillEditProposal>, &'static [u8])> {
    let rows = EDIT_PROPOSAL
        .scan_with_bytes(&vault.store, txn)?
        .into_iter()
        .map(
            |(sequence, proposal, key, body)| CanonicalSkillEditProposal {
                sequence,
                key,
                body,
                proposal,
            },
        )
        .collect();
    Ok((rows, EDIT_PROPOSAL.decl().prefix))
}
