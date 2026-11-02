//! The opener's lineage and its forks never settle their own proposal
//! (DEC-0006 "Proposals, settlements and the review bundle", FIX 5064). A
//! proof answers from that lineage when one of its verified credential chains
//! holds a slip the proposal froze when it opened, or reaches the delegation
//! root of one: the opener itself, an ancestor, a child at any depth, or a
//! sibling fork, one minted after the proposal opened included. A different
//! lineage, a separately paired credential, one merely minted by the same
//! host, and a proof no credential carried share none of it.

use std::collections::BTreeSet;

use crate::Vault;
use crate::authority::SlipAuthorityState;
use crate::error::Result;

use super::AuthenticatedOwner;

impl AuthenticatedOwner {
    /// The verified credential chains this proof was carried under, in
    /// `txn`'s authority snapshot (FIX 5064): its carried slip, that slip's
    /// verified parent (or the slip a renewal renews, FIX 5481) and every
    /// logged ancestor up to their delegation root, then the host root a host
    /// action acts under (FIX 2222) and that root's own logged ancestry. A
    /// proof no credential carried has none. Every id
    /// comes from a verified slip or the log, never from a wire value; a
    /// proposal freezes these as the lineage that, with its forks, never
    /// settles it.
    ///
    /// # Errors
    /// A failure to read the authority snapshot.
    pub(crate) fn credential_lineage_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Vec<[u8; 32]>> {
        let fold = vault.authority_view_readonly_in_txn(txn)?;
        Ok(self.lineage_in(&fold.slips))
    }

    /// Whether this proof answers from the lineage `opener` names, or from a
    /// fork of it, in `txn`'s authority snapshot (FIX 5064). `opener` is the
    /// lineage a proposal froze when it opened; its delegation roots are
    /// resolved again here, so a fork minted after it opened is caught too.
    /// Every proposal door refuses such an answer: the opener's lineage and
    /// its forks never settle their own proposal. An empty `opener`, or a
    /// proof no credential carried, shares no lineage.
    ///
    /// # Errors
    /// A failure to read the authority snapshot.
    pub(crate) fn answers_from_slip_lineage_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        opener: &[[u8; 32]],
    ) -> Result<bool> {
        if opener.is_empty() {
            return Ok(false);
        }
        let fold = vault.authority_view_readonly_in_txn(txn)?;
        let answer = self.lineage_in(&fold.slips);
        Ok(reaches_opener_lineage(&fold.slips, &answer, opener))
    }

    /// [`Self::credential_lineage_in_txn`] over one snapshot's slip state.
    fn lineage_in(&self, slips: &SlipAuthorityState) -> Vec<[u8; 32]> {
        let carried = self.carried_slip().map(|credential| {
            let claims = credential.claims();
            let mut chain = vec![claims.slip_id];
            // Its verified parent, or the slip a renewal renews (FIX 5481).
            let prior = claims
                .parent_id
                .or_else(|| slips.lineage_link(&claims.slip_id));
            if let Some(prior) = prior {
                chain.extend(slips.delegation_chain(&prior));
            }
            chain
        });
        let host = self
            .host_action
            .as_ref()
            .and_then(|action| action.root_slip_id())
            .map(|root| slips.delegation_chain(&root));
        let mut lineage = Vec::new();
        for slip in carried.into_iter().chain(host).flatten() {
            if !lineage.contains(&slip) {
                lineage.push(slip);
            }
        }
        lineage
    }
}

/// Whether an answer whose credential chains are `answer` comes from the
/// lineage `opener` froze, or from a fork of it: the one policy hook of CALLS
/// `FIX 5064 lineage boundary`. The boundary is the delegation root of each
/// opener slip's actual logged chain, never its signing host, person or
/// machine. The answer is refused when its chains hold a frozen opener slip
/// (the check before FIX 5064) or reach one of those roots.
fn reaches_opener_lineage(
    slips: &SlipAuthorityState,
    answer: &[[u8; 32]],
    opener: &[[u8; 32]],
) -> bool {
    let roots: BTreeSet<[u8; 32]> = opener
        .iter()
        .filter_map(|slip| slips.delegation_chain(slip).last().copied())
        .collect();
    answer
        .iter()
        .any(|slip| opener.contains(slip) || roots.contains(slip))
}

impl Vault {
    /// The verified credential chain `credential` heads, in `txn`'s
    /// authority snapshot (FIX 10693): the slip, its verified parent or the
    /// slip a renewal renews, and every logged ancestor up to their
    /// delegation root, as a proof's carried slip reads in
    /// [`AuthenticatedOwner::credential_lineage_in_txn`]. A consult consent
    /// case freezes it as its opener's lineage.
    ///
    /// # Errors
    /// A failure to read the authority snapshot.
    pub(crate) fn slip_lineage_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        credential: &crate::authority::VerifiedSlip,
    ) -> Result<Vec<[u8; 32]>> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let claims = credential.claims();
        let mut lineage = vec![claims.slip_id];
        let prior = claims
            .parent_id
            .or_else(|| fold.slips.lineage_link(&claims.slip_id));
        if let Some(prior) = prior {
            for slip in fold.slips.delegation_chain(&prior) {
                if !lineage.contains(&slip) {
                    lineage.push(slip);
                }
            }
        }
        Ok(lineage)
    }

    /// Whether the credential chains `answer`, frozen with a word, come from
    /// the lineage `opener` froze, or from a fork of it, in `txn`'s
    /// authority snapshot (FIX 10693): the boundary
    /// [`AuthenticatedOwner::answers_from_slip_lineage_in_txn`] draws for a
    /// live proof, drawn over chains already frozen. An empty `opener`
    /// shares no lineage.
    ///
    /// # Errors
    /// A failure to read the authority snapshot.
    pub(crate) fn frozen_lineages_meet_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        answer: &[[u8; 32]],
        opener: &[[u8; 32]],
    ) -> Result<bool> {
        if opener.is_empty() {
            return Ok(false);
        }
        let fold = self.authority_view_readonly_in_txn(txn)?;
        Ok(reaches_opener_lineage(&fold.slips, answer, opener))
    }
}
