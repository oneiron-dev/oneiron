//! Log-derived capability mint ancestry and monotone subtree tombstones.
use super::*;
use crate::error::Result;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldedSlip {
    pub action: SlipMintAction,
    pub signer: AuthorityKey,
    pub entry_hash: AuthorityEntryHash,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SlipAuthorityState {
    pub mints: BTreeMap<[u8; 32], FoldedSlip>,
    pub revoked: BTreeSet<[u8; 32]>,
    pub consumed: BTreeSet<[u8; 32]>,
}
impl SlipAuthorityState {
    pub(super) fn apply(
        &mut self,
        entry: &AuthorityLogEntry,
        hash: AuthorityEntryHash,
    ) -> Result<()> {
        match &entry.op {
            AuthorityOp::SlipMint(action) => {
                action.validate()?;
                let claims = &action.claims;
                if entry.vault_id != Some(claims.vault_id)
                    || self.mints.contains_key(&claims.slip_id)
                    || self.revoked.contains(&claims.slip_id)
                    || self.consumed.contains(&claims.slip_id)
                {
                    return Err(invalid_authority());
                }
                if let Some(parent) = claims.parent_id {
                    let prior = self.mints.get(&parent).ok_or_else(invalid_authority)?;
                    if !claims.narrows(&prior.action.claims) || !self.ancestry_live(&parent) {
                        return Err(invalid_authority());
                    }
                }
                self.mints.insert(
                    claims.slip_id,
                    FoldedSlip {
                        action: action.clone(),
                        signer: entry.signer.public_key.clone(),
                        entry_hash: hash,
                    },
                );
            }
            AuthorityOp::SlipRevoke { slip_id } => {
                self.revoked.insert(*slip_id);
            }
            AuthorityOp::SlipConsume { slip_id } => {
                // Consumption is a monotone subtree kill. An offline single-use
                // caveat is not in the base claims, so any live slip may be burnt.
                if !self.ancestry_live(slip_id) {
                    return Err(invalid_authority());
                }
                // A one-shot ancestor is one grant, not one grant per child.
                // Burning any descendant spends every single-use ancestor too.
                let mut burn = vec![*slip_id];
                let mut parent = self
                    .mints
                    .get(slip_id)
                    .and_then(|m| m.action.claims.parent_id);
                while let Some(id) = parent {
                    let mint = self.mints.get(&id).ok_or_else(invalid_authority)?;
                    if mint.action.claims.single_use {
                        burn.push(id);
                    }
                    parent = mint.action.claims.parent_id;
                }
                self.consumed.extend(burn);
            }
            _ => return Err(invalid_authority()),
        }
        Ok(())
    }
    /// Union is commutative; colliding identifiers are unusable, never first-wins.
    pub(super) fn merge_from(&mut self, other: &Self) {
        self.revoked.extend(&other.revoked);
        self.consumed.extend(&other.consumed);
        for (id, mint) in &other.mints {
            match self.mints.get(id) {
                Some(prior) if prior != mint => {
                    self.revoked.insert(*id);
                    if mint.entry_hash < prior.entry_hash {
                        self.mints.insert(*id, mint.clone());
                    }
                }
                None => {
                    self.mints.insert(*id, mint.clone());
                }
                _ => {}
            }
        }
    }
    fn ancestry_live(&self, id: &[u8; 32]) -> bool {
        self.ancestors(id).is_some()
    }
    fn ancestors(&self, id: &[u8; 32]) -> Option<Vec<&FoldedSlip>> {
        let mut current = Some(*id);
        let mut seen = BTreeSet::new();
        let mut path = Vec::new();
        while let Some(id) = current {
            if !seen.insert(id) || self.revoked.contains(&id) || self.consumed.contains(&id) {
                return None;
            }
            let mint = self.mints.get(&id)?;
            path.push(mint);
            current = mint.action.claims.parent_id;
        }
        Some(path)
    }
    /// Every ancestor's minting host must still be live in the final roster.
    #[must_use]
    pub fn is_live(&self, id: &[u8; 32], roster: &BTreeMap<AuthorityKey, FoldedDevice>) -> bool {
        self.ancestors(id).is_some_and(|path| {
            path.iter().all(|mint| {
                roster.get(&mint.signer).is_some_and(|host| {
                    !host.revoked && host.roles & (ROLE_OWNER | ROLE_ADMIN) != 0
                })
            })
        })
    }
}

impl AuthorityFold {
    /// Log provenance, signer liveness and unresolved fork quarantine all apply
    /// to every ancestor of a delegated slip, including a pre-fork mint.
    #[must_use]
    pub fn slip_is_live(&self, id: &[u8; 32]) -> bool {
        self.vault_id.is_some()
            && !self.vault_root_is_conflicted()
            && self.slips.is_live(id, &self.roster)
            && self.slips.ancestors(id).is_some_and(|path| {
                path.iter().all(|mint| {
                    self.valid_entries.contains(&mint.entry_hash)
                        && !self.authority_forks.iter().any(|fork| {
                            fork.signer == mint.signer
                                && fork.status == AuthorityForkStatus::Quarantined
                        })
                })
            })
    }
}
