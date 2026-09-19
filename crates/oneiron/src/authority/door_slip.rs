//! Signed capability mints and monotone consumption in the authority DAG.

use super::*;
use std::collections::{BTreeMap, BTreeSet};

/// The immutable scope of one authority-minted door slip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityDoorSlip {
    /// Registered holder; verified independently by the transport.
    pub holder_ref: String,
    /// Class identifier, resolved by the engine registry at use time.
    pub verb_class: String,
    /// Exact secret or repository records.
    pub records: BTreeSet<String>,
    /// Exact door effectors.
    pub channels: BTreeSet<String>,
    /// Parent mint hash; absent only for an authority-root grant.
    pub parent: Option<AuthorityEntryHash>,
    /// Optional federation grant and direction bound, joined against live pact state.
    pub pact: Option<(
        crate::entity_id::EntityId,
        crate::federation::FederationDirectionScope,
    )>,
    /// Inclusive start and exclusive expiry in authority-plane seconds.
    pub issued_at: u64,
    pub expires_at: u64,
    /// Redeemable only once, at the minting authority device.
    pub single_use: bool,
}

impl AuthorityDoorSlip {
    pub(super) fn validate(&self) -> crate::error::Result<()> {
        let bounded = |s: &str| !s.is_empty() && s.len() <= 512 && !s.chars().any(char::is_control);
        if !bounded(&self.holder_ref)
            || crate::credential_door::verb_class_members(&self.verb_class).is_none()
            || self.records.is_empty()
            || self.records.len() > 256
            || self.channels.is_empty()
            || self.channels.len() > 16
            || self
                .records
                .iter()
                .chain(&self.channels)
                .any(|s| !bounded(s) || crate::credential_door::names_a_floor(s))
            || self
                .channels
                .iter()
                .any(|s| s != crate::credential_door::DOOR_RECEIVE_PACK_EFFECTOR)
            || self.expires_at <= self.issued_at
            || self.single_use
                && (self.records.len() != 1
                    || self.channels.len() != 1
                    || self.expires_at - self.issued_at
                        > crate::credential_door::DOOR_ONE_SHOT_MAX_LIFETIME_SECS)
        {
            return Err(invalid_authority());
        }
        if let Some((_, scope)) = &self.pact {
            scope.validate()?;
        }
        Ok(())
    }
}

/// A mint proven by the fold, including the device that alone may spend it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldedDoorSlip {
    pub scope: AuthorityDoorSlip,
    pub issuer: AuthorityKey,
}

pub(super) fn apply_door_slip(
    state: &mut FoldState,
    op: &AuthorityOp,
    hash: AuthorityEntryHash,
    signer: &AuthorityKey,
) -> bool {
    match op {
        AuthorityOp::MintDoorSlip(scope) => {
            if let Some(parent_hash) = scope.parent {
                let Some(parent) = state.door_slips.get(&parent_hash) else {
                    return false;
                };
                let parent_scope = &parent.scope;
                let Some(parent_verbs) =
                    crate::credential_door::verb_class_members(&parent_scope.verb_class)
                else {
                    return false;
                };
                let Some(verbs) = crate::credential_door::verb_class_members(&scope.verb_class)
                else {
                    return false;
                };
                if parent_scope.single_use
                    || parent_scope.holder_ref != scope.holder_ref
                    || !parent_verbs.contains(&"mint")
                    || !verbs.iter().all(|verb| parent_verbs.contains(verb))
                    || !scope.records.is_subset(&parent_scope.records)
                    || !scope.channels.is_subset(&parent_scope.channels)
                    || parent_scope.pact.as_ref().is_some_and(|(grant, bound)| {
                        scope.pact.as_ref().is_none_or(|(child_grant, child)| {
                            grant != child_grant || !child.is_narrowing_of(bound)
                        })
                    })
                    || scope.issued_at < parent_scope.issued_at
                    || scope.expires_at > parent_scope.expires_at
                    || !door_slip_live(
                        &state.door_slips,
                        &state.spent_door_slips,
                        &state.roster,
                        &[],
                        &parent_hash,
                    )
                {
                    return false;
                }
            }
            state.door_slips.insert(
                hash,
                FoldedDoorSlip {
                    scope: scope.clone(),
                    issuer: signer.clone(),
                },
            );
            true
        }
        AuthorityOp::SpendDoorSlip { mint_hash } => {
            let Some(mint) = state.door_slips.get(mint_hash) else {
                return false;
            };
            // Only the issuing authority can redeem. A different vault replica
            // must contact that authority, not spend an offline snapshot.
            if &mint.issuer != signer
                || !mint.scope.single_use
                || state.spent_door_slips.contains(mint_hash)
            {
                return false;
            }
            state.spent_door_slips.insert(*mint_hash);
            true
        }
        AuthorityOp::RevokeDoorSlip { mint_hash } => {
            // Monotone tombstone, including an as-yet unseen mint.
            state.spent_door_slips.insert(*mint_hash);
            true
        }
        _ => false,
    }
}

pub(super) fn door_slip_live(
    slips: &BTreeMap<AuthorityEntryHash, FoldedDoorSlip>,
    dead: &BTreeSet<AuthorityEntryHash>,
    roster: &BTreeMap<AuthorityKey, FoldedDevice>,
    forks: &[AuthorityFork],
    hash: &AuthorityEntryHash,
) -> bool {
    let mut next = Some(*hash);
    let mut visited = BTreeSet::new();
    while let Some(id) = next {
        if !visited.insert(id) || dead.contains(&id) {
            return false;
        }
        let Some(mint) = slips.get(&id) else {
            return false;
        };
        if !roster
            .get(&mint.issuer)
            .is_some_and(folded_device_can_authority_consent)
            || forks.iter().any(|fork| {
                fork.signer == mint.issuer && fork.status == AuthorityForkStatus::Quarantined
            })
        {
            return false;
        }
        next = mint.scope.parent;
    }
    true
}

impl AuthorityFold {
    /// Returns only a live mint; parent death, issuer revocation, quarantine,
    /// and spend all remove authority without editing the immutable payload.
    pub fn live_door_slip(&self, hash: &AuthorityEntryHash) -> Option<&FoldedDoorSlip> {
        if door_slip_live(
            &self.door_slips,
            &self.spent_door_slips,
            &self.roster,
            &self.authority_forks,
            hash,
        ) {
            self.door_slips.get(hash)
        } else {
            None
        }
    }
}
