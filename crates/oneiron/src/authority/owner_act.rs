//! The L02 side of the owner-act record (mesh contract §3): the one rule
//! every owner act's carrier is judged by, and what an act's receipt says of
//! the key work that follows it (contract §5). The record itself, its codec
//! and its shape check are `oneiron_authority::authority::OwnerAct`.

use std::collections::BTreeMap;

use super::*;

/// Whether `key` may carry an owner act for `machine`, judged on `machine`'s
/// folded chains and the authority `roster` of the same fold. The one signer
/// rule: the writer, the full fold, the resumed fold, the race, stale renewal
/// and every replica ask it, before and after the owner anchor, so every
/// replica admits the same carriers, and the store doors' structure
/// (`vouches_for`, `is_stranger`, the import order's `wanted`) takes the
/// install key any profile names, in any role, as this does.
///
/// The owner's ruling (10-19 00:5x): "Linking together machines is like a
/// computronium mesh. it doesn't matter where you said yes, if you said so.
/// i can do action X from my phone that impacts an engine on my laptop." The
/// gate is the owner's authenticated say-so at the writer; the signature
/// only says which of the vault's machines carried it. So this admits a
/// live physical machine profile of this vault whose install key is `key`,
/// in any role (yours, work or school, rented, a hosted node, an execution
/// node), as the sync wire accepts a proven peer machine
/// ([`AuthorityFold::machine_proof_key`]) and not only a "yours" one. Live:
/// not removed in any chain, not conflicted or poisoned, not stale, held or
/// unsettled where the view says so. A role change between linked roles
/// never revokes it; only removal does. It never admits a key the authority
/// roster names (the host root, an owner or roster device key: FIX 2222, the
/// unattended host root acts as nobody), nor an engine MACHINE writer, which
/// no profile names.
pub(crate) fn owner_act_signer_admits(
    machine: Option<&FoldedMachine>,
    roster: &BTreeMap<AuthorityKey, FoldedDevice>,
    key: &[u8; 32],
) -> bool {
    !roster.contains_key(&AuthorityKey::Ed25519(*key))
        && machine.is_some_and(|folded| {
            folded.chains().all(|(_, chain)| !chain.removed)
                && folded
                    .chains()
                    .any(|(_, chain)| chain.is_live() && chain.profile.machine_key == *key)
        })
}

/// What an owner act's commit did about the key work that follows it (mesh
/// contract §5, the honest receipt). Only a holder opens, mints or rewraps a
/// key: a carrier that holds none records the decision, and its receipt says
/// so, never "done".
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyWork {
    /// The decision is recorded and needs no key work: the world reads
    /// everywhere, so no key counts for it.
    Recorded,
    /// The decision is recorded, and a holder still has to mint or rewrap
    /// the key: this install may not read the world, or holds no wrap of
    /// its current key.
    AwaitingHolder,
    /// The decision is recorded and this install did the key work in the
    /// same commit: it minted the world's first key, wrapped the current key
    /// to the readers that lacked it, or found every reader holding it.
    Enacted,
}
