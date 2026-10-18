//! Who may hold an active custody change's bytes (WILL L04 row 04): the
//! recipients the owner permits, each bound to the profile entry and the
//! encryption key he saw, carried inline in the request and in the custody
//! transition that enacts it (CALLS CUSTODY_PERMITS).
//!
//! Any live linked install may be permitted, in any role: his own machine, a
//! linked work, school or rented one, or a hosted node. A machine is never
//! added because it was linked or because the roster gained it: linking
//! alone is not his consent. A permit stands while its machine is still a
//! live linked install of the vault with the very key permitted; a changed
//! key needs a fresh permit, and a role change between linked roles alone
//! leaves it standing. Only a key that imports may be permitted, as a value
//! sealed to any other could not be opened.

use oneiron_crypto::HybridPublicKey;

use crate::EntityId;
use crate::authority::{AuthorityFold, CustodyRecipientPermit, MachineRevision};

const KEY_DIGEST_DOMAIN: &[u8] = b"oneiron/custody-permit-key/v1";

/// How a custody change names who may hold its bytes (CALLS
/// CUSTODY_PERMITS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyPermits {
    /// The request carries each permitted recipient inline, with the exact
    /// profile entry and encryption key digest the owner permitted; its
    /// transition seals to exactly those, and a receiver checks the two
    /// lists are one. No automatic list of the owner's machines, no reseal
    /// for a machine the roster gains.
    InlineExactBytePermits,
}

const CUSTODY_PERMITS: CustodyPermits = CustodyPermits::InlineExactBytePermits;

/// The digest a permit binds of one machine's encryption key: its canonical
/// suite, then its public key bytes.
pub(crate) fn encryption_key_digest(suite: u16, key: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(KEY_DIGEST_DOMAIN);
    hasher.update(&suite.to_be_bytes());
    hasher.update(key);
    *hasher.finalize().as_bytes()
}

/// The live revisions that stand for `machine` here under the key its
/// connection proves, linked in any role: none when no chain of it is live,
/// or one of its chains removed it (only removal ends a linked install).
fn live_revisions(fold: &AuthorityFold, machine: EntityId) -> Vec<&MachineRevision> {
    let (Some(proof), Some(folded)) = (fold.machine_proof_key(machine), fold.machine(machine))
    else {
        return Vec::new();
    };
    if folded.chains().any(|(_, chain)| chain.removed) {
        return Vec::new();
    }
    folded
        .roster_trusted
        .iter()
        .chain(folded.chains().map(|(_, chain)| chain))
        .filter(|revision| revision.is_live() && revision.profile.machine_key == proof)
        .collect()
}

fn revision_key_digest(revision: &MachineRevision) -> [u8; 32] {
    let key = &revision.profile.encryption_key;
    encryption_key_digest(key.suite, &key.key)
}

/// The key a holder's input is sealed to: `holder`'s, when it is a live
/// linked install with an encryption key that imports (CALLS
/// CUSTODY_EXECUTOR).
pub(crate) fn holder_key(fold: &AuthorityFold, holder: EntityId) -> Option<HybridPublicKey> {
    live_revisions(fold, holder)
        .into_iter()
        .find_map(|revision| HybridPublicKey::from_bytes(&revision.profile.encryption_key.key).ok())
}

/// The permit the owner gives `machine` as the fold stands: the profile
/// entry and key digest of its live linked revision whose key imports.
/// `None` when it is no live linked install with such a key.
pub(crate) fn permit_for(fold: &AuthorityFold, machine: EntityId) -> Option<CustodyRecipientPermit> {
    live_revisions(fold, machine).into_iter().find_map(|revision| {
        HybridPublicKey::from_bytes(&revision.profile.encryption_key.key)
            .ok()
            .map(|_| CustodyRecipientPermit {
                machine,
                profile: revision.entry,
                encryption_key: revision_key_digest(revision),
            })
    })
}

/// The permit `machine` would get now, with its encryption key's suite and
/// bytes, for a surface that seals a protected input itself. Listing it is
/// not the owner's consent.
pub(crate) fn candidate_for(
    fold: &AuthorityFold,
    machine: EntityId,
) -> Option<(CustodyRecipientPermit, u16, Vec<u8>)> {
    let permit = permit_for(fold, machine)?;
    live_revisions(fold, machine)
        .into_iter()
        .find(|revision| revision_key_digest(revision) == permit.encryption_key)
        .map(|revision| {
            let key = &revision.profile.encryption_key;
            (permit, key.suite, key.key.clone())
        })
}

/// The key each of `permits` seals to, when every one still stands: its
/// machine a live linked install whose live revision carries the very key
/// permitted, and that key imports. `None` when any recipient changed.
pub(crate) fn permitted_keys(
    fold: &AuthorityFold,
    permits: &[CustodyRecipientPermit],
) -> Option<Vec<(CustodyRecipientPermit, HybridPublicKey)>> {
    match CUSTODY_PERMITS {
        CustodyPermits::InlineExactBytePermits => permits
            .iter()
            .map(|permit| {
                live_revisions(fold, permit.machine)
                    .into_iter()
                    .filter(|revision| revision_key_digest(revision) == permit.encryption_key)
                    .find_map(|revision| {
                        HybridPublicKey::from_bytes(&revision.profile.encryption_key.key).ok()
                    })
                    .map(|public| (*permit, public))
            })
            .collect(),
    }
}

/// The permits for `machines`, ascending by machine, one each: what a door
/// records for the recipients the owner named. The first machine that is no
/// live linked install with an importable key is returned as the error.
pub(crate) fn permits_for(
    fold: &AuthorityFold,
    machines: &[EntityId],
) -> std::result::Result<Vec<CustodyRecipientPermit>, EntityId> {
    let mut permits = machines
        .iter()
        .map(|machine| permit_for(fold, *machine).ok_or(*machine))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    permits.sort_unstable_by_key(|permit| permit.machine);
    permits.dedup_by_key(|permit| permit.machine);
    Ok(permits)
}
