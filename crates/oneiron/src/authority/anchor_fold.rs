//! The owner anchor's entries (world privacy P6b, contract §4 and E2(b)): a
//! root record, which its own anchor signs alone, and the `Owned` or `Removed`
//! marks a valid root's anchor signs in its own chain of a machine.
//!
//! Both fold before the roster, consent and quorum checks: on a hosted vault
//! the roster key is the host's, and its cosign would let the host refuse the
//! owner a root. Validity never reads this install's pin, so every install
//! keeps the same entries; the pin decides only which anchor's chain counts.
//! No root makes another one invalid, and an anchor never joins the roster.

use super::*;

/// The anchor fold of one entry: `None` when the roster's rules judge it.
pub(super) fn fold_anchor_entry(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    signer: &AuthorityKey,
    hash: AuthorityEntryHash,
    restriction_only: bool,
) -> Option<std::result::Result<(), AuthorityFoldIssue>> {
    let anchor = match (&entry.op, signer) {
        (AuthorityOp::OwnerRoot(record), _) => {
            return Some(advance(state, entry, signer, hash).map(|()| {
                state
                    .root_anchors
                    .entry(record.anchor_key)
                    .or_default()
                    .insert(record.root);
                state.anchor_entries.insert(hash);
            }));
        }
        // A roster that also names the anchor's public key changes nothing:
        // anyone can enrol a public key, and that must not take the owner's
        // anchor off its own chain.
        (AuthorityOp::MachineProfile(_), AuthorityKey::Ed25519(key))
            if state.root_anchors.contains_key(key) =>
        {
            *key
        }
        _ => return None,
    };
    let AuthorityOp::MachineProfile(profile) = &entry.op else {
        return None;
    };
    if !entry.cosigns.is_empty() {
        return Some(Err(AuthorityFoldIssue::InvalidEntry(hash)));
    }
    Some(
        advance(state, entry, signer, hash)
            .and_then(|()| apply_anchor_profile(state, anchor, profile, hash, restriction_only))
            .map(|()| {
                state.anchor_entries.insert(hash);
            }),
    )
}

/// A strictly higher sequence for the signer, recorded.
fn advance(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    signer: &AuthorityKey,
    hash: AuthorityEntryHash,
) -> std::result::Result<(), AuthorityFoldIssue> {
    if state
        .seqs
        .get(signer)
        .is_some_and(|prior| entry.seq <= *prior)
    {
        return Err(AuthorityFoldIssue::NonMonotonicSeq(hash));
    }
    state.seqs.insert(signer.clone(), entry.seq);
    Ok(())
}
