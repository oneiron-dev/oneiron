//! The host history handoff's causal anchor (FIX 11241, ported from the bel
//! build: 9f46db33fa, then 163d550a15): the host-authored entry that is
//! equal to, or a signed-parent ancestor of, every current head, and the
//! causally latest such entry. One shared parent graph per call, one
//! ancestor closure per head and one walk to drop each host row below
//! another, never a scan of the signed log per candidate pair.
use std::collections::{BTreeMap, BTreeSet};

use super::super::{AuthorityKey, AuthorityOp};
use crate::HostingPrivacyPosture;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::store::Store;

/// Of `authored`, the host's valid entries, those equal to or a
/// signed-parent ancestor of every head in `heads`, less each one below
/// another of them: the causally latest common anchors. One is the anchor;
/// several are incomparable maxima, which the caller refuses. `parents` maps
/// each entry the store or the adopted image's evidence holds to its signed
/// parents. `None` when a walk reaches an entry `parents` does not hold,
/// below an adopted image's evidence, so the caller keeps its own rule.
fn latest_common_authored(
    parents: &BTreeMap<[u8; 32], Vec<[u8; 32]>>,
    authored: &[[u8; 32]],
    heads: &BTreeSet<[u8; 32]>,
) -> Option<Vec<[u8; 32]>> {
    let closure = |mut stack: Vec<[u8; 32]>| -> Option<BTreeSet<[u8; 32]>> {
        let mut seen = BTreeSet::new();
        while let Some(hash) = stack.pop() {
            if seen.insert(hash) {
                stack.extend(parents.get(&hash)?.iter().copied());
            }
        }
        Some(seen)
    };
    let mut common: BTreeSet<[u8; 32]> = authored.iter().copied().collect();
    for head in heads {
        let past = closure(vec![*head])?;
        common.retain(|hash| past.contains(hash));
    }
    let mut below = Vec::new();
    for candidate in &common {
        below.extend(parents.get(candidate)?.iter().copied());
    }
    let below = closure(below)?;
    Some(common.difference(&below).copied().collect())
}

/// One exact, fold-verified causal authority anchor for scoped history signatures.
/// Fail closed if the root is absent, conflicted or its signer is revoked.
pub(crate) fn machine_history_host_context(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
    signer: &AuthorityKey,
) -> Result<([u8; 32], [u8; 32])> {
    let fold = super::super::authority_view_readonly_for_store_in_txn(store, posture, txn)?;
    let vault_id = fold.vault_id.ok_or_else(super::denied)?;
    if fold.vault_root_is_conflicted()
        || !fold
            .roster
            .get(signer)
            .is_some_and(|root| !root.revoked && root.roles & super::super::ROLE_OWNER != 0)
    {
        return Err(super::denied());
    }
    // A successor root has no authored sequence yet: its trust event is the
    // predecessor-signed ReRoot, not an arbitrary lexicographically maximal
    // concurrent head. Pin that exact causal ancestor for history handoff.
    let mut re_roots = Vec::new();
    let mut authored_entries = Vec::new();
    let mut parents_by_hash = std::collections::BTreeMap::new();
    for id in
        store.port_entity_ids_by_type(txn, crate::registry::ENTITY_TYPE_AUTHORITY_LOG, None)?
    {
        let id = id?;
        let raw = EntityStoreRead::port_entity_raw(store, txn, &id)?
            .ok_or(Error::CorruptedIndex("authority head row"))?;
        let entry = super::super::decode_authority_log_entry_body(
            raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
                .ok_or(Error::CorruptedIndex("authority head header"))?,
        )?;
        let hash = super::super::authority_entry_hash(&entry)?;
        if super::super::authority_log_entity_id_from_hash(&hash)? != id {
            return Err(Error::CorruptedIndex("authority history key"));
        }
        parents_by_hash.insert(hash, entry.parent_hashes.clone());
        if !fold.valid_entries.contains(&hash) {
            continue;
        }
        if matches!(&entry.op, AuthorityOp::ReRoot { new_device } if new_device.key == *signer) {
            re_roots.push(hash);
        }
        if entry.signer_key() == signer {
            authored_entries.push(hash);
        }
    }
    // On a vault that adopted a checkpoint image, the covered rows count as
    // well (OF-469, slice E): a covered ReRoot to `signer` by the body the
    // image carries, an entry `signer` authored by the row's summary, each
    // only while the current fold holds it valid, and each once, stored or
    // not. The signed parent paths below, never a sequence or image frontier,
    // decide which authored entry is the causal anchor.
    if let Some(evidence) = super::super::adopted_evidence::adopted_evidence_in_txn(store, txn)? {
        for (hash, row) in evidence.rows() {
            parents_by_hash
                .entry(*hash)
                .or_insert_with(|| row.parents.clone());
            if !fold.valid_entries.contains(hash) {
                continue;
            }
            if !re_roots.contains(hash)
                && evidence.body(hash).is_some_and(|entry| {
                    matches!(&entry.op, AuthorityOp::ReRoot { new_device } if new_device.key == *signer)
                })
            {
                re_roots.push(*hash);
            }
            if !authored_entries.contains(hash) && row.signer == *signer {
                authored_entries.push(*hash);
            }
        }
    }
    // The host's causally latest authored entry beneath every current head
    // (FIX 11241): an install-signed or owner append that became the only
    // head no longer retires the host's anchor. Where a signed parent path
    // leaves both the stored rows and the adopted image's evidence, the walk
    // cannot judge it, and today's rule holds: a current head the host
    // authored.
    let latest_ancestors = if re_roots.is_empty() && !fold.append_heads.is_empty() {
        latest_common_authored(&parents_by_hash, &authored_entries, &fold.append_heads)
            .unwrap_or_else(|| {
                authored_entries
                    .iter()
                    .filter(|hash| fold.append_heads.contains(*hash))
                    .copied()
                    .collect()
            })
    } else {
        Vec::new()
    };
    let head = match re_roots.as_slice() {
        [head] => *head,
        [] => match latest_ancestors.as_slice() {
            [head] => *head,
            _ => return Err(super::denied()),
        },
        _ => return Err(super::denied()),
    };
    Ok((vault_id, head))
}
