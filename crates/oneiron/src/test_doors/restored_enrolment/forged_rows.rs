//! Hand-signed authority rows for the restored-copy guards (row
//! RESTORED-COPIES-R2-TESTS, part 2). A row of a chosen op, signed by a
//! chosen key at a chosen sequence over chosen parents, lets a test lay a row
//! below its signer's sequence floor (`rows_floor`) beside a sibling of a
//! higher sequence that does not descend from it, or an owner's join no
//! public door writes. No public writer does either: each signs at the next
//! sequence over the vault's heads. Beside them, an owner root this install
//! does not pin, or one it pins, with its anchor's mark of a machine, or one
//! it does not pin with its anchor's removal of a machine, which no public
//! writer signs (row RESTORED-HELD-RESTRICTION-REVIEW-TESTS). The rows are
//! stored as any row is; the fold judges them.

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;

use crate::authority::{
    AuthorityEntryHash, AuthorityKey, AuthorityOp, MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
    MachineEncryptionKey, MachineEnrolmentRequest, MachineProfile, MachineRole, OwnerRootRecord,
};
use crate::error::Result;
use crate::world_keys::RecoveryRootSeed;
use crate::{EntityId, TimeRange, Vault};

/// The key a hand-signed row is signed with.
pub enum RowSigner<'key> {
    /// An install key alone: a carrier's, or a restored copy's.
    Install(&'key SigningKey),
    /// An install key, with the cosign of the key the vault proves owner
    /// acts with (row CARRIER-OWNER-PROOF), as an answer an owner key proves.
    InstallWithOwnerProof(&'key SigningKey),
    /// The key the vault proves owner acts with, alone: a self-host's root.
    OwnerProof,
}

/// A hand-signed row as it was stored: its entry and its sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedRow {
    pub entry: AuthorityEntryHash,
    pub seq: u64,
}

/// `vault`'s install: its machine id and the install key it carries acts
/// with.
///
/// # Errors
/// An install with no machine identity yet; storage faults.
pub fn install_key(vault: &Vault) -> Result<(EntityId, SigningKey)> {
    let txn = vault.store.env.read_txn()?;
    let machine = crate::identity::read_machine_id_in_txn(vault, &txn)?
        .ok_or_else(crate::authority::invalid_authority)?;
    let key = crate::identity::read_machine_signing_key_in_txn(vault, &txn)?
        .ok_or_else(crate::authority::invalid_authority)?;
    Ok((machine, key))
}

/// `op`, signed by `signer` at `seq` (the signer's next sequence on `vault`'s
/// fold when `None`) over `parents`, and stored on `vault`.
///
/// # Errors
/// No owner key held here for a signer that needs one, a shape the entry
/// encoding refuses (no parents, or more than one entry names), and the
/// owner key's refusal to sign; storage faults.
pub fn put_signed_row(
    vault: &Vault,
    signer: RowSigner<'_>,
    op: AuthorityOp,
    seq: Option<u64>,
    parents: BTreeSet<AuthorityEntryHash>,
) -> Result<SignedRow> {
    let mut txn = vault.store.env.write_txn()?;
    let fold = vault.authority_view_readonly_in_txn(&txn)?;
    let now = vault.instant_in_txn(&txn)?.secs();
    let proof = match signer {
        RowSigner::Install(_) => None,
        RowSigner::InstallWithOwnerProof(_) | RowSigner::OwnerProof => Some(
            vault
                .owner_proof_signer(&fold)
                .ok_or_else(crate::authority::invalid_authority)?,
        ),
    };
    let entry = match (signer, &proof) {
        (RowSigner::Install(key), _) => {
            let seq = sequence_or_next(&fold, &install_authority_key(key), seq)?;
            crate::authority::sign_side_entry(&fold, key, seq, parents, op, now)?
        }
        (RowSigner::InstallWithOwnerProof(key), proof) => {
            let seq = sequence_or_next(&fold, &install_authority_key(key), seq)?;
            crate::authority::sign_side_entry_with_owner_proof(
                &fold,
                key,
                seq,
                parents,
                op,
                now,
                proof.as_ref(),
            )?
        }
        (RowSigner::OwnerProof, Some(proof)) => {
            let key = proof.key();
            let seq = sequence_or_next(&fold, &key, seq)?;
            let mut entry =
                crate::authority::unsigned_side_entry(&fold, key, seq, parents, op, now)?;
            entry.signer.signature =
                proof.sign(&fold, &crate::authority::authority_transcript(&entry)?)?;
            entry
        }
        (RowSigner::OwnerProof, None) => return Err(crate::authority::invalid_authority()),
    };
    let row = SignedRow {
        entry: crate::authority::authority_entry_hash(&entry)?,
        seq: entry.seq,
    };
    let at = TimeRange {
        start: now,
        end: now,
    };
    vault.put_authority_log_entries_in_txn(&mut txn, &[(entry, at, now)])?;
    txn.commit()?;
    Ok(row)
}

/// An owner root of `owner` that this install does not pin, published by a
/// fresh anchor, and that anchor's mark of `request`'s machine, as an anchor
/// marks a machine of its own chain. Returns the mark's entry.
///
/// # Errors
/// A request of another vault; storage faults.
pub fn publish_unpinned_root_and_mark(
    vault: &Vault,
    owner: EntityId,
    request: &MachineEnrolmentRequest,
) -> Result<AuthorityEntryHash> {
    publish_root_and_mark(vault, owner, request, false)
}

/// An owner root of `owner` published by a fresh anchor, that anchor's mark
/// of `request`'s machine, and this install's pin of the root, in one write:
/// a held mark under the pinned anchor and no roster row of the machine.
/// Returns the mark's entry.
///
/// # Errors
/// A request of another vault; storage faults.
pub fn publish_pinned_root_and_mark(
    vault: &Vault,
    owner: EntityId,
    request: &MachineEnrolmentRequest,
) -> Result<AuthorityEntryHash> {
    publish_root_and_mark(vault, owner, request, true)
}

/// An owner root of `owner` that this install does not pin, published by a
/// fresh anchor, and that anchor's removal of `request`'s machine with the
/// request's keys and proof, as the first revision of its own chain of that
/// machine: a terminal row, act-free, that no install carries. The machine's
/// row must exist already (an enrolment filed it). Returns the removal's
/// entry.
///
/// # Errors
/// A request of another vault; storage faults.
pub fn publish_unpinned_root_and_removal(
    vault: &Vault,
    owner: EntityId,
    request: &MachineEnrolmentRequest,
) -> Result<AuthorityEntryHash> {
    let (anchor, record) = fresh_owner_root(owner, request)?;
    let mut txn = vault.store.env.write_txn()?;
    vault.publish_owner_root_in_txn(&mut txn, &anchor, record)?;
    let fold = vault.authority_view_readonly_in_txn(&txn)?;
    if fold.vault_id != Some(request.vault_id) {
        return Err(crate::authority::invalid_authority());
    }
    let removal = MachineProfile {
        machine: request.machine,
        owner,
        machine_key: request.machine_key,
        device_class: request.device_class,
        encryption_key: request.encryption_key.clone(),
        role: MachineRole::Removed,
        revision: 1,
        machine_proof: request.machine_proof,
        seen_world_edits: BTreeSet::new(),
        carrier: None,
        act: None,
        restored_from: request.restored_from,
    };
    removal.validate()?;
    let fold = vault
        .join_anchor_frontier_in_txn(&mut txn, &fold, &anchor)?
        .unwrap_or(fold);
    let now = vault.instant_in_txn(&txn)?.secs();
    let entry = crate::authority::anchor_signed_entry(
        &fold,
        &anchor,
        AuthorityOp::MachineProfile(removal),
        now,
    )?;
    let removal = vault.put_anchor_entry_in_txn(&mut txn, entry)?;
    txn.commit()?;
    Ok(removal)
}

/// A fresh owner root of `owner` on `request`'s vault: its anchor key and
/// the record the anchor publishes.
fn fresh_owner_root(
    owner: EntityId,
    request: &MachineEnrolmentRequest,
) -> Result<(SigningKey, OwnerRootRecord)> {
    let seed = RecoveryRootSeed::generate()?;
    let root = seed.public(&request.vault_id)?;
    let record = OwnerRootRecord {
        owner,
        root: root.id,
        recovery_key: MachineEncryptionKey {
            suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
            key: root.recovery_key.to_bytes(),
        },
        anchor_key: root.anchor_key,
    };
    Ok((seed.anchor(), record))
}

fn publish_root_and_mark(
    vault: &Vault,
    owner: EntityId,
    request: &MachineEnrolmentRequest,
    pin: bool,
) -> Result<AuthorityEntryHash> {
    let (anchor, record) = fresh_owner_root(owner, request)?;
    let root_id = record.root;
    let anchor_key = record.anchor_key;
    let mut txn = vault.store.env.write_txn()?;
    vault.publish_owner_root_in_txn(&mut txn, &anchor, record)?;
    let mark = vault.append_anchor_mark_in_txn(&mut txn, &anchor, owner, request)?;
    if pin {
        let pinned = crate::authority::PinnedRoot {
            id: root_id,
            anchor_key,
        };
        crate::authority::write_pinned_root_in_txn(&vault.store, &mut txn, pinned, None)?;
    }
    txn.commit()?;
    Ok(mark)
}

fn install_authority_key(key: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(key.verifying_key().to_bytes())
}

fn sequence_or_next(
    fold: &crate::authority::AuthorityFold,
    signer: &AuthorityKey,
    seq: Option<u64>,
) -> Result<u64> {
    match seq {
        Some(seq) => Ok(seq),
        None => crate::authority::next_sequence(fold, signer),
    }
}
