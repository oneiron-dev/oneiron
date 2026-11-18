//! The owner's door into the vault for an install born of a restore when no
//! machine of the vault that has joined is left to pair it (row
//! RESTORED-COPIES-ENROL-EACH-OTHER; Setting DESIGN pass 15e "Joined", the
//! second way; RULING RESTORED-COPIES-JOIN-SCOPE = A).
//!
//! A copy restored from a checkpoint image joins when a joined machine
//! pairs it. An owner who lost every device has none; he says so on the
//! copy, and that word is an owner act, proved like any other
//! (CARRIER-SELF-ANSWER): a key the vault trusts as the owner's, held on this
//! install ([`Vault::owner_proof_signer`]), signs it. The recovery credential
//! that opened the image proves nobody's will. An owner who holds no such
//! key goes through the root first: the escrowed root seed can enrol a new
//! owner key here.
//!
//! In one transaction the door files this install's root-signed enrolment,
//! which the fold holds, and the owner's [`RestoredMachineJoin`] row naming
//! it, signed by that key alone, with no carrier: the copy carries nothing
//! before it joins. It commits only when the fold reads the machine live.
//! The signature proves the owner's word, not that no other machine exists:
//! run on two copies of one image, each joins, as the owner said twice.

use super::world_key_support::{next_sequence, unsigned_side_entry};
use super::*;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::{TimeRange, Vault};

/// The proof was carried by a transport credential or a host action: the
/// owner joins a restored install from that install alone. Nothing was
/// written.
const BOUND_PROOF: &str = "joining a restored install takes the owner's proof from this install, \
                           with no transport credential or host action bound to it";
/// No root roots the vault here yet. Nothing was written.
const NOT_ROOTED: &str = "no root roots this vault yet, so there is nothing to join";
/// This install was not born of a restore. Nothing was written.
const NOT_RESTORED: &str = "this install was not restored from a checkpoint; it enrols as any \
                            install does";
/// This install holds no key the vault trusts as the owner's. Nothing was
/// written.
const NO_OWNER_KEY: &str = "this install holds no owner key the vault trusts, so the owner's word \
                            that no other machine is left cannot be proved here; enrol an owner \
                            key with the root seed, or pair this install from a machine of the \
                            vault";
/// The fold did not count the join. Nothing was written.
const JOIN_NOT_COUNTED: &str = "the vault's fold did not count the owner's join of this restored \
                                install; nothing was written";

impl Vault {
    /// The owner's word, on this install, that no other machine of the vault
    /// is left: files this install's enrolment in `role` under `issuer`, the
    /// vault's root, and joins it by the owner's act, signed by an owner key
    /// this install holds. Returns the machine as it then stands. A no-op
    /// returning the machine when it already stands here.
    ///
    /// # Errors
    /// [`crate::error::RecordError::AuthorityRefused`] for a bound proof, a
    /// vault no root roots, an install no restore made, no owner key held
    /// here, a root that is not `issuer`, or a join the fold does not count;
    /// an owner refusal when the proof is no longer the vault's live owner;
    /// storage faults. Nothing is written on any error.
    pub fn join_restored_install(
        &self,
        issuer: &HostSlipIssuer,
        owner: &AuthenticatedOwner,
        role: MachineRole,
    ) -> Result<FoldedMachine> {
        if !owner.is_unbound() {
            return Err(authority_refused(BOUND_PROOF));
        }
        let vault_id = self
            .authority_fold()?
            .vault_id
            .ok_or_else(|| authority_refused(NOT_ROOTED))?;
        // The install's identity, minted and signed outside the writer.
        let encryption_key = self.machine_encryption_key(vault_id)?;
        let request = self.machine_enrolment_request(vault_id, encryption_key)?;
        if request.restored_from.is_none() {
            return Err(authority_refused(NOT_RESTORED));
        }
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        if let Some(folded) = fold.machine(request.machine) {
            return Ok(folded.clone());
        }
        let proof = self
            .owner_proof_signer(&fold)
            .ok_or_else(|| authority_refused(NO_OWNER_KEY))?;
        let enrolment = match fold.unjoined_restored_enrolment(request.machine) {
            Some(held) => held,
            None => self.file_restored_enrolment_in_txn(&mut txn, issuer, actor, &request, role)?,
        };
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let target = request.machine;
        let act = OwnerAct::by_owner(
            actor,
            OwnerActKind::RestoredMachineJoin,
            target,
            ActSurface::ThisInstall,
            restored_machine_join_seen(&enrolment),
        );
        let op = AuthorityOp::RestoredMachineJoin(RestoredMachineJoin { act, enrolment });
        self.append_owner_signed_in_txn(&mut txn, &fold, op, proof.as_ref())?;
        let after = self.authority_view_readonly_in_txn(&txn)?;
        let folded = after
            .machine(target)
            .filter(|folded| {
                folded
                    .roster
                    .as_ref()
                    .is_some_and(|roster| roster.is_live())
            })
            .cloned()
            .ok_or_else(|| authority_refused(JOIN_NOT_COUNTED))?;
        txn.commit()?;
        Ok(folded)
    }

    /// Appends `op`, signed alone by `proof`'s owner key over the authority
    /// transcript, on `fold`'s main-log heads (joined first when wider than
    /// one entry names, in the host family, whose rule is a live owner
    /// roster key: FIX 7908, 11867).
    fn append_owner_signed_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fold: &AuthorityFold,
        op: AuthorityOp,
        proof: &dyn CheckpointRootSigner,
    ) -> Result<()> {
        let key = proof.root();
        let sign = |transcript: &[u8]| proof.sign_owner_proof(transcript);
        let joiner = FrontierSigner::Callback(&key, &sign);
        let joined = self.prepare_authority_frontier_in_txn(txn, fold, joiner, MAX_PARENTS)?;
        let fold = joined.as_deref().unwrap_or(fold);
        let seq = next_sequence(fold, &key)?;
        let parents = fold.append_heads.iter().copied().collect();
        let now = self.instant_in_txn(txn)?.secs();
        let mut entry = unsigned_side_entry(fold, key, seq, parents, op, now)?;
        entry.signer.signature = proof.sign_owner_proof(&authority_transcript(&entry)?)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])
            .map(drop)
    }
}
