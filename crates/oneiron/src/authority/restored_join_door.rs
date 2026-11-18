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
use crate::{EntityId, TimeRange, Vault};

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
/// The root given is not the vault's. Nothing was written.
const NOT_THE_ROOT: &str = "the host root given is not this vault's root, so it cannot file this \
                            install's enrolment; nothing was written";
/// This install's machine stands, but not live under its keys: removed,
/// conflicted or under other keys. Nothing was written.
const NOT_LIVE_HERE: &str = "this install's machine stands in the vault, but not live under this \
                             install's keys (removed, conflicted or under other keys), and a \
                             removed machine never comes back; nothing was written";
/// The vault holds an enrolment of this install's machine that is not this
/// install's ask. Nothing was written.
const HELD_DIFFERS: &str = "the vault holds an enrolment of this install's machine that names \
                            other keys, another class, another origin, another owner or another \
                            role than this install asks; nothing was written";

/// A kit restore of an install born of a restore that has not joined,
/// whose kit's root authority key R this vault does not take as the owner's
/// proof (a key the host holds, on a hosted install): R's word joins no
/// restored install. The words say nothing of what was written, as the
/// kit restore's other refusals (the sealed bundle's restore gives them
/// after its history's import committed; REVIEW-9517 round 2 P1).
const KEY_PROVES_NO_JOIN: &str = "this install was restored from a checkpoint and has not joined \
                                  the vault, and this recovery kit's root key does not prove the \
                                  owner's word here, so the kit cannot join it; pair this install \
                                  from a machine of the vault";

/// An owner key's signature over an entry's transcript, made on the fold
/// the entry is signed on.
type FoldSign<'a> = dyn Fn(&AuthorityFold, &[u8]) -> Result<Vec<u8>> + 'a;

/// Whether `folded` stands live under `request`'s keys: the machine this
/// install is.
fn stands_as_this_install(folded: &FoldedMachine, request: &MachineEnrolmentRequest) -> bool {
    folded.roster.as_ref().is_some_and(|roster| {
        roster.is_live()
            && roster.profile.machine_key == request.machine_key
            && roster.profile.encryption_key == request.encryption_key
    })
}

/// Whether a held enrolment's `profile` is this install's ask: its keys,
/// class and origin, the owner who joins it and the role he names.
fn held_is_this_ask(
    profile: &MachineProfile,
    request: &MachineEnrolmentRequest,
    owner: EntityId,
    role: MachineRole,
) -> bool {
    profile.machine_key == request.machine_key
        && profile.encryption_key == request.encryption_key
        && profile.device_class == request.device_class
        && profile.restored_from == request.restored_from
        && profile.owner == owner
        && profile.role == role
}

impl Vault {
    /// The owner's word, on this install, that no other machine of the vault
    /// is left: files this install's enrolment in `role` under `issuer`, the
    /// vault's root, and joins it by the owner's act, signed by an owner key
    /// this install holds. Returns the machine as it then stands. A no-op
    /// returning the machine when it already stands live here under this
    /// install's keys.
    ///
    /// Every refusal the door can read before this install's identity is
    /// minted comes first: an install no restore made, and, for one that has
    /// not joined, no owner key held here or a root that is not `issuer`
    /// (REVIEW-9509/9511 P1). An enrolment the vault already holds for this
    /// install's machine is joined only when it is this install's ask
    /// (REVIEW-9510 P1), and the join commits only when the fold reads the
    /// machine live under this install's keys.
    ///
    /// # Errors
    /// [`crate::error::RecordError::AuthorityRefused`] for a bound proof, a
    /// vault no root roots, an install no restore made, no owner key held
    /// here, a root that is not `issuer`, a machine that stands here but not
    /// live under this install's keys (a removed one never comes back), a
    /// held enrolment that is not this install's ask, or a join the fold
    /// does not count; an owner refusal when the proof is no longer the
    /// vault's live owner; storage faults. Nothing is written on any error
    /// but the install's own identity, minted once the reads above pass.
    pub fn join_restored_install(
        &self,
        issuer: &HostSlipIssuer,
        owner: &AuthenticatedOwner,
        role: MachineRole,
    ) -> Result<FoldedMachine> {
        if !owner.is_unbound() {
            return Err(authority_refused(BOUND_PROOF));
        }
        self.restored_join_preflight(Some(issuer))?;
        // The clock rows and backfills `authority_fold` commits, as every
        // door's first read does, only once nothing above refuses.
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
            return if stands_as_this_install(folded, &request) {
                Ok(folded.clone())
            } else {
                Err(authority_refused(NOT_LIVE_HERE))
            };
        }
        let proof = self
            .owner_proof_signer(&fold)
            .ok_or_else(|| authority_refused(NO_OWNER_KEY))?;
        // Only holds under a scope this install counts, the roster's and its
        // pinned anchor's: an unpinned anchor's mark refuses nothing here
        // (REVIEW-9509 round 2 P1).
        let mut held = fold.counted_waiting_enrolments(request.machine).peekable();
        let enrolment = if held.peek().is_some() {
            let mut held: Vec<_> = held.collect();
            if !held
                .iter()
                .all(|(_, held)| held_is_this_ask(&held.profile, &request, actor, role))
            {
                return Err(authority_refused(HELD_DIFFERS));
            }
            held.sort_by_key(|(hash, _)| **hash);
            *held[0].0
        } else {
            self.file_restored_enrolment_in_txn(&mut txn, issuer, actor, &request, role)?
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
        let sign: &FoldSign<'_> = &|fold, transcript| proof.sign(fold, transcript);
        self.append_owner_signed_in_txn(&mut txn, &fold, op, (&proof.key(), sign))?;
        let after = self.authority_view_readonly_in_txn(&txn)?;
        let folded = after
            .machine(target)
            .filter(|folded| stands_as_this_install(folded, &request))
            .cloned()
            .ok_or_else(|| authority_refused(JOIN_NOT_COUNTED))?;
        txn.commit()?;
        Ok(folded)
    }

    /// Every refusal [`Self::join_restored_install`] reads before it writes,
    /// in one read-only snapshot: a vault no root roots, an install no restore
    /// made, and, given `issuer`, for an install that has not joined, no owner
    /// key held here or a root that is not `issuer`. Writes nothing, so a
    /// command checks it before it provisions this install's keys or its
    /// owner actor, first without the issuer its keystore holds and then with
    /// it (REVIEW-9511 P1).
    ///
    /// # Errors
    /// [`crate::error::RecordError::AuthorityRefused`] naming the refusal;
    /// storage faults.
    pub fn restored_join_preflight(&self, issuer: Option<&HostSlipIssuer>) -> Result<()> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        if fold.vault_id.is_none() {
            return Err(authority_refused(NOT_ROOTED));
        }
        if crate::identity::read_restored_from_image_in_txn(self, &txn)?.is_none() {
            return Err(authority_refused(NOT_RESTORED));
        }
        let Some(issuer) = issuer else {
            return Ok(());
        };
        let stands = crate::identity::read_machine_id_in_txn(self, &txn)?
            .is_some_and(|machine| fold.machine(machine).is_some());
        if !stands {
            if self.owner_proof_signer(&fold).is_none() {
                return Err(authority_refused(NO_OWNER_KEY));
            }
            super::slip_vault::require_host(&fold, issuer)
                .map_err(|_| authority_refused(NOT_THE_ROOT))?;
        }
        Ok(())
    }

    /// A kit restore's join of this install when a restore made it (Engine
    /// ANSWER KIT-RESTORE-JOINS-RESTORED-COPY = A): `signer`, the kit's root
    /// authority key R held behind `sign`, a live owner key of the roster,
    /// files this install's enrolment as its own roster row, which the fold
    /// holds, and joins it by the owner's [`RestoredMachineJoin`], each
    /// signed by R alone, in the caller's transaction. A kit restore signed
    /// by R is the owner's proved act RESTORED-COPIES-JOIN-SCOPE = A names,
    /// so the fold takes R's join as it takes any owner key's
    /// ([`super::restored_join`]). Writes nothing for an install no restore
    /// made, or one whose machine stands in the vault: the restore anchors
    /// it and puts it on the roster as any install. The join stands only
    /// when the fold reads the machine live under this install's keys.
    /// Returns whether it joined this install.
    ///
    /// # Errors
    /// [`crate::error::RecordError::AuthorityRefused`] when R gives no
    /// owner's proof here ([`Self::restored_join_by_key_precheck`]) or the
    /// fold does not count the join; an enrolment the fold holds for the
    /// machine under other keys or another origin; storage faults.
    pub(crate) fn join_restored_install_by_key_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        (signer, sign): (&AuthorityKey, &dyn Fn(&[u8]) -> Result<Vec<u8>>),
        owner: EntityId,
        request: &MachineEnrolmentRequest,
    ) -> Result<bool> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        if request.restored_from.is_none() || fold.machine(request.machine).is_some() {
            return Ok(false);
        }
        if !self.key_proves_owner_word(&fold, signer) {
            return Err(authority_refused(KEY_PROVES_NO_JOIN));
        }
        let enrolment =
            self.file_restored_enrolment_by_key_in_txn(txn, (signer, sign), owner, request)?;
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let act = OwnerAct::by_owner(
            owner,
            OwnerActKind::RestoredMachineJoin,
            request.machine,
            ActSurface::ThisInstall,
            restored_machine_join_seen(&enrolment),
        );
        let op = AuthorityOp::RestoredMachineJoin(RestoredMachineJoin { act, enrolment });
        let by_key: &FoldSign<'_> = &|_, transcript| sign(transcript);
        self.append_owner_signed_in_txn(txn, &fold, op, (signer, by_key))?;
        let joined = self
            .authority_view_readonly_in_txn(txn)?
            .machine(request.machine)
            .is_some_and(|folded| stands_as_this_install(folded, request));
        if !joined {
            return Err(authority_refused(JOIN_NOT_COUNTED));
        }
        Ok(true)
    }

    /// [`Self::join_restored_install_by_key_in_txn`]'s refusal, read before
    /// a kit restore mints this install's identity: this install was born
    /// of a restore, no machine of it stands in `fold`, and `signer`, the
    /// kit's R, gives no owner's proof there.
    ///
    /// # Errors
    /// [`crate::error::RecordError::AuthorityRefused`] naming the refusal;
    /// storage faults.
    pub(crate) fn restored_join_by_key_precheck(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        signer: &AuthorityKey,
    ) -> Result<()> {
        if crate::identity::read_restored_from_image_in_txn(self, txn)?.is_none() {
            return Ok(());
        }
        let stands = crate::identity::read_machine_id_in_txn(self, txn)?
            .is_some_and(|machine| fold.machine(machine).is_some());
        if !stands && !self.key_proves_owner_word(fold, signer) {
            return Err(authority_refused(KEY_PROVES_NO_JOIN));
        }
        Ok(())
    }

    /// Whether `fold` takes `key` as the owner's proof on this install
    /// ([`AuthorityFold::proves_owner_acts`], the writer's side of the
    /// fold's `gives_owner_proof`), in the one suite a proof is made in.
    fn key_proves_owner_word(&self, fold: &AuthorityFold, key: &AuthorityKey) -> bool {
        let hosted = self.privacy_posture() == crate::HostingPrivacyPosture::Hosted;
        matches!(key, AuthorityKey::Ed25519(_)) && fold.proves_owner_acts(key, hosted)
    }

    /// Appends `op`, signed alone by the owner key `key` behind `sign` over
    /// the authority transcript, on `fold`'s main-log heads (joined first
    /// when wider than one entry names, in the host family, whose rule is a
    /// live owner roster key: FIX 7908, 11867). The key signs each entry
    /// through its own check, on the fold the entry is signed on: a join
    /// carries no op, so every join's parent state is `fold`'s, and the
    /// row's is the joined fold's.
    fn append_owner_signed_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fold: &AuthorityFold,
        op: AuthorityOp,
        (key, sign): (&AuthorityKey, &FoldSign<'_>),
    ) -> Result<()> {
        let frontier_sign = |transcript: &[u8]| sign(fold, transcript);
        let joiner = FrontierSigner::Callback(key, &frontier_sign);
        let joined = self.prepare_authority_frontier_in_txn(txn, fold, joiner, MAX_PARENTS)?;
        let fold = joined.as_deref().unwrap_or(fold);
        let seq = next_sequence(fold, key)?;
        let parents = fold.append_heads.iter().copied().collect();
        let now = self.instant_in_txn(txn)?.secs();
        let mut entry = unsigned_side_entry(fold, key.clone(), seq, parents, op, now)?;
        entry.signer.signature = sign(fold, &authority_transcript(&entry)?)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])
            .map(drop)
    }
}
