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
//!
//! The door asks for the person only for a join that has work to do (row
//! RESTORED-JOIN-DOOR-ASKS-BEFORE-ITS-ALREADY-JOINED-RETURN). Before the ask
//! it reads, with nothing readied and nothing written, every answer the
//! writer gives without the owner's proof: an owner proof that is no longer
//! this vault's live owner, the machine that already stands live under this
//! install's keys (returned, and nobody is asked), a machine that stands any
//! other way, a held enrolment that is not this install's ask, and a role
//! no join names. The writer makes each of these checks again.

use super::world_key_support::{next_sequence, unsigned_side_entry};
use super::*;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::world_keys::{OwnerActImportance, owner_presence_reasons};
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

/// This install as a join names it: its machine, its keys, its class and
/// the image a restore made it from. The writer takes them from the request
/// this install signed; the door's read before the ask takes them from what
/// the install holds already, with nothing readied
/// ([`Vault::read_held_install_keys`]).
struct JoiningInstall<'a> {
    machine: EntityId,
    machine_key: [u8; 32],
    /// `None` on the read of an install whose encryption slot holds no seed:
    /// readying it makes a new key, which no profile in the fold names.
    encryption_key: Option<&'a MachineEncryptionKey>,
    device_class: MachineDeviceClass,
    restored_from: Option<[u8; 32]>,
}

impl<'a> From<&'a MachineEnrolmentRequest> for JoiningInstall<'a> {
    fn from(request: &'a MachineEnrolmentRequest) -> Self {
        Self {
            machine: request.machine,
            machine_key: request.machine_key,
            encryption_key: Some(&request.encryption_key),
            device_class: request.device_class,
            restored_from: request.restored_from,
        }
    }
}

/// Whether `folded` stands live under `install`'s keys: the machine this
/// install is.
fn stands_as_this_install(folded: &FoldedMachine, install: &JoiningInstall<'_>) -> bool {
    folded.roster.as_ref().is_some_and(|roster| {
        roster.is_live()
            && roster.profile.machine_key == install.machine_key
            && Some(&roster.profile.encryption_key) == install.encryption_key
    })
}

/// The machine `fold` holds under `install`'s id: returned when it stands
/// live under this install's keys, refused when it stands any other way (a
/// removed machine never comes back). `None` when the fold holds none: the
/// join has work to do.
fn standing_machine(
    fold: &AuthorityFold,
    install: &JoiningInstall<'_>,
) -> Result<Option<FoldedMachine>> {
    match fold.machine(install.machine) {
        Some(folded) if stands_as_this_install(folded, install) => Ok(Some(folded.clone())),
        Some(_) => Err(authority_refused(NOT_LIVE_HERE)),
        None => Ok(None),
    }
}

/// Whether a held enrolment's `profile` is this install's ask: its keys,
/// class and origin, the owner who joins it and the role he names.
fn held_is_this_ask(
    profile: &MachineProfile,
    install: &JoiningInstall<'_>,
    owner: EntityId,
    role: MachineRole,
) -> bool {
    profile.machine_key == install.machine_key
        && Some(&profile.encryption_key) == install.encryption_key
        && profile.device_class == install.device_class
        && profile.restored_from == install.restored_from
        && profile.owner == owner
        && profile.role == role
}

impl Vault {
    /// The owner's word, on this install, that no other machine of the vault
    /// is left: files this install's enrolment in `role` under `issuer`, the
    /// vault's root, and joins it by the owner's act, signed by an owner key
    /// this install holds. Returns the machine as it then stands. A no-op
    /// returning the machine when it already stands live here under this
    /// install's keys: the door reads that before it asks for the person
    /// (`restored_join_read`), so a second join asks nobody.
    ///
    /// Every refusal the door can read before this install's identity is
    /// minted comes first: an install no restore made, and, for one that has
    /// not joined, no owner key held here or a root that is not `issuer`
    /// (REVIEW-9509/9511 P1). An enrolment the vault already holds for this
    /// install's machine is joined only when it is this install's ask
    /// (REVIEW-9510 P1), and the join commits only when the fold reads the
    /// machine live under this install's keys. The person is asked after
    /// every answer the read can give and before the identity is minted.
    ///
    /// # Errors
    /// [`crate::error::RecordError::AuthorityRefused`] for a bound proof, a
    /// vault no root roots, an install no restore made, no owner key held
    /// here, a root that is not `issuer`, a machine that stands here but not
    /// live under this install's keys (a removed one never comes back), a
    /// held enrolment that is not this install's ask, or a join the fold
    /// does not count; an owner refusal when the proof is no longer the
    /// vault's live owner; [`invalid_authority`] for the role `Removed`,
    /// which joins nothing; storage faults. Nothing is written on any error
    /// but the install's own identity, minted once the reads above pass and
    /// the owner has confirmed: not the authority clock's reading either,
    /// which commits with the join. A declined confirm, or a host with no
    /// keystore, therefore leaves this install's machine as it was.
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
        // Read-only up to the writer: a refusal there commits nothing, not
        // even the clock reading `authority_fold` would store (REVIEW-9524
        // P1). The writer takes the reading, so it commits only with the join.
        let vault_id = {
            let txn = self.store.env.read_txn()?;
            self.authority_view_readonly_in_txn(&txn)?.vault_id
        }
        .ok_or_else(|| authority_refused(NOT_ROOTED))?;
        // The confirm comes before the install's identity is minted: the
        // mint writes, and on a restored copy, whose signing slot is empty
        // beside the image's device key, it forgets the image's machine
        // first. The keystore read before it refuses a host that installed
        // none with no prompt.
        self.device_keystore()?;
        if let Some(standing) = self.restored_join_read(owner, vault_id, role)? {
            return Ok(standing);
        }
        // The role is checked last, where the enrolment's writer checks it
        // (`joining_profile`): `Removed` joins nothing.
        if role == MachineRole::Removed {
            return Err(invalid_authority());
        }
        let witness = self.owner_presence(
            OwnerActImportance::Important,
            owner_presence_reasons::JOIN_RESTORED_INSTALL,
        )?;
        let ground = OwnerProofGround::witnessed(&witness);
        // The install's identity, minted and signed outside the writer. The
        // preflight read the restore's mark already; the request names it.
        let encryption_key = self.machine_encryption_key(vault_id)?;
        let request = self.machine_enrolment_request(vault_id, encryption_key)?;
        if request.restored_from.is_none() {
            return Err(authority_refused(NOT_RESTORED));
        }
        let mut txn = self.store.env.write_txn()?;
        self.instant_in_write_txn(&mut txn)?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let install = JoiningInstall::from(&request);
        if let Some(standing) = standing_machine(&fold, &install)? {
            return Ok(standing);
        }
        let proof = self
            .owner_proof_signer(&fold, &ground)
            .ok_or_else(|| authority_refused(NO_OWNER_KEY))?;
        // Only holds under a scope this install counts, the roster's and its
        // pinned anchor's: an unpinned anchor's mark refuses nothing here
        // (REVIEW-9509 round 2 P1).
        let held: Vec<_> = fold.counted_waiting_enrolments(request.machine).collect();
        if !held
            .iter()
            .all(|(_, held)| held_is_this_ask(&held.profile, &install, actor, role))
        {
            return Err(authority_refused(HELD_DIFFERS));
        }
        // The join names a roster enrolment: a pinned anchor's mark joins
        // under its anchor and heads no roster chain, which the join must
        // (REVIEW-9539 round 2 P1). With none held, the root files one, and
        // the join names that exact entry.
        let roster_enrolment = held
            .iter()
            .filter(|(_, held)| held.admitter == MachineAdmitter::Roster)
            .map(|(hash, _)| **hash)
            .min();
        let enrolment = match roster_enrolment {
            Some(enrolment) => enrolment,
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
        let op = AuthorityOp::RestoredMachineJoin(RestoredMachineJoin {
            act,
            enrolment: RestoredJoinEnrolment::Held(enrolment),
        });
        let sign: &FoldSign<'_> = &|fold, transcript| proof.sign(fold, transcript);
        self.append_owner_signed_in_txn(&mut txn, &fold, op, (&proof.key(), sign))?;
        let after = self.authority_view_readonly_in_txn(&txn)?;
        let folded = after
            .machine(target)
            .filter(|folded| stands_as_this_install(folded, &install))
            .cloned()
            .ok_or_else(|| authority_refused(JOIN_NOT_COUNTED))?;
        txn.commit()?;
        // The work the queue held while the copy had not joined is claimable
        // now: wake its observers, and the deadline watchers that armed
        // nothing for it, so it starts at once (RULING
        // RESTORED-UNJOINED-OWNER-DIRECT-WORK = A).
        self.store.notify_attempt_observers();
        self.store.notify_proactivity_changes();
        Ok(folded)
    }

    /// What [`Self::join_restored_install`] answers without the owner's
    /// proof, read before it asks for the person, in the writer's order.
    /// Nothing is readied and nothing is written.
    ///
    /// The owner's proof is revalidated first, as the writer's first check.
    /// Then, where this install's keys can be read as it holds them
    /// ([`Self::read_held_install_keys`]): the machine the
    /// fold holds under this install's id is returned when it stands live
    /// under those keys, and the door then asks nobody; a machine that
    /// stands any other way and a held enrolment that is not this install's
    /// ask are refused.
    ///
    /// `None` when the join has work to do. `None` also where only readying
    /// the install can say which machine it is: it has no machine id yet,
    /// its signing slot is empty, or the vault's device key row is absent or
    /// names another key. Readying may then mint a new machine, so the door
    /// asks first and the writer answers.
    ///
    /// # Errors
    /// An owner refusal when the proof is no longer the vault's live owner;
    /// [`crate::error::RecordError::AuthorityRefused`] naming the refusal;
    /// keystore and storage faults.
    fn restored_join_read(
        &self,
        owner: &AuthenticatedOwner,
        vault_id: [u8; 32],
        role: MachineRole,
    ) -> Result<Option<FoldedMachine>> {
        let actor = {
            let txn = self.store.env.read_txn()?;
            owner.revalidate_as_vault_owner_in_txn(self, &txn)?
        };
        // The keystore is read outside every snapshot.
        let Some(held) = self.read_held_install_keys(vault_id)? else {
            return Ok(None);
        };
        let txn = self.store.env.read_txn()?;
        if crate::identity::read_machine_id_in_txn(self, &txn)? != Some(held.signer.machine) {
            return Ok(None);
        }
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let install = JoiningInstall {
            machine: held.signer.machine,
            machine_key: held.signer.machine_key.verifying_key().to_bytes(),
            encryption_key: held.encryption_key.as_ref(),
            device_class: self.config.machine_device_class,
            restored_from: crate::identity::read_restored_from_image_in_txn(self, &txn)?,
        };
        if let Some(standing) = standing_machine(&fold, &install)? {
            return Ok(Some(standing));
        }
        let waiting_is_this_installs_ask = fold
            .counted_waiting_enrolments(install.machine)
            .all(|(_, waiting)| held_is_this_ask(&waiting.profile, &install, actor, role));
        if !waiting_is_this_installs_ask {
            return Err(authority_refused(HELD_DIFFERS));
        }
        Ok(None)
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
            if !self.holds_proving_owner_key(&fold) {
                return Err(authority_refused(NO_OWNER_KEY));
            }
            super::slip_vault::require_host(&fold, issuer)
                .map_err(|_| authority_refused(NOT_THE_ROOT))?;
        }
        Ok(())
    }

    /// Whether this install is a copy restored from an image of a vault a
    /// root roots that has not joined it, in its own snapshot (the one test,
    /// [`crate::setting::restored::restored_unjoined_in_txn`]): a host's
    /// runner of the image's own work (its hooks, reader children, parked
    /// code runs) asks it before it starts any, and starts none while it
    /// holds (row RESTORED-UNJOINED-STARTS-NO-WORK). An install no restore
    /// made reads its mark alone. The first snapshot after the join reads it
    /// joined.
    ///
    /// # Errors
    /// An install row that does not decode; the fold's errors; storage
    /// faults.
    pub fn restored_unjoined(&self) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        crate::setting::restored::restored_unjoined_in_txn(self, &txn)
    }

    /// The refusal of new outward work on an install born of a restore of a
    /// vault a root roots that has not joined it: its restored-from mark
    /// stands, and it has no machine id or the vault's fold holds no machine
    /// under it (the one test, [`crate::setting::restored::restored_unjoined_in_txn`]).
    /// Such a copy starts no work of its own: no agent turn, no scheduled job,
    /// no send (Setting DESIGN pass 15e "Joined"; row
    /// RESTORED-UNJOINED-STARTS-NO-WORK). Read in `txn` through the cached
    /// fold, before anything is written; an install no restore made reads its
    /// mark alone. The snapshot after its join commits reads it joined, so the
    /// work it held starts with no restart.
    ///
    /// # Errors
    /// [`crate::error::RecordError::AuthorityRefused`] naming
    /// [`super::machine_answers::RESTORED_NOT_JOINED`] on such a copy; an
    /// install row that does not decode; the fold's errors; storage faults.
    pub(crate) fn refuse_work_while_restored_unjoined_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<()> {
        if crate::setting::restored::restored_unjoined_in_txn(self, txn)? {
            return Err(authority_refused(
                super::machine_answers::RESTORED_NOT_JOINED,
            ));
        }
        Ok(())
    }

    /// A kit restore's join of this install when a restore made it (Engine
    /// ANSWER KIT-RESTORE-JOINS-RESTORED-COPY = A): `signer`, the kit's root
    /// authority key R held behind `sign`, a live owner key of the roster,
    /// files this install's enrolment as its own act-free roster revision
    /// and joins it, in one owner's [`RestoredMachineJoin`] row in its
    /// inline form, signed by R alone, in the caller's transaction. One R
    /// row, as main's kit restore puts a machine on the roster in one R row,
    /// so two kit restores of copies of one image stay equal-sequence
    /// siblings and neither floors the other (Engine ANSWER
    /// KIT-JOIN-ONE-R-ROW = A; REVIEW-9534 round 2 P1). A kit restore signed
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
        let profile = self.kit_restore_enrolment_profile_in_txn(txn, &fold, owner, request)?;
        let act = OwnerAct::by_owner(
            owner,
            OwnerActKind::RestoredMachineJoin,
            request.machine,
            ActSurface::ThisInstall,
            restored_machine_join_inline_seen(&profile)?,
        );
        let op = AuthorityOp::RestoredMachineJoin(RestoredMachineJoin {
            act,
            enrolment: RestoredJoinEnrolment::Inline(profile),
        });
        let by_key: &FoldSign<'_> = &|_, transcript| sign(transcript);
        self.append_owner_signed_in_txn(txn, &fold, op, (signer, by_key))?;
        let joined = self
            .authority_view_readonly_in_txn(txn)?
            .machine(request.machine)
            .is_some_and(|folded| stands_as_this_install(folded, &JoiningInstall::from(request)));
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
