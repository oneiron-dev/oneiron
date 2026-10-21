//! The owner's machine answers as one install writes them (mesh PR1b): he
//! enrols, re-marks and removes a machine from any surface where he is
//! authenticated, and this install carries his act with its own install key
//! under a live profile of any role. The explicit bootstrap arms (the host's
//! own node, a fresh self-host first install) stay host-root-signed with no
//! act, and a host re-root carries only them (C3, C4).

use ed25519_dalek::SigningKey;

use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::{EntityId, TimeRange, Vault};

use super::slip_vault::{next_entry, require_host};
use super::*;

/// The owner's say-so one machine answer carries (mesh PR1b): who decided,
/// as whom, from which surface (audit only), of which kind, and on which
/// revision of the target the deciding surface showed him; `None` takes the
/// writer's current one (a caller that showed none).
#[derive(Debug, Clone, Copy)]
pub(super) struct AnswerAct {
    pub(super) owner: EntityId,
    pub(super) by: ActBy,
    pub(super) surface: ActSurface,
    pub(super) kind: OwnerActKind,
    pub(super) seen: Option<[u8; 32]>,
}

impl AnswerAct {
    /// The owner's own answer from `surface`: a removal for `Removed`, an
    /// answer for any other role.
    fn by_owner(
        owner: EntityId,
        surface: ActSurface,
        role: MachineRole,
        seen: Option<[u8; 32]>,
    ) -> Self {
        let kind = if role == MachineRole::Removed {
            OwnerActKind::MachineRemoval
        } else {
            OwnerActKind::MachineAnswer
        };
        Self {
            owner,
            by: ActBy::Owner,
            surface,
            kind,
            seen,
        }
    }
}

/// This install cannot carry the owner's answer: it has no machine identity
/// or install key, or no live profile of it in the vault stands under that
/// key. Key possession and integrity: an answer is signed by the install that
/// carries it, and FIX 2222 keeps every roster key (the host root included)
/// out. Nothing was written.
pub(super) fn no_carrier() -> Error {
    Error::InvalidConfig(
        "this install has no live machine profile in the vault to carry the owner's machine \
         answer; nothing was written"
            .to_owned(),
    )
}

/// The answer would name more rows than one authority entry may: the log's
/// encoding bound (`MAX_PARENTS`), never a possession test. It refuses
/// atomically (C5).
fn answer_parent_bound(named: usize) -> Error {
    Error::InvalidConfig(format!(
        "this machine answer would name {named} parent rows, more than the {MAX_PARENTS} one \
         authority entry names; nothing was written"
    ))
}

/// The first roster revision of a joining machine: its own identity
/// material, the owner's answer and revision 1. A machine joins the roster's
/// chain once; a later answer changes its role through
/// [`Vault::set_machine_role`] and its class through
/// [`class_revision_profile`], and nothing that joins replaces its key.
fn joining_profile(
    fold: &AuthorityFold,
    owner: EntityId,
    request: &MachineEnrolmentRequest,
    role: MachineRole,
) -> Result<MachineProfile> {
    if role == MachineRole::Removed
        || fold.vault_id != Some(request.vault_id)
        || fold
            .machine(request.machine)
            .is_some_and(|folded| folded.roster.is_some())
    {
        return Err(invalid_authority());
    }
    Ok(MachineProfile {
        machine: request.machine,
        owner,
        machine_key: request.machine_key,
        device_class: request.device_class,
        encryption_key: request.encryption_key.clone(),
        role,
        revision: 1,
        machine_proof: request.machine_proof,
        seen_world_edits: std::collections::BTreeSet::new(),
        carrier: None,
        act: None,
    })
}

/// The class-only revision of a machine the roster already holds (FIX 3835;
/// CALLS: MACHINE_CLASS_REVISION = SameIdentityFreshProof): its host now
/// declares another class, and its request carries the machine's fresh proof
/// over it, which the owner approves as he approves an enrolment. Only for a
/// live machine under the same id and both the same keys, in the role it
/// stands in: its role stays [`Vault::set_machine_role`]'s, its keys are
/// never replaced, and a removed or conflicted machine never comes back. The
/// next revision tops every chain's, as a role change's does.
fn class_revision_profile(
    fold: &AuthorityFold,
    owner: EntityId,
    request: &MachineEnrolmentRequest,
    role: MachineRole,
) -> Result<MachineProfile> {
    let folded = fold
        .machine(request.machine)
        .ok_or_else(invalid_authority)?;
    let mut heads: Vec<_> = folded.chains().map(|(_, head)| head).collect();
    heads.sort_by_key(|head| head.profile.revision);
    let current = heads.last().ok_or_else(invalid_authority)?;
    if fold.vault_id != Some(request.vault_id)
        || !folded.roster.as_ref().is_some_and(MachineRevision::is_live)
        || heads.iter().any(|head| {
            head.removed
                || head.conflicted
                || head.profile.machine_key != request.machine_key
                || head.profile.encryption_key != request.encryption_key
        })
        || current.profile.role != role
        || current.profile.device_class == request.device_class
    {
        return Err(invalid_authority());
    }
    let profile = MachineProfile {
        owner,
        device_class: request.device_class,
        machine_proof: request.machine_proof,
        revision: current
            .profile
            .revision
            .checked_add(1)
            .ok_or_else(invalid_authority)?,
        carrier: None,
        act: None,
        ..current.profile.clone()
    };
    if !profile.proof_verifies(&request.vault_id) {
        return Err(invalid_authority());
    }
    Ok(profile)
}

impl Vault {
    /// The owner adds a machine, from any surface where he is authenticated
    /// (`surface`, audit only; the mesh ruling, 10-19). `role` is the owner's
    /// answer: only `Owned(Yours)` makes it mine; a hosted or rented node is
    /// never mine. The MACHINE row is created when absent. Lands one
    /// `MachineProfile` carrying his act, signed by this install as its
    /// carrier, revalidating the owner in the write transaction, then seals
    /// the portable credentials again for the roster it changed. `seen` is
    /// the machine's revision the deciding surface showed him
    /// ([`FoldedMachine::answer_revision`], zero for a machine no revision
    /// names); a stale one is a conflict, never a silent overwrite. A
    /// machine the roster already holds takes its class-only revision here
    /// instead (FIX 3835): the class its host now declares, under the fresh
    /// proof its request carries, in the role it stands in.
    ///
    /// # Errors
    /// [`Error::ConcurrentWrite`] when `seen` is not the machine's current
    /// revision; [`Error::InvalidConfig`] when this install carries no live
    /// profile or the answer would name more parents than one entry may;
    /// [`invalid_authority`] for a held machine that is not live, is removed
    /// or conflicted, names other keys or another role, or keeps its class.
    pub fn enroll_machine(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        request: &MachineEnrolmentRequest,
        role: MachineRole,
        seen: Option<[u8; 32]>,
    ) -> Result<FoldedMachine> {
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let answer = AnswerAct::by_owner(actor, surface, role, seen);
        let folded = self.enroll_machine_in_txn(&mut txn, answer, request, role)?;
        txn.commit()?;
        #[cfg(feature = "sync")]
        self.reseal_after_machine_admission()?;
        Ok(folded)
    }

    /// The owner changes a machine's answer or removes it, from any surface
    /// where he is authenticated, carried by this install under his act in
    /// the roster's chain. Removal is terminal. His answer supersedes every
    /// head of the machine he saw, an anchor's mark included (C5); `seen` is
    /// as for [`Self::enroll_machine`]. A role change between linked roles
    /// takes no carrier power away; only a removal does. The credentials are
    /// sealed again for the roster it changed.
    ///
    /// # Errors
    /// As [`Self::enroll_machine`], and [`invalid_authority`] for a machine no
    /// revision names or one already removed.
    pub fn set_machine_role(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        machine: EntityId,
        role: MachineRole,
        seen: Option<[u8; 32]>,
    ) -> Result<FoldedMachine> {
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let folded = fold.machine(machine).ok_or_else(invalid_authority)?;
        // The machine's identity as its newest head names it, the roster's
        // or an anchor's; the next revision tops every chain's.
        let mut heads: Vec<_> = folded.chains().map(|(_, head)| head).collect();
        heads.sort_by_key(|head| head.profile.revision);
        let current = heads.last().ok_or_else(invalid_authority)?;
        if heads.iter().any(|head| head.removed) {
            return Err(invalid_authority());
        }
        let profile = MachineProfile {
            owner: actor,
            role,
            revision: current
                .profile
                .revision
                .checked_add(1)
                .ok_or_else(invalid_authority)?,
            carrier: None,
            act: None,
            ..current.profile.clone()
        };
        let answer = AnswerAct::by_owner(actor, surface, role, seen);
        let folded = self.append_owner_answer_in_txn(&mut txn, &fold, answer, profile)?;
        txn.commit()?;
        #[cfg(feature = "sync")]
        self.reseal_after_machine_admission()?;
        Ok(folded)
    }

    /// Enrols in the caller's transaction under the owner's act, carried by
    /// this install; the caller has checked `answer.owner`.
    pub(super) fn enroll_machine_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        answer: AnswerAct,
        request: &MachineEnrolmentRequest,
        role: MachineRole,
    ) -> Result<FoldedMachine> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        // A machine the roster holds never joins again; only its class is
        // revised here (FIX 3835).
        let profile = if fold
            .machine(request.machine)
            .is_some_and(|folded| folded.roster.is_some())
        {
            class_revision_profile(&fold, answer.owner, request, role)?
        } else {
            joining_profile(&fold, answer.owner, request, role)?
        };
        self.ensure_machine_row_in_txn(txn, request.machine)?;
        self.append_owner_answer_in_txn(txn, &fold, answer, profile)
    }

    /// Enrols in the caller's transaction on the explicit bootstrap arm
    /// (C4): the host root signs, with no owner act. Only the host's own
    /// node and a fresh self-host first install take it; the fold judges the
    /// root's custody, so a hosted root never answers "yours" here.
    pub(super) fn enroll_bootstrap_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        owner: EntityId,
        request: &MachineEnrolmentRequest,
        role: MachineRole,
    ) -> Result<FoldedMachine> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        require_host(&fold, issuer)?;
        let profile = joining_profile(&fold, owner, request, role)?;
        self.ensure_machine_row_in_txn(txn, request.machine)?;
        self.append_machine_profile_in_txn(txn, issuer, &fold, profile)
    }

    /// This install as the carrier of the owner's act: its machine and its
    /// install key, under a live profile of any role the one carrier rule
    /// admits ([`owner_act_signer_admits`]). Key possession: an act is
    /// signed by the install that carries it; there is no root-key exception
    /// (FIX 2222).
    pub(super) fn carrier_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
    ) -> Result<(EntityId, SigningKey)> {
        let machine = crate::identity::read_machine_id_in_txn(self, txn)?.ok_or_else(no_carrier)?;
        let key =
            crate::identity::read_machine_signing_key_in_txn(self, txn)?.ok_or_else(no_carrier)?;
        let public_key = key.verifying_key().to_bytes();
        if !owner_act_signer_admits(fold.machine(machine), &fold.roster, &public_key) {
            return Err(no_carrier());
        }
        Ok((machine, key))
    }

    /// Signs and lands one owner answer in the caller's transaction, carried
    /// by this install: the answer names the target's revision the owner
    /// saw, and its parents are the main-log heads alone. The carrier's and
    /// the target's standing rows (the pinned anchor's mark among them) are
    /// main-log rows among those heads or their ancestors, so the fold at
    /// the heads carries them and the answer supersedes every head of the
    /// target it saw (C5, FIX 4987). It names no stranger anchor's row, which
    /// a replica may not store. The fold is the judge: an answer it refused
    /// never reports success.
    pub(super) fn append_owner_answer_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fold: &AuthorityFold,
        answer: AnswerAct,
        mut profile: MachineProfile,
    ) -> Result<FoldedMachine> {
        let (carrier, key) = self.carrier_in_txn(txn, fold)?;
        let target = fold.machine(profile.machine);
        let current = target.map_or([0; 32], FoldedMachine::answer_revision);
        // Revision integrity (contract §4): the owner decided on what the
        // surface showed him.
        if answer.seen.is_some_and(|seen| seen != current) {
            return Err(Error::ConcurrentWrite(
                "the machine's answer changed since it was read",
            ));
        }
        profile.seen_world_edits =
            super::act_standing::acknowledged_by_in_txn(&self.store, txn, fold, profile.machine)?;
        profile.carrier = Some(carrier);
        profile.act = Some(OwnerAct {
            owner: answer.owner,
            by: answer.by,
            surface: answer.surface,
            act: answer.kind,
            target: profile.machine,
            seen: current,
            answer: None,
        });
        profile.validate()?;
        // FIX 7908: join a frontier wider than one entry names, else today's path.
        let joiner = FrontierSigner::Install(carrier, &key);
        let joined = self.prepare_authority_frontier_in_txn(txn, fold, joiner, MAX_PARENTS)?;
        let fold = joined.as_deref().unwrap_or(fold);
        let parents = fold.append_heads.clone();
        if parents.len() > MAX_PARENTS {
            return Err(answer_parent_bound(parents.len()));
        }
        let signer = AuthorityKey::Ed25519(key.verifying_key().to_bytes());
        let seq = next_sequence(fold, &signer)?;
        let now = self.instant_in_txn(txn)?.secs();
        let entry = sign_side_entry(
            fold,
            &key,
            seq,
            parents,
            AuthorityOp::MachineProfile(profile.clone()),
            now,
        )?;
        self.land_machine_profile_in_txn(txn, entry, &profile, now)
    }

    /// Signs every live root-signed roster standing again under `next`, in
    /// the caller's transaction: bootstrap maintenance only (C3). A re-root
    /// revokes every roster key, and a standing that rests on a revoked key
    /// goes stale. An owner's admitted answer rests on its carrier's act and
    /// no roster key, so it survives the re-root as it is; the new root never
    /// copies an act into a revision it signs. An anchor's chain rests on no
    /// roster key and is not the roster's to carry.
    pub(super) fn carry_machine_standing_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        before: &AuthorityFold,
        next: &HostSlipIssuer,
    ) -> Result<usize> {
        let mut carried = 0;
        for machine in before
            .machines
            .iter()
            .filter(|(_, folded)| {
                folded
                    .roster
                    .as_ref()
                    .is_some_and(|roster| roster.is_live() && roster.profile.act.is_none())
            })
            .map(|(machine, _)| *machine)
        {
            let fold = self.authority_view_readonly_in_txn(txn)?;
            let current = fold
                .machine(machine)
                .and_then(|folded| folded.roster.as_ref())
                .ok_or_else(invalid_authority)?;
            let profile = MachineProfile {
                revision: current
                    .profile
                    .revision
                    .checked_add(1)
                    .ok_or_else(invalid_authority)?,
                ..current.profile.clone()
            };
            self.append_machine_profile_in_txn(txn, next, &fold, profile)?;
            carried += 1;
        }
        Ok(carried)
    }

    /// Signs one bootstrap revision under the host root (C3, C4), with no
    /// owner act.
    fn append_machine_profile_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        fold: &AuthorityFold,
        mut profile: MachineProfile,
    ) -> Result<FoldedMachine> {
        profile.seen_world_edits =
            super::act_standing::acknowledged_by_in_txn(&self.store, txn, fold, profile.machine)?;
        profile.validate()?;
        // FIX 7908: join a frontier wider than one entry names, else today's path.
        let joiner = FrontierSigner::Host(issuer);
        let joined = self.prepare_authority_frontier_in_txn(txn, fold, joiner, MAX_PARENTS)?;
        let fold = joined.as_deref().unwrap_or(fold);
        let now = self.instant_in_txn(txn)?.secs();
        let entry = next_entry(
            issuer,
            fold,
            AuthorityOp::MachineProfile(profile.clone()),
            now,
        )?;
        self.land_machine_profile_in_txn(txn, entry, &profile, now)
    }

    /// Lands one machine revision and reads the fold back. A removal keeps
    /// the effect of every act the machine carried that it saw (its
    /// `seen_world_edits`: world edits, grant travel choices and machine
    /// answers alike); one it never saw raced it and counts only stricter. A
    /// role change takes no carrier power away, so every revision lists
    /// them.
    fn land_machine_profile_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        entry: AuthorityLogEntry,
        profile: &MachineProfile,
        now: u64,
    ) -> Result<FoldedMachine> {
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])?;
        // The fold is the judge: a profile it refused never reports success.
        let removal = profile.role == MachineRole::Removed;
        self.authority_view_readonly_in_txn(txn)?
            .machine(profile.machine)
            .filter(|folded| {
                folded.roster.as_ref().is_some_and(|roster| {
                    roster.profile == *profile && (roster.is_live() || removal)
                })
            })
            .cloned()
            .ok_or_else(invalid_authority)
    }
}
