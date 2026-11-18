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

use super::machine_identity::SERVING_INSTALL_ROLE;
use super::slip_vault::{next_entry, require_host};
use super::*;

/// What an owner's machine answer did once the fold judged it (row
/// CARRIER-OWNER-PROOF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineAnswerLanding {
    /// The answer stands: the machine as the fold now holds it.
    Stands(FoldedMachine),
    /// The answer needed an owner key's proof and this install holds none. It
    /// is stored and HELD: it asks the owner on an owner device and stands
    /// for nothing until he confirms there. `answer` is its log entry;
    /// `machine` is the machine as it still stands, `None` when no revision
    /// names it yet.
    Held {
        answer: AuthorityEntryHash,
        machine: Option<FoldedMachine>,
    },
}

impl MachineAnswerLanding {
    /// The machine as the fold holds it after the answer: changed by an
    /// answer that stands, unchanged by a held one.
    #[must_use]
    pub fn machine(&self) -> Option<&FoldedMachine> {
        match self {
            Self::Stands(machine) => Some(machine),
            Self::Held { machine, .. } => machine.as_ref(),
        }
    }

    /// The held answer's log entry; `None` for an answer that stands.
    #[must_use]
    pub fn held(&self) -> Option<AuthorityEntryHash> {
        match self {
            Self::Stands(_) => None,
            Self::Held { answer, .. } => Some(*answer),
        }
    }

    /// The machine an answer that stands gave; `None` for a held answer.
    #[must_use]
    pub fn into_standing(self) -> Option<FoldedMachine> {
        match self {
            Self::Stands(machine) => Some(machine),
            Self::Held { .. } => None,
        }
    }
}

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
    pub(super) fn by_owner(
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

/// A machine born of a restore is not a machine of the vault until a joined
/// machine joins it (row RESTORED-COPIES-ENROL-EACH-OTHER): the bootstrap arm
/// never enrols it, and the fold holds a root-signed enrolment of it until an
/// entry signed by a joined machine of the vault descends from it, or the
/// owner's word that no other machine is left names it
/// (`Vault::join_restored_install`).
pub(crate) const RESTORED_NOT_JOINED: &str = "this install was restored from a checkpoint and has \
     not joined the vault: a machine of the vault that has joined must pair it, or, when no other \
     machine is left, the owner joins it here with an owner key";

/// What the fold did with one landed machine revision: an owner's answer as
/// it landed, or a restored machine's enrolment, held until it joins (row
/// RESTORED-COPIES-ENROL-EACH-OTHER).
enum Landed {
    Answer(MachineAnswerLanding),
    Restored,
}

/// The roster's chain holds the machine a roster key would put on it as
/// removed, or names it with other keys: no roster key's revision replaces
/// either. Nothing was written.
const ROSTER_HOLDS_MACHINE_OTHERWISE: &str = "the vault's roster holds this machine as removed, \
                                              or names it with other keys; nothing was written";

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
///
/// A machine born of a restore whose enrolment the fold holds unjoined (row
/// RESTORED-COPIES-ENROL-EACH-OTHER) joins on that held chain: the fold lays
/// it under a carried answer, so the answer is numbered above every held
/// revision, and it must name the same machine and encryption keys and
/// origin, or it refuses and nothing is written (REVIEW-9509/9510 P1). Only
/// the enrolments held under a scope this install counts are read: the
/// roster's and its pinned anchor's (REVIEW-9509 round 2 P1).
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
    let held = fold
        .counted_waiting_enrolments(request.machine)
        .map(|(_, held)| &held.profile);
    let mut revision = 1;
    for held in held {
        if held.machine_key != request.machine_key
            || held.encryption_key != request.encryption_key
            || held.restored_from != request.restored_from
        {
            return Err(invalid_authority());
        }
        revision = revision.max(held.revision.saturating_add(1));
    }
    Ok(MachineProfile {
        machine: request.machine,
        owner,
        machine_key: request.machine_key,
        device_class: request.device_class,
        encryption_key: request.encryption_key.clone(),
        role,
        revision,
        machine_proof: request.machine_proof,
        seen_world_edits: std::collections::BTreeSet::new(),
        carrier: None,
        act: None,
        restored_from: request.restored_from,
    })
}

/// The class-only revision of a machine the roster already holds (FIX 3835;
/// CALLS: MACHINE_CLASS_REVISION = SameIdentityFreshProof): its host now
/// declares another class, and its request carries the machine's fresh proof
/// over it, which the owner approves as he approves an enrolment. Only for a
/// live machine under the same id and both the same keys, in the role it
/// stands in: its role stays [`Vault::set_machine_role`]'s, its keys are
/// never replaced, and a removed or conflicted machine never comes back. The
/// next revision tops every head the machine stands under here
/// ([`FoldedMachine::standing_heads`]), as a role change's does; another
/// anchor's chain neither numbers it nor refuses it.
fn class_revision_profile(
    fold: &AuthorityFold,
    owner: EntityId,
    request: &MachineEnrolmentRequest,
    role: MachineRole,
) -> Result<MachineProfile> {
    let folded = fold
        .machine(request.machine)
        .ok_or_else(invalid_authority)?;
    let mut heads = folded.standing_heads(fold.pinned_root.as_ref());
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
        // The proof signs the request's origin; the fold refuses one that is
        // not the machine's (row RESTORED-COPIES-ENROL-EACH-OTHER).
        restored_from: request.restored_from,
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
    /// An answer that needs an owner key's proof, carried by an install that
    /// holds none, lands [`MachineAnswerLanding::Held`] (row
    /// CARRIER-OWNER-PROOF): it is stored and asks the owner on an owner
    /// device, the machine stands as before, and no credential is sealed
    /// again.
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
    ) -> Result<MachineAnswerLanding> {
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let answer = AnswerAct::by_owner(actor, surface, role, seen);
        let landing = self.enroll_machine_in_txn(&mut txn, answer, request, role)?;
        txn.commit()?;
        #[cfg(feature = "sync")]
        if landing.held().is_none() {
            self.reseal_after_machine_admission()?;
        }
        Ok(landing)
    }

    /// The owner changes a machine's answer or removes it, from any surface
    /// where he is authenticated, carried by this install under his act in
    /// the roster's chain. Removal is terminal. His answer supersedes every
    /// head of the machine he saw, an anchor's mark included (C5); `seen` is
    /// as for [`Self::enroll_machine`]. A role change between linked roles
    /// takes no carrier power away; only a removal does. The credentials are
    /// sealed again for the roster it changed. A held answer changes no
    /// roster, as for [`Self::enroll_machine`].
    ///
    /// The answer is numbered above, copies the identity of, and is refused
    /// by a removal in the heads the machine stands under on this install
    /// alone ([`FoldedMachine::standing_heads`]): the roster's and the
    /// pinned anchor's. The mark of an anchor this install does not pin
    /// changes none of the three.
    ///
    /// # Errors
    /// As [`Self::enroll_machine`], and [`invalid_authority`] for a machine no
    /// roster revision and no mark of the pinned anchor names, or one already
    /// removed there.
    pub fn set_machine_role(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        machine: EntityId,
        role: MachineRole,
        seen: Option<[u8; 32]>,
    ) -> Result<MachineAnswerLanding> {
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let folded = fold.machine(machine).ok_or_else(invalid_authority)?;
        // The machine's identity as the newest head it stands under names
        // it, the roster's or the pinned anchor's; the next revision tops
        // both.
        let mut heads = folded.standing_heads(fold.pinned_root.as_ref());
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
        let landing = self.append_owner_answer_in_txn(&mut txn, &fold, answer, profile)?;
        txn.commit()?;
        #[cfg(feature = "sync")]
        if landing.held().is_none() {
            self.reseal_after_machine_admission()?;
        }
        Ok(landing)
    }

    /// Enrols in the caller's transaction under the owner's act, carried by
    /// this install; the caller has checked `answer.owner`.
    pub(super) fn enroll_machine_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        answer: AnswerAct,
        request: &MachineEnrolmentRequest,
        role: MachineRole,
    ) -> Result<MachineAnswerLanding> {
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
        // A pairing answers a machine's revision 1 only
        // (`MachineProfile::validate_act`): a restored machine that joins on
        // its held chain is numbered above it, and the owner's pairing then
        // stands as his answer for it (REVIEW-9509/9511 round 2 P1).
        let mut answer = answer;
        if profile.revision > 1 && matches!(answer.kind, OwnerActKind::Pairing) {
            answer.kind = OwnerActKind::MachineAnswer;
        }
        self.ensure_machine_row_in_txn(txn, request.machine)?;
        self.append_owner_answer_in_txn(txn, &fold, answer, profile)
    }

    /// Whether this install may sign a revision in `role` under a host root
    /// with no owner act: the bootstrap arm (C4) and the re-root carry (C3).
    /// Under the Hosted posture a host root never answers for the owner
    /// (the writer rule of [`AuthorityFold::offers_owner_proof`]), so an
    /// owner's answer (`Owned`) needs his act, carried by a machine. The
    /// fold keeps such an answer a self-host root signed before its log was
    /// folded as hosted; a hosted install never writes a new one (Engine
    /// ANSWER HOSTED-REFOLD-SELF-HOST-ROOT-CUSTODY = A).
    pub(super) fn host_root_may_sign_role(&self, role: MachineRole) -> bool {
        !(matches!(role, MachineRole::Owned(_))
            && self.privacy_posture() == crate::HostingPrivacyPosture::Hosted)
    }

    /// Enrols in the caller's transaction on the explicit bootstrap arm
    /// (C4): the host root signs, with no owner act. Only the host's own
    /// node and a fresh self-host first install take it; the fold judges the
    /// root's custody, so a hosted root never answers "yours" here, and a
    /// hosted install signs no owner's answer with any host root it holds
    /// ([`Self::host_root_may_sign_role`]): it refuses, writing nothing.
    pub(super) fn enroll_bootstrap_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        owner: EntityId,
        request: &MachineEnrolmentRequest,
        role: MachineRole,
    ) -> Result<FoldedMachine> {
        if !self.host_root_may_sign_role(role) {
            return Err(no_carrier());
        }
        let fold = self.authority_view_readonly_in_txn(txn)?;
        require_host(&fold, issuer)?;
        // A machine born of a restore joins only through a joined machine
        // (row RESTORED-COPIES-ENROL-EACH-OTHER); the fold would hold it.
        if request.restored_from.is_some() {
            return Err(authority_refused(RESTORED_NOT_JOINED));
        }
        let profile = joining_profile(&fold, owner, request, role)?;
        self.ensure_machine_row_in_txn(txn, request.machine)?;
        self.append_machine_profile_in_txn(txn, issuer, &fold, profile)
    }

    /// A root-signed enrolment of an install born of a restore (row
    /// RESTORED-COPIES-ENROL-EACH-OTHER): the fold holds it until an entry
    /// signed by a joined machine descends from it, or the owner's word
    /// names it. Returns that enrolment's entry for the caller to commit.
    /// Refuses a request no restore made, and one the fold did not hold.
    /// Only the owner's join door (`Vault::join_restored_install`) writes
    /// one, beside that word, and the test door that proves the fold's hold
    /// and join.
    pub(crate) fn file_restored_enrolment_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        owner: EntityId,
        request: &MachineEnrolmentRequest,
        role: MachineRole,
    ) -> Result<AuthorityEntryHash> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        require_host(&fold, issuer)?;
        if request.restored_from.is_none() {
            return Err(invalid_authority());
        }
        let profile = joining_profile(&fold, owner, request, role)?;
        self.ensure_machine_row_in_txn(txn, request.machine)?;
        match self.append_root_signed_in_txn(txn, issuer, &fold, profile)? {
            Landed::Restored => self
                .authority_view_readonly_in_txn(txn)?
                .unjoined_restored_enrolment(request.machine)
                .ok_or_else(invalid_authority),
            Landed::Answer(_) => Err(invalid_authority()),
        }
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
    /// never reports success, and one it holds for the owner's proof reports
    /// held.
    pub(super) fn append_owner_answer_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fold: &AuthorityFold,
        answer: AnswerAct,
        mut profile: MachineProfile,
    ) -> Result<MachineAnswerLanding> {
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
        // The owner key this install holds proves the answer beside the
        // carrier's signature (row CARRIER-OWNER-PROOF); with none, an
        // answer that needs the proof is held.
        let proof = self.owner_proof_signer(fold);
        let entry = sign_side_entry_with_owner_proof(
            fold,
            &key,
            seq,
            parents,
            AuthorityOp::MachineProfile(profile.clone()),
            now,
            proof.as_ref(),
        )?;
        self.land_machine_profile_in_txn(txn, entry, &profile, now)
    }

    /// Signs every live root-signed roster standing again under `next`, in
    /// the caller's transaction: bootstrap maintenance only (C3). A re-root
    /// revokes every roster key, and a standing that rests on a revoked key
    /// goes stale. An owner's admitted answer rests on its carrier's act and
    /// no roster key, so it survives the re-root as it is; the new root never
    /// copies an act into a revision it signs. An anchor's chain rests on no
    /// roster key and is not the roster's to carry. Under the Hosted posture
    /// `next` is stamped for the cloud and answers for nobody
    /// ([`Self::host_root_may_sign_role`]): an owner's answer the old root
    /// signed (`Owned`, as a self-host root does before its vault is moved
    /// or reopened as hosted) is not signed again, which the fold would
    /// refuse, rolling the whole move back. Another machine's such answer
    /// goes stale with the old root until the owner answers again through a
    /// machine that carries his act. This install's own is carried on as
    /// [`SERVING_INSTALL_ROLE`], the role a hosted serving install takes,
    /// so the vault keeps the carrier of those answers: stale, its profile
    /// would refuse every start's bootstrap and every owner act here (review
    /// of #9474, round 2).
    pub(super) fn carry_machine_standing_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        before: &AuthorityFold,
        next: &HostSlipIssuer,
    ) -> Result<usize> {
        let serving = crate::identity::read_machine_id_in_txn(self, txn)?;
        let mut carried = 0;
        for machine in before
            .machines
            .iter()
            .filter(|(machine, folded)| {
                folded.roster.as_ref().is_some_and(|roster| {
                    roster.is_live()
                        && roster.profile.act.is_none()
                        && (self.host_root_may_sign_role(roster.profile.role)
                            || serving == Some(**machine))
                })
            })
            .map(|(machine, _)| *machine)
        {
            let fold = self.authority_view_readonly_in_txn(txn)?;
            let current = fold
                .machine(machine)
                .and_then(|folded| folded.roster.as_ref())
                .ok_or_else(invalid_authority)?;
            let role = if self.host_root_may_sign_role(current.profile.role) {
                current.profile.role
            } else {
                SERVING_INSTALL_ROLE
            };
            let profile = MachineProfile {
                revision: current
                    .profile
                    .revision
                    .checked_add(1)
                    .ok_or_else(invalid_authority)?,
                role,
                ..current.profile.clone()
            };
            self.append_machine_profile_in_txn(txn, next, &fold, profile)?;
            carried += 1;
        }
        Ok(carried)
    }

    /// Signs one bootstrap revision under the host root (C3, C4), with no
    /// owner act. A restored machine's enrolment, which the fold holds,
    /// refuses here ([`RESTORED_NOT_JOINED`]): it stands for nothing.
    fn append_machine_profile_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        fold: &AuthorityFold,
        profile: MachineProfile,
    ) -> Result<FoldedMachine> {
        match self.append_root_signed_in_txn(txn, issuer, fold, profile)? {
            Landed::Answer(landing) => landing.into_standing().ok_or_else(invalid_authority),
            Landed::Restored => Err(authority_refused(RESTORED_NOT_JOINED)),
        }
    }

    /// [`Self::append_machine_profile_in_txn`]'s write, and what the fold did.
    fn append_root_signed_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        fold: &AuthorityFold,
        mut profile: MachineProfile,
    ) -> Result<Landed> {
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
        // A root-signed revision carries no act, so the fold never holds it
        // for the owner's proof; it holds a restored machine's enrolment.
        self.land_revision_in_txn(txn, entry, &profile, now)
    }

    /// Puts `request`'s machine on the roster's chain in the caller's
    /// transaction, signed by `signer`, a live owner key of the roster held
    /// behind `sign`: the kit's root authority key R at the kit restore
    /// (ANCHORS-1 = A: on every install the owner's roster keys decide, the
    /// kit's R among them; FIX KIT-RESTORE-ANCHOR-ONLY-INSTALL-COUNTS-NO-WRAP).
    /// Only the roster's chain admits an owner act's carrier and a world key
    /// wrap's publisher, so a machine only an anchor marked does neither.
    /// The row is one act-free `Owned(Yours)` revision with the request's
    /// keys and proof, the next of the roster's chain: an owner-held
    /// signer's approval, which no custodian's later revision reaches. An
    /// accepted roster chain whose head already says this machine is the
    /// owner's own with these keys needs no row (`None`); a live head in any
    /// other role, such as the `Unanswered` profile a serving install's
    /// startup writes, takes the row above it (REVIEW-9488 P1 4). A removed
    /// machine, or a roster head with other keys, is refused. The fold is
    /// the judge: the revision must stand.
    pub(crate) fn put_machine_on_roster_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        (signer, sign): (&AuthorityKey, &dyn Fn(&[u8]) -> Result<Vec<u8>>),
        owner: EntityId,
        request: &MachineEnrolmentRequest,
    ) -> Result<Option<AuthorityEntryHash>> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        if vault_id != request.vault_id {
            return Err(invalid_authority());
        }
        let folded = fold.machine(request.machine);
        let same_keys = |revision: &MachineRevision| {
            revision.profile.machine_key == request.machine_key
                && revision.profile.encryption_key == request.encryption_key
        };
        let head = folded.and_then(|folded| folded.roster.as_ref());
        if let Some(head) = head
            && (head.removed || !same_keys(head))
        {
            return Err(authority_refused(ROSTER_HOLDS_MACHINE_OTHERWISE));
        }
        if folded
            .and_then(|folded| folded.roster_trusted.as_ref())
            .is_some_and(|trusted| trusted.says_yours() && same_keys(trusted))
        {
            return Ok(None);
        }
        let revision = match head {
            Some(head) => head
                .profile
                .revision
                .checked_add(1)
                .ok_or_else(invalid_authority)?,
            None => 1,
        };
        self.ensure_machine_row_in_txn(txn, request.machine)?;
        let profile = MachineProfile {
            machine: request.machine,
            owner,
            machine_key: request.machine_key,
            device_class: request.device_class,
            encryption_key: request.encryption_key.clone(),
            role: MachineRole::Owned(MachineOwnership::Yours),
            revision,
            machine_proof: request.machine_proof,
            seen_world_edits: super::act_standing::acknowledged_by_in_txn(
                &self.store,
                txn,
                &fold,
                request.machine,
            )?,
            // A roster key's own revision: no install carries it, and no
            // owner act rides it (the bootstrap arm's shape, C4).
            carrier: None,
            act: None,
            // The request's own origin, which its proof signs: an install
            // born of a restore stays held until it joins (row
            // RESTORED-COPIES-ENROL-EACH-OTHER).
            restored_from: request.restored_from,
        };
        self.append_owner_signed_roster_revision_in_txn(txn, (signer, sign), &fold, profile)
            .map(Some)
    }

    /// `standing`, a roster revision of its machine, again as the next
    /// revision above that machine's roster head, signed by `signer`, a live
    /// owner key of the roster held behind `sign`, in the caller's
    /// transaction: a kit change's carry of a standing the R it revokes
    /// signed ([`Self::carry_recovery_authority_approvals_in_txn`],
    /// WAYBACK-R-REVOCATION-STALES-R-APPROVALS = A), as
    /// [`Self::carry_machine_standing_in_txn`] carries a host re-root's. The
    /// carry chose the standing while it was live, before the revocation: the
    /// roster head, or the accepted chain's head below a custodial one
    /// (REVIEW-9488 P1 5). An aged standing reads stale here, and the new
    /// revision stands again.
    ///
    /// # Errors
    /// A machine with no roster head, or a revision that does not stand.
    pub(crate) fn carry_roster_standing_under_key_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        (signer, sign): (&AuthorityKey, &dyn Fn(&[u8]) -> Result<Vec<u8>>),
        standing: &MachineProfile,
    ) -> Result<AuthorityEntryHash> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let head = fold
            .machine(standing.machine)
            .and_then(|folded| folded.roster.as_ref())
            .ok_or_else(invalid_authority)?;
        let profile = MachineProfile {
            revision: head
                .profile
                .revision
                .checked_add(1)
                .ok_or_else(invalid_authority)?,
            seen_world_edits: super::act_standing::acknowledged_by_in_txn(
                &self.store,
                txn,
                &fold,
                standing.machine,
            )?,
            ..standing.clone()
        };
        self.append_owner_signed_roster_revision_in_txn(txn, (signer, sign), &fold, profile)
    }

    /// Signs `profile`, an act-free roster revision, by `signer`, a live
    /// owner key of the roster held behind `sign`, and lands it in the
    /// caller's transaction ([`Self::put_machine_on_roster_in_txn`],
    /// [`Self::carry_roster_standing_under_key_in_txn`]). The fold is the
    /// judge: the revision must stand.
    fn append_owner_signed_roster_revision_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        (signer, sign): (&AuthorityKey, &dyn Fn(&[u8]) -> Result<Vec<u8>>),
        fold: &AuthorityFold,
        profile: MachineProfile,
    ) -> Result<AuthorityEntryHash> {
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        profile.validate()?;
        // FIX 7908: join a frontier wider than one entry names, else today's path.
        let joiner = FrontierSigner::Callback(signer, sign);
        let joined = self.prepare_authority_frontier_in_txn(txn, fold, joiner, MAX_PARENTS)?;
        let fold = joined.as_deref().unwrap_or(fold);
        let parents = fold.append_heads.clone();
        if parents.is_empty() {
            return Err(invalid_authority());
        }
        if parents.len() > MAX_PARENTS {
            return Err(answer_parent_bound(parents.len()));
        }
        let now = self.instant_in_txn(txn)?.secs();
        let mut entry = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some(vault_id),
            seq: next_sequence(fold, signer)?,
            parent_hashes: parents.into_iter().collect(),
            op: AuthorityOp::MachineProfile(profile.clone()),
            signer: AuthoritySignature {
                suite: signer.suite(),
                public_key: signer.clone(),
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: now,
        };
        entry.signer.signature = sign(&authority_transcript(&entry)?)?;
        let hash = authority_entry_hash(&entry)?;
        // An owner-held signer's revision carries no act, so the fold never
        // holds it: it stands or the door refuses.
        self.land_machine_profile_in_txn(txn, entry, &profile, now)?
            .into_standing()
            .ok_or_else(invalid_authority)?;
        Ok(hash)
    }

    /// Lands one machine revision and reads the fold back. A removal keeps
    /// the effect of every act the machine carried that it saw (its
    /// `seen_world_edits`: world edits, grant travel choices and machine
    /// answers alike); one it never saw raced it and counts only stricter. A
    /// role change takes no carrier power away, so every revision lists
    /// them.
    ///
    /// An answer the fold holds for the owner's proof moved no head: it
    /// reports held, with the machine as it still stands, and the caller
    /// commits it so an owner device can ask (row CARRIER-OWNER-PROOF).
    fn land_machine_profile_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        entry: AuthorityLogEntry,
        profile: &MachineProfile,
        now: u64,
    ) -> Result<MachineAnswerLanding> {
        match self.land_revision_in_txn(txn, entry, profile, now)? {
            Landed::Answer(landing) => Ok(landing),
            Landed::Restored => Err(authority_refused(RESTORED_NOT_JOINED)),
        }
    }

    /// [`Self::land_machine_profile_in_txn`], and its third verdict: a
    /// restored machine's enrolment the fold holds until it joins.
    fn land_revision_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        entry: AuthorityLogEntry,
        profile: &MachineProfile,
        now: u64,
    ) -> Result<Landed> {
        let at = TimeRange {
            start: now,
            end: now,
        };
        let answer = authority_entry_hash(&entry)?;
        self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])?;
        // The fold is the judge: a profile it refused never reports success.
        let removal = profile.role == MachineRole::Removed;
        let after = self.authority_view_readonly_in_txn(txn)?;
        let machine = after.machine(profile.machine);
        if let Some(folded) = machine.filter(|folded| {
            folded
                .roster
                .as_ref()
                .is_some_and(|roster| roster.profile == *profile && (roster.is_live() || removal))
        }) {
            return Ok(Landed::Answer(MachineAnswerLanding::Stands(folded.clone())));
        }
        let held = after
            .held_machine_answers()
            .get(&profile.machine)
            .is_some_and(|held| held.contains_key(&answer));
        if held {
            return Ok(Landed::Answer(MachineAnswerLanding::Held {
                answer,
                machine: machine.cloned(),
            }));
        }
        if after
            .restored_enrolments()
            .get(&answer)
            .is_some_and(|enrolment| enrolment.joined_by.is_none())
        {
            return Ok(Landed::Restored);
        }
        Err(invalid_authority())
    }
}
