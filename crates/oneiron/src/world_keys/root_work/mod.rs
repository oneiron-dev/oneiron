//! Root work (WILL L04 row 02): the owner decides a change to one install's
//! recovery root on any surface he is authenticated on, and that exact
//! install, the target, makes it.
//!
//! The deciding install records an owner work request
//! ([`Vault::request_root_change`]) naming the target as its executor,
//! exactly (CALLS ROOT_WORK_EXECUTOR): never elected, never redirected. The
//! request carries ids only ([`RootChange`]); no seed, piece, passphrase,
//! enrolment code, prepared root or carry list enters it, a receipt or the
//! log. Its `seen` is the revision of the owner roots and of the target's
//! standing ([`AuthorityFold::root_work_revision`], CALLS ROOT_WORK_REVISION),
//! which the target computes again in its own writer transaction: another
//! revision refuses the request as a root revision mismatch, which says the
//! target may need to sync before the owner asks again (FIX 4738), and a
//! removed owner as not live.
//!
//! A pin needs nothing the target lacks, so the target's pickup makes it
//! (`super::owner_work`). Every other change needs the root's seed or kit,
//! which only the target receives: it stays pending until the owner, on any
//! surface that reaches the target, supplies it there
//! ([`Vault::run_root_request`]). Missing or wrong material is a typed call
//! refusal and leaves the request pending (CALLS
//! ROOT_WORK_MISSING_MATERIAL). A counted request that binds a root stands on
//! the target as the owner's fingerprint of that root (CALLS
//! ROOT_REQUEST_CONFIRMS); it never replaces the seed gate's own rules.
//! "Enacted" means the exact target change committed, nothing more (CALLS
//! ROOT_WORK_COMPLETION).
//!
//! The owner may cancel a pending root request from any surface he is
//! authenticated on ([`Vault::cancel_root_request`], FIX 4739, CALLS
//! ROOT_WORK_CANCEL): an act carried by the install he asks on, ids only,
//! that takes effect on the target whenever it syncs, however long it was
//! offline. A newer request on the same target supersedes an older one in
//! its causal past (CALLS ROOT_WORK_SUPERSESSION). The target decides at
//! execution: a request its fold holds cancelled or superseded leaves its
//! pickup and its pending-root read, and its recheck never runs it; no result
//! is signed for it, and its receipt, derived from the fold, says cancelled
//! or superseded. A request the target answered before it had the cancel
//! keeps that answer, and the cancel's receipt says it came too late
//! ("already enacted"). Nothing is ordered by clock or hash, nothing is
//! undone, and nothing expires.
//!
//! A pin request whose pickup committed a wait for a root the target did
//! not store yet owns that wait (FIX 5582): once the target folds the
//! request cancelled or superseded, its store gate stops taking that root's
//! row and its anchor's marks as its own, and the next pickup clears the
//! wait byte-free ([`Vault::settle_root_request_waits`]). The pin stays, a
//! wait the owner made at the pin door stays, and an activation's kit
//! issued under a request that ended stays listed, its request's state
//! beside it, for the target's own kit door to confirm.
//!
//! No location, origin, substrate or hosted-mode rule reads anything here.
//! What stays is real: only the target holds the seed it is given, and the
//! seed gate, the stored pin and the kit inventory decide what it opens.

mod execute;

use std::collections::BTreeSet;

use super::{
    AnchoredMachine, ConfirmedWorldKit, IssuedWorldKit, KitConfirmation, MachineSecret,
    OwnerWorkReceipt, OwnerWorkUnassigned, RecoveryRootSeed, RootRestore, WorldKitRestore,
};
use crate::authority::{
    ActSurface, AuthorityEntryHash, AuthorityFold, MachineEnrolmentRequest, OwnerWorkBody,
    OwnerWorkKind, OwnerWorkOutcome, OwnerWorkRefusal, OwnerWorkRequest, RecoveryRootId,
    RequestCode, RootChange, end_request_wait_in_txn, ended_request_wait, invalid_authority,
    read_pin_row_in_txn,
};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::recovery::{KitIssue, KitPassphrase, KitPiece};
use crate::{EntityId, Vault};

/// Which install makes a root change (CALLS ROOT_WORK_EXECUTOR).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootExecutor {
    /// Exactly the target the owner named, when it is a linked install of
    /// the vault whose proof key stands here and not the install the owner
    /// asked on. Never elected and never redirected: only a new owner act
    /// names another.
    ExactTarget,
}

const ROOT_WORK_EXECUTOR: RootExecutor = RootExecutor::ExactTarget;

/// The independent proof a counted root request gives its target (CALLS
/// ROOT_REQUEST_CONFIRMS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootRequestProof {
    /// The root a counted request binds stands as
    /// [`KitConfirmation::Fingerprint`] of it: the owner named that root on
    /// an authenticated surface, independently of the seed the target
    /// checks. The seed or kit must still grow into it, and the stored-pin,
    /// drawn-seed and pending-kit rules still stand.
    BoundRootIsFingerprint,
}

const ROOT_REQUEST_CONFIRMS: RootRequestProof = RootRequestProof::BoundRootIsFingerprint;

/// What missing or wrong material does to a root request (CALLS
/// ROOT_WORK_MISSING_MATERIAL).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MissingMaterial {
    /// A typed call refusal: the request stays pending, never consumed and
    /// never answered refused.
    Pending,
}

const ROOT_WORK_MISSING_MATERIAL: MissingMaterial = MissingMaterial::Pending;

/// When a root change's commit closes its request (CALLS
/// ROOT_WORK_COMPLETION).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootCompletion {
    /// The exact target change committed (its pin, marks, root record or
    /// restore), with the result in the same transaction. Not that every key
    /// was wrapped again (the target's report lists the rest), nor that every
    /// replica holds it. A pin that awaits its root has not made the change,
    /// and an activation's kit issue has not either.
    ExactTargetCommit,
}

const ROOT_WORK_COMPLETION: RootCompletion = RootCompletion::ExactTargetCommit;

/// The refusal a root request gets when its target computes another revision
/// than the act's `seen` (CALLS ROOT_WORK_REVISION, FIX 4738). Typed apart
/// from a stale settings act: the inequality does not say whether the target
/// has not yet folded a root record or mark the recorder held, or the roots
/// moved since. The refusal stands and nothing is replayed; the owner reviews
/// where the target stands and asks again.
const ROOT_REVISION_REFUSAL: OwnerWorkRefusal = OwnerWorkRefusal::RootRevisionMismatch;

/// The cancel door's refusal for a request this install folds as no root
/// request: nothing is written.
const NO_ROOT_REQUEST: &str = "no root request with this id is recorded here; nothing was written";

/// The install that makes a root change on `target` (CALLS
/// ROOT_WORK_EXECUTOR), or why the recorder can name none: the target is the
/// recorder itself, whose own root door makes the change, or it is no linked
/// install of the vault.
pub(crate) fn root_work_executor(
    fold: &AuthorityFold,
    target: EntityId,
    recorder: EntityId,
) -> std::result::Result<EntityId, OwnerWorkUnassigned> {
    match ROOT_WORK_EXECUTOR {
        RootExecutor::ExactTarget if target == recorder => {
            Err(OwnerWorkUnassigned::TargetIsRecorder)
        }
        RootExecutor::ExactTarget if fold.machine_proof_key(target).is_none() => {
            Err(OwnerWorkUnassigned::TargetNotLinked)
        }
        RootExecutor::ExactTarget => Ok(target),
    }
}

/// What a counted request's change stands as on its target (CALLS
/// ROOT_REQUEST_CONFIRMS): the fingerprint of the root it binds; none for an
/// activation, whose root the target draws.
fn request_confirmation(change: RootChange) -> Option<KitConfirmation> {
    match ROOT_REQUEST_CONFIRMS {
        RootRequestProof::BoundRootIsFingerprint => change.root().map(KitConfirmation::Fingerprint),
    }
}

/// Whether a committed change that left `awaiting` closes its request (CALLS
/// ROOT_WORK_COMPLETION).
fn change_closes(awaiting: Option<RecoveryRootId>) -> bool {
    match ROOT_WORK_COMPLETION {
        RootCompletion::ExactTargetCommit => awaiting.is_none(),
    }
}

/// A missing or wrong material refusal (CALLS ROOT_WORK_MISSING_MATERIAL):
/// typed, and the request stays pending.
fn material_refused(reason: &'static str) -> Error {
    match ROOT_WORK_MISSING_MATERIAL {
        MissingMaterial::Pending => super::refused(reason),
    }
}

/// The secret a root change needs, as the target's caller holds it, for the
/// one call that makes the change. `Debug` is redacted.
#[derive(Clone, Copy)]
pub enum RootSecret<'a> {
    /// The root's seed.
    Seed(&'a RecoveryRootSeed),
    /// The root's kit pieces as the owner saved them: two, or one and the
    /// passphrase.
    Kit {
        pieces: &'a [&'a KitPiece],
        passphrase: Option<&'a KitPassphrase>,
    },
}

impl std::fmt::Debug for RootSecret<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Seed(_) => "RootSecret::Seed(<redacted>)",
            Self::Kit { .. } => "RootSecret::Kit(<redacted>)",
        })
    }
}

/// What the target's caller supplies for a pending root request
/// ([`Vault::run_root_request`]): the material its change needs, borrowed for
/// that call only and never stored. `Debug` is redacted.
#[derive(Clone, Copy)]
pub enum RootMaterial<'a> {
    /// An activation's first step: a kit for a fresh root, over the homes
    /// the owner picked. Its pieces go to this caller only, and the request
    /// stays pending until the kit's confirm.
    IssueKit(&'a KitIssue<'a>),
    /// An activation's second step: the kit's pieces as saved (two, or one
    /// and the passphrase) and the machines the new root carries.
    ConfirmKit {
        pieces: &'a [&'a KitPiece],
        passphrase: Option<&'a KitPassphrase>,
        carry: &'a BTreeSet<EntityId>,
    },
    /// A restore: the bound root's seed or kit.
    Restore(RootSecret<'a>),
    /// An anchoring: the bound root's seed or kit, the machine's enrolment
    /// request, and the code that machine shows when it is not this one.
    Anchor {
        secret: RootSecret<'a>,
        request: &'a MachineEnrolmentRequest,
        code: Option<RequestCode>,
    },
}

impl std::fmt::Debug for RootMaterial<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::IssueKit(_) => "RootMaterial::IssueKit(<redacted>)",
            Self::ConfirmKit { .. } => "RootMaterial::ConfirmKit(<redacted>)",
            Self::Restore(_) => "RootMaterial::Restore(<redacted>)",
            Self::Anchor { .. } => "RootMaterial::Anchor(<redacted>)",
        })
    }
}

/// What the target did with a root request and its caller's material: the
/// report its own root door gives, to this caller only.
#[derive(Debug)]
pub enum RootWorkDone {
    /// Answered refused, for the reason given: the request is closed.
    Refused { reason: OwnerWorkRefusal },
    /// The activation's kit, issued: its pieces for this caller to place.
    /// Nothing is published, the inventory lists the kit pending, and the
    /// request stays pending until the kit's confirm.
    KitIssued(Box<IssuedWorldKit>),
    /// The activation's kit, confirmed: its root is live here and the
    /// request enacted. With `mirror_pending`, the change committed but a
    /// sealed vault's page-seal mirror was not rewritten: the next sealed
    /// open repairs it, and nothing is drawn again.
    KitConfirmed {
        kit: Box<ConfirmedWorldKit>,
        mirror_pending: bool,
    },
    /// The world keys wrapped to the bound root, restored from its seed:
    /// enacted. The keys kept on another machine or withheld are listed.
    Restored(Box<RootRestore>),
    /// The same, from the bound root's kit.
    KitRestored(Box<WorldKitRestore>),
    /// The machine, anchored with the bound root's seed: enacted.
    Anchored(Box<AnchoredMachine>),
}

impl RootWorkDone {
    /// The words a surface shows.
    #[must_use]
    pub fn text(&self) -> &'static str {
        match self {
            Self::Refused { .. } => "refused by the target",
            Self::KitIssued(_) => "kit issued; confirm it on the target to finish",
            Self::KitConfirmed {
                mirror_pending: true,
                ..
            } => "committed; mirror pending",
            Self::KitConfirmed { .. }
            | Self::Restored(_)
            | Self::KitRestored(_)
            | Self::Anchored(_) => "enacted on the target",
        }
    }
}

impl Vault {
    /// Records the owner's root `change` for the install `target`, in one
    /// writer transaction signed by this install as the carrier of his act.
    /// Any surface he is authenticated on may decide it (the console, a phone
    /// or the CLI), and no recovery secret is asked for: the seed or kit is
    /// supplied on the target alone. `surface` is audit only. The act's
    /// `seen` is the roots' and the target's revision as this install folds
    /// them (CALLS ROOT_WORK_REVISION). For a target this install cannot name
    /// (itself, or one that is not linked) nothing is written, and the
    /// receipt says why.
    pub fn request_root_change(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        target: EntityId,
        change: RootChange,
    ) -> Result<OwnerWorkReceipt> {
        self.with_write_txn(|txn| {
            let seen = self
                .authority_view_readonly_in_txn(txn)?
                .root_work_revision(target, change);
            let work = OwnerWorkBody::Root { change };
            self.record_owner_work_in_txn(txn, owner, surface, target, seen, work)
        })
    }

    /// Records the owner's cancel of the root request signed as entry
    /// `request` (CALLS ROOT_WORK_CANCEL), in one writer transaction signed
    /// by this install as the carrier of his act. Any surface he is
    /// authenticated on may decide it; it carries ids only, and `surface` is
    /// audit only. It takes effect on the target whenever the target folds
    /// it, however long it was offline: the target never runs a request its
    /// fold holds cancelled, and signs no result for it. A result the target
    /// signed before it had the cancel stands, and nothing is undone. The
    /// answer is the request's receipt: cancelled, or that earlier answer
    /// with the cancel marked "already enacted" (or "already refused"). A
    /// request this install folds a cancel of already records nothing again;
    /// for a request this install folds as no root request, nothing is
    /// written and the call is refused.
    pub fn cancel_root_request(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        request: AuthorityEntryHash,
    ) -> Result<OwnerWorkReceipt> {
        self.with_write_txn(|txn| {
            let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let fold = self.authority_view_readonly_in_txn(txn)?;
            let target = match fold.owner_work_request(&request) {
                Some(asked) if asked.kind() == OwnerWorkKind::Root => asked.act.target,
                _ => return Err(super::refused(NO_ROOT_REQUEST)),
            };
            if fold.owner_work_cancels(&request).next().is_none() {
                self.record_owner_work_cancel_in_txn(txn, actor, surface, target, request)?;
            }
            let after = self.authority_view_readonly_in_txn(txn)?;
            OwnerWorkReceipt::of(&after, request).ok_or_else(invalid_authority)
        })
    }

    /// The root requests naming this install that count here and have no
    /// result yet, ascending by entry hash, each with its change and receipt:
    /// what the target's surface shows the owner. A request the owner
    /// cancelled, or a newer one on this install superseded, is not listed
    /// (CALLS ROOT_WORK_CANCEL, ROOT_WORK_SUPERSESSION). Ids only. An owner's
    /// read: the proof is revalidated.
    pub fn pending_root_requests(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<Vec<(AuthorityEntryHash, RootChange, OwnerWorkReceipt)>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let Some(me) = crate::identity::read_machine_id_in_txn(self, &txn)? else {
            return Ok(Vec::new());
        };
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        Ok(fold
            .pending_owner_work_for(me)
            .filter_map(|(hash, request)| match request.work {
                OwnerWorkBody::Root { change } => {
                    OwnerWorkReceipt::of(&fold, hash).map(|receipt| (hash, change, receipt))
                }
                _ => None,
            })
            .collect())
    }

    /// The pickup's arm for the root request signed as entry `hash`, naming
    /// this install, in the caller's transaction: rechecked first, then a
    /// pin is made here as the act's owner, and its result closes the
    /// request with it once the pin stands (CALLS ROOT_WORK_COMPLETION). A
    /// pin awaiting its root stays pending, its wait committed as the
    /// request's own (FIX 5582). Every other change stays pending (`None`):
    /// it needs a seed or kit that only this install's caller supplies
    /// ([`Self::run_root_request`]).
    pub(crate) fn root_work_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fold: &AuthorityFold,
        hash: AuthorityEntryHash,
        request: &OwnerWorkRequest,
        change: RootChange,
        secret: &MachineSecret,
    ) -> Result<Option<OwnerWorkOutcome>> {
        if let Some(reason) = self.root_work_refusal(txn, fold, request, change)? {
            return Ok(Some(OwnerWorkOutcome::Refused { reason }));
        }
        match change {
            RootChange::Pin { root } => {
                let owner = request.act.owner;
                let report = self.pin_owner_root_in_txn(txn, owner, secret, root, Some(hash))?;
                Ok(change_closes(report.awaiting).then_some(OwnerWorkOutcome::enacted()))
            }
            RootChange::Activate | RootChange::Restore { .. } | RootChange::Anchor { .. } => {
                Ok(None)
            }
        }
    }

    /// Clears the wait a root request's pickup committed once this install's
    /// fold holds that request cancelled by the owner or superseded by a
    /// newer request on this install (FIX 5582; CALLS ROOT_WORK_CANCEL,
    /// ROOT_WORK_SUPERSESSION). Byte-free: no secret is read, no result is
    /// signed, and nothing the request did is undone. The store gate already
    /// read no wait for it in the snapshot that folded the cancel or the
    /// newer request; this clears what the pin singleton keeps. The pin, the
    /// earlier admitter, the owner's own wait and a wait another request owns
    /// all stay. The pickup runs it first, before it lists any work.
    pub(crate) fn settle_root_request_waits(&self) -> Result<()> {
        {
            let txn = self.store.env.read_txn()?;
            if self.ended_root_request_wait(&txn)?.is_none() {
                return Ok(());
            }
        }
        self.with_write_txn(|txn| {
            if let Some(request) = self.ended_root_request_wait(txn)? {
                end_request_wait_in_txn(&self.store, txn, request)?;
            }
            Ok(())
        })
    }

    /// The root request whose committed wait has ended in `txn`'s snapshot,
    /// if the pin singleton keeps one.
    fn ended_root_request_wait(&self, txn: &heed::RoTxn<'_>) -> Result<Option<AuthorityEntryHash>> {
        let row = read_pin_row_in_txn(&self.store, txn)?;
        if row.awaited_for.is_none() {
            return Ok(None);
        }
        let fold = self.authority_view_readonly_in_txn(txn)?;
        Ok(ended_request_wait(&row, &fold))
    }

    /// The first recheck a root request fails in this transaction: its owner
    /// is no longer a live vault owner, or the roots' and the target's
    /// revision here differs from the act's `seen` (CALLS ROOT_WORK_REVISION,
    /// [`ROOT_REVISION_REFUSAL`]).
    fn root_work_refusal(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        request: &OwnerWorkRequest,
        change: RootChange,
    ) -> Result<Option<OwnerWorkRefusal>> {
        let owner = &request.act.owner;
        Ok(
            if !crate::policy_model::is_live_vault_owner_in_txn(self, txn, owner)? {
                Some(OwnerWorkRefusal::OwnerNotLive)
            } else if fold.root_work_revision(request.act.target, change) != request.act.seen {
                Some(ROOT_REVISION_REFUSAL)
            } else {
                None
            },
        )
    }
}
