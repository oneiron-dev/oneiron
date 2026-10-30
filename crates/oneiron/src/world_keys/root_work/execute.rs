//! The target's door for a root request and the material its change needs
//! ([`Vault::run_root_request`]): the root's seed or kit, an enrolment and
//! its code, or the kit an activation issues, supplied on the target alone
//! and held only for this call.
//!
//! The door finds the counted request still pending here and checks the
//! material against its change. Then one writer transaction rechecks the
//! request (a stale one is answered refused, and returned; one whose basis
//! this install has not folded yet signs nothing and stays pending, FIX
//! 5551), makes the change through its root door's own transaction body and
//! appends the enacted result beside it. No writer nests in another, and
//! every check the root door makes before its transaction runs here too.
//!
//! The target decides at execution (FIX 4739): a request its fold holds
//! cancelled by the owner, or superseded by a newer request on this install,
//! is pending no longer, at the door's first read or at the recheck. It
//! never runs, the call is refused with which of the two it is, and nothing
//! is written: no result is signed for it, and its receipt, derived from the
//! fold, says the same (CALLS ROOT_WORK_CANCEL, ROOT_WORK_SUPERSESSION).

use std::collections::BTreeSet;

use super::super::kit::KitSeed;
use super::super::{ConfirmedWorldKit, RecoveryRootSeed, WorldKitRestore, refused};
use super::{
    RootMaterial, RootRecheck, RootSecret, RootWorkDone, material_refused, request_confirmation,
};
use crate::authority::{
    AuthorityEntryHash, AuthorityFold, MachineEnrolmentRequest, OwnerWorkBody, OwnerWorkOutcome,
    OwnerWorkRefusal, OwnerWorkRequest, RecoveryRootId, RequestCode, RootChange,
};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::recovery::{KitId, KitIssue, KitPassphrase, KitPiece};
use crate::{EntityId, Vault};

/// One pending root request this install answers, as the door read it.
#[derive(Debug, Clone, Copy)]
struct Asked {
    me: EntityId,
    hash: AuthorityEntryHash,
    change: RootChange,
    /// The vault the request's roots and enrolments are bound to.
    vault_id: [u8; 32],
}

/// What one writer transaction for a root request did.
enum Answered<T> {
    /// The change committed.
    Done(T),
    /// The recheck refused it; the refused result committed.
    Refused(OwnerWorkRefusal),
    /// This install has not folded every root or mark the owner saw: the
    /// change never ran, no result was signed, and the request stays
    /// pending (CALLS ROOT_WORK_BASIS).
    AwaitsBasis,
}

impl<T> Answered<T> {
    /// The change, or the report for anything but a committed change.
    fn done(self) -> std::result::Result<T, RootWorkDone> {
        match self {
            Self::Done(done) => Ok(done),
            Self::Refused(reason) => Err(RootWorkDone::Refused { reason }),
            Self::AwaitsBasis => Err(RootWorkDone::AwaitingBasis),
        }
    }
}

/// Whether the change's commit answers its request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// The change is the request's: its enacted result commits with it.
    Enacted,
    /// A step on the way, an activation's kit issue: no result yet.
    Pending,
}

/// The seed the caller supplied, or the one its kit's pieces rebuilt here.
enum HeldSeed<'a> {
    Supplied(&'a RecoveryRootSeed),
    Rebuilt(Box<KitSeed>),
}

impl HeldSeed<'_> {
    fn seed(&self) -> &RecoveryRootSeed {
        match self {
            Self::Supplied(seed) => seed,
            Self::Rebuilt(kit) => &kit.seed,
        }
    }
}

/// An anchoring's enrolment as the caller supplied it, with the root and
/// machine the request's change binds.
struct Enrolment<'a> {
    root: RecoveryRootId,
    machine: EntityId,
    request: &'a MachineEnrolmentRequest,
    code: Option<RequestCode>,
}

/// No pending root request with this id names this install: a call refusal,
/// and nothing is written.
fn no_request() -> Error {
    refused("no pending root request with this id names this install")
}

/// Why the root request signed as entry `hash` is not pending on `me`: the
/// owner cancelled it, or a newer request on this install superseded it,
/// before it ran here, and it never runs (CALLS ROOT_WORK_CANCEL,
/// ROOT_WORK_SUPERSESSION); else [`no_request`]. A call refusal, and nothing
/// is written.
fn not_pending(fold: &AuthorityFold, me: EntityId, hash: AuthorityEntryHash) -> Error {
    let mine = fold
        .owner_work_request(&hash)
        .is_some_and(|request| request.executor == me);
    if mine && fold.root_request_cancelled(&hash) {
        refused(
            "the owner cancelled this root request before it ran here; it never runs, and \
             nothing was written",
        )
    } else if mine && fold.root_request_superseded(&hash) {
        refused(
            "a newer root request on this install superseded this one before it ran here; it \
             never runs, and nothing was written",
        )
    } else {
        no_request()
    }
}

/// The counted root request signed as entry `hash` that names `me` and has
/// no result yet, with its change.
fn pending_root(
    fold: &AuthorityFold,
    me: EntityId,
    hash: AuthorityEntryHash,
) -> Option<(OwnerWorkRequest, RootChange)> {
    fold.pending_owner_work_for(me)
        .find_map(|(pending, request)| match request.work {
            OwnerWorkBody::Root { change, .. } if pending == hash => {
                Some((request.clone(), change))
            }
            _ => None,
        })
}

/// The supplied seed grows into the root the request binds: a seed of
/// another root is the wrong material.
fn bound_seed(seed: &RecoveryRootSeed, asked: Asked, root: RecoveryRootId) -> Result<()> {
    if seed.public(&asked.vault_id)?.id != root {
        return Err(material_refused(
            "the seed is not of the root the request names",
        ));
    }
    Ok(())
}

impl Vault {
    /// Runs the root request signed as entry `request`, pending on this
    /// install, with the `material` the owner supplied here, from any surface
    /// that reaches this install and authenticates him (`owner`, revalidated
    /// as a live vault owner). The material is checked against the request's
    /// change; missing or wrong material is a typed refusal, and the request
    /// stays pending (CALLS ROOT_WORK_MISSING_MATERIAL). Then one writer
    /// transaction rechecks the request (a stale one, or one whose owner is
    /// gone, is answered refused and returned), makes the change through its
    /// root door's own body, and appends the enacted result with it. A bound
    /// root stands as the owner's fingerprint of it (CALLS
    /// ROOT_REQUEST_CONFIRMS). The report goes to this caller only.
    ///
    /// An activation takes two calls: [`RootMaterial::IssueKit`] issues its
    /// kit and returns the pieces, the request still pending, and
    /// [`RootMaterial::ConfirmKit`] confirms the kit, activates its root and
    /// closes the request. A pin request takes no material: the pickup makes
    /// it.
    pub fn run_root_request(
        &self,
        owner: &AuthenticatedOwner,
        request: AuthorityEntryHash,
        material: RootMaterial<'_>,
    ) -> Result<RootWorkDone> {
        let asked = self.pending_root_request(owner, request)?;
        match (asked.change, material) {
            (RootChange::Activate, RootMaterial::IssueKit(issue)) => {
                self.run_kit_issue(owner, asked, issue)
            }
            (
                RootChange::Activate,
                RootMaterial::ConfirmKit {
                    pieces,
                    passphrase,
                    carry,
                },
            ) => self.run_kit_confirm(owner, asked, pieces, passphrase, carry),
            (RootChange::Restore { root }, RootMaterial::Restore(secret)) => {
                self.run_restore(owner, asked, root, secret)
            }
            (
                RootChange::Anchor { root, machine },
                RootMaterial::Anchor {
                    secret,
                    request,
                    code,
                },
            ) => {
                let enrolment = Enrolment {
                    root,
                    machine,
                    request,
                    code,
                };
                self.run_anchor(owner, asked, &enrolment, secret)
            }
            (RootChange::Pin { .. }, _) => Err(material_refused(
                "a pin request takes no material: this install's pickup makes it",
            )),
            _ => Err(material_refused(
                "this is not the material the root request's change needs",
            )),
        }
    }

    /// The request signed as entry `hash`, pending on this install, read in
    /// one snapshot with the owner's revalidation.
    fn pending_root_request(
        &self,
        owner: &AuthenticatedOwner,
        hash: AuthorityEntryHash,
    ) -> Result<Asked> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let me = crate::identity::read_machine_id_in_txn(self, &txn)?.ok_or_else(no_request)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let vault_id = fold.vault_id.ok_or_else(no_request)?;
        let (_, change) =
            pending_root(&fold, me, hash).ok_or_else(|| not_pending(&fold, me, hash))?;
        Ok(Asked {
            me,
            hash,
            change,
            vault_id,
        })
    }

    /// One writer transaction for `asked`: its recheck, then `effect` and,
    /// for [`Answer::Enacted`], the enacted result beside it. A request that
    /// fails the recheck is answered refused in this commit and `effect`
    /// never runs: [`Answered::Refused`]. One whose basis this install has
    /// not folded yet (FIX 5551) signs nothing, `effect` never runs, and it
    /// stays pending: [`Answered::AwaitsBasis`]. One this fold holds
    /// cancelled or superseded is pending no longer: `effect` never runs, no
    /// result is signed, and the call is refused ([`not_pending`]).
    fn answer_root_request<T>(
        &self,
        asked: Asked,
        answer: Answer,
        effect: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<T>,
    ) -> Result<Answered<T>> {
        self.with_write_txn(|txn| {
            let fold = self.authority_view_readonly_in_txn(txn)?;
            let (request, _) = pending_root(&fold, asked.me, asked.hash)
                .ok_or_else(|| not_pending(&fold, asked.me, asked.hash))?;
            match self.root_work_recheck(txn, &fold, &request)? {
                RootRecheck::Runs => {}
                RootRecheck::Refused(reason) => {
                    let outcome = OwnerWorkOutcome::Refused { reason };
                    self.append_owner_work_result_in_txn(txn, asked.hash, asked.me, outcome)?;
                    return Ok(Answered::Refused(reason));
                }
                RootRecheck::AwaitsBasis => return Ok(Answered::AwaitsBasis),
            }
            let done = effect(txn)?;
            if answer == Answer::Enacted {
                let outcome = OwnerWorkOutcome::enacted();
                self.append_owner_work_result_in_txn(txn, asked.hash, asked.me, outcome)?;
            }
            Ok(Answered::Done(done))
        })
    }

    /// An activation's first step: a kit for a fresh root, drawn before the
    /// transaction, and its pending row listed in it, naming the request
    /// (FIX 5585). The pieces go to this caller only, and the request stays
    /// pending. A kit whose row did not commit keeps no piece pending here
    /// (FIX 12046).
    fn run_kit_issue(
        &self,
        owner: &AuthenticatedOwner,
        asked: Asked,
        issue: &KitIssue<'_>,
    ) -> Result<RootWorkDone> {
        let kit = self.draw_world_kit(owner, issue)?;
        let listed = self.answer_root_request(asked, Answer::Pending, |txn| {
            self.list_issued_kit_in_txn(txn, owner, &kit, Some(asked.hash))
        });
        let report = match listed.map(Answered::done) {
            Ok(Ok(())) => return Ok(RootWorkDone::KitIssued(Box::new(kit))),
            Ok(Err(report)) => Ok(report),
            Err(error) => Err(error),
        };
        self.drop_unlisted_kit_piece(&kit.manifest);
        report
    }

    /// An activation's second step: the pieces rebuild a pending kit's
    /// root, which goes live here with `carry` and every refusal of the
    /// activation; the kit's rows, its escrow wrap and the enacted result
    /// commit together. A sealed vault's page-seal mirror is rewritten after
    /// the commit: a failure there reports the change committed and the
    /// mirror pending, and draws nothing again.
    fn run_kit_confirm(
        &self,
        owner: &AuthenticatedOwner,
        asked: Asked,
        pieces: &[&KitPiece],
        passphrase: Option<&KitPassphrase>,
        carry: &BTreeSet<EntityId>,
    ) -> Result<RootWorkDone> {
        let (row, prepared) = self.draw_kit_confirm(owner, pieces, passphrase)?;
        let (secret, request) = self.activation_prep(owner, &prepared, carry)?;
        let transition = self.begin_wrap_transition()?;
        let confirmed = self.answer_root_request(asked, Answer::Enacted, |txn| {
            let activated =
                self.activate_owner_root_in_txn(txn, owner, &secret, &request, &prepared, carry)?;
            let (replaced, escrow) = self.confirm_kit_rows_in_txn(txn, &transition, &row)?;
            Ok(ConfirmedWorldKit {
                kit: row.kit,
                activated,
                replaced,
                escrow,
            })
        })?;
        // A kit the answer made current: its piece leaves its pending key
        // slots, and the kits it replaced keep none pending (FIX 11977, 12046).
        let replaced: &[KitId] = match &confirmed {
            Answered::Done(kit) => kit.replaced.as_slice(),
            Answered::Refused(_) | Answered::AwaitsBasis => &[],
        };
        self.settle_pending_kit_pieces(replaced);
        let mirror_pending = match transition.finish() {
            Ok(()) => false,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a root request's kit confirm committed; its page-seal mirror is pending"
                );
                true
            }
        };
        Ok(match confirmed.done() {
            Ok(kit) => RootWorkDone::KitConfirmed {
                kit: Box::new(kit),
                mirror_pending,
            },
            Err(report) => report,
        })
    }

    /// A restore: the bound root's seed, supplied or rebuilt from its kit
    /// here, opens the world keys wrapped to it, through the seed gate with
    /// the request's fingerprint. The keys this machine may read join the
    /// session once the change commits.
    fn run_restore(
        &self,
        owner: &AuthenticatedOwner,
        asked: Asked,
        root: RecoveryRootId,
        secret: RootSecret<'_>,
    ) -> Result<RootWorkDone> {
        let held = self.held_seed(secret)?;
        let seed = held.seed();
        bound_seed(seed, asked, root)?;
        let confirm = request_confirmation(asked.change);
        let (machine, request) = self.seed_door_prep(owner, seed, confirm)?;
        let restored = self.answer_root_request(asked, Answer::Enacted, |txn| {
            self.restore_world_keys_in_txn(txn, owner, &machine, &request, seed, confirm)
        })?;
        let (keys, usable) = match restored.done() {
            Ok(done) => done,
            Err(report) => return Ok(report),
        };
        for key in usable {
            self.ring_world_key(key);
        }
        Ok(match held {
            HeldSeed::Supplied(_) => RootWorkDone::Restored(Box::new(keys)),
            HeldSeed::Rebuilt(kit) => RootWorkDone::KitRestored(Box::new(WorldKitRestore {
                kit: kit.kit,
                root,
                keys,
                reissue_advised: kit.reissue_advised,
            })),
        })
    }

    /// An anchoring: the bound root's seed marks the request's machine. This
    /// install's own request pins the seed's root, through the seed gate with
    /// the request's fingerprint; another machine's needs the code it shows
    /// and the root pinned here already.
    fn run_anchor(
        &self,
        owner: &AuthenticatedOwner,
        asked: Asked,
        enrolment: &Enrolment<'_>,
        secret: RootSecret<'_>,
    ) -> Result<RootWorkDone> {
        let held = self.held_seed(secret)?;
        let seed = held.seed();
        bound_seed(seed, asked, enrolment.root)?;
        let request = enrolment.request;
        if request.machine != enrolment.machine || request.vault_id != asked.vault_id {
            return Err(material_refused(
                "the enrolment request is not of the machine the request names",
            ));
        }
        let anchored = if self.is_own_enrolment(request)? {
            let confirm = request_confirmation(asked.change);
            let machine = self.own_anchor_prep(owner, seed, request, confirm)?;
            self.answer_root_request(asked, Answer::Enacted, |txn| {
                self.anchor_own_machine_in_txn(txn, owner, &machine, seed, request, confirm)
            })?
        } else if enrolment.code == Some(request.code()) {
            self.answer_root_request(asked, Answer::Enacted, |txn| {
                self.anchor_other_machine_in_txn(txn, owner, seed, request)
            })?
        } else {
            return Err(material_refused(
                "the request code is not the one the new machine shows",
            ));
        };
        Ok(match anchored.done() {
            Ok(machine) => RootWorkDone::Anchored(Box::new(machine)),
            Err(report) => report,
        })
    }

    /// The seed `secret` names: the caller's own, or the one its kit's
    /// pieces rebuild here, with this machine's own piece of the kit when it
    /// keeps one (FIX 2063).
    fn held_seed<'a>(&self, secret: RootSecret<'a>) -> Result<HeldSeed<'a>> {
        Ok(match secret {
            RootSecret::Seed(seed) => HeldSeed::Supplied(seed),
            RootSecret::Kit { pieces, passphrase } => {
                HeldSeed::Rebuilt(Box::new(self.kit_seed_here(pieces, passphrase)?))
            }
        })
    }
}
