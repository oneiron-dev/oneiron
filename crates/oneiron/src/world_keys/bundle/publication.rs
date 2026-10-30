//! Sealed bundle publication on the owner's ask (WILL L04 row 03): he asks on
//! any surface he is authenticated on, an install that holds every key the
//! bundle seals publishes it to the home he named, and every reader checks
//! that request in the bundle's own signed provenance.
//!
//! - The deciding install records an owner work request
//!   ([`Vault::request_bundle_publication`]) whose act targets the home. It
//!   names its executor by one rule ([`bundle_publish_executor`], CALLS
//!   BUNDLE_PUBLISH_EXECUTOR): any role, any substrate. Its `seen` is the
//!   vault-wide world policy revision, for audit only (CALLS
//!   BUNDLE_PUBLISH_REVISION).
//! - The executor's pickup only rechecks ([`Vault::publish_bundle_work_in_txn`])
//!   and leaves it pending: publication is network work, never done in a
//!   writer transaction. The sealed bundle relay after the authority catch-up
//!   publishes it, with the request's entry hash in the bundle's provenance,
//!   and appends the enacted result once the home acknowledged that commit
//!   (`sync::client`'s bundle publication, CALLS BUNDLE_PUBLISH_COMPLETION).
//! - A take, a carry and a kit restore admit a bundle's publisher by one
//!   verifier ([`OpenedVaultBundle::require_publisher`], CALLS
//!   BUNDLE_PUBLISH_PROOF): a machine the owner vouched for, or the executor
//!   of the counted request the provenance names, signing with its own install
//!   key, for the home it was read from. A generic enacted result proves
//!   nothing.
//!
//! No location, origin, substrate or hosted-mode rule reads anything here.
//! What stays is real: the sealed-copy recipient policy, key possession (an
//! executor opens only the keys it holds as an eligible reader), historical
//! carry integrity, and the root alone never publishing.

#[cfg(feature = "sync")]
use super::super::{CapsuleRead, LatestRead};
use super::super::{OwnerWorkReceipt, OwnerWorkUnassigned};
use super::{OpenedVaultBundle, bundle_carries};
use crate::authority::{
    ActSurface, AuthorityEntryHash, AuthorityFold, BUNDLE_PUBLISH_REVISION_CONTEXT, Destination,
    OwnerWorkBody, OwnerWorkOutcome, OwnerWorkRefusal, OwnerWorkRequest, WrapRecipient,
    act_revision,
};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::policy_model::is_live_vault_owner_in_txn;
use crate::{EntityId, Vault};

/// What a publication's `seen` is for (CALLS BUNDLE_PUBLISH_REVISION).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublishRevision {
    /// The vault-wide world policy revision when the owner asked, for audit
    /// only: the executor always seals to the policy current in its own
    /// read, so a policy edit never makes the request stale.
    SealsCurrentPolicy,
}

const BUNDLE_PUBLISH_REVISION: PublishRevision = PublishRevision::SealsCurrentPolicy;

/// Which install publishes (CALLS BUNDLE_PUBLISH_EXECUTOR).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublishExecutor {
    /// The lowest machine id among the vault's linked installs whose proof
    /// key stands here and that hold, as an eligible reader, a counted wrap
    /// of the current key of every world the home's bundle seals, so it can
    /// seal them all. Any role and any substrate; the recorder too, since
    /// publishing never runs in the act's commit. Never the home itself,
    /// which keeps the bundle and relays to no home of its own. Pinned:
    /// only a new owner act names another.
    LowestEligibleHolder,
}

const BUNDLE_PUBLISH_EXECUTOR: PublishExecutor = PublishExecutor::LowestEligibleHolder;

/// What proves a publisher the owner's trust does not (CALLS
/// BUNDLE_PUBLISH_PROOF).
#[cfg(feature = "sync")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublishProof {
    /// The bundle's signed provenance names a counted bundle publication
    /// request whose executor is the publisher and whose home is the one the
    /// bundle was read from, and a key some chain of that executor names
    /// signed it. The fold counts a request only with its carrier admitted
    /// and its owner live at its parents.
    RequestHashAndExecutorKey,
}

#[cfg(feature = "sync")]
const BUNDLE_PUBLISH_PROOF: PublishProof = PublishProof::RequestHashAndExecutorKey;

/// The vault-wide world policy revision on `fold` (CALLS
/// BUNDLE_PUBLISH_REVISION): [`act_revision`] over every world's live edits.
fn bundle_publish_revision(fold: &AuthorityFold) -> [u8; 32] {
    match BUNDLE_PUBLISH_REVISION {
        PublishRevision::SealsCurrentPolicy => act_revision(
            BUNDLE_PUBLISH_REVISION_CONTEXT,
            fold.worlds
                .values()
                .flat_map(|world| world.live.keys().copied()),
        ),
    }
}

/// The install that publishes the vault's bundle to `home` (CALLS
/// BUNDLE_PUBLISH_EXECUTOR), or why none can: the home is no linked install
/// here, or no install but it holds every key its bundle seals.
pub(crate) fn bundle_publish_executor(
    fold: &AuthorityFold,
    home: EntityId,
) -> std::result::Result<EntityId, OwnerWorkUnassigned> {
    if fold.machine_proof_key(home).is_none() {
        return Err(OwnerWorkUnassigned::TargetNotLinked);
    }
    match BUNDLE_PUBLISH_EXECUTOR {
        PublishExecutor::LowestEligibleHolder => fold
            .machines
            .keys()
            .copied()
            .find(|machine| {
                *machine != home
                    && fold.machine_proof_key(*machine).is_some()
                    && holds_every_key(fold, home, *machine)
            })
            .ok_or(OwnerWorkUnassigned::NoBundleHolder),
    }
}

/// Whether `machine` may read, and holds a counted wrap of the current key
/// of, every world a bundle kept by `home` seals: each private world with a
/// key whose sealed copies may rest there. Key possession and the owner's
/// read choice; no role or substrate.
fn holds_every_key(fold: &AuthorityFold, home: EntityId, machine: EntityId) -> bool {
    let reader = Destination::Machine(machine);
    fold.all_world_keys()
        .map(|key| key.id.world)
        .filter(|world| bundle_carries(fold, *world, Destination::Machine(home)))
        .all(|world| {
            fold.world_readable_on(world, reader)
                && fold.current_world_key(world).is_some_and(|current| {
                    current
                        .wraps
                        .get(&WrapRecipient::Machine(machine))
                        .is_some_and(|wraps| !wraps.is_empty())
                })
        })
}

/// Whether the counted request signed as entry `request` asks `machine` to
/// publish to `holder`: a bundle publication naming it as executor, for that
/// home. `None` for a reader that names no home, a kit restore, whose kit is
/// the owner's own root.
pub(super) fn asks(
    fold: &AuthorityFold,
    request: &AuthorityEntryHash,
    machine: EntityId,
    holder: Option<Destination>,
) -> bool {
    fold.counted_owner_work_request(request)
        .is_some_and(|asked| match asked.work {
            OwnerWorkBody::PublishBundle { home } => {
                asked.executor == machine
                    && holder.is_none_or(|holder| holder == Destination::Machine(home))
            }
            OwnerWorkBody::WorldKey { .. }
            | OwnerWorkBody::Root { .. }
            | OwnerWorkBody::Custody { .. }
            | OwnerWorkBody::ExportSecret(_) => false,
        })
}

impl OpenedVaultBundle {
    /// The owner work request its publisher published it for, from the
    /// signed provenance; `None` for the cadence's own upload.
    #[must_use]
    pub fn request(&self) -> Option<AuthorityEntryHash> {
        self.request
    }

    /// The one publisher check a take, a carry and a kit restore after its
    /// authority import share: a machine the owner vouched for signed it
    /// ([`Self::signed_by_owner_machine`]), or the install his counted
    /// request asked to publish to `holder` did (CALLS BUNDLE_PUBLISH_PROOF).
    /// `holder` is the home it was read from; `None` for a kit restore,
    /// which names none. Refused otherwise.
    #[cfg(feature = "sync")]
    pub(crate) fn require_publisher(
        &self,
        fold: &AuthorityFold,
        holder: Option<Destination>,
    ) -> Result<()> {
        if self.signed_by_owner_machine(fold) {
            return Ok(());
        }
        let asked = match BUNDLE_PUBLISH_PROOF {
            PublishProof::RequestHashAndExecutorKey => self.request.is_some_and(|request| {
                asks(fold, &request, self.publisher, holder)
                    && fold.machine(self.publisher).is_some_and(|machine| {
                        machine
                            .roster
                            .iter()
                            .chain(&machine.roster_trusted)
                            .chain(machine.anchored.values())
                            .any(|chain| self.signed_by(&chain.profile.machine_key))
                    })
            }),
        };
        if asked {
            return Ok(());
        }
        Err(super::super::refused(
            "no machine the owner vouched for or asked to publish signed the bundle",
        ))
    }
}

impl Vault {
    /// Records the owner's ask that the vault's sealed bundle be published to
    /// `home`, the linked install that keeps it, in one writer transaction
    /// signed by this install as the carrier of his act. Any surface he is
    /// authenticated on may ask; `surface` is audit only. The request names
    /// the install that publishes (CALLS BUNDLE_PUBLISH_EXECUTOR); with none,
    /// nothing is written and the receipt says why. Its `seen` is the
    /// vault-wide world policy revision here, for audit only (CALLS
    /// BUNDLE_PUBLISH_REVISION). Ids only.
    pub fn request_bundle_publication(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        home: EntityId,
    ) -> Result<OwnerWorkReceipt> {
        self.with_write_txn(|txn| {
            let fold = self.authority_view_readonly_in_txn(txn)?;
            let seen = bundle_publish_revision(&fold);
            let work = OwnerWorkBody::PublishBundle { home };
            self.record_owner_work_in_txn(txn, owner, surface, home, seen, work)
        })
    }

    /// The pickup's arm for a bundle publication naming `executor`, this
    /// install: it rechecks that the act's owner is still a live vault owner,
    /// that `home` is still a linked install, and that this install still
    /// holds every key the bundle seals, and answers refused for the first
    /// that fails. Otherwise it stays pending (`None`): the sealed bundle
    /// relay publishes it, never this transaction.
    pub(crate) fn publish_bundle_work_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        request: &OwnerWorkRequest,
        home: EntityId,
        executor: EntityId,
    ) -> Result<Option<OwnerWorkOutcome>> {
        let reason = if !is_live_vault_owner_in_txn(self, txn, &request.act.owner)? {
            Some(OwnerWorkRefusal::OwnerNotLive)
        } else if fold.machine_proof_key(home).is_none() {
            Some(OwnerWorkRefusal::HomeNotLinked)
        } else if !holds_every_key(fold, home, executor) {
            Some(OwnerWorkRefusal::ExecutorNotReader)
        } else {
            None
        };
        Ok(reason.map(|reason| OwnerWorkOutcome::Refused { reason }))
    }

    /// The bundle publications naming this install that count here and have
    /// no result yet, ascending by entry hash, each with its home.
    #[cfg(feature = "sync")]
    pub(crate) fn pending_bundle_publications(
        &self,
    ) -> Result<Vec<(AuthorityEntryHash, EntityId)>> {
        let txn = self.store.env.read_txn()?;
        let Some(me) = crate::identity::read_machine_id_in_txn(self, &txn)? else {
            return Ok(Vec::new());
        };
        Ok(self
            .authority_view_readonly_in_txn(&txn)?
            .pending_owner_work_for(me)
            .filter_map(|(hash, asked)| match asked.work {
                OwnerWorkBody::PublishBundle { home } => Some((hash, home)),
                OwnerWorkBody::WorldKey { .. }
                | OwnerWorkBody::Root { .. }
                | OwnerWorkBody::Custody { .. }
                | OwnerWorkBody::ExportSecret(_) => None,
            })
            .collect())
    }

    /// What the home's newest generation, `bundle` and `pads` read from
    /// `holder`, is to this install's publication for `request`: whether it
    /// is that publication (it opens here, passes the publisher check, names
    /// that request and this install sealed it), how each of its outer
    /// capsules opened here (FIX 4785), and the worlds whose authority capsule
    /// it files sealed to no root pinned here now (FIX 4496). A bundle that
    /// does not open here is not this install's publication. Reads only.
    #[cfg(feature = "sync")]
    pub(crate) fn read_latest_for_request(
        &self,
        bundle: &super::SealedVaultBundle,
        pads: &super::SealedKeyPads,
        holder: Destination,
        request: AuthorityEntryHash,
    ) -> Result<(bool, LatestRead)> {
        let me = self.machine_secret_outside_txn()?.machine;
        let opened = self.open_vault_bundle(bundle, holder);
        let named = opened
            .as_ref()
            .is_ok_and(|opened| opened.publisher == me && opened.request == Some(request));
        let awaiting_reader = match &opened {
            Ok(opened) => {
                let txn = self.store.env.read_txn()?;
                let pinned = self.authority_view_readonly_in_txn(&txn)?.pinned_root;
                opened.worlds_awaiting_reader(pinned.map(|pin| pin.id))
            }
            Err(_) => Vec::new(),
        };
        let read = LatestRead::Read {
            bundle: CapsuleRead::of(&opened),
            pads: CapsuleRead::of(&self.open_key_pads(pads)),
            awaiting_reader,
        };
        Ok((named, read))
    }

    /// Appends the enacted result of the bundle publication `request`, in a
    /// writer transaction of its own, once it still names this install,
    /// counts, has no result and its owner is still a live vault owner.
    /// Returns whether it appended; otherwise it stays as it stands.
    #[cfg(feature = "sync")]
    pub(crate) fn enact_bundle_publication(&self, request: AuthorityEntryHash) -> Result<bool> {
        self.with_write_txn(|txn| {
            let Some(me) = crate::identity::read_machine_id_in_txn(self, txn)? else {
                return Ok(false);
            };
            let fold = self.authority_view_readonly_in_txn(txn)?;
            let Some(owner) = fold.pending_owner_work_for(me).find_map(|(hash, asked)| {
                (hash == request && matches!(asked.work, OwnerWorkBody::PublishBundle { .. }))
                    .then_some(asked.act.owner)
            }) else {
                return Ok(false);
            };
            if !is_live_vault_owner_in_txn(self, txn, &owner)? {
                return Ok(false);
            }
            self.append_owner_work_result_in_txn(txn, request, me, OwnerWorkOutcome::enacted())?;
            Ok(true)
        })
    }
}
