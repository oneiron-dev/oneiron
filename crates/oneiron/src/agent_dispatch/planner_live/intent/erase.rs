//! A planned intent's erase (Engine 10-22). An intent is erasable when the
//! erased entity is its asker or the AGENT_DEF its plan seats, the target
//! that seats the whole group. Behind the permanent hard-delete marker the
//! intent takes its erased form, a text-free receipt: its row, parent,
//! project, launch and team ids and its recorded times, state `erased` and
//! whose erase it was, and no ask, digest, adapter key, placed stamp, plan,
//! refusal, start, pack or exposure. An erased asker is forgotten with it;
//! the content goes first, so the match is never lost before it.
//!
//! Every write of an intent passes the same fence, so a copy read before an
//! erase, a late settle, freeze, launch, refusal or exposure among them,
//! writes the erased form back, never the text. A launch on an erased
//! target records that outcome and launches nothing. Without the marker an
//! actor's scrub forgets the asker alone, as it always has (FIX 4582): the
//! intent keeps the rest, and one in flight is in doubt (FIX 5097). It keeps
//! the asker's erase selector too, a hash that names no one, so that asker's
//! later hard erase still reaches the intent (FIX 9182). An erase runs here
//! before the attempt payload pass, which takes an asker-erased intent's ask
//! out of the rows it launched (FIX 9181).

use std::collections::BTreeSet;

use crate::Vault;
use crate::agent_dispatch::AgentDispatcher;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{DeletionMarker, EntityStoreRead, TombstoneStoreRead};
use crate::store::Store;
use crate::team::{PlannedIntentView, SpawnErasure};

use super::{INTENTS, IntentName, IntentPhase, LaunchStand, PlannedIntent, PlannedLaunch};

/// The derivation context of an asker's erase selector.
const ASKER_ERASE_KEY_CONTEXT: &str = "oneiron spawn planned intent asker erase v1";

/// The erase selector of the asker `actor` (FIX 9182): a domain-separated
/// hash of its id, which an erase of `actor` recomputes to find the intents
/// it asked after a plain scrub forgot it. It grants nothing.
pub(super) fn asker_erase_key(actor: &EntityId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(ASKER_ERASE_KEY_CONTEXT);
    hasher.update(actor.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Who among an intent's asker and its plan's target an erase reached.
#[derive(Clone, Copy)]
struct Reached {
    asker: bool,
    target: bool,
}

impl PlannedIntent {
    /// The AGENT_DEF its plan seats, which seats the whole group; `None`
    /// before it planned, and once erased.
    fn target(&self) -> Option<EntityId> {
        self.plan.as_ref().map(|plan| plan.plan.agent_def)
    }

    /// Leaves this intent in its erased form: an erased asker is forgotten,
    /// the first erase's cause stays, and every id and recorded time stays.
    /// Erasing an erased intent again changes only whom it names.
    fn erase(&mut self, reached: Reached) {
        if reached.asker {
            self.actor = None;
            self.asker_erase_key = None;
        }
        let cause = if reached.target {
            SpawnErasure::TargetErased
        } else {
            SpawnErasure::AskerErased
        };
        self.erasure = Some(self.erasure.unwrap_or(cause));
        self.phase = IntentPhase::Erased;
        self.ask = None;
        self.ask_digest = None;
        self.placement_key = None;
        self.placed = None;
        self.plan = None;
        self.refusal = None;
        self.pattern_launch = None;
        self.pattern_pack = None;
        self.leader_exposures.clear();
    }
}

impl AgentDispatcher<'_> {
    /// An actor's scrub of the planned intents (FIX 4582, Engine 10-22).
    /// Behind its permanent hard-delete marker it is an erase, as an asker
    /// or a target: [`Self::erase_planned_intent_content_in_txn`]. Without
    /// the marker, each intent it asked keeps its key, ask, custody, plan or
    /// refusal, frozen start and pack, launch and leader exposures and its
    /// asker's erase selector, and names no asker: its asker can no longer
    /// replay, settle or launch it, and a launched team's leader still runs
    /// with what its launch froze.
    /// One still in flight moves to in doubt (FIX 5097): its custody can no
    /// longer settle it. One-way, in the scrub's own transaction. An id
    /// whose entity is no actor scans nothing.
    ///
    /// # Errors
    ///
    /// Storage errors, or an intent row that cannot be read.
    pub(crate) fn erase_planned_intent_actor_in_txn(
        vault: &Vault,
        wtxn: &mut heed::RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        if crate::typed_body::names_no_actor(vault, wtxn, actor)? {
            return Ok(());
        }
        if hard_marked_in_txn(&vault.store, wtxn, actor)? {
            let erased = BTreeSet::from([*actor]);
            return Self::erase_planned_intent_content_in_txn(&vault.store, wtxn, &erased);
        }
        let mut named = Vec::new();
        for row in INTENTS.iter_from(&vault.store, wtxn, &[])? {
            let (key, mut intent) = row?;
            if intent.actor == Some(*actor) {
                intent.actor = None;
                if intent.phase == IntentPhase::InFlight {
                    intent.phase = IntentPhase::InDoubt;
                }
                named.push((key, intent));
            }
        }
        for (key, intent) in named {
            INTENTS.put(&vault.store, wtxn, &key, &intent)?;
        }
        Ok(())
    }

    /// An erase of `erased` from the planned intents (Engine 10-22): each
    /// intent one of them asked, or whose plan seats one as its target,
    /// takes its erased form in every phase, and an erased asker is
    /// forgotten. An asker a plain scrub forgot is found by its erase
    /// selector (FIX 9182). One pass over the intents, in the erase's own
    /// transaction.
    /// An id stored as anything but a person, a machine or an AGENT_DEF
    /// asks and seats nothing, and is passed over.
    ///
    /// # Errors
    ///
    /// Storage errors, or an intent row that cannot be read.
    pub(crate) fn erase_planned_intent_content_in_txn(
        store: &Store,
        wtxn: &mut heed::RwTxn<'_>,
        erased: &BTreeSet<EntityId>,
    ) -> Result<()> {
        let mut ids = BTreeSet::new();
        let mut selectors = BTreeSet::new();
        for id in erased {
            if !names_no_actor(store, wtxn, id)? {
                ids.insert(*id);
                selectors.insert(asker_erase_key(id));
            }
        }
        if ids.is_empty() {
            return Ok(());
        }
        let mut rows = Vec::new();
        for row in INTENTS.iter_from(store, wtxn, &[])? {
            let (key, mut intent) = row?;
            let reached = Reached {
                asker: intent.actor.is_some_and(|actor| ids.contains(&actor))
                    || intent
                        .asker_erase_key
                        .is_some_and(|selector| selectors.contains(&selector)),
                target: intent.target().is_some_and(|target| ids.contains(&target)),
            };
            if reached.asker || reached.target {
                intent.erase(reached);
                rows.push((key, intent));
            }
        }
        for (key, intent) in rows {
            INTENTS.put(store, wtxn, &key, &intent)?;
        }
        Ok(())
    }

    /// The keys of the planned intents an asker's erase took, as the 64 hex
    /// their launches' dedupe keys carry (FIX 9181), read in `txn`: each row
    /// one of them launched holds its asker's ask in its plan and briefing.
    ///
    /// # Errors
    ///
    /// Storage errors, or an intent row that cannot be read.
    pub(crate) fn asker_erased_intent_keys_in(
        store: &Store,
        txn: &heed::RoTxn<'_>,
    ) -> Result<BTreeSet<String>> {
        let mut keys = BTreeSet::new();
        for row in INTENTS.iter_from(store, txn, &[])? {
            let (key, intent) = row?;
            if intent.erasure == Some(SpawnErasure::AskerErased) {
                keys.insert(crate::entity_id::bytes_to_hex_lower(&key));
            }
        }
        Ok(keys)
    }

    /// Whether an asker's erase took the planned intent whose key is
    /// `intent_key`, as the 64 hex a launch's dedupe key carries, read in
    /// `txn` (FIX 9181). A key that names no intent is none.
    ///
    /// # Errors
    ///
    /// Storage errors, or an intent row that cannot be read.
    pub(crate) fn intent_asker_erased_in(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        intent_key: &str,
    ) -> Result<bool> {
        let Some(key) = crate::task_verb::decode_hex::<32>(intent_key) else {
            return Ok(false);
        };
        Ok(INTENTS
            .get(store, txn, &key)?
            .is_some_and(|intent| intent.erasure == Some(SpawnErasure::AskerErased)))
    }

    /// Whether an erase took the target `planned`'s plan seats: its
    /// permanent hard-delete marker, read on `txn` as the fence reads it.
    pub(in super::super) fn target_erased_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        planned: &PlannedLaunch,
    ) -> bool {
        marked_in_txn(&self.vault.store, txn, planned.row.target())
    }

    /// Records, in one writer, that an erase took the target the plan of
    /// the intent `name` names seats: the intent takes its erased form, with
    /// the typed `target_erased` outcome, and nothing launches. One another
    /// call settled meanwhile answers what it kept.
    ///
    /// # Errors
    ///
    /// As [`Self::planned_launch_in_txn`]; storage errors.
    pub(in super::super) fn record_target_erased(
        &self,
        name: &IntentName<'_>,
        at: u64,
    ) -> Result<PlannedIntentView> {
        let wtxn = self.vault.store.env.write_txn()?;
        match self.planned_launch_in_txn(&wtxn, name)? {
            LaunchStand::Planned(planned) => self.record_target_erased_in_txn(wtxn, *planned, at),
            LaunchStand::Settled(view) => Ok(*view),
        }
    }

    /// [`Self::record_target_erased`] in the launch's own writer, which it
    /// commits, with nothing queued.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(in super::super) fn record_target_erased_in_txn(
        &self,
        mut wtxn: heed::RwTxn<'_>,
        planned: PlannedLaunch,
        at: u64,
    ) -> Result<PlannedIntentView> {
        let PlannedLaunch {
            key,
            mut row,
            intent_key,
        } = planned;
        row.erase(Reached {
            asker: false,
            target: true,
        });
        row.updated_at = at;
        put_intent_in_txn(&self.vault.store, &mut wtxn, &key, &mut row)?;
        wtxn.commit()?;
        row.view(&intent_key)
    }
}

/// Writes `row` at `key` on `wtxn` through the erase's fence: when the
/// permanent hard-delete marker stands for its asker or its plan's target,
/// `row` takes its erased form first, so a copy read before an erase writes
/// the erased form back. An erased row stays erased. A marker that cannot be
/// read leaves `row` as it is: the fence never fails the write it stands in.
///
/// # Errors
///
/// Storage errors from the write.
pub(super) fn put_intent_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    row: &mut PlannedIntent,
) -> Result<()> {
    let reached = Reached {
        asker: marked_in_txn(store, wtxn, row.actor),
        target: marked_in_txn(store, wtxn, row.target()),
    };
    if reached.asker || reached.target || row.phase == IntentPhase::Erased {
        row.erase(reached);
    }
    INTENTS.put(store, wtxn, key, row)
}

/// Whether the permanent hard-delete marker stands for `id`, read on `txn`.
fn hard_marked_in_txn(store: &Store, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    store.port_deletion_marked(txn, DeletionMarker::HardDelete, id)
}

/// [`hard_marked_in_txn`] for the fence: `false` for no id, and a marker
/// that cannot be read is logged without content and reads as none.
fn marked_in_txn(store: &Store, txn: &heed::RoTxn<'_>, id: Option<EntityId>) -> bool {
    let Some(id) = id else {
        return false;
    };
    hard_marked_in_txn(store, txn, &id).unwrap_or_else(|_| {
        tracing::warn!("planned intent fence: a hard-delete marker could not be read");
        false
    })
}

/// Whether `id` is a stored row of a type no actor has: no person, machine
/// or AGENT_DEF. A missing row may have been one.
fn names_no_actor(store: &Store, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    Ok(store
        .port_entity_raw(txn, id)?
        .as_deref()
        .and_then(crate::batch::EntityMetadataHeader::parse)
        .is_some_and(|header| {
            !matches!(
                header.entity_type,
                crate::registry::ENTITY_TYPE_PERSON
                    | crate::registry::ENTITY_TYPE_MACHINE
                    | crate::registry::ENTITY_TYPE_AGENT_DEF
            )
        }))
}
