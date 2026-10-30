//! FIX 8875 stage 2: the free-time rows a home move carries, split into
//! content-free facts and each actor's content, which L03's carrier seals
//! under that actor's erasable key (`sync::home_handoff::actor_content`).
//!
//! Each family's export partitions its rows: the facts first (ids,
//! revisions, boundaries, settings, outcomes, act witnesses), then every
//! actor-bearing field as a typed piece on its row, grouped by the actor it
//! names. A policy's subject, its setter and its linked machine may make
//! three partitions; a note goes to its author's, not its cycle's subject's.
//! A piece names no actor itself: the partition holding it is that actor's.
//!
//! Adoption rejoins them scrubbed-first (FIX 10764): an actor erased here
//! gives no piece, and a row whose subject's piece is not here is
//! [`FreeTimeAdoptRow::Scrubbed`], non-executable history that never lands
//! and never conflicts. Only a [`FreeTimeAdoptRow::Live`] row reaches the
//! families' set-once, act-witness and equality checks. An attribution or a
//! note whose actor's piece is not here reads as absent, never as another
//! actor.

use std::collections::BTreeMap;

use heed::RoTxn;
use serde::{Deserialize, Serialize};

use super::super::cycle::FreeTimeOwnTimeChoice;
use super::super::policy::{FreeTimePolicy, FreeTimePolicyRecord, FreeTimeSchedule, FreeTimeSplit};
use super::{erased_in_txn, invalid};
use crate::authority::ActSurface;
use crate::sync::home_handoff::{ActorContent, Partitioned};
use crate::{EntityId, Result, Vault};

/// Which of the five free-time sections a row stands in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum FreeTimeSlot {
    Policy,
    Clock,
    Cycle,
    Item,
    Receipt,
}

/// One row of one section, by its place among the section's facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FreeTimeRowRef {
    slot: FreeTimeSlot,
    row: u32,
}

/// One piece of an actor's content, on the row it belongs to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum FreeTimeActorPiece {
    /// The actor is the row's subject agent.
    Subject { row: FreeTimeRowRef },
    /// The owner who set the row's policy.
    PolicySetter { row: FreeTimeRowRef },
    /// The agent whose act within its Grant set the row's policy, and that
    /// Grant.
    PolicyAgent {
        row: FreeTimeRowRef,
        grant: Option<EntityId>,
    },
    /// The linked machine the row's policy was said on.
    PolicyMachine { row: FreeTimeRowRef },
    /// The linked machine the clear the row witnesses was said on.
    ClearMachine { row: FreeTimeRowRef },
    /// The note the actor wrote on the row's cycle: when, and its words.
    Note {
        row: FreeTimeRowRef,
        at: u64,
        text: String,
    },
    /// The subject's own-time choice on the row's cycle.
    Choice {
        row: FreeTimeRowRef,
        choice: FreeTimeOwnTimeChoice,
    },
    /// The subject's landed proposal and context-read code on the row's
    /// receipt.
    ReceiptDetail {
        row: FreeTimeRowRef,
        proposal: Option<EntityId>,
        context_unread: Option<String>,
    },
}

impl FreeTimeActorPiece {
    fn row(&self) -> FreeTimeRowRef {
        match self {
            Self::Subject { row }
            | Self::PolicySetter { row }
            | Self::PolicyAgent { row, .. }
            | Self::PolicyMachine { row }
            | Self::ClearMachine { row }
            | Self::Note { row, .. }
            | Self::Choice { row, .. }
            | Self::ReceiptDetail { row, .. } => *row,
        }
    }
}

/// One actor's content in one section: the carrier seals it under that
/// actor's key.
#[derive(Serialize, Deserialize)]
pub(crate) struct FreeTimeActorPartition {
    actor: EntityId,
    pieces: Vec<FreeTimeActorPiece>,
}

impl ActorContent for FreeTimeActorPartition {
    fn actor(&self) -> EntityId {
        self.actor
    }
}

/// A family's rows as a move carries them: its facts, and each actor's
/// partition.
pub(crate) type FreeTimePartitioned<F> = Partitioned<F, FreeTimeActorPartition>;

/// One carried row as adoption finds it.
pub(crate) enum FreeTimeAdoptRow<Live, F> {
    /// Its subject's content opened here: the row as its old home kept it,
    /// less any attribution whose actor's content did not.
    Live(Live),
    /// Its subject's content did not open here, or its subject is erased
    /// here: non-executable history that lands nothing and conflicts with
    /// nothing.
    Scrubbed(F),
}

/// The pieces one section's partition gathers, by actor.
pub(super) struct Pieces {
    slot: FreeTimeSlot,
    by_actor: BTreeMap<EntityId, Vec<FreeTimeActorPiece>>,
}

impl Pieces {
    pub(super) fn new(slot: FreeTimeSlot) -> Self {
        Self {
            slot,
            by_actor: BTreeMap::new(),
        }
    }

    /// The ref of the section's row `index`.
    pub(super) fn row(&self, index: usize) -> Result<FreeTimeRowRef> {
        let row = u32::try_from(index)
            .map_err(|_| invalid("a section has more rows than a row ref holds"))?;
        Ok(FreeTimeRowRef {
            slot: self.slot,
            row,
        })
    }

    pub(super) fn push(&mut self, actor: EntityId, piece: FreeTimeActorPiece) {
        self.by_actor.entry(actor).or_default().push(piece);
    }

    /// `facts` with every partition gathered.
    pub(super) fn partitioned<F>(self, facts: F) -> FreeTimePartitioned<F> {
        Partitioned {
            facts,
            actors: self
                .by_actor
                .into_iter()
                .map(|(actor, pieces)| FreeTimeActorPartition { actor, pieces })
                .collect(),
        }
    }
}

/// The pieces of one section that opened here, by row: what a rejoin reads.
pub(super) struct Joined {
    by_row: BTreeMap<u32, Vec<(EntityId, FreeTimeActorPiece)>>,
}

impl Joined {
    /// `parts`, the partitions of the section `slot` whose keys opened
    /// here, less every one whose actor is erased here (FIX 10764) and any
    /// piece on another section's row.
    ///
    /// # Errors
    ///
    /// A store read that fails.
    pub(super) fn in_txn(
        vault: &Vault,
        txn: &RoTxn<'_>,
        slot: FreeTimeSlot,
        parts: Vec<FreeTimeActorPartition>,
    ) -> Result<Self> {
        let mut by_row: BTreeMap<u32, Vec<(EntityId, FreeTimeActorPiece)>> = BTreeMap::new();
        for part in parts {
            if erased_in_txn(vault, txn, &part.actor)? {
                continue;
            }
            for piece in part.pieces {
                let row = piece.row();
                if row.slot == slot {
                    by_row.entry(row.row).or_default().push((part.actor, piece));
                }
            }
        }
        Ok(Self { by_row })
    }

    /// The first piece on row `row` that `pick` takes, with its actor.
    pub(super) fn find<T>(
        &self,
        row: u32,
        pick: impl Fn(&FreeTimeActorPiece) -> Option<T>,
    ) -> Option<(EntityId, T)> {
        self.by_row
            .get(&row)?
            .iter()
            .find_map(|(actor, piece)| pick(piece).map(|found| (*actor, found)))
    }

    /// The actor of the first piece on row `row` that `is` names.
    pub(super) fn actor(
        &self,
        row: u32,
        is: impl Fn(&FreeTimeActorPiece) -> bool,
    ) -> Option<EntityId> {
        self.find(row, |piece| is(piece).then_some(()))
            .map(|(actor, ())| actor)
    }

    /// Row `row`'s subject, when its content opened here.
    pub(super) fn subject(&self, row: u32) -> Option<EntityId> {
        self.actor(row, |piece| {
            matches!(piece, FreeTimeActorPiece::Subject { .. })
        })
    }
}

/// How a policy or a clear was said, without the machine it was said on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum SurfaceKind {
    ThisInstall,
    LinkedDevice,
    HostedConsole,
}

/// `surface` as a kind, and the linked machine it names.
fn surface_kind(surface: &ActSurface) -> (SurfaceKind, Option<EntityId>) {
    match surface {
        ActSurface::ThisInstall => (SurfaceKind::ThisInstall, None),
        ActSurface::LinkedDevice { machine } => (SurfaceKind::LinkedDevice, Some(*machine)),
        ActSurface::HostedConsole => (SurfaceKind::HostedConsole, None),
    }
}

/// The surface `kind` names, with `machine` for a linked device: none for a
/// linked device whose machine's piece is not here.
fn surface_of(kind: Option<SurfaceKind>, machine: Option<EntityId>) -> Option<ActSurface> {
    match kind? {
        SurfaceKind::ThisInstall => Some(ActSurface::ThisInstall),
        SurfaceKind::LinkedDevice => machine.map(|machine| ActSurface::LinkedDevice { machine }),
        SurfaceKind::HostedConsole => Some(ActSurface::HostedConsole),
    }
}

/// One agent's policy row without any actor: its settings, revision, times,
/// `prior` and act witnesses, as they were, never hashed again.
#[derive(Serialize, Deserialize)]
pub(super) struct PolicyFacts {
    policy: Option<PolicySettings>,
    acts: Vec<[u8; 32]>,
    clear_surface: Option<SurfaceKind>,
}

/// The policy in force without its agent, its setter or its linked machine.
#[derive(Serialize, Deserialize)]
struct PolicySettings {
    revision: u64,
    total_units: u64,
    schedule: FreeTimeSchedule,
    pinned_split: Option<FreeTimeSplit>,
    cap_shown_at_ms: u64,
    set_at: u64,
    surface: Option<SurfaceKind>,
    prior: [u8; 32],
}

/// `record`'s facts: the scrubbed form, pure and idempotent.
pub(super) fn scrubbed_policy(record: &FreeTimePolicyRecord) -> PolicyFacts {
    PolicyFacts {
        policy: record.policy.as_ref().map(|policy| PolicySettings {
            revision: policy.revision,
            total_units: policy.total_units,
            schedule: policy.schedule.clone(),
            pinned_split: policy.pinned_split,
            cap_shown_at_ms: policy.cap_shown_at_ms,
            set_at: policy.set_at,
            surface: policy
                .surface
                .as_ref()
                .map(|surface| surface_kind(surface).0),
            prior: policy.prior,
        }),
        acts: record.acts.clone(),
        clear_surface: record
            .clear_surface
            .as_ref()
            .map(|surface| surface_kind(surface).0),
    }
}

/// Partitions `agent`'s policy row `record`, row `row` of its section, into
/// `pieces`: its subject, its owner setter, its acting agent with the Grant,
/// and the linked machines it and its clear were said on, each in that
/// actor's partition. Returns its facts.
pub(super) fn partition_policy(
    pieces: &mut Pieces,
    row: FreeTimeRowRef,
    agent: EntityId,
    record: &FreeTimePolicyRecord,
) -> PolicyFacts {
    pieces.push(agent, FreeTimeActorPiece::Subject { row });
    if let Some(policy) = record.policy.as_ref() {
        if let Some(owner) = policy.set_by {
            pieces.push(owner, FreeTimeActorPiece::PolicySetter { row });
        }
        if let Some(acting) = policy.set_by_agent {
            let grant = policy.set_grant;
            pieces.push(acting, FreeTimeActorPiece::PolicyAgent { row, grant });
        }
        if let Some((_, Some(machine))) = policy.surface.as_ref().map(surface_kind) {
            pieces.push(machine, FreeTimeActorPiece::PolicyMachine { row });
        }
    }
    if let Some((_, Some(machine))) = record.clear_surface.as_ref().map(surface_kind) {
        pieces.push(machine, FreeTimeActorPiece::ClearMachine { row });
    }
    scrubbed_policy(record)
}

/// Rejoins the policy row `row` of `facts` with the pieces that opened here:
/// scrubbed with no subject; otherwise the record with each attribution
/// whose actor's piece is here, and none for one whose is not.
pub(super) fn rejoin_policy(
    joined: &Joined,
    row: u32,
    facts: PolicyFacts,
) -> FreeTimeAdoptRow<(EntityId, FreeTimePolicyRecord), PolicyFacts> {
    let Some(agent) = joined.subject(row) else {
        return FreeTimeAdoptRow::Scrubbed(facts);
    };
    let machine = joined.actor(row, |piece| {
        matches!(piece, FreeTimeActorPiece::PolicyMachine { .. })
    });
    let clear_machine = joined.actor(row, |piece| {
        matches!(piece, FreeTimeActorPiece::ClearMachine { .. })
    });
    let setter = joined.actor(row, |piece| {
        matches!(piece, FreeTimeActorPiece::PolicySetter { .. })
    });
    let acting = joined.find(row, |piece| match piece {
        FreeTimeActorPiece::PolicyAgent { grant, .. } => Some(*grant),
        _ => None,
    });
    let policy = facts.policy.map(|settings| FreeTimePolicy {
        agent,
        revision: settings.revision,
        total_units: settings.total_units,
        schedule: settings.schedule,
        pinned_split: settings.pinned_split,
        cap_shown_at_ms: settings.cap_shown_at_ms,
        set_by: setter,
        set_by_agent: acting.map(|(acting, _)| acting),
        set_grant: acting.and_then(|(_, grant)| grant),
        set_at: settings.set_at,
        surface: surface_of(settings.surface, machine),
        prior: settings.prior,
    });
    FreeTimeAdoptRow::Live((
        agent,
        FreeTimePolicyRecord {
            policy,
            acts: facts.acts,
            clear_surface: surface_of(facts.clear_surface, clear_machine),
        },
    ))
}
