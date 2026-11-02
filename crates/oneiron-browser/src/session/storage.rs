//! The session's per-origin storage snapshots (FIX 6680, BROWSER-SPLIT
//! PR3b): what an engine switch carries of the top-level origins its tab
//! visited before the current one. Neither engine reads a departed origin's
//! storage, so the session keeps each origin's local and session store as a
//! read last found them while a document of it stood: right before an act's
//! input (riding the change check's mark), once an act's page settled,
//! before a person's input and when they hand the browser back, and, on
//! Chromium, as the document is left (`exit`). Each kept store names its
//! phase and the last receipt the session had landed by then.
//!
//! The snapshots live on the session, outside its engine group, so they
//! survive a switch: the carried tab's become the target tab's at commit,
//! as its origin history does, and only the pipe of the engine the session
//! runs keeps reads. A closed tab's go once another tab is in front, since
//! a switch reads only the tab in front (FIX 6891). They are page-controlled
//! input, bounded by [`switch_state_limits`] and charged, before they grow,
//! to a charge of their own on the host's retained line, apart from every
//! driver's live-handle charge and the switch's own. An origin past a bound
//! is not kept: a value-free loss names it, the oldest read given up first,
//! and past the bound on losses a count stands for the rest. A read that
//! failed keeps what an earlier one found. Values stay here and in a
//! switch's import: never logged, never in a record.

use super::BrowserSession;
use crate::cdp::Visits;
use crate::driver::CdpDriver;
use crate::driver::state::{Store, StoreRead};
use crate::retention::HandleRetention;
use crate::{SnapshotBounds, StoragePhase, SwitchComponent, SwitchLoss, SwitchNotCarried};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// What the session's snapshots hold of a page at most
/// (`switch_state_limits`, CALLS row, open). A page's storage is
/// page-controlled input: a snapshot past a bound is not carried, and the
/// record says so, never cut short and called whole. A switch's own read of
/// its cookies and its current origin's stores takes them whole (FIX 8008).
/// `read_chars`, `snapshot_origins` and `snapshot_bytes` are defaults a
/// call's `SnapshotBounds` stands in for (FIX 10335).
pub(crate) struct SwitchStateLimits {
    /// Items one store holds.
    pub(crate) items: usize,
    /// UTF-16 code units of one store's keys and values: at six bytes each
    /// as JSON at worst, one store's read stays inside the host's 32 MiB
    /// bound on one CDP message.
    pub(crate) store_chars: usize,
    /// Top-level origins one tab's history keeps; older ones are counted.
    pub(crate) origins: usize,
    /// UTF-16 code units of both stores of one origin that one read after
    /// an act, at hand-back or as a Chromium document is left carries: at
    /// seven bytes each at worst, an exit read's payload, escaped twice,
    /// stays inside the 32 MiB bound on one CDP message with room to spare.
    pub(crate) read_chars: usize,
    /// The same for a read right before an input: inside the change
    /// check's window, or before a person's input reaches the page.
    pub(crate) input_chars: usize,
    /// Origins one tab's snapshots keep.
    pub(crate) snapshot_origins: usize,
    /// Bytes all the session's snapshots hold: keys, values, origin names
    /// and their bookkeeping.
    pub(crate) snapshot_bytes: usize,
    /// Losses one tab's snapshots name each with its origin; past them,
    /// one count.
    pub(crate) losses: usize,
}

/// See [`SwitchStateLimits`]: the five million characters Chromium grants
/// one origin's store less room for its JSON, and snapshots of as many
/// origins as a long run's tab visits, held to 64 MiB.
pub(crate) const fn switch_state_limits() -> SwitchStateLimits {
    SwitchStateLimits {
        items: 10_000,
        store_chars: 4 << 20,
        origins: 256,
        read_chars: 4 << 20,
        input_chars: 1 << 20,
        snapshot_origins: 64,
        snapshot_bytes: 64 << 20,
        losses: 256,
    }
}

/// What a kept item, origin and loss cost the charge beside their text.
const ITEM_BYTES: usize = 2 * std::mem::size_of::<String>();
const ORIGIN_BYTES: usize = 256;
const LOSS_BYTES: usize = 128;

/// One store as one read of a page found it.
pub(crate) enum StoreSample {
    /// Its items, key and value, and their UTF-16 code units.
    Items {
        pairs: Vec<(String, String)>,
        chars: u64,
    },
    /// Past the read's bounds, holding `count` items.
    Over { count: u64 },
    /// The page did not answer.
    Lost,
    /// The page threw reading it.
    Threw,
}

/// One read of an origin's two stores, local then session.
pub(crate) struct Sample {
    pub(crate) origin: String,
    /// Read off a Lightpanda document that relaxed `document.domain`: the
    /// bucket of its effective domain.
    pub(crate) relaxed: bool,
    pub(crate) stores: [StoreSample; 2],
}

/// One store's items as a read kept them, and when.
#[derive(Clone)]
pub(crate) struct Items {
    pub(crate) pairs: Vec<(String, String)>,
    /// Their UTF-16 code units.
    pub(crate) chars: u64,
    pub(crate) phase: StoragePhase,
    /// The last receipt the session had landed when they were read.
    pub(crate) after: u64,
    pub(crate) relaxed: bool,
}

/// One store of a snapshot: its items, or why no read kept any.
enum Kept {
    Items(Items),
    Lost {
        reason: SwitchLoss,
        count: Option<u64>,
        phase: StoragePhase,
        after: u64,
    },
}

/// One origin's two stores, as kept.
struct Snapshot {
    stores: [Kept; 2],
    /// The phase and receipt of the last read that answered.
    phase: StoragePhase,
    after: u64,
    /// Read order: the oldest is given up first.
    order: u64,
    /// Carried in by a switch, and read by no engine since: its stores
    /// are the target's own, exactly, until a document of it stands again.
    imported: bool,
    bytes: usize,
}

/// One tab's snapshots and the losses they name.
#[derive(Default)]
struct Tab {
    origins: HashMap<String, Snapshot>,
    losses: Vec<SwitchNotCarried>,
    /// Losses past the bound, counted only.
    overflow: u64,
}

/// The snapshots of every tab the session's engine drives, by the tab's
/// target, and their charge.
pub(crate) struct OriginSnapshots {
    tabs: HashMap<String, Tab>,
    /// The bounds kept now: `read_chars`, `snapshot_origins` and
    /// `snapshot_bytes`, defaults until a call named its own (FIX 10335).
    bounds: (usize, usize, usize),
    charge: Box<dyn HandleRetention>,
    /// The bytes the charge holds.
    held: usize,
    order: u64,
    /// The last receipt the session landed.
    receipt: u64,
    /// The pipe whose reads are kept: the engine the session runs.
    live: u64,
    /// Pipes given a sink so far.
    pipes: u64,
    /// The closed tabs whose snapshots were dropped: a late read of one (a
    /// Chromium exit read that raced the close) keeps nothing (FIX 7411).
    dropped: HashSet<String>,
}

/// The session's snapshots, shared with its engine's pipe: the pipe's
/// reader keeps a document's exit read, the driver its other reads.
pub(crate) type Collector = Arc<Mutex<OriginSnapshots>>;

/// Where one engine's pipe keeps its pages' reads.
#[derive(Clone)]
pub(crate) struct Sink {
    collector: Collector,
    pipe: u64,
}

impl Sink {
    /// The bound one read after an act, at hand-back or on exit takes now.
    pub(crate) fn read_chars(&self) -> usize {
        lock(&self.collector).bounds.0
    }

    /// Keeps `sample`, read off tab `tab` in `phase`.
    pub(crate) fn keep(&self, tab: &str, phase: StoragePhase, sample: Sample) {
        lock(&self.collector).keep(self.pipe, tab, phase, sample);
    }

    /// Names `origin` as one tab `tab` showed whose storage no switch
    /// carries, and why.
    pub(crate) fn exclude(&self, tab: &str, origin: String, reason: SwitchLoss) {
        lock(&self.collector).exclude(self.pipe, tab, origin, reason);
    }

    /// Drops what the snapshots hold of tab `tab`, closed and no longer in
    /// front, and gives its bytes back to the charge (FIX 6891).
    pub(crate) fn drop_tab(&self, tab: &str) {
        lock(&self.collector).drop_tab(self.pipe, tab);
    }
}

fn lock(collector: &Collector) -> MutexGuard<'_, OriginSnapshots> {
    collector.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Each store a switch carries, and the component its record names.
pub(super) const STORES: [(Store, SwitchComponent); 2] = [
    (Store::Local, SwitchComponent::LocalStorage),
    (Store::Session, SwitchComponent::SessionStorage),
];

/// A store's component in a record, local then session.
const STORE_COMPONENTS: [SwitchComponent; 2] = [STORES[0].1, STORES[1].1];

/// A store's loss, as a record lists it.
pub(crate) fn store_loss(
    component: SwitchComponent,
    origin: &str,
    reason: SwitchLoss,
    count: Option<u64>,
    when: (StoragePhase, u64),
) -> SwitchNotCarried {
    SwitchNotCarried {
        component,
        origin: Some(origin.to_owned()),
        cookies: Vec::new(),
        attribute: None,
        count,
        phase: Some(when.0),
        after_receipt: Some(when.1),
        reason,
    }
}

/// What one tab's snapshots and the losses they name hold of the charge.
fn tab_bytes(kept: &Tab) -> usize {
    let origins: usize = kept.origins.values().map(|snapshot| snapshot.bytes).sum();
    let losses: usize = kept
        .losses
        .iter()
        .map(|loss| LOSS_BYTES + loss.origin.as_ref().map_or(0, String::len))
        .sum();
    origins + losses
}

fn kept_bytes(origin: &str, stores: &[Kept; 2]) -> usize {
    let items: usize = stores
        .iter()
        .map(|kept| match kept {
            Kept::Items(items) => items
                .pairs
                .iter()
                .map(|(key, value)| key.len() + value.len() + ITEM_BYTES)
                .sum::<usize>(),
            Kept::Lost { .. } => 0,
        })
        .sum();
    ORIGIN_BYTES + origin.len() + items
}

/// One store of a new read, kept over what an earlier one kept.
fn merge(read: StoreSample, earlier: Option<Kept>, kept: (StoragePhase, u64, bool)) -> Kept {
    let (phase, after, relaxed) = kept;
    let (reason, count) = match read {
        StoreSample::Items { pairs, chars } => {
            return Kept::Items(Items {
                pairs,
                chars,
                phase,
                after,
                relaxed,
            });
        }
        StoreSample::Over { count } => (SwitchLoss::Limit, Some(count)),
        StoreSample::Lost => (SwitchLoss::ContextLost, None),
        StoreSample::Threw => (SwitchLoss::ReadException, None),
    };
    match earlier {
        Some(Kept::Items(items)) if reason != SwitchLoss::Limit => Kept::Items(items),
        _ => Kept::Lost {
            reason,
            count,
            phase,
            after,
        },
    }
}

impl OriginSnapshots {
    /// Snapshots charged through `charge`, holding nothing yet.
    pub(crate) fn collector(charge: Box<dyn HandleRetention>) -> Collector {
        let limits = switch_state_limits();
        Arc::new(Mutex::new(Self {
            tabs: HashMap::new(),
            bounds: (
                limits.read_chars,
                limits.snapshot_origins,
                limits.snapshot_bytes,
            ),
            charge,
            held: 0,
            order: 0,
            receipt: 0,
            live: 1,
            pipes: 0,
            dropped: HashSet::new(),
        }))
    }

    /// The sink of the next pipe: the session's first engine's is kept
    /// from the start, a switch target's from its commit.
    pub(crate) fn sink(collector: &Collector) -> Sink {
        let mut snapshots = lock(collector);
        snapshots.pipes += 1;
        Sink {
            collector: Arc::clone(collector),
            pipe: snapshots.pipes,
        }
    }

    /// The session landed receipt `seq`: later reads follow it.
    pub(crate) fn landed(collector: &Collector, seq: u64) {
        lock(collector).receipt = seq;
    }

    /// Keeps `bounds` from now on, each named one in place of the one kept
    /// (`snapshot_bounds_policy`, CALLS row, FIX 10335): what the snapshots
    /// hold past a lower one gives way at the next read kept.
    pub(crate) fn bound(collector: &Collector, bounds: &SnapshotBounds) {
        let size = |bound: Option<u64>, kept: usize| {
            bound.map_or(kept, |bound| usize::try_from(bound).unwrap_or(usize::MAX))
        };
        let mut snapshots = lock(collector);
        let (chars, origins, bytes) = snapshots.bounds;
        snapshots.bounds = (
            size(bounds.read_chars, chars),
            size(bounds.snapshot_origins, origins),
            size(bounds.snapshot_bytes, bytes),
        );
    }

    fn keep(&mut self, pipe: u64, tab: &str, phase: StoragePhase, sample: Sample) {
        if pipe != self.live || self.dropped.contains(tab) {
            return;
        }
        let Sample {
            origin,
            relaxed,
            stores: [local, session],
        } = sample;
        let fresh = !matches!((&local, &session), (StoreSample::Lost, StoreSample::Lost));
        let earlier = self
            .tabs
            .get_mut(tab)
            .and_then(|kept| kept.origins.remove(&origin));
        let after = self.receipt;
        let (old_local, old_session, last) = match earlier {
            Some(old) => {
                self.held = self.held.saturating_sub(old.bytes);
                let [old_local, old_session] = old.stores;
                let last = (old.phase, old.after, old.order, old.imported);
                (Some(old_local), Some(old_session), Some(last))
            }
            None => (None, None, None),
        };
        let stores = [
            merge(local, old_local, (phase, after, relaxed)),
            merge(session, old_session, (phase, after, relaxed)),
        ];
        let (phase, after, order, imported) = match last {
            Some(last) if !fresh => last,
            _ => {
                self.order += 1;
                (phase, after, self.order, false)
            }
        };
        // A later read that kept items replaces what gave its origin up.
        if fresh && let Some(kept) = self.tabs.get_mut(tab) {
            let gone = |loss: &SwitchNotCarried| {
                loss.origin.as_deref() == Some(origin.as_str())
                    && matches!(
                        loss.reason,
                        SwitchLoss::EvictedOldest | SwitchLoss::HostCapacity
                    )
            };
            let before = kept.losses.len();
            kept.losses.retain(|loss| !gone(loss));
            let freed = before - kept.losses.len();
            self.held = self
                .held
                .saturating_sub(freed * (LOSS_BYTES + origin.len()));
        }
        let bytes = kept_bytes(&origin, &stores);
        let room = self.make_room(tab, bytes);
        if room && self.charge.resize(self.held + bytes) {
            self.held += bytes;
            let snapshot = Snapshot {
                stores,
                phase,
                after,
                order,
                imported,
                bytes,
            };
            let kept = self.tabs.entry(tab.to_owned()).or_default();
            kept.origins.insert(origin, snapshot);
            return;
        }
        // Past the snapshots' bound, or the host's line holds no more: the
        // origin is not kept, and each store it read is named.
        self.charge.resize(self.held);
        let reason = if room {
            SwitchLoss::HostCapacity
        } else {
            SwitchLoss::Limit
        };
        for (store, component) in stores.into_iter().zip(STORE_COMPONENTS) {
            if let Kept::Items(items) = store {
                let count = Some(items.pairs.len() as u64);
                let when = (items.phase, items.after);
                let loss = store_loss(component, &origin, reason, count, when);
                self.note(tab, loss);
            }
        }
    }

    /// Gives up the oldest snapshots until tab `tab` keeps fewer origins
    /// than its bound and `bytes` more fit the snapshots' bound: whether
    /// they do.
    fn make_room(&mut self, tab: &str, bytes: usize) -> bool {
        let (_, origins, held) = self.bounds;
        loop {
            let count = self.tabs.get(tab).map_or(0, |kept| kept.origins.len());
            let crowded = count >= origins;
            if !crowded && self.held + bytes <= held {
                return true;
            }
            let oldest = self
                .tabs
                .iter()
                .filter(|(at, _)| !crowded || at.as_str() == tab)
                .flat_map(|(at, kept)| kept.origins.iter().map(move |(o, s)| (s.order, at, o)))
                .min()
                .map(|(_, at, origin)| (at.clone(), origin.clone()));
            let Some((at, origin)) = oldest else {
                return false;
            };
            let Some(gone) = self
                .tabs
                .get_mut(&at)
                .and_then(|kept| kept.origins.remove(&origin))
            else {
                return false;
            };
            self.held = self.held.saturating_sub(gone.bytes);
            self.charge.resize(self.held);
            let when = (gone.phase, gone.after);
            let loss = store_loss(
                SwitchComponent::Storage,
                &origin,
                SwitchLoss::EvictedOldest,
                None,
                when,
            );
            self.note(&at, loss);
        }
    }

    /// Names `loss` on tab `tab`, charged; past the bound or the line, it
    /// is counted only.
    fn note(&mut self, tab: &str, loss: SwitchNotCarried) {
        let bound = switch_state_limits().losses;
        let bytes = LOSS_BYTES + loss.origin.as_ref().map_or(0, String::len);
        let room = self
            .tabs
            .get(tab)
            .is_none_or(|kept| kept.losses.len() < bound);
        let kept = if room && self.charge.resize(self.held + bytes) {
            self.held += bytes;
            true
        } else {
            false
        };
        let at = self.tabs.entry(tab.to_owned()).or_default();
        if kept {
            at.losses.push(loss);
        } else {
            at.overflow += 1;
        }
    }

    fn exclude(&mut self, pipe: u64, tab: &str, origin: String, reason: SwitchLoss) {
        if pipe != self.live || self.dropped.contains(tab) {
            return;
        }
        let named = self.tabs.get(tab).is_some_and(|kept| {
            kept.losses
                .iter()
                .any(|loss| loss.reason == reason && loss.origin.as_ref() == Some(&origin))
        });
        if named {
            return;
        }
        let loss = SwitchNotCarried {
            component: SwitchComponent::Storage,
            origin: Some(origin),
            cookies: Vec::new(),
            attribute: None,
            count: None,
            phase: None,
            after_receipt: None,
            reason,
        };
        self.note(tab, loss);
    }

    /// Drops tab `tab`'s snapshots and the losses they name, read by the
    /// engine the session runs, and resizes the charge to what stays.
    fn drop_tab(&mut self, pipe: u64, tab: &str) {
        if pipe != self.live {
            return;
        }
        self.dropped.insert(tab.to_owned());
        if let Some(gone) = self.tabs.remove(tab) {
            self.held = self.held.saturating_sub(tab_bytes(&gone));
            self.charge.resize(self.held);
        }
    }

    /// The carried tab's snapshots once the target committed: they are
    /// the target tab `to`'s, read by `sink`'s pipe from now on, and each
    /// is the target's own until a document of it stands again. The other
    /// tabs stayed with the source.
    pub(crate) fn carry(collector: &Collector, from: &str, to: String, sink: &Sink) {
        let mut snapshots = lock(collector);
        let mut carried = snapshots.tabs.remove(from).unwrap_or_default();
        for snapshot in carried.origins.values_mut() {
            snapshot.imported = true;
        }
        let held = tab_bytes(&carried);
        snapshots.tabs = HashMap::from([(to, carried)]);
        snapshots.held = held;
        snapshots.charge.resize(held);
        snapshots.live = sink.pipe;
    }
}

/// What a switch carries of the origins the tab visited before the current
/// one, and what it reports of them.
pub(crate) struct Plan {
    /// Each origin a snapshot holds a store of, oldest read first, with its
    /// local and session store.
    pub(crate) seed: Vec<(String, [Option<Items>; 2])>,
    pub(crate) losses: Vec<SwitchNotCarried>,
}

/// The origins whose stores a switch seeds into the target, and what it
/// reports of the others (`switch_storage_scope`, CALLS row, open; extends
/// PR3's): every committed top-level http or https origin of the carried
/// tab, the current one read fresh and seeded last, each other from its
/// snapshot. An origin no read caught is `never_sampled`; a snapshot whose
/// document stood past its last read, and was left with no exit read,
/// carries what it read and names the tail it did not see; one carried in
/// by an earlier switch and not shown since is the target's own, whole. In-
/// page frames of other origins, opaque and non-web documents are named,
/// never carried; `about:` documents hold their creator's origin's storage.
pub(crate) fn switch_storage_scope(
    collector: &Collector,
    tab: &str,
    current: Option<&str>,
    visited: Option<&Visits>,
    shown: &[String],
) -> Plan {
    let snapshots = lock(collector);
    let mut plan = Plan {
        seed: Vec::new(),
        losses: Vec::new(),
    };
    let Some(kept) = snapshots.tabs.get(tab) else {
        for origin in visited.into_iter().flat_map(|visits| &visits.origins) {
            if Some(origin.as_str()) != current {
                plan.losses.push(never_sampled(origin));
            }
        }
        return plan;
    };
    let mut origins: Vec<_> = kept
        .origins
        .iter()
        .filter(|(origin, _)| Some(origin.as_str()) != current)
        .collect();
    origins.sort_by_key(|(_, snapshot)| snapshot.order);
    for (origin, snapshot) in origins {
        let mut stores = [None, None];
        for ((store, component), slot) in snapshot
            .stores
            .iter()
            .zip(STORE_COMPONENTS)
            .zip(&mut stores)
        {
            match store {
                Kept::Items(items) => {
                    if items.relaxed {
                        let reason = SwitchLoss::EffectiveOriginMismatch;
                        let when = (items.phase, items.after);
                        let count = Some(items.pairs.len() as u64);
                        let loss = store_loss(component, origin, reason, count, when);
                        plan.losses.push(loss);
                    }
                    *slot = Some(items.clone());
                }
                Kept::Lost {
                    reason,
                    count,
                    phase,
                    after,
                } => {
                    let loss = store_loss(component, origin, *reason, *count, (*phase, *after));
                    plan.losses.push(loss);
                }
            }
        }
        if stores.iter().all(Option::is_none) {
            continue;
        }
        let shown = shown.contains(origin);
        if switch_storage_freshness_policy(snapshot.phase, snapshot.imported, shown) {
            let when = (snapshot.phase, snapshot.after);
            let reason = SwitchLoss::DepartureTailUnobserved;
            let loss = store_loss(SwitchComponent::Storage, origin, reason, None, when);
            plan.losses.push(loss);
        }
        plan.seed.push((origin.clone(), stores));
    }
    for loss in &kept.losses {
        if loss.origin.as_deref() != current {
            plan.losses.push(loss.clone());
        }
    }
    for origin in visited.into_iter().flat_map(|visits| &visits.origins) {
        let named = |loss: &SwitchNotCarried| loss.origin.as_ref() == Some(origin);
        if Some(origin.as_str()) != current
            && !kept.origins.contains_key(origin)
            && !kept.losses.iter().any(named)
        {
            plan.losses.push(never_sampled(origin));
        }
    }
    if kept.overflow > 0 {
        plan.losses.push(SwitchNotCarried {
            component: SwitchComponent::Storage,
            origin: None,
            cookies: Vec::new(),
            attribute: None,
            count: Some(kept.overflow),
            phase: None,
            after_receipt: None,
            reason: SwitchLoss::Limit,
        });
    }
    plan
}

/// Reads `origin`'s two stores off the source page, fresh, and keeps the
/// read in the session's snapshots too.
pub(super) fn export_stores(
    driver: &CdpDriver,
    origin: &str,
    after: u64,
    losses: &mut Vec<SwitchNotCarried>,
) -> [Option<Items>; 2] {
    let phase = StoragePhase::SwitchExport;
    let mut stores = [None, None];
    let mut sample = [StoreSample::Lost, StoreSample::Lost];
    let mut relaxed = false;
    for (((store, component), kept), read) in STORES.into_iter().zip(&mut stores).zip(&mut sample) {
        let loss = |reason, count| store_loss(component, origin, reason, count, (phase, after));
        match driver.read_store(store, origin) {
            StoreRead::Items {
                pairs,
                chars,
                relaxed: other,
            } => {
                relaxed |= other;
                if other {
                    let count = Some(pairs.len() as u64);
                    losses.push(loss(SwitchLoss::EffectiveOriginMismatch, count));
                }
                let pairs_read = pairs.clone();
                *read = StoreSample::Items {
                    pairs: pairs_read,
                    chars,
                };
                *kept = Some(Items {
                    pairs,
                    chars,
                    phase,
                    after,
                    relaxed: other,
                });
            }
            StoreRead::Lost => losses.push(loss(SwitchLoss::ContextLost, None)),
            StoreRead::Threw => {
                losses.push(loss(SwitchLoss::ReadException, None));
                *read = StoreSample::Threw;
            }
        }
    }
    let read = Sample {
        origin: origin.to_owned(),
        relaxed,
        stores: sample,
    };
    driver.keep(phase, read);
    stores
}

/// The bytes of a store pair's keys and values.
pub(super) fn store_bytes(stores: &[Option<Items>; 2]) -> usize {
    let pairs = stores.iter().flatten().flat_map(|items| &items.pairs);
    pairs.map(|(key, value)| key.len() + value.len()).sum()
}

/// Lists each store of `stores` as not held by the host's line.
pub(super) fn not_held(
    origin: &str,
    stores: [Option<Items>; 2],
    losses: &mut Vec<SwitchNotCarried>,
) {
    for ((_, component), store) in STORES.into_iter().zip(stores) {
        if let Some(items) = store {
            let count = Some(items.pairs.len() as u64);
            let when = (items.phase, items.after);
            let reason = SwitchLoss::HostCapacity;
            losses.push(store_loss(component, origin, reason, count, when));
        }
    }
}

/// Whether a carried snapshot's origin may hold writes no read saw
/// (`switch_storage_freshness_policy`, CALLS row, open): each carried store
/// names the phase of its read and the last receipt the session had landed
/// then. A snapshot whose last read was not taken as its document was left
/// has a tail after that receipt no read saw, once a document of it stood
/// past the read; one a switch carried in, and no document of it shown
/// since, is the target's own, whole. Values never enter a record.
fn switch_storage_freshness_policy(phase: StoragePhase, imported: bool, shown: bool) -> bool {
    if imported {
        shown
    } else {
        phase != StoragePhase::Exit
    }
}

fn never_sampled(origin: &str) -> SwitchNotCarried {
    SwitchNotCarried {
        component: SwitchComponent::Storage,
        origin: Some(origin.to_owned()),
        cookies: Vec::new(),
        attribute: None,
        count: None,
        phase: None,
        after_receipt: None,
        reason: SwitchLoss::NeverSampled,
    }
}

impl BrowserSession {
    /// Tells the snapshots the session landed its newest receipt.
    pub(super) fn landed(&self) {
        if let Some(collector) = &self.snapshots {
            OriginSnapshots::landed(collector, self.receipt_seq);
        }
    }
}
