//! OF-181: the lens frames this server holds for the cards it rendered.
//!
//! A host-rendered generated-UI card is driven by events its client sends
//! back, and the proof those events are checked against never leaves this
//! host: the [`LensRenderFrame`] that minted the card's backing refs, the
//! exact [`GeneratedUiRender`] the client was handed, and the card's current
//! `$state`, kept apart from the schema and initial values the render
//! declared. This store keeps them per card, for the caller that rendered
//! it: keyed by the credential's idempotency principal (the exact verified
//! instrument and its caveats), the caller's locality and the card id. It is
//! process-local; a card it does not hold, after a restart too, is rendered
//! again.
//!
//! Retention (CALLS "OF-181 lens frame retention"): a frame lives until its
//! card is closed or the server drops, charged to `server.retained`. No count
//! bounds it. Only the retained line's memory floor evicts, oldest first, and
//! an evicted or unknown card answers a refusal that says to re-render.
//!
//! Locking: the map's lock is held only to find, add, re-charge or drop an
//! entry, never across a registry dispatch. Each card serializes its own
//! events on its own lock, which an event holds from its validation to its
//! effect.
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use oneiron::claim::CallerLocality;
use oneiron::lens::{
    GeneratedUiRender, GeneratedUiStateSnapshot, LensHostBackingRef, LensRenderFrame, LensRenderId,
};
use oneiron::memory::{MEMORY_CODE_INTERNAL, MemoryError, MemoryResult};

use crate::auth::CoreAuth;
use crate::byte_line::{ByteLine, HeldBytes};
use crate::wire_telemetry::{LimitQuestions, WireTelemetry};

/// The cards this server holds frames for, charged to the retained line.
pub(crate) struct LensFrameStore {
    line: Arc<ByteLine>,
    questions: Arc<LimitQuestions>,
    frames: Mutex<Frames>,
}

/// One held card: the frame and the render its caller was handed, and the
/// card's current `$state`.
pub(crate) struct HeldCard {
    pub(crate) frame: LensRenderFrame,
    pub(crate) render: GeneratedUiRender,
    /// The current `$state`, apart from `render.state` (the declared schema
    /// and initial values). Its lock serializes the card's events.
    pub(crate) state: tokio::sync::Mutex<GeneratedUiStateSnapshot>,
}

/// Whose card a frame is: the credential's idempotency principal, where it
/// called from, and the card.
#[derive(Clone, PartialEq, Eq, Hash)]
struct FrameKey {
    principal: String,
    on_device: bool,
    card: LensRenderId,
}

struct Frames {
    cards: HashMap<FrameKey, Entry>,
    /// The held cards by arrival, oldest first: the order the floor evicts in.
    arrival: BTreeMap<u64, FrameKey>,
    next: u64,
    /// The bytes every held card stands for.
    bytes: usize,
    /// The store's one charge on the retained line, moved to `bytes`.
    charge: HeldBytes,
}

struct Entry {
    arrival: u64,
    /// What the card stands for apart from its current `$state`.
    base: usize,
    /// `base` and its current `$state`.
    bytes: usize,
    card: Arc<HeldCard>,
}

impl LensFrameStore {
    /// An empty store charging `line`, its crossings asked on `telemetry`'s
    /// questions.
    pub(crate) fn new(line: &Arc<ByteLine>, telemetry: &WireTelemetry) -> Self {
        Self {
            line: Arc::clone(line),
            questions: Arc::clone(telemetry.limit_questions()),
            frames: Mutex::new(Frames {
                cards: HashMap::new(),
                arrival: BTreeMap::new(),
                next: 0,
                bytes: 0,
                charge: line.empty(),
            }),
        }
    }

    /// Holds `frame` and the `render` it is about to hand `auth`'s caller,
    /// for that caller's events on the card. A renderer calls this once per
    /// card, before its response leaves, with the very render it returns.
    ///
    /// The card is charged to the retained line. Where the line refuses it,
    /// the oldest held cards are evicted until it fits; a card that still
    /// does not fit with none older left is not held, so its events answer
    /// the re-render refusal as an evicted card's do.
    pub(crate) fn record(
        &self,
        auth: &CoreAuth,
        frame: LensRenderFrame,
        render: GeneratedUiRender,
    ) -> MemoryResult<()> {
        if &render.card_id != frame.render_id() {
            return Err(MemoryError::new(
                MEMORY_CODE_INTERNAL,
                "a held lens frame must be the frame of the render it is held with",
                &[],
            ));
        }
        let key = FrameKey::new(auth, render.card_id.clone());
        let base = footprint(&key, &frame, &render);
        let state = render.state.clone();
        let bytes = base + state_footprint(&state);
        let card = Arc::new(HeldCard {
            frame,
            render,
            state: tokio::sync::Mutex::new(state),
        });
        let mut frames = self.lock();
        // A card id names one render, so a held key is this card again.
        if let Some(arrival) = frames.cards.get(&key).map(|entry| entry.arrival) {
            frames.evict(arrival);
        }
        if !frames.fit(&self.line, &self.questions, bytes, None) {
            frames.settle(&self.line, &self.questions);
            return Ok(());
        }
        let arrival = frames.next;
        frames.next += 1;
        frames.bytes += bytes;
        frames.arrival.insert(arrival, key.clone());
        frames.cards.insert(
            key,
            Entry {
                arrival,
                base,
                bytes,
                card,
            },
        );
        Ok(())
    }

    /// The card `card` that `auth`'s caller rendered here, if this store
    /// still holds it.
    pub(crate) fn card(&self, auth: &CoreAuth, card: &LensRenderId) -> Option<Arc<HeldCard>> {
        let key = FrameKey::new(auth, card.clone());
        self.lock()
            .cards
            .get(&key)
            .map(|entry| Arc::clone(&entry.card))
    }

    /// Re-charges `held`, which `auth`'s caller holds, for its next `$state`
    /// before the caller moves it there. `false`: the card is no longer held,
    /// closed meanwhile or evicted, now too when the floor reached it as the
    /// oldest card left.
    pub(crate) fn restate(
        &self,
        auth: &CoreAuth,
        held: &Arc<HeldCard>,
        state: &GeneratedUiStateSnapshot,
    ) -> bool {
        let key = FrameKey::new(auth, held.render.card_id.clone());
        let state_bytes = state_footprint(state);
        let mut frames = self.lock();
        let Some((arrival, base, old)) = frames
            .cards
            .get(&key)
            .filter(|entry| Arc::ptr_eq(&entry.card, held))
            .map(|entry| (entry.arrival, entry.base, entry.bytes))
        else {
            return false;
        };
        frames.bytes -= old;
        if frames.fit(
            &self.line,
            &self.questions,
            base + state_bytes,
            Some(arrival),
        ) {
            frames.bytes += base + state_bytes;
            if let Some(entry) = frames.cards.get_mut(&key) {
                entry.bytes = base + state_bytes;
            }
            return true;
        }
        // The floor reached this card, now the oldest held: it goes too.
        frames.bytes += old;
        frames.evict(arrival);
        frames.settle(&self.line, &self.questions);
        false
    }

    /// Closes the card `card` that `auth`'s caller rendered here, giving its
    /// bytes back. `false` when it was not held.
    pub(crate) fn close(&self, auth: &CoreAuth, card: &LensRenderId) -> bool {
        let key = FrameKey::new(auth, card.clone());
        let mut frames = self.lock();
        let Some(arrival) = frames.cards.get(&key).map(|entry| entry.arrival) else {
            return false;
        };
        frames.evict(arrival);
        frames.settle(&self.line, &self.questions);
        true
    }

    fn lock(&self) -> MutexGuard<'_, Frames> {
        // Each change to the map and its counts is one step under the lock,
        // so a holder that panicked left them whole.
        self.frames.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl FrameKey {
    fn new(auth: &CoreAuth, card: LensRenderId) -> Self {
        Self {
            principal: auth.idempotency_principal(),
            on_device: auth.locality() == CallerLocality::OnDevice,
            card,
        }
    }
}

impl Frames {
    /// Moves the charge to the held cards' bytes and `incoming`, evicting the
    /// oldest held card while the retained line refuses it. `false` when it
    /// still refuses and no card is left to evict ahead of `own`, the card
    /// `incoming` stands for when it is held already.
    fn fit(
        &mut self,
        line: &ByteLine,
        questions: &LimitQuestions,
        incoming: usize,
        own: Option<u64>,
    ) -> bool {
        loop {
            if line.try_resize(&mut self.charge, self.bytes + incoming, questions) {
                return true;
            }
            let Some(oldest) = self.arrival.first_key_value().map(|(arrival, _)| *arrival) else {
                return false;
            };
            if Some(oldest) == own {
                return false;
            }
            self.evict(oldest);
        }
    }

    /// Drops the card that arrived at `arrival` from the map and its count;
    /// [`Self::settle`] gives its bytes back.
    fn evict(&mut self, arrival: u64) {
        let Some(key) = self.arrival.remove(&arrival) else {
            return;
        };
        if let Some(entry) = self.cards.remove(&key) {
            self.bytes -= entry.bytes;
        }
    }

    /// Shrinks the charge to the held cards' bytes, which always fits.
    fn settle(&mut self, line: &ByteLine, questions: &LimitQuestions) {
        let _ = line.try_resize(&mut self.charge, self.bytes, questions);
    }
}

/// The bytes a held card stands for apart from its current `$state`: its
/// render's encoding, its frame's backing rows and its key.
fn footprint(key: &FrameKey, frame: &LensRenderFrame, render: &GeneratedUiRender) -> usize {
    serde_json::to_vec(render).map_or(0, |encoded| encoded.len())
        + std::mem::size_of::<Entry>()
        + std::mem::size_of::<HeldCard>()
        + frame.backing_refs().len() * std::mem::size_of::<LensHostBackingRef>()
        + key.principal.len()
        + key.card.as_str().len()
}

/// The bytes a card's current `$state` stands for: its encoding.
fn state_footprint(state: &GeneratedUiStateSnapshot) -> usize {
    serde_json::to_vec(state).map_or(0, |encoded| encoded.len())
}
