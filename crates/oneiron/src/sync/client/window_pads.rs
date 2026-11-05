//! The device's side of the window pad envelope (KS-5, FIX 7107). Each window
//! write it sends goes in its envelope for the home this connection proved
//! ([`prepare_window_pads`]); each envelope the home sends is put back
//! together and its pads installed here ([`admit_window_pads`]) before its
//! payload reaches an import door. A sealed envelope's payload first passes
//! the isolated check that door runs, as the home checks before it installs
//! (FIX 10474): nothing of a refused one installs, and a world update whose
//! edge waits on an endpoint waits in its envelope, uninstalled, until the
//! check passes.
//!
//! A send the home answers is held until its receipt comes: a residence
//! update by its queue sequence, whose acknowledgment then names its queued
//! row's own bytes for the clear; a sealed owner-lane update by its projected
//! payload, a witness its window's convergence waits on. A `NotReady`
//! receipt sends the same bytes again as the carrier at once, and the
//! window's sends go as the carrier for the rest of the connection. An
//! envelope whose pads do not install here imports nothing: the home is told
//! `NotReady` and asked for the window again, which it then sends as the
//! carrier. Everything here lives for one connection (KEEP TODAY).

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;

use base64::Engine;
use loro::LoroDoc;

use super::base::{ResidenceReceipt, SyncClient};
use crate::authority::PeerMachine;
use crate::sync::loro_support::doc_version_vector;
use crate::sync::transport::{
    self, MAX_DECODED_PAYLOAD_BYTES, MAX_WINDOW_PAD_PAYLOAD_BYTES, ReceivedWindowPadEnvelope,
    TransportError, WindowPadArrival, WindowPadAssembly, WindowPadBinding, WindowPadForm,
    WindowPadKind, WindowPadPayload, WindowPadReadiness, WindowPadReceipt,
    is_window_admission_read_fault, window_sub_tags,
};
use crate::sync::types::WindowKey;
use crate::sync::window::{
    PreparedWindowPads, ReplacementByteBound, UpdateVerdict, WINDOW_PAD_PART_REPAIR,
    WINDOW_PAD_RECEIPT_WITNESS, WindowPadPartRepair, WindowPadReceiptWitness, admit_window_pads,
    carrier_window_pads, check_bounded_replacement, check_promotion_snapshot,
    check_window_update_residence_with_vault, check_window_update_with_staged_worlds,
    prepare_window_pads,
};

/// A sealed world update whose isolated check waits on an edge endpoint no
/// staged update resolves yet (FIX 10474). Its capsule installs only once the
/// check passes; until then it keeps the envelope it came in, with the memory
/// its received bytes hold, and the machine its connection proved.
pub(crate) struct DeferredSealedUpdate {
    key: WindowKey,
    envelope: ReceivedWindowPadEnvelope,
    from: PeerMachine,
}

/// What a sealed envelope's isolated check found (FIX 10474).
enum SealedCheck {
    /// Its payload passes: its capsule installs.
    Admitted,
    /// A world update waiting on an edge endpoint: it waits in its envelope.
    Waits,
    /// Refused, with what answers it: nothing installs.
    Answered(Vec<Vec<u8>>),
}

/// The refusal an own-device update's import door gives.
const UPDATE_REFUSAL: &str = "entity outside window residence";

/// What the isolated check of a world update refuses while an endpoint of one
/// of its edges is in no window and no staged update yet.
const EDGE_ENDPOINT_UNRESOLVED: &str = "edge endpoint unresolved";

/// A send held for the home's receipt.
#[derive(PartialEq, Eq, Hash)]
enum SentKey {
    /// A residence update, by its queue sequence.
    Residence(u64),
    /// A sealed owner-lane update, by window and projected payload digest.
    Update(String, [u8; 32]),
}

struct Sent {
    window: String,
    sub_tag: u8,
    binding: WindowPadBinding,
    /// The bytes as queued or made, kept to go again as the carrier on a
    /// `NotReady`; none once they did.
    resend: Option<Vec<u8>>,
    /// BLAKE3 of those bytes: what the queued row's clear compares.
    queued: [u8; 32],
}

/// One connection's window pad state.
#[derive(Default)]
pub(crate) struct WindowPadLedger {
    assembly: WindowPadAssembly,
    sent: HashMap<SentKey, Sent>,
    /// Windows the home answered `NotReady` for: their sends go as the
    /// carrier.
    carrier: HashSet<String>,
    /// First frames released whose parts follow them, by envelope id.
    released: HashSet<[u8; 32]>,
    /// The last update past one frame this connection made for each window,
    /// its envelope id and payload, read whole when its first frame is
    /// judged (FIX 8247). A later one of the window takes its place.
    continued: HashMap<String, ([u8; 32], Vec<u8>)>,
}

fn invalid(why: &'static str) -> TransportError {
    TransportError::InvalidPayload(why)
}

impl SyncClient {
    fn window_pad_ledger(&self) -> std::sync::MutexGuard<'_, WindowPadLedger> {
        self.window_pads
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Forgets every association of the last connection, the sealed updates
    /// it left waiting included: the next exchange asks for them again.
    pub(crate) fn reset_window_pads(&mut self) {
        *self.window_pad_ledger() = WindowPadLedger::default();
        self.deferred_sealed_updates.clear();
    }

    /// `payload`, a window write of `window_key`, made ready for the home this
    /// connection proved; `context` holds its dependencies. A window the home
    /// answered `NotReady` for sends the carrier.
    pub(crate) fn prepare_window_send(
        &self,
        window_key: &str,
        payload: &[u8],
        context: Option<&LoroDoc>,
    ) -> Result<PreparedWindowPads, TransportError> {
        let key = WindowKey::try_new(window_key).ok_or(TransportError::InvalidWindowKey)?;
        // FIX 7608 slice 4: the home gets a marked repo item's masked copy,
        // made before any pad is; one that cannot be masked fails this send
        // and stays in the window, owed to the next exchange. A copy the home
        // may hold an older one of is re-authored with it (FIX 10729).
        let masked =
            crate::sync::selector::prepare_repo_sync_frame_for_home(&self.vault, payload, context)
                .map_err(|error| TransportError::Storage(error.to_string()))?;
        let payload = masked.as_deref().unwrap_or(payload);
        if self.window_pad_ledger().carrier.contains(window_key) {
            return Ok(carrier_window_pads(&self.vault, &key, payload, context));
        }
        Ok(prepare_window_pads(
            &self.vault,
            &key,
            payload,
            context,
            self.home_peer,
        ))
    }

    /// The frames `prepared` goes as under `sub_tag` and `queue_seq`, the send
    /// held for the home's receipt where one comes. `raw` is the write as
    /// queued or made.
    pub(crate) fn window_send_frames(
        &self,
        prepared: &PreparedWindowPads,
        window_key: &str,
        sub_tag: u8,
        queue_seq: Option<u64>,
        raw: &[u8],
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        let (frames, binding) = prepared.frames(window_key, sub_tag, queue_seq)?;
        // An update past one frame is judged whole as its first frame leaves,
        // from the payload kept here until then (FIX 8247).
        if sub_tag == window_sub_tags::UPDATE
            && let Some(id) = frames.first().and_then(|first| continued_frame_id(first))
        {
            let payload = prepared.envelope(WindowPadKind::Update, queue_seq).payload;
            self.window_pad_ledger()
                .continued
                .insert(window_key.to_owned(), (id, payload));
        }
        self.record_window_send(prepared, window_key, sub_tag, queue_seq, raw, binding);
        Ok(frames)
    }

    pub(crate) fn window_send_batch_frames(
        &self,
        prepared: &PreparedWindowPads,
        window_key: &str,
        sub_tag: u8,
        queue_seq: Option<u64>,
        raw: &[u8],
    ) -> Result<(Vec<Vec<u8>>, WindowPadBinding), TransportError> {
        let (frames, binding) = prepared.frames_batched(window_key, sub_tag, queue_seq)?;
        // Each batch draw checks the buffered whole update; no standalone
        // continuation copy is needed for these frames.
        self.record_window_send(prepared, window_key, sub_tag, queue_seq, raw, binding);
        Ok((frames, binding))
    }

    fn record_window_send(
        &self,
        prepared: &PreparedWindowPads,
        window_key: &str,
        sub_tag: u8,
        queue_seq: Option<u64>,
        raw: &[u8],
        binding: WindowPadBinding,
    ) {
        let sealed = prepared.form() == WindowPadForm::Sealed;
        let key = match queue_seq {
            Some(seq) => SentKey::Residence(seq),
            None if sealed => SentKey::Update(window_key.to_owned(), binding.payload_digest),
            None => return,
        };
        self.window_pad_ledger().sent.insert(
            key,
            Sent {
                window: window_key.to_owned(),
                sub_tag,
                binding,
                resend: sealed.then(|| raw.to_vec()),
                queued: *blake3::hash(raw).as_bytes(),
            },
        );
    }

    /// Forgets only this unfinished send, never a newer binding or envelope.
    pub(crate) fn forget_window_send(
        &self,
        window_key: &str,
        binding: &WindowPadBinding,
        first_id: Option<[u8; 32]>,
    ) {
        let mut ledger = self.window_pad_ledger();
        let key = match binding.queue_seq {
            Some(seq) => SentKey::Residence(seq),
            None => SentKey::Update(window_key.to_owned(), binding.payload_digest),
        };
        if ledger
            .sent
            .get(&key)
            .is_some_and(|sent| sent.window == window_key && sent.binding == *binding)
        {
            ledger.sent.remove(&key);
        }
        if ledger
            .continued
            .get(window_key)
            .is_some_and(|(id, _)| Some(*id) == first_id)
        {
            ledger.continued.remove(window_key);
        }
    }

    /// [`Self::prepare_window_send`] and [`Self::window_send_frames`] at once,
    /// for a write made now.
    pub(crate) fn window_pad_frames(
        &self,
        window_key: &str,
        sub_tag: u8,
        queue_seq: Option<u64>,
        payload: &[u8],
        context: Option<&LoroDoc>,
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        let prepared = self.prepare_window_send(window_key, payload, context)?;
        self.window_send_frames(&prepared, window_key, sub_tag, queue_seq, payload)
    }

    /// Whether a sealed update of `window_key` the home has not answered is
    /// held and its window's convergence waits on it: only when the owner
    /// turned the wait on ([`WINDOW_PAD_RECEIPT_WITNESS`]).
    pub(crate) fn window_pads_owed(&self, window_key: &str) -> bool {
        match WINDOW_PAD_RECEIPT_WITNESS {
            WindowPadReceiptWitness::Off => false,
            WindowPadReceiptWitness::On => self
                .window_pad_ledger()
                .sent
                .keys()
                .any(|key| matches!(key, SentKey::Update(window, _) if window == window_key)),
        }
    }

    /// The home's receipt `payload` for a send of `window_key`, under
    /// `RESIDENCE_ACK`, `RESIDENCE_HELD` or `WINDOW_PAD_RECEIPT`. A residence
    /// ACK confirms durable bytes; Held answers without retiring the row. A
    /// `NotReady` sends the same bytes again as the carrier, returned. A
    /// receipt for no send held here is passed over: its row stays queued.
    pub(super) fn accept_window_pad_receipt(
        &mut self,
        window_key: &str,
        sub_tag: u8,
        payload: &[u8],
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        let receipt = WindowPadReceipt::decode(payload)?;
        let held = sub_tag == window_sub_tags::RESIDENCE_HELD;
        if held && receipt.readiness == WindowPadReadiness::NotReady {
            return Err(invalid("held residence receipt has no admitted pads"));
        }
        let key = if sub_tag == window_sub_tags::RESIDENCE_ACK || held {
            SentKey::Residence(
                receipt
                    .binding
                    .queue_seq
                    .ok_or_else(|| invalid("invalid residence acknowledgment"))?,
            )
        } else {
            SentKey::Update(window_key.to_owned(), receipt.binding.payload_digest)
        };
        let Some(sent) = self.window_pad_ledger().sent.remove(&key) else {
            return Ok(Vec::new());
        };
        if sent.window != window_key || sent.binding != receipt.binding {
            return Err(invalid("conflicting residence acknowledgment"));
        }
        if receipt.readiness == WindowPadReadiness::NotReady
            && let Some(raw) = sent.resend
        {
            // Nothing of it landed: the same bytes go again as the carrier.
            tracing::warn!(
                window = window_key,
                "home did not install window pads; the carrier goes again"
            );
            self.window_pad_ledger()
                .carrier
                .insert(window_key.to_owned());
            let window = self.window(window_key);
            let carrier = carrier_window_pads(
                &self.vault,
                &WindowKey::new(window_key),
                &raw,
                window.as_ref().map(|window| &window.doc),
            );
            return self.window_send_frames(
                &carrier,
                window_key,
                sent.sub_tag,
                sent.binding.queue_seq,
                &raw,
            );
        }
        if let SentKey::Residence(seq) = key {
            let answer = if held {
                ResidenceReceipt::Held(sent.queued)
            } else {
                ResidenceReceipt::Durable(sent.queued)
            };
            if self
                .residence_acks
                .insert(seq, answer)
                .is_some_and(|old| old.digest() != &sent.queued)
            {
                return Err(invalid("conflicting residence acknowledgment"));
            }
        }
        Ok(Vec::new())
    }

    /// One window frame of `key` from the home under `sub_tag`: a notice as it
    /// is, or an envelope's payload once the envelope is whole and its pads
    /// are installed here, under the sub-tag its first frame came under.
    /// `Break` carries what answers a frame that is done with here: a part
    /// still to come, a receipt, or a `NotReady` and the ask for the window
    /// again.
    pub(super) fn accept_window_pad_frame<'a>(
        &mut self,
        key: &WindowKey,
        sub_tag: u8,
        payload: &'a [u8],
    ) -> Result<ControlFlow<Vec<Vec<u8>>, (u8, WindowPadPayload<'a>)>, TransportError> {
        if sub_tag == window_sub_tags::WINDOW_PAD_RECEIPT {
            return self
                .accept_window_pad_receipt(key.as_str(), sub_tag, payload)
                .map(ControlFlow::Break);
        }
        let arrival = self
            .window_pad_ledger()
            .assembly
            .accept(key.as_str(), sub_tag, payload)?;
        let (sub_tag, envelope) = match arrival {
            WindowPadArrival::Notice => {
                return Ok(ControlFlow::Continue((
                    sub_tag,
                    WindowPadPayload::borrowed(payload),
                )));
            }
            WindowPadArrival::Streaming => return Ok(ControlFlow::Break(Vec::new())),
            WindowPadArrival::Broken => {
                // A lost frame: the window's next exchange sends it again.
                match WINDOW_PAD_PART_REPAIR {
                    WindowPadPartRepair::FreshCapsuleRebind => {
                        tracing::warn!(%key, "window pad envelope arrived incomplete");
                        self.schedule_world_pad_repair(key);
                    }
                }
                return Ok(ControlFlow::Break(Vec::new()));
            }
            WindowPadArrival::Envelope(sub_tag, envelope) => (sub_tag, envelope),
        };
        // FIX 10474: a sealed capsule installs for a payload its import door's
        // isolated check admits, as the home installs one only after its own.
        if envelope.form == WindowPadForm::Sealed {
            match self.sealed_payload_check(key, sub_tag, &envelope.payload)? {
                SealedCheck::Admitted => {}
                SealedCheck::Waits => {
                    self.defer_sealed_update(key, envelope)?;
                    // What it carries may prove an edge another staged update waits on.
                    let mut answers = Vec::new();
                    self.drain_staged_world_updates(Some(&mut answers))?;
                    return Ok(ControlFlow::Break(answers));
                }
                SealedCheck::Answered(answer) => return Ok(ControlFlow::Break(answer)),
            }
        }
        // FIX 10480: a sealed update's pads are read over the document it
        // imports into, with the world updates still staged for its window.
        let receipt = {
            let window = (envelope.form == WindowPadForm::Sealed
                && envelope.kind == WindowPadKind::Update)
                .then(|| self.ensure_window(key.as_str()))
                .transpose()?;
            let staged = window
                .as_ref()
                .and_then(|window| self.staged_pad_context(key, &window.doc));
            let context = staged
                .as_ref()
                .or(window.as_ref().map(|window| &window.doc));
            admit_window_pads(&self.vault, key, &envelope, context)
        };
        if receipt.readiness != WindowPadReadiness::NotReady {
            // FIX 7608 slice 4: a copy edit lands on its source; a held one imports nothing.
            return Ok(
                match envelope
                    .into_payload()
                    .try_map_owned(|payload| self.admitted_window_payload(key, payload))?
                {
                    Some(payload) => ControlFlow::Continue((sub_tag, payload)),
                    None => ControlFlow::Break(Vec::new()),
                },
            );
        }
        self.not_ready_answer(key, sub_tag, &receipt)
            .map(ControlFlow::Break)
    }

    /// What answers an envelope of `key` under `sub_tag` whose pads did not
    /// install here: nothing of it imports. The home is told, sends this
    /// window as the carrier from now on, and is asked for it again.
    fn not_ready_answer(
        &self,
        key: &WindowKey,
        sub_tag: u8,
        receipt: &WindowPadReceipt,
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        match WINDOW_PAD_PART_REPAIR {
            WindowPadPartRepair::FreshCapsuleRebind => self.schedule_world_pad_repair(key),
        }
        let ask = if sub_tag == window_sub_tags::REPLACEMENT {
            transport::encode_window_sync(key.as_str(), window_sub_tags::REPLACEMENT_REQUEST, &[])
        } else {
            let window = self.ensure_window(key.as_str())?;
            transport::encode_window_sync(
                key.as_str(),
                window_sub_tags::VV_REQUEST,
                &doc_version_vector(&window.doc),
            )
        };
        Ok(vec![
            transport::encode_window_sync(
                key.as_str(),
                window_sub_tags::WINDOW_PAD_RECEIPT,
                &receipt.encode(),
            )
            .into_result()?,
            ask.into_result()?,
        ])
    }

    /// The isolated check a sealed envelope's `payload` of `key` under
    /// `sub_tag` passes before its capsule installs: the one its import door
    /// runs, on the bytes that door reads ([`Self::payload_as_admitted`]),
    /// without the cutoffs they carry staged (FIX 10474). An own-device update
    /// is read over its window with the world updates still staged for it, a
    /// replacement over a fresh window. A federation lane's frames take the
    /// federation admission at their door, and the other kinds the checks
    /// their callers run.
    fn sealed_payload_check(
        &self,
        key: &WindowKey,
        sub_tag: u8,
        payload: &[u8],
    ) -> Result<SealedCheck, TransportError> {
        if self.config.federation_peer.is_some() {
            return Ok(SealedCheck::Admitted);
        }
        match sub_tag {
            window_sub_tags::UPDATE => {
                let window = self.ensure_window(key.as_str())?;
                let Some(admitted) = self.payload_as_admitted(payload, Some(&window.doc)) else {
                    return Ok(SealedCheck::Admitted);
                };
                let payload: &[u8] = &admitted;
                // A base window's import reads no staged world row.
                let world = key.world().is_some();
                let evidence = if world {
                    self.staged_entity_evidence()?
                } else {
                    HashMap::new()
                };
                let staged = world
                    .then(|| self.staged_pad_context(key, &window.doc))
                    .flatten();
                let doc = staged.as_ref().unwrap_or(&window.doc);
                match check_window_update_with_staged_worlds(
                    &self.vault,
                    doc,
                    payload,
                    key,
                    &evidence,
                ) {
                    Ok(()) => Ok(SealedCheck::Admitted),
                    Err(crate::Error::InvalidConfig(reason))
                        if world && reason == EDGE_ENDPOINT_UNRESOLVED =>
                    {
                        Ok(SealedCheck::Waits)
                    }
                    // Built on history this window's own shallow root cut
                    // away: the server's replacement brings it level.
                    Err(_)
                        if crate::sync::window::update_reaches_below_root(&window.doc, payload) =>
                    {
                        Ok(SealedCheck::Answered(vec![
                            transport::encode_window_sync(
                                key.as_str(),
                                window_sub_tags::REPLACEMENT_REQUEST,
                                &[],
                            )
                            .into_result()?,
                        ]))
                    }
                    Err(error) => Err(TransportError::from_window_admission(
                        &error,
                        UPDATE_REFUSAL,
                    )),
                }
            }
            window_sub_tags::REPLACEMENT => {
                let window = self.window(key.as_str());
                let Some(admitted) =
                    self.payload_as_admitted(payload, window.as_ref().map(|window| &window.doc))
                else {
                    return Ok(SealedCheck::Admitted);
                };
                let payload: &[u8] = &admitted;
                let evidence = self.staged_entity_evidence()?;
                check_bounded_replacement(
                    &self.vault,
                    key,
                    payload,
                    &evidence,
                    ReplacementByteBound::NetworkFrame,
                )
                .map(|()| SealedCheck::Admitted)
                .map_err(|error| {
                    if is_window_admission_read_fault(&error) {
                        TransportError::Storage(error.to_string())
                    } else {
                        TransportError::InvalidPayload("window replacement rejected")
                    }
                })
            }
            // A residence update goes up to the home only: one that came
            // down has no door here, and nothing of it installs.
            _ => Ok(SealedCheck::Answered(Vec::new())),
        }
    }

    /// `payload` as its import door reads it, `context` the window it imports
    /// into: its repo copies translated onto the sources this device holds,
    /// with nothing recorded (FIX 7608 slice 4). `None` when it holds on a
    /// ruled cause or its translation fails here: its door judges it once its
    /// pads are in, as it always did (FIX 10474). The recorded translation
    /// runs again after the pads install.
    fn payload_as_admitted<'p>(
        &self,
        payload: &'p [u8],
        context: Option<&LoroDoc>,
    ) -> Option<Cow<'p, [u8]>> {
        crate::sync::selector::repo_sync_frame_as_admitted(&self.vault, payload, context)
            .ok()
            .flatten()
    }

    /// Keeps `envelope`, a sealed world update of `key` whose isolated check
    /// waits on an edge endpoint, uninstalled until the check passes (FIX
    /// 10474). It shares the staged updates' memory bound: past it, one
    /// waits alone, as a staged update does.
    fn defer_sealed_update(
        &mut self,
        key: &WindowKey,
        envelope: ReceivedWindowPadEnvelope,
    ) -> Result<(), TransportError> {
        // The own-device import's bound on one update (FIX 8247).
        if envelope.payload.len() > MAX_WINDOW_PAD_PAYLOAD_BYTES {
            return Err(TransportError::FrameTooLarge {
                size: envelope.payload.len(),
                max: MAX_WINDOW_PAD_PAYLOAD_BYTES,
            });
        }
        self.deferred_sealed_updates.push(DeferredSealedUpdate {
            key: key.clone(),
            envelope,
            from: self.home_peer,
        });
        if self.staged_world_bytes() > MAX_DECODED_PAYLOAD_BYTES && self.staged_world_count() > 1 {
            self.deferred_sealed_updates.pop();
            return Err(TransportError::InvalidPayload(
                "unresolved world updates past the memory bound",
            ));
        }
        Ok(())
    }

    /// The bytes every world update waiting here holds: staged, or sealed and
    /// deferred.
    pub(super) fn staged_world_bytes(&self) -> usize {
        let staged: usize = self
            .staged_world_updates
            .iter()
            .map(|(_, bytes, _)| bytes.len())
            .sum();
        let deferred: usize = self
            .deferred_sealed_updates
            .iter()
            .map(|update| update.envelope.payload.len())
            .sum();
        staged + deferred
    }

    /// How many world updates wait here: staged, or sealed and deferred.
    pub(super) fn staged_world_count(&self) -> usize {
        self.staged_world_updates.len() + self.deferred_sealed_updates.len()
    }

    /// Every world update waiting here, by window: the bytes of each staged
    /// one, then the payload of each deferred sealed one.
    pub(super) fn waiting_world_updates(&self) -> impl Iterator<Item = (&WindowKey, &[u8])> {
        let staged = self
            .staged_world_updates
            .iter()
            .map(|(key, bytes, _)| (key, bytes.as_slice()));
        let deferred = self
            .deferred_sealed_updates
            .iter()
            .map(|update| (&update.key, update.envelope.payload.as_slice()));
        staged.chain(deferred)
    }

    /// Installs each deferred sealed update whose isolated check now passes
    /// with `evidence` over its live window (FIX 10474): its pads go into
    /// custody and its payload, as the window imports it, joins the staged
    /// updates, to import as they do. One whose pads do not install imports
    /// nothing: under `answers` it goes, its answer added there; with none,
    /// it stays deferred, its pads' repair scheduled. One a demotion closed
    /// is dropped. Returns whether any left the deferred list installed or
    /// answered.
    ///
    /// # Errors
    ///
    /// A refusal other than a waiting edge endpoint; the update is dropped.
    pub(super) fn install_deferred_sealed_updates(
        &mut self,
        evidence: &HashMap<crate::EntityId, (WindowKey, Vec<u8>)>,
        mut answers: Option<&mut Vec<Vec<u8>>>,
    ) -> Result<bool, TransportError> {
        let mut progressed = false;
        let mut index = 0;
        while index < self.deferred_sealed_updates.len() {
            let key = self.deferred_sealed_updates[index].key.clone();
            let live = self.ensure_window(key.as_str())?;
            // A window demoted since its frame was deferred stays closed.
            if !self.full_window_exchange_allowed(key.as_str())? {
                self.deferred_sealed_updates.remove(index);
                continue;
            }
            let checked = {
                let payload: &[u8] = &self.deferred_sealed_updates[index].envelope.payload;
                match self.payload_as_admitted(payload, Some(&live.doc)) {
                    // Its door judges it once its pads are in.
                    None => Ok(()),
                    Some(admitted) => check_window_update_with_staged_worlds(
                        &self.vault,
                        &live.doc,
                        &admitted,
                        &key,
                        evidence,
                    ),
                }
            };
            match checked {
                Ok(()) => {}
                Err(crate::Error::InvalidConfig(reason)) if reason == EDGE_ENDPOINT_UNRESOLVED => {
                    index += 1;
                    continue;
                }
                Err(error) => {
                    self.deferred_sealed_updates.remove(index);
                    return Err(TransportError::from_window_admission(
                        &error,
                        "staged world residence denied",
                    ));
                }
            }
            let deferred = self.deferred_sealed_updates.remove(index);
            // Read over its window with the updates still waiting for it
            // (FIX 10480), itself no longer among them.
            let receipt = {
                let staged = self.staged_pad_context(&key, &live.doc);
                admit_window_pads(
                    &self.vault,
                    &key,
                    &deferred.envelope,
                    Some(staged.as_ref().unwrap_or(&live.doc)),
                )
            };
            if receipt.readiness == WindowPadReadiness::NotReady {
                let Some(answers) = answers.as_deref_mut() else {
                    match WINDOW_PAD_PART_REPAIR {
                        WindowPadPartRepair::FreshCapsuleRebind => {
                            self.schedule_world_pad_repair(&key);
                        }
                    }
                    self.deferred_sealed_updates.insert(index, deferred);
                    index += 1;
                    continue;
                };
                answers.extend(self.not_ready_answer(&key, window_sub_tags::UPDATE, &receipt)?);
                progressed = true;
                continue;
            }
            progressed = true;
            // FIX 7608 slice 4: a copy edit lands on its source; a held one imports nothing.
            if let Some(payload) = deferred
                .envelope
                .into_payload()
                .try_map_owned(|payload| self.admitted_window_payload(&key, payload))?
            {
                self.staged_world_updates
                    .push((key, payload.to_vec(), deferred.from));
            }
        }
        Ok(progressed)
    }

    /// A bulk state's envelope for `key`, its pads installed here first.
    /// `cold` is the window's durable state when the window is not open: a
    /// sealed state passes its isolated check over the open window, or else
    /// over `cold`, before its capsule installs (FIX 10474).
    ///
    /// # Errors
    ///
    /// Bytes that are no bulk envelope; a state its check refuses or whose
    /// pads did not install, so nothing of it imports and its marker stays
    /// for the retry.
    pub(super) fn bulk_window_state(
        &self,
        key: &WindowKey,
        state: &[u8],
        cold: Option<&LoroDoc>,
    ) -> Result<Vec<u8>, TransportError> {
        let envelope = transport::decode_window_pad_envelope(state)?;
        if envelope.kind != WindowPadKind::BulkState {
            return Err(invalid("bulk state outside its envelope"));
        }
        // A bulk state is read over the window it lands in, when that is open.
        let readiness = {
            let window = self.window(key.as_str());
            if envelope.form == WindowPadForm::Sealed
                && let Some(doc) = window.as_ref().map(|window| &window.doc).or(cold)
                && let Some(admitted) = self.payload_as_admitted(&envelope.payload, None)
            {
                check_window_update_residence_with_vault(&self.vault, doc, &admitted, key)
                    .map_err(|error| {
                        TransportError::from_window_admission(
                            &error,
                            "bulk window residence denied",
                        )
                    })?;
            }
            admit_window_pads(
                &self.vault,
                key,
                &envelope,
                window.as_ref().map(|window| &window.doc),
            )
            .readiness
        };
        if readiness == WindowPadReadiness::NotReady {
            return Err(TransportError::Storage(
                "bulk window pads not installed".into(),
            ));
        }
        // FIX 7608 slice 4: copy rows land on the sources this device holds.
        self.admitted_whole_payload(key, envelope.payload)
    }

    /// A promotion reply's snapshot of `window`, its envelope in base64, the
    /// pads it owes installed here first. Pads that do not install leave the
    /// snapshot as it is: the reply's pad rows still carry each pad, and the
    /// hydration after it asks again. A sealed snapshot first passes its
    /// isolated check over `held`, the window a retain merges it into, or
    /// over an empty one for a first promotion (FIX 10474); `None` when that
    /// check refuses it, and nothing of it installs.
    pub(super) fn promotion_snapshot(
        &self,
        window: &WindowKey,
        encoded: &str,
        held: Option<&LoroDoc>,
    ) -> Result<Option<Vec<u8>>, TransportError> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| invalid("invalid promotion snapshot"))?;
        let envelope = transport::decode_window_pad_envelope(&bytes)?;
        if envelope.kind != WindowPadKind::Promotion {
            return Err(invalid("promotion snapshot outside its envelope"));
        }
        if envelope.form == WindowPadForm::Sealed {
            let empty;
            let doc = match held {
                Some(doc) => doc,
                None => {
                    empty = LoroDoc::new();
                    &empty
                }
            };
            if let Some(admitted) = self.payload_as_admitted(&envelope.payload, None)
                && let Err(error) = check_promotion_snapshot(&self.vault, doc, &admitted)
            {
                tracing::warn!(%window, kind = ?error.kind(), "promotion snapshot refused");
                return Ok(None);
            }
        }
        // A promotion's snapshot holds its own history.
        if admit_window_pads(&self.vault, window, &envelope, None).readiness
            == WindowPadReadiness::NotReady
        {
            tracing::warn!(%window, "promoted window pads not installed; its pad rows land them");
        }
        // FIX 7608 slice 4: copy rows land on the sources this device holds.
        self.admitted_whole_payload(window, envelope.payload)
            .map(Some)
    }

    /// `doc` with each world update still waiting for `key`, staged or sealed
    /// and deferred, imported over a fork of it, when one is: an update that
    /// follows a waiting one builds on it (FIX 10480, FIX 10474). One that
    /// does not import adds nothing to read over; nothing here is kept.
    fn staged_pad_context(&self, key: &WindowKey, doc: &LoroDoc) -> Option<LoroDoc> {
        let mut staged = self
            .waiting_world_updates()
            .filter(|(staged, _)| *staged == key)
            .peekable();
        staged.peek()?;
        let scratch = doc.fork();
        for (_, bytes) in staged {
            let _ = scratch.import(bytes);
        }
        Some(scratch)
    }

    /// Whether a window frame of `key` about to leave carries what a
    /// device-only world now keeps here: an `UPDATE` by its envelope's
    /// payload, a part by the first frame it follows. A frame that cannot be
    /// read stays. A sealed update kept here is no longer owed an answer.
    pub(crate) fn window_frame_withheld(&self, key: &str, sub_tag: u8, payload: &[u8]) -> bool {
        match sub_tag {
            window_sub_tags::UPDATE => {
                let (id, inner, streams) = match transport::window_pad_frame_payload(payload) {
                    Ok((id, inner, streams)) => (id, Cow::Borrowed(inner), streams),
                    // A first frame whose payload continues in parts: the
                    // payload this device made, read whole (FIX 8247).
                    Err(_) => {
                        let id = transport::window_pad_frame_id(payload);
                        let mut ledger = self.window_pad_ledger();
                        let Some((id, whole)) = ledger
                            .continued
                            .remove(key)
                            .filter(|(made, _)| Some(*made) == id)
                        else {
                            if id.is_some() {
                                tracing::warn!(
                                    window = key,
                                    "window update past one frame withheld: payload not held"
                                );
                            }
                            return true;
                        };
                        drop(ledger);
                        (id, Cow::Owned(whole), true)
                    }
                };
                let withheld = self.update_verdict(key, &inner) != UpdateVerdict::Portable;
                let mut ledger = self.window_pad_ledger();
                if withheld {
                    let digest = *blake3::hash(&inner).as_bytes();
                    ledger.sent.remove(&SentKey::Update(key.to_owned(), digest));
                } else if streams {
                    ledger.released.insert(id);
                }
                withheld
            }
            window_sub_tags::WINDOW_PAD_PART => transport::window_pad_part_id(payload)
                .is_none_or(|id| !self.window_pad_ledger().released.contains(&id)),
            _ => false,
        }
    }
}

/// The envelope id of `frame`, a window frame this device made, when it is a
/// first frame whose payload continues in parts (FIX 8247).
fn continued_frame_id(frame: &[u8]) -> Option<[u8; 32]> {
    let (_, _, payload) = transport::decode_window_sync(frame.get(1..)?).ok()?;
    if transport::window_pad_frame_payload(payload).is_ok() {
        return None;
    }
    transport::window_pad_frame_id(payload)
}
