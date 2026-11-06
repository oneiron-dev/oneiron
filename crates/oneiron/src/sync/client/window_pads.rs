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

mod deferred;

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
    /// A held copy edit: it imports nothing, so its capsule does not install;
    /// its door records the hold.
    Held,
}

/// A sealed payload as its import door reads it (FIX 7608 slice 4, FIX
/// 10474).
enum Translated<'p> {
    /// The bytes it imports.
    Bytes(Cow<'p, [u8]>),
    /// A copy edit that holds on its ruled cause: nothing of it imports.
    Held,
}

/// A whole window state that holds a copy edit is not imported, as its door
/// refuses it.
fn held_whole_state() -> TransportError {
    TransportError::Storage(
        "a whole window state holds a copy edit on its ruled cause; it is not imported".into(),
    )
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
        self.document_parts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
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
                SealedCheck::Held => {
                    if self.record_held_window_payload(key, &envelope.payload)? {
                        return Ok(ControlFlow::Break(Vec::new()));
                    }
                    // Its door admits it after all: it installs as any other.
                }
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
            if envelope.form == WindowPadForm::Sealed {
                let admitted = match self.payload_as_admitted(&envelope.payload, None)? {
                    Translated::Bytes(admitted) => admitted,
                    Translated::Held => return Err(held_whole_state()),
                };
                if let Some(doc) = window.as_ref().map(|window| &window.doc).or(cold) {
                    check_window_update_residence_with_vault(&self.vault, doc, &admitted, key)
                        .map_err(|error| {
                            TransportError::from_window_admission(
                                &error,
                                "bulk window residence denied",
                            )
                        })?;
                }
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
    /// check or the promotion byte bound refuses it, and nothing of it
    /// installs.
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
            let admitted = match self.payload_as_admitted(&envelope.payload, None)? {
                Translated::Bytes(admitted) => admitted,
                Translated::Held => return Err(held_whole_state()),
            };
            // The promotion door bounds the translated snapshot this returns
            // (`MAX_PROMOTION_SNAPSHOT_BYTES`): one past it is refused here,
            // before its pads install.
            if admitted.len() > crate::sync::residence::MAX_PROMOTION_SNAPSHOT_BYTES {
                tracing::warn!(%window, bytes = admitted.len(), "promotion snapshot too large");
                return Ok(None);
            }
            if let Err(error) = check_promotion_snapshot(&self.vault, doc, &admitted) {
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
