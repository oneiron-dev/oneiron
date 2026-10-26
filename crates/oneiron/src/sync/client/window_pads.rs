//! The device's side of the window pad envelope (KS-5, FIX 7107). Each window
//! write it sends goes in its envelope for the home this connection proved
//! ([`prepare_window_pads`]); each envelope the home sends is put back
//! together and its pads installed here ([`admit_window_pads`]) before its
//! payload reaches an import door.
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

use super::base::SyncClient;
use crate::sync::loro_support::doc_version_vector;
use crate::sync::transport::{
    self, TransportError, WindowPadArrival, WindowPadAssembly, WindowPadBinding, WindowPadForm,
    WindowPadKind, WindowPadReadiness, WindowPadReceipt, window_sub_tags,
};
use crate::sync::types::WindowKey;
use crate::sync::window::{
    PreparedWindowPads, UpdateVerdict, WINDOW_PAD_PART_REPAIR, WINDOW_PAD_RECEIPT_WITNESS,
    WindowPadPartRepair, WindowPadReceiptWitness, admit_window_pads, carrier_window_pads,
    prepare_window_pads,
};

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

    /// Forgets every association of the last connection.
    pub(crate) fn reset_window_pads(&self) {
        *self.window_pad_ledger() = WindowPadLedger::default();
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
        let sealed = prepared.form() == WindowPadForm::Sealed;
        let key = match queue_seq {
            Some(seq) => SentKey::Residence(seq),
            None if sealed => SentKey::Update(window_key.to_owned(), binding.payload_digest),
            None => return Ok(frames),
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
        Ok(frames)
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
    /// `RESIDENCE_ACK` or `WINDOW_PAD_RECEIPT`. One that binds a residence
    /// update acknowledges its queued row by that row's own bytes; a
    /// `NotReady` sends the same bytes again as the carrier, returned. A
    /// receipt for no send held here is passed over: its row stays queued.
    pub(super) fn accept_window_pad_receipt(
        &mut self,
        window_key: &str,
        sub_tag: u8,
        payload: &[u8],
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        let receipt = WindowPadReceipt::decode(payload)?;
        let key = if sub_tag == window_sub_tags::RESIDENCE_ACK {
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
        if let SentKey::Residence(seq) = key
            && self
                .residence_acks
                .insert(seq, sent.queued)
                .is_some_and(|old| old != sent.queued)
        {
            return Err(invalid("conflicting residence acknowledgment"));
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
    ) -> Result<ControlFlow<Vec<Vec<u8>>, (u8, Cow<'a, [u8]>)>, TransportError> {
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
                return Ok(ControlFlow::Continue((sub_tag, Cow::Borrowed(payload))));
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
        let receipt = admit_window_pads(&self.vault, key, &envelope);
        if receipt.readiness != WindowPadReadiness::NotReady {
            // FIX 7608 slice 4: a copy edit lands on its source; a held one imports nothing.
            return Ok(match self.admitted_window_payload(key, envelope.payload)? {
                Some(payload) => ControlFlow::Continue((sub_tag, Cow::Owned(payload))),
                None => ControlFlow::Break(Vec::new()),
            });
        }
        // Nothing of it imports. The home is told, sends this window as the
        // carrier from now on, and is asked for it again.
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
        Ok(ControlFlow::Break(vec![
            transport::encode_window_sync(
                key.as_str(),
                window_sub_tags::WINDOW_PAD_RECEIPT,
                &receipt.encode(),
            )
            .into_result()?,
            ask.into_result()?,
        ]))
    }

    /// A bulk state's envelope for `key`, its pads installed here first.
    ///
    /// # Errors
    ///
    /// Bytes that are no bulk envelope; pads that did not install, so nothing
    /// of it imports and its marker stays for the retry.
    pub(super) fn bulk_window_state(
        &self,
        key: &WindowKey,
        state: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        let envelope = transport::decode_window_pad_envelope(state)?;
        if envelope.kind != WindowPadKind::BulkState {
            return Err(invalid("bulk state outside its envelope"));
        }
        if admit_window_pads(&self.vault, key, &envelope).readiness == WindowPadReadiness::NotReady
        {
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
    /// hydration after it asks again.
    pub(super) fn promotion_snapshot(
        &self,
        window: &WindowKey,
        encoded: &str,
    ) -> Result<Vec<u8>, TransportError> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| invalid("invalid promotion snapshot"))?;
        let envelope = transport::decode_window_pad_envelope(&bytes)?;
        if envelope.kind != WindowPadKind::Promotion {
            return Err(invalid("promotion snapshot outside its envelope"));
        }
        if admit_window_pads(&self.vault, window, &envelope).readiness
            == WindowPadReadiness::NotReady
        {
            tracing::warn!(%window, "promoted window pads not installed; its pad rows land them");
        }
        // FIX 7608 slice 4: copy rows land on the sources this device holds.
        self.admitted_whole_payload(window, envelope.payload)
    }

    /// Whether a window frame of `key` about to leave carries what a
    /// device-only world now keeps here: an `UPDATE` by its envelope's
    /// payload, a part by the first frame it follows. A frame that cannot be
    /// read stays. A sealed update kept here is no longer owed an answer.
    pub(crate) fn window_frame_withheld(&self, key: &str, sub_tag: u8, payload: &[u8]) -> bool {
        match sub_tag {
            window_sub_tags::UPDATE => {
                let Ok((id, inner, streams)) = transport::window_pad_frame_payload(payload) else {
                    return true;
                };
                let withheld = self.update_verdict(key, inner) != UpdateVerdict::Portable;
                let mut ledger = self.window_pad_ledger();
                if withheld {
                    let digest = *blake3::hash(inner).as_bytes();
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
