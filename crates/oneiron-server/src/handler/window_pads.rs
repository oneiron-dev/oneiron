//! The home's side of the window pad envelope (KS-5, FIX 7107). Every window
//! frame that carries a window's bytes arrives in its envelope: it is put
//! back together on its socket, and its pads are installed here
//! ([`oneiron::sync::window::admit_window_pads`]) after its admission and
//! before it persists, imports or fans out. Every such frame this home sends
//! leaves in its envelope too, sealed at the socket's last door ([`release`])
//! for the one machine that socket proved, after every withholding recheck:
//! fan-out, version answers, replacements and selector updates alike. What
//! the queues and the fan-out carry before that door is what they carried
//! before; no socket is handed another's capsule.
//!
//! A machine that could not install what this home sealed for it answers
//! `NotReady`: the window goes to that socket as today's carrier for the rest
//! of the connection (KEEP TODAY).

use oneiron::sync::WindowKey;
use oneiron::sync::transport::{
    WindowPadArrival, WindowPadEnvelope, WindowPadReadiness, WindowPadReceipt,
};
use oneiron::sync::window::{carrier_window_pads, prepare_window_pads};

use super::conn_state::ConnState;
use super::socket_stop::StoppingTransport;
use crate::protocol::{self, ProtocolError, window_sub_tags};
use crate::server::SyncServer;

/// What one inbound window frame is, once its envelope is read.
pub(super) enum Inbound {
    /// A notice, as it was.
    Frame,
    /// Done with here: a part still to come, a broken delivery or a receipt.
    Done,
    /// A whole envelope, with the sub-tag its first frame came under.
    Envelope(u8, WindowPadEnvelope),
}

fn invalid(error: oneiron::sync::TransportError) -> ProtocolError {
    ProtocolError::InvalidPayload(protocol::transport_err_msg(error))
}

/// Takes one inbound window frame of `key` under `sub_tag` on this socket. A
/// device's `NotReady` receipt sends it this window as the carrier from now
/// on. A broken delivery is a lost frame: the device sends its row again.
pub(super) fn accept(
    conn_state: &mut ConnState,
    key: &WindowKey,
    sub_tag: u8,
    payload: &[u8],
) -> Result<Inbound, ProtocolError> {
    if sub_tag == window_sub_tags::WINDOW_PAD_RECEIPT {
        if WindowPadReceipt::decode(payload)
            .map_err(invalid)?
            .readiness
            == WindowPadReadiness::NotReady
        {
            tracing::warn!(window = %key, "device did not install window pads; the carrier goes");
            conn_state.window_pad_carrier.insert(key.clone());
        }
        return Ok(Inbound::Done);
    }
    match conn_state
        .window_pads
        .accept(key.as_str(), sub_tag, payload)
        .map_err(invalid)?
    {
        WindowPadArrival::Notice => Ok(Inbound::Frame),
        WindowPadArrival::Streaming => Ok(Inbound::Done),
        WindowPadArrival::Broken => {
            tracing::warn!(window = %key, "window pad envelope arrived incomplete");
            Ok(Inbound::Done)
        }
        WindowPadArrival::Envelope(sub_tag, envelope) => Ok(Inbound::Envelope(sub_tag, envelope)),
    }
}

/// What this home did with the pads of `envelope`, an update of `key` that
/// passed its admission: installed into custody here, committed and read
/// back, before anything of it persists.
pub(super) fn admit(
    server: &SyncServer,
    key: &WindowKey,
    envelope: &WindowPadEnvelope,
) -> WindowPadReceipt {
    oneiron::sync::window::admit_window_pads(server.vault(), key, envelope)
}

/// The receipt frame for an envelope a device sent under `sub_tag`: a
/// residence update's acknowledgment, or an owner-lane update's receipt.
pub(super) fn receipt_frame(
    window_key: &str,
    sub_tag: u8,
    receipt: &WindowPadReceipt,
) -> Result<Vec<u8>, ProtocolError> {
    let answer = if sub_tag == window_sub_tags::RESIDENCE_UPDATE {
        window_sub_tags::RESIDENCE_ACK
    } else {
        window_sub_tags::WINDOW_PAD_RECEIPT
    };
    protocol::encode_window_sync(window_key, answer, &receipt.encode())
        .into_result()
        .map_err(invalid)
}

/// What `frame` becomes as it leaves this socket: a window `UPDATE` or
/// `REPLACEMENT` in its envelope for the machine the socket proved, sealed
/// here from this home's custody, or as today's carrier where it may not be;
/// a message's live partial only where its conversation may go (FIX 9537);
/// any other frame as it is. A frame no envelope can carry is dropped,
/// warned: none was sendable before either.
pub(super) fn release(server: &SyncServer, conn_state: &ConnState, frame: Vec<u8>) -> Vec<Vec<u8>> {
    if !super::ephemeral::releases_frame(server, conn_state, &frame) {
        return Vec::new();
    }
    let enveloped = frame.first() == Some(&protocol::TAG_WINDOW_SYNC)
        && protocol::decode_window_sync(&frame[1..]).is_ok_and(|(_, sub_tag, _)| {
            matches!(
                sub_tag,
                window_sub_tags::UPDATE | window_sub_tags::REPLACEMENT
            )
        });
    if !enveloped {
        return vec![frame];
    }
    let Ok((window_key, sub_tag, payload)) = protocol::decode_window_sync(&frame[1..]) else {
        return Vec::new();
    };
    let Some(key) = WindowKey::try_new(window_key) else {
        return Vec::new();
    };
    let window = server.reassert_manager.window(&key);
    let context = window.as_ref().map(|window| &window.doc);
    // FIX 7608 slice 4: a peer gets a marked repo item's masked copy, made
    // before any pad is. One that cannot be masked is withheld, never sent
    // raw; nothing retires it, so the window's next exchange owes it again.
    let masked =
        match oneiron::sync::selector::prepare_repo_sync_frame(server.vault(), payload, context) {
            Ok(masked) => masked,
            Err(error) => {
                tracing::warn!(window = window_key, %error, "window blob withheld: no masked copy");
                return Vec::new();
            }
        };
    let payload = masked.as_deref().unwrap_or(payload);
    let prepared = if conn_state.window_pad_carrier.contains(&key) {
        carrier_window_pads(server.vault(), &key, payload, context)
    } else {
        prepare_window_pads(
            server.vault(),
            &key,
            payload,
            context,
            conn_state.peer_machine(server.vault()),
        )
    };
    match prepared.frames(window_key, sub_tag, None) {
        Ok((frames, _)) => frames,
        Err(error) => {
            tracing::warn!(
                window = window_key,
                error = protocol::transport_err_msg(error),
                "window frame not enveloped"
            );
            Vec::new()
        }
    }
}

/// Sends `frame` as it leaves this socket ([`release`]); false once a send
/// fails. The frames are made before the send, so the send holds neither
/// the server nor the socket's state.
pub(super) fn send_released<'t>(
    server: &SyncServer,
    conn_state: &ConnState,
    transport: &'t mut StoppingTransport,
    frame: Vec<u8>,
) -> impl Future<Output = bool> + use<'t> {
    let frames = release(server, conn_state, frame);
    async move {
        for frame in frames {
            if !transport.send_binary(frame).await {
                return false;
            }
        }
        true
    }
}
