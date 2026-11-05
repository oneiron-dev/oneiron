//! The QUIC Initial name gate on the native datagram relay (FIX 8991).
//!
//! The Engine ruled (FIX 8272): a QUIC Initial's server name is judged
//! where it parses, and other opaque TCP and UDP goes on unchanged. The
//! gate reads a datagram only when a name of the owner allowlist admits its
//! address (`RawAuthority::Named`). No allowlist, an allowlisted address
//! and an owner raw endpoint grant admit it unread, as before; port 53
//! stays the host resolver's.
//!
//! The gate walks the datagram's coalesced long-header packets. It opens
//! each version 1 or version 2 Initial under the client keys of the
//! packet's own Destination Connection ID, as a server opens the first
//! Initial of a new connection. An Initial that does not open can open no
//! connection: it is a later Initial of a connection whose first Initial
//! the gate judged, so it goes on. So does an Initial with no CRYPTO
//! frame, and so does all else the walk does not reach.
//!
//! The CRYPTO frames of the opened Initials go to their flow, which
//! reassembles them until the ClientHello is whole. The ClientHello is
//! judged as the stream name gate judges one (FIX 7652), by the same
//! parser: its outer server name must be bound to the address now, and an
//! encrypted ClientHello (ECH) is judged by that outer name. A datagram
//! whose ClientHello is not whole yet is held, and the guest gets no reply
//! for it. The call that makes the ClientHello whole and admits it sends
//! the held datagrams and then its own, in that order, through one socket.
//!
//! What the gate does not do: it judges the name a connection opens with.
//! The relay still sends one datagram batch and reads one reply per call,
//! from a fresh source port, so it is not a full QUIC transport. Opaque UDP
//! to an address a name admits is unchanged, as the ruling says, and that
//! includes the short-header packets of an admitted connection.

mod crypto;
mod flows;
mod initial;
mod reassembly;

use self::flows::{FlowKey, Frames, Step};
pub(super) use self::flows::{FlowTable, Release};
use super::{OpenEgressProxy, dns, name_gate};
use crate::policy_model::{PolicyClassifyDecision, PolicyVerdictCategory};
use std::io;
use std::net::SocketAddr;

/// A datagram the QUIC Initial name gate refused (FIX 8991), with the
/// stream name gate's stable reasons. Nothing it carried is sent; the
/// owner's raw endpoint grant for its endpoint admits it unread.
#[derive(Clone, Debug, thiserror::Error)]
pub enum EgressDatagramNameRefusal {
    /// `egress_name_unverifiable`: the Initial carries no name the
    /// allowlist can check: a ClientHello with no server name or one that
    /// does not parse, a frame the gate does not read, CRYPTO that
    /// disagrees or runs past the ClientHello, or a flow the host-net byte
    /// floor cannot hold.
    #[error(
        "egress_name_unverifiable: the QUIC Initial to {target} carries no name the owner allowlist can check ({why})"
    )]
    Unverifiable {
        target: SocketAddr,
        why: &'static str,
    },
    /// `egress_name_ungranted`: the ClientHello names `name`, which the
    /// allowlist does not admit or which is not bound to the address now.
    #[error(
        "egress_name_ungranted: the QUIC Initial to {target} names {name}, which the owner allowlist does not bind to that address"
    )]
    Ungranted { target: SocketAddr, name: String },
}

impl EgressDatagramNameRefusal {
    /// The refusal's stable reason.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Unverifiable { .. } => "egress_name_unverifiable",
            Self::Ungranted { .. } => "egress_name_ungranted",
        }
    }

    /// The address and port the refused datagram was sent to.
    #[must_use]
    pub const fn target(&self) -> SocketAddr {
        match self {
            Self::Unverifiable { target, .. } | Self::Ungranted { target, .. } => *target,
        }
    }
}

/// What the gate does with one datagram.
pub(super) enum Gated<'a> {
    /// Send it as before: no Initial that opens carries CRYPTO, or its
    /// CRYPTO agrees with its flow's admitted ClientHello.
    Forward,
    /// Its flow holds it; the guest gets no reply for it.
    Held,
    /// Its flow's ClientHello is whole and admitted: send the held
    /// datagrams first, through the same socket.
    Release(Release<'a>),
}

/// Judges `datagram` to `target`, an address a name of the allowlist
/// admits. A refusal is receipted as a blocked `datagram_name` naming the
/// address and port.
pub(super) fn gate<'a>(
    proxy: &'a OpenEgressProxy,
    target: SocketAddr,
    datagram: &[u8],
) -> io::Result<Gated<'a>> {
    let unverifiable = |why| EgressDatagramNameRefusal::Unverifiable { target, why };
    let flows = &proxy.quic_flows;
    let opened = match read(flows, target, datagram) {
        Ok(Some(opened)) => opened,
        Ok(None) => return Ok(Gated::Forward),
        Err(why) => return Err(refuse(proxy, unverifiable(why))),
    };
    let step = flows.ingest(opened.key, opened.number, opened.frames, datagram, proxy);
    let release = match step {
        Step::Agreed => return Ok(Gated::Forward),
        Step::Held => return Ok(Gated::Held),
        Step::Whole(release) => release,
        Step::Refused(refusal) => return Err(refuse(proxy, refusal)),
        Step::Unsettled => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "another call's release of the QUIC flow did not settle",
            ));
        }
    };
    let refusal = match name_gate::client_hello_names(release.hello()) {
        Err(why) => Some(unverifiable(why)),
        Ok(names) => names
            .into_iter()
            .find(|name| !dns::name_bound(proxy, name, target.ip()))
            .map(|name| EgressDatagramNameRefusal::Ungranted { target, name }),
    };
    match refusal {
        None => Ok(Gated::Release(release)),
        Some(refusal) => {
            release.refuse(refusal.clone());
            Err(refuse(proxy, refusal))
        }
    }
}

/// The CRYPTO one datagram's opened Initials carry for their flow.
struct Opened {
    key: FlowKey,
    /// The largest packet number among those Initials.
    number: u64,
    frames: Frames,
}

/// The flow `datagram`'s opened Initials carry CRYPTO for, if any. Their
/// frames are read whole; those of Initials of more than one connection in
/// one datagram cannot be judged.
fn read(
    flows: &FlowTable,
    target: SocketAddr,
    datagram: &[u8],
) -> Result<Option<Opened>, &'static str> {
    let mut found: Option<Opened> = None;
    for packet in initial::initials(datagram) {
        let key = (target, packet.version, packet.dcid.to_vec());
        let Some(opened) = crypto::open(&packet, flows.largest(&key)) else {
            continue;
        };
        let frames: Frames = initial::crypto_frames(&opened.payload).map(|frames| {
            frames
                .into_iter()
                .map(|(offset, data)| (offset, data.to_vec()))
                .collect()
        });
        if frames.as_ref().is_ok_and(Vec::is_empty) {
            continue;
        }
        match found.as_mut() {
            None => {
                found = Some(Opened {
                    key,
                    number: opened.number,
                    frames,
                });
            }
            Some(first) if first.key == key => {
                first.number = first.number.max(opened.number);
                let earlier = std::mem::replace(&mut first.frames, Ok(Vec::new()));
                first.frames = earlier.and_then(|mut all| {
                    all.extend(frames?);
                    Ok(all)
                });
            }
            Some(_) => return Err("the datagram carries Initials of more than one connection"),
        }
    }
    Ok(found)
}

/// Receipts `refusal` as a blocked `datagram_name` naming its address and
/// port, and answers it as the datagram's error.
fn refuse(proxy: &OpenEgressProxy, refusal: EgressDatagramNameRefusal) -> io::Error {
    if let Err(error) = proxy.record(
        "datagram_name",
        &format!("udp://{}", refusal.target()),
        refusal.to_string().as_bytes(),
        PolicyClassifyDecision::Block,
        PolicyVerdictCategory::None,
        None,
    ) {
        tracing::error!(%error, "egress datagram name refusal receipt failed");
    }
    io::Error::new(io::ErrorKind::PermissionDenied, refusal)
}
