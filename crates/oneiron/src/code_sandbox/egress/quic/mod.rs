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
//! each version 1 or version 2 Initial under its connection's client keys:
//! those of the Destination Connection ID the connection's first Initial
//! carried (RFC 9001 5.2). An Initial finds its flow by its own Destination
//! Connection ID or through the flow's alias, and its packet number is
//! rebuilt against the flow's largest. An Initial of no flow opens under
//! the keys of its own Destination Connection ID, its number rebuilt from
//! 0, as a server opens a new connection's first Initial. An Initial that
//! does not open is refused as unverifiable: a server whose packet number
//! state differs from the gate's could still open it and read a ClientHello
//! the gate never judged. An opened Initial of no flow with no CRYPTO frame
//! goes on, and so does all else the walk does not reach.
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
//! The reply to a datagram sent to a named address is walked too, unopened:
//! long headers are plaintext. A version 1 or version 2 server Initial or
//! Handshake whose Destination Connection ID is the client Source
//! Connection ID of one admitted flow at that address, in that version,
//! makes its Source Connection ID that flow's alias. The client's later
//! Initials go there under the flow's keys. A Retry or a Version
//! Negotiation packet teaches nothing: after a Retry the client's next
//! Initial opens under its own new Destination Connection ID and is judged
//! as a new flow. A flow and its alias end together, after the egress
//! datagram timeout; a later Initial of its connection then opens under no
//! keys the gate holds and is refused.
//!
//! What the gate does not do: it judges the name a connection opens with.
//! The relay still sends one datagram batch and reads one reply per call,
//! from a fresh source port, so it is not a full QUIC transport. Every reply
//! the guest gets from a named address passes the gate, but a server
//! datagram the relay does not read reaches neither. A reply in another
//! version than its flow's teaches no alias. Opaque UDP to an address a
//! name admits is unchanged, as the ruling says, and that includes the
//! short-header packets of an admitted connection.

mod crypto;
mod flows;
mod initial;
mod reassembly;

pub(super) use self::flows::{FlowTable, Release};
use self::flows::{Frames, Opened, Step};
use self::initial::PacketType;
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
    /// allowlist can check: it does not open under its connection's keys,
    /// its ClientHello has no server name or does not parse, it carries a
    /// frame the gate does not read or CRYPTO that disagrees or runs past
    /// the ClientHello, or the host-net byte floor cannot hold its flow.
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
    /// Send it as before: it carries no Initial, only Initials of no flow
    /// that carry no CRYPTO, or Initials of an admitted flow whose CRYPTO,
    /// if any, agrees with its ClientHello.
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
    let step = flows.ingest(opened, datagram, proxy);
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

/// Why an Initial that does not open is refused.
const UNOPENED: &str = "an Initial that does not open under its connection's keys";

/// What `datagram`'s Initials carry for their flow, once each opened under
/// its connection's keys; none when they are all of no flow and carry no
/// CRYPTO. Their frames are read whole; Initials of more than one
/// connection in one datagram cannot be judged.
fn read(
    flows: &FlowTable,
    target: SocketAddr,
    datagram: &[u8],
) -> Result<Option<Opened>, &'static str> {
    let mut found: Option<Opened> = None;
    let mut tracked = false;
    for packet in initial::initials(datagram) {
        let flow = flows.connection(target, packet.version, packet.dcid);
        tracked |= flow.is_some();
        let (key, largest) = match flow {
            Some((key, largest)) => (key, Some(largest)),
            None => ((target, packet.version, packet.dcid.to_vec()), None),
        };
        let opened = crypto::open(&packet, &key.2, largest).ok_or(UNOPENED)?;
        let frames: Frames = initial::crypto_frames(&opened.payload).map(|frames| {
            frames
                .into_iter()
                .map(|(offset, data)| (offset, data.to_vec()))
                .collect()
        });
        match found.as_mut() {
            None => {
                found = Some(Opened {
                    key,
                    client_scid: packet.scid.to_vec(),
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
    let crypto_free = found
        .as_ref()
        .is_some_and(|opened| opened.frames.as_ref().is_ok_and(Vec::is_empty));
    if crypto_free && !tracked {
        return Ok(None);
    }
    Ok(found)
}

/// Teaches the flows at `target` the server connection IDs `reply` names:
/// the reply to a datagram to `target`, an address a name of the allowlist
/// admits. Its long headers are read unopened. Each version 1 or version 2
/// server Initial or Handshake makes its Source Connection ID the alias of
/// the one admitted flow whose client's Source Connection ID it is sent to.
/// The walk stops at a Retry or a Version Negotiation packet.
pub(super) fn observe_reply(proxy: &OpenEgressProxy, target: SocketAddr, reply: &[u8]) {
    for packet in initial::long_packets(reply) {
        if matches!(
            packet.packet_type,
            PacketType::Initial | PacketType::Handshake
        ) {
            proxy
                .quic_flows
                .learn_alias(target, packet.version, packet.dcid, packet.scid);
        }
    }
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
