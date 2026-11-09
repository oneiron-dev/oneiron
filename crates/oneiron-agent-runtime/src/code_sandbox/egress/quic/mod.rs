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
//!
//! Lifted half (core split, `oneiron-agent-runtime`): the modules and re-exports below moved out of
//! `oneiron`; everything that stays there is re-exported by the glob.

pub use oneiron::code_sandbox::egress::quic::*;

#[doc(hidden)]
pub mod crypto;
#[doc(hidden)]
pub mod flows;
#[doc(hidden)]
pub mod initial;
#[doc(hidden)]
pub mod reassembly;

pub use crypto::CodeSandboxEgressQuicCryptoClientKeysExt;
pub use flows::CodeSandboxEgressQuicFlowsFlowTableExt;
pub use flows::CodeSandboxEgressQuicFlowsReleaseExt;
pub use flows::CodeSandboxEgressQuicFlowsReleaseExt;
pub use initial::CodeSandboxEgressQuicInitialVersionExt;
pub use initial::CodeSandboxEgressQuicInitialReaderExt;
pub use reassembly::CodeSandboxEgressQuicReassemblyCryptoStreamExt;
