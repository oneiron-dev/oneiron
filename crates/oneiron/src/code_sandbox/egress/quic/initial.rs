//! QUIC long headers and Initial frames, as the datagram name gate reads
//! them (FIX 8991): RFC 9000 17.2 and 19, and RFC 9369 3 for version 2.
//!
//! The gate walks a datagram's coalesced long-header packets by their
//! Length fields: Initial, 0-RTT and Handshake. The walk stops at a short
//! header, a Retry, a Version Negotiation packet or a version it does not
//! know. What follows has no boundary the gate can read, so it is opaque.
//! The fixed bit is not checked: a server that greases it (RFC 9287) still
//! reads the packet. The same walk reads the plaintext headers of a
//! server's reply, unopened, for the connection IDs it carries.

/// The QUIC versions whose Initials the gate opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum Version {
    /// QUIC version 1 (RFC 9000).
    One,
    /// QUIC version 2 (RFC 9369).
    Two,
}

impl Version {
    /// The version a long header's version field names, if the gate knows
    /// it. Version 0 is Version Negotiation.
    const fn from_wire(version: u32) -> Option<Self> {
        match version {
            0x0000_0001 => Some(Self::One),
            0x6b33_43cf => Some(Self::Two),
            _ => None,
        }
    }

    /// The packet type a long header's two type bits name in this version
    /// (RFC 9000 17.2, RFC 9369 3.2).
    const fn packet_type(self, bits: u8) -> PacketType {
        match (self, bits) {
            (Self::One, 0) | (Self::Two, 1) => PacketType::Initial,
            (Self::One, 1) | (Self::Two, 2) => PacketType::ZeroRtt,
            (Self::One, 2) | (Self::Two, 3) => PacketType::Handshake,
            _ => PacketType::Retry,
        }
    }
}

/// A long-header packet type.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum PacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

/// One long-header packet of a datagram, bounded by its Length field.
pub(super) struct LongPacket<'a> {
    pub(super) version: Version,
    pub(super) packet_type: PacketType,
    /// Its Destination Connection ID.
    pub(super) dcid: &'a [u8],
    /// Its Source Connection ID.
    pub(super) scid: &'a [u8],
    /// The packet, from its first byte to the end its Length sets.
    pub(super) bytes: &'a [u8],
    /// Where its protected packet number starts in `bytes`.
    pub(super) number_at: usize,
}

/// The long-header packets `datagram` carries, in order, up to where the
/// walk stops.
pub(super) fn long_packets(datagram: &[u8]) -> Vec<LongPacket<'_>> {
    let mut packets = Vec::new();
    let mut rest = datagram;
    while let Some(packet) = long_packet(rest) {
        rest = &rest[packet.bytes.len()..];
        packets.push(packet);
    }
    packets
}

/// The Initial packets `datagram` carries, in order.
pub(super) fn initials(datagram: &[u8]) -> Vec<LongPacket<'_>> {
    long_packets(datagram)
        .into_iter()
        .filter(|packet| packet.packet_type == PacketType::Initial)
        .collect()
}

/// The long-header packet `bytes` starts with, when its type carries a
/// Length. None where the walk stops, or for a packet its own Length does
/// not fit.
fn long_packet(bytes: &[u8]) -> Option<LongPacket<'_>> {
    let mut reader = Reader::new(bytes);
    let first = reader.u8()?;
    if first & 0x80 == 0 {
        return None;
    }
    let version = Version::from_wire(reader.u32()?)?;
    let packet_type = version.packet_type((first >> 4) & 0x03);
    if packet_type == PacketType::Retry {
        return None;
    }
    let dcid = reader.connection_id()?;
    let scid = reader.connection_id()?;
    if packet_type == PacketType::Initial {
        let token = reader.varint()?;
        reader.take(usize::try_from(token).ok()?)?;
    }
    let length = usize::try_from(reader.varint()?).ok()?;
    let number_at = reader.at;
    let end = number_at.checked_add(length)?;
    Some(LongPacket {
        version,
        packet_type,
        dcid,
        scid,
        bytes: bytes.get(..end)?,
        number_at,
    })
}

// The frame types an Initial may carry that the gate reads (RFC 9000 12.4,
// 19): PADDING, PING, ACK, ACK with ECN counts, CRYPTO and the transport
// CONNECTION_CLOSE.
const PADDING: u64 = 0x00;
const PING: u64 = 0x01;
const ACK: u64 = 0x02;
const ACK_ECN: u64 = 0x03;
const CRYPTO: u64 = 0x06;
const CONNECTION_CLOSE: u64 = 0x1c;

/// The CRYPTO frames an opened Initial's payload carries, as offset and
/// bytes, in order. Every frame is read. A frame the gate does not read,
/// or one that does not parse, is why the payload cannot be judged.
pub(super) fn crypto_frames(payload: &[u8]) -> Result<Vec<(u64, &[u8])>, &'static str> {
    let malformed = "an Initial frame does not parse";
    let mut reader = Reader::new(payload);
    let mut crypto = Vec::new();
    while !reader.is_empty() {
        match reader.varint().ok_or(malformed)? {
            PADDING | PING => {}
            kind @ (ACK | ACK_ECN) => reader.ack(kind == ACK_ECN).ok_or(malformed)?,
            CRYPTO => crypto.push(reader.crypto().ok_or(malformed)?),
            CONNECTION_CLOSE => reader.connection_close().ok_or(malformed)?,
            _ => return Err("an Initial carries a frame the gate does not read"),
        }
    }
    Ok(crypto)
}

/// A cursor over QUIC wire fields.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    const fn is_empty(&self) -> bool {
        self.at >= self.bytes.len()
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(len)?;
        let taken = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(taken)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|bytes| bytes[0])
    }

    fn u32(&mut self) -> Option<u32> {
        let bytes = self.take(4)?;
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// A connection ID: a length byte, at most 20 in versions 1 and 2, and
    /// that many bytes.
    fn connection_id(&mut self) -> Option<&'a [u8]> {
        let len = self.u8()?;
        if len > 20 {
            return None;
        }
        self.take(usize::from(len))
    }

    /// A variable-length integer (RFC 9000 16): its first two bits give its
    /// width of 1, 2, 4 or 8 bytes, and the rest its value.
    fn varint(&mut self) -> Option<u64> {
        let first = *self.bytes.get(self.at)?;
        let bytes = self.take(1_usize << (first >> 6))?;
        Some(
            bytes[1..]
                .iter()
                .fold(u64::from(first & 0x3f), |value, byte| {
                    (value << 8) | u64::from(*byte)
                }),
        )
    }

    /// An ACK frame's fields after its type (RFC 9000 19.3).
    fn ack(&mut self, ecn: bool) -> Option<()> {
        // Largest Acknowledged and ACK Delay.
        self.varint()?;
        self.varint()?;
        let ranges = self.varint()?;
        // First ACK Range, then each Gap and ACK Range Length.
        self.varint()?;
        for _ in 0..ranges {
            self.varint()?;
            self.varint()?;
        }
        if ecn {
            for _ in 0..3 {
                self.varint()?;
            }
        }
        Some(())
    }

    /// A CRYPTO frame's offset and data (RFC 9000 19.6).
    fn crypto(&mut self) -> Option<(u64, &'a [u8])> {
        let offset = self.varint()?;
        let length = self.varint()?;
        offset.checked_add(length).filter(|end| *end < 1 << 62)?;
        Some((offset, self.take(usize::try_from(length).ok()?)?))
    }

    /// A transport CONNECTION_CLOSE frame's fields (RFC 9000 19.19).
    fn connection_close(&mut self) -> Option<()> {
        // Error Code and Frame Type.
        self.varint()?;
        self.varint()?;
        let reason = self.varint()?;
        self.take(usize::try_from(reason).ok()?)?;
        Some(())
    }
}
