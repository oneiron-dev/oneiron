//! The client Initial keys of a QUIC connection, and the opening of one
//! Initial packet with them (FIX 8991): RFC 9001 5, RFC 9369 3.3.
//!
//! The keys derive from the Destination Connection ID of the connection's
//! first Initial, its key epoch (RFC 9001 5.2): the client keeps them when
//! it sends its later Initials to the ID the server chose. HMAC and HKDF are
//! written here on SHA-256: the engine has no HMAC or HKDF crate of its own.

use super::initial::{LongPacket, Version};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::aes::cipher::BlockEncrypt;
use aes_gcm::aes::{Aes128, Block};
use aes_gcm::{Aes128Gcm, KeyInit};
use sha2::{Digest, Sha256};

/// An Initial packet opened under its connection's client keys.
pub(super) struct OpenedInitial {
    /// Its full packet number.
    pub(super) number: u64,
    /// Its frames, in the clear.
    pub(super) payload: Vec<u8>,
}

/// Opens `packet`, an Initial, under the client keys `epoch` derives: the
/// Destination Connection ID of its connection's first Initial (RFC 9001
/// 5.3, 5.4). Its packet number is rebuilt against `largest`, the largest
/// number of the connection the gate opened, or from 0 for a connection
/// the gate has no flow for. None when it does not authenticate.
pub(super) fn open(
    packet: &LongPacket<'_>,
    epoch: &[u8],
    largest: Option<u64>,
) -> Option<OpenedInitial> {
    let keys = ClientKeys::derive(packet.version, epoch);
    let at = packet.number_at;
    // The sample starts four bytes past the packet number's start,
    // whatever its length, and lies inside this packet.
    let sample = packet.bytes.get(at + 4..at + 20)?.try_into().ok()?;
    let mask = keys.mask(sample);
    let mut header = packet.bytes.get(..at + 4)?.to_vec();
    header[0] ^= mask[0] & 0x0f;
    let length = usize::from(header[0] & 0x03) + 1;
    header.truncate(at + length);
    let mut truncated = 0_u64;
    for (byte, unmask) in header[at..].iter_mut().zip(&mask[1..]) {
        *byte ^= unmask;
        truncated = (truncated << 8) | u64::from(*byte);
    }
    let number = rebuild(largest, truncated, 8 * length as u32);
    let payload = Payload {
        msg: &packet.bytes[at + length..],
        aad: &header,
    };
    let payload = Aes128Gcm::new(&keys.key.into())
        .decrypt(&keys.nonce(number).into(), payload)
        .ok()?;
    Some(OpenedInitial { number, payload })
}

/// The full packet number nearest the one after `largest` whose low `bits`
/// are `truncated` (RFC 9000 A.3). After none it is the number as sent.
fn rebuild(largest: Option<u64>, truncated: u64, bits: u32) -> u64 {
    let expected = largest.map_or(0, |largest| largest + 1);
    let window = 1_u64 << bits;
    let half = window / 2;
    let candidate = (expected & !(window - 1)) | truncated;
    if candidate + half <= expected && candidate < (1 << 62) - window {
        candidate + window
    } else if candidate > expected + half && candidate >= window {
        candidate - window
    } else {
        candidate
    }
}

/// A connection's client Initial packet protection keys.
pub struct ClientKeys {
    key: [u8; 16],
    iv: [u8; 12],
    pub hp: [u8; 16],
}

impl ClientKeys {

    /// The AEAD nonce of packet `number`: the IV with the number XORed
    /// into its right end (RFC 9001 5.3).
    fn nonce(&self, number: u64) -> [u8; 12] {
        let mut nonce = self.iv;
        for (byte, number) in nonce[4..].iter_mut().zip(number.to_be_bytes()) {
            *byte ^= number;
        }
        nonce
    }
}

