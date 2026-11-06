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

/// One version's Initial salt and packet protection labels.
struct InitialSuite {
    salt: [u8; 20],
    key: &'static [u8],
    iv: &'static [u8],
    hp: &'static [u8],
}

/// Version 1 (RFC 9001 5.1, 5.2).
const VERSION_1: InitialSuite = InitialSuite {
    salt: [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ],
    key: b"quic key",
    iv: b"quic iv",
    hp: b"quic hp",
};

/// Version 2 (RFC 9369 3.3.1, 3.3.2).
const VERSION_2: InitialSuite = InitialSuite {
    salt: [
        0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d,
        0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
    ],
    key: b"quicv2 key",
    iv: b"quicv2 iv",
    hp: b"quicv2 hp",
};

/// The label prefix of HKDF-Expand-Label (RFC 8446 7.1).
const TLS13: &[u8] = b"tls13 ";

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
struct ClientKeys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

impl ClientKeys {
    /// The client Initial keys `version` derives from `dcid` (RFC 9001
    /// 5.2, RFC 9369 3.3). The `client in` label is the same in both.
    fn derive(version: Version, dcid: &[u8]) -> Self {
        let suite = match version {
            Version::One => &VERSION_1,
            Version::Two => &VERSION_2,
        };
        let initial = hmac(&suite.salt, dcid);
        let client: [u8; 32] = expand_label(&initial, b"client in");
        Self {
            key: expand_label(&client, suite.key),
            iv: expand_label(&client, suite.iv),
            hp: expand_label(&client, suite.hp),
        }
    }

    /// The header protection mask of `sample` (RFC 9001 5.4.3): the first
    /// five bytes of its one AES-128 block under the header key.
    fn mask(&self, sample: [u8; 16]) -> [u8; 5] {
        let mut block = Block::from(sample);
        Aes128::new(&self.hp.into()).encrypt_block(&mut block);
        let mut mask = [0; 5];
        mask.copy_from_slice(&block[..5]);
        mask
    }

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

/// HMAC-SHA256 of `message` under `key` (RFC 2104): a 64-byte block, inner
/// pad 0x36 and outer pad 0x5c. HKDF-Extract is this with the salt as key.
fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0; 64];
    if key.len() > block.len() {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new_with_prefix(block.map(|byte| byte ^ 0x36));
    inner.update(message);
    let mut outer = Sha256::new_with_prefix(block.map(|byte| byte ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// HKDF-Expand-Label of `secret` with an empty context (RFC 8446 7.1), for
/// an output of one SHA-256 block or less: the first block of HKDF-Expand,
/// whose info is the output length, the prefixed label and the context.
fn expand_label<const N: usize>(secret: &[u8], label: &[u8]) -> [u8; N] {
    let mut info = Vec::with_capacity(4 + TLS13.len() + label.len() + 1);
    info.extend_from_slice(&(N as u16).to_be_bytes());
    info.push((TLS13.len() + label.len()) as u8);
    info.extend_from_slice(TLS13);
    info.extend_from_slice(label);
    // The empty context's length, then HKDF-Expand's first block counter.
    info.extend_from_slice(&[0, 1]);
    let block = hmac(secret, &info);
    let mut output = [0; N];
    output.copy_from_slice(&block[..N]);
    output
}
