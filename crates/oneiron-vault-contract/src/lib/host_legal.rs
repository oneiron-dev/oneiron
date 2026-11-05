//! HOST-private legal-clone capture framing. This is not the tenant ctl or
//! an owner/member API. Transport authentication belongs to the accepted socket.

use std::io::{self, Read, Write};

use crate::MAX_CTL_LINE;

const MAGIC: [u8; 6] = *b"ONLC\x01\x01";
const ACK: u8 = 0xa1;

/// One explicit, non-prospective claim-free ledger capture. Recipient bytes
/// are a HOST-created per-order PUBLIC hybrid key, never a private seed.
#[derive(Clone, PartialEq, Eq)]
pub struct CaptureRequest {
    pub order: [u8; 16],
    pub capture: [u8; 16],
    pub source_vault: [u8; 32],
    pub generation: u64,
    pub ends_at: u64,
    pub recipient: Vec<u8>,
}

impl CaptureRequest {
    pub fn write_to(&self, out: &mut impl Write) -> io::Result<()> {
        if self.recipient.len() > MAX_CTL_LINE {
            return Err(invalid("legal capture public key framing"));
        }
        out.write_all(&MAGIC)?;
        out.write_all(&self.order)?;
        out.write_all(&self.capture)?;
        out.write_all(&self.source_vault)?;
        out.write_all(&self.generation.to_be_bytes())?;
        out.write_all(&self.ends_at.to_be_bytes())?;
        out.write_all(&(self.recipient.len() as u32).to_be_bytes())?;
        out.write_all(&self.recipient)
    }

    pub fn read_from(input: &mut impl Read) -> io::Result<Self> {
        if read_array::<6>(input)? != MAGIC {
            return Err(invalid("legal capture protocol"));
        }
        let order = read_array(input)?;
        let capture = read_array(input)?;
        let source_vault = read_array(input)?;
        let generation = u64::from_be_bytes(read_array(input)?);
        let ends_at = u64::from_be_bytes(read_array(input)?);
        let len = u32::from_be_bytes(read_array(input)?) as usize;
        if len > MAX_CTL_LINE {
            return Err(invalid("legal capture public key framing"));
        }
        let mut recipient = vec![0; len];
        input.read_exact(&mut recipient)?;
        Ok(Self {
            order,
            capture,
            source_vault,
            generation,
            ends_at,
            recipient,
        })
    }

    pub fn digest(&self) -> io::Result<[u8; 32]> {
        struct Sink(blake3::Hasher);
        impl Write for Sink {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.update(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut sink = Sink(blake3::Hasher::new());
        self.write_to(&mut sink)?;
        Ok(*sink.0.finalize().as_bytes())
    }
}

/// Descriptor and summary payloads are encrypted, not plaintext AAD.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    Accepted = 1,
    Descriptor = 2,
    Content = 3,
    Summary = 4,
    Ready = 5,
}

/// Opaque member/part ordinals only. No source keys or content fingerprints
/// are exposed by this header. Payload is streamed; no capture-wide Vec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    pub kind: FrameKind,
    pub member: u64,
    pub part: u64,
    pub len: u64,
}

impl FrameHeader {
    pub fn bytes(self) -> [u8; 25] {
        let mut out = [0; 25];
        out[0] = self.kind as u8;
        out[1..9].copy_from_slice(&self.member.to_be_bytes());
        out[9..17].copy_from_slice(&self.part.to_be_bytes());
        out[17..25].copy_from_slice(&self.len.to_be_bytes());
        out
    }

    pub fn read_from(input: &mut impl Read) -> io::Result<Self> {
        let raw = read_array::<25>(input)?;
        let kind = match raw[0] {
            1 => FrameKind::Accepted,
            2 => FrameKind::Descriptor,
            3 => FrameKind::Content,
            4 => FrameKind::Summary,
            5 => FrameKind::Ready,
            _ => return Err(invalid("legal capture frame kind")),
        };
        Ok(Self {
            kind,
            member: u64::from_be_bytes(raw[1..9].try_into().expect("fixed header")),
            part: u64::from_be_bytes(raw[9..17].try_into().expect("fixed header")),
            len: u64::from_be_bytes(raw[17..25].try_into().expect("fixed header")),
        })
    }
}

/// HOST sends this only AFTER durably committing the entire capture. Both
/// digests refer to this exact request and the preceding complete frame stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaptureAck {
    pub request: [u8; 32],
    pub transcript: [u8; 32],
}

impl CaptureAck {
    pub fn write_to(self, out: &mut impl Write) -> io::Result<()> {
        out.write_all(&[ACK])?;
        out.write_all(&self.request)?;
        out.write_all(&self.transcript)
    }

    pub fn read_from(input: &mut impl Read) -> io::Result<Self> {
        if read_array::<1>(input)? != [ACK] {
            return Err(invalid("legal capture acknowledgment"));
        }
        Ok(Self {
            request: read_array(input)?,
            transcript: read_array(input)?,
        })
    }
}

fn read_array<const N: usize>(input: &mut impl Read) -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Sensitive source metadata. This is plaintext ONLY inside the encrypted
/// descriptor envelope; never put it in ordinary telemetry or frame headers.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureDescriptor {
    pub component: u8,
    pub decision: [u8; 16],
    pub source_key: Vec<u8>,
    pub source_key_digest: [u8; 32],
    pub revision: [u8; 32],
    pub plaintext_fingerprint: [u8; 32],
    pub plaintext_len: u64,
    pub chunk_count: u64,
}

/// Immutable capture completion manifest, itself encrypted to the SAME
/// order recipient. The descriptor hash covers exact encoded descriptors.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureSummary {
    pub order: [u8; 16],
    pub capture: [u8; 16],
    pub source_vault: [u8; 32],
    pub generation: u64,
    pub ends_at: u64,
    pub decisions: u64,
    pub components: u64,
    pub plaintext_bytes: u64,
    pub descriptors_hash: [u8; 32],
}

/// Actual source-store identity from the already manager-owned process channel.
/// It is not an order/reader credential. HOST binds it to its SAME running Actor
/// before constructing the order-bound capture request that echoes this value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceHello {
    pub source_vault: [u8; 32],
}

impl SourceHello {
    pub fn write_to(self, out: &mut impl Write) -> io::Result<()> {
        out.write_all(b"ONLH\x01")?;
        out.write_all(&self.source_vault)
    }

    pub fn read_from(input: &mut impl Read) -> io::Result<Self> {
        if read_array::<5>(input)? != *b"ONLH\x01" {
            return Err(invalid("legal source hello"));
        }
        Ok(Self {
            source_vault: read_array(input)?,
        })
    }
}
