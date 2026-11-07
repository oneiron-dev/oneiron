//! HOST-private legal-clone capture framing. This is not the tenant ctl or
//! an owner/member API. Transport authentication belongs to the accepted socket.

use std::io::{self, Read, Write};

use crate::MAX_CTL_LINE;

const MAGIC: [u8; 6] = *b"ONLC\x01\x01";
const RELEASE_MAGIC: [u8; 6] = *b"ONLC\x01\x02";
const ACK: u8 = 0xa1;

/// One actual live registry entry. The source compares this with its own entry;
/// neither these wire fields nor a timestamp confer capture authority.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveSessionTarget {
    pub session_ref: String,
    pub instance: [u8; 16],
}

/// Identity kept INSIDE an encrypted descriptor. Gate decisions, live
/// session entries and on-record messages are separate source families, not
/// interchangeable ids.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(
    tag = "family",
    content = "source",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CaptureSource {
    GateDecision([u8; 16]),
    LiveSession(LiveSessionTarget),
    /// One stored on-record MESSAGE entity, by its 16-byte id.
    Message([u8; 16]),
}

/// Exact native source family chosen by the already admitted HOST order.
/// Whole-family capture is explicit; an empty selected list captures nothing.
#[derive(Clone, PartialEq, Eq)]
pub enum CaptureScope {
    AllClaimFreeGateDecisions,
    GateDecisions(Vec<[u8; 16]>),
    LiveSession(LiveSessionTarget),
    /// Exact stored on-record MESSAGE entities, strictly increasing ids. Each
    /// must be a stored MESSAGE row; it is copied with its document rows and
    /// its outgoing edge rows. Messages stored later are never included.
    Messages(Vec<[u8; 16]>),
    /// New on-record messages, the order's explicit prospective permission:
    /// each new base MESSAGE row the selector covers is sealed to this order
    /// when it lands, while the order stands and before its `ends_at`. No
    /// other scope ever captures a message stored after its request.
    ProspectiveMessages(MessageSelector),
}

/// Which new on-record messages a prospective order covers. Closed; a new
/// selector is a new wire tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageSelector {
    /// Every new base on-record MESSAGE row of this vault.
    Vault,
}

impl CaptureScope {
    pub fn includes(&self, decision: &[u8; 16]) -> bool {
        match self {
            Self::AllClaimFreeGateDecisions => true,
            Self::GateDecisions(ids) => ids.binary_search(decision).is_ok(),
            Self::LiveSession(_) | Self::Messages(_) | Self::ProspectiveMessages(_) => false,
        }
    }

    fn write_to(&self, out: &mut impl Write) -> io::Result<()> {
        match self {
            Self::AllClaimFreeGateDecisions => out.write_all(&[1]),
            Self::GateDecisions(ids) => {
                if !ids.windows(2).all(|pair| pair[0] < pair[1]) {
                    return Err(invalid("legal capture decision order"));
                }
                out.write_all(&[2])?;
                out.write_all(&(ids.len() as u64).to_be_bytes())?;
                for id in ids {
                    out.write_all(id)?;
                }
                Ok(())
            }
            Self::LiveSession(target) => {
                out.write_all(&[3])?;
                out.write_all(&(target.session_ref.len() as u64).to_be_bytes())?;
                out.write_all(target.session_ref.as_bytes())?;
                out.write_all(&target.instance)
            }
            Self::Messages(ids) => {
                if !ids.windows(2).all(|pair| pair[0] < pair[1]) {
                    return Err(invalid("legal capture message order"));
                }
                out.write_all(&[4])?;
                out.write_all(&(ids.len() as u64).to_be_bytes())?;
                for id in ids {
                    out.write_all(id)?;
                }
                Ok(())
            }
            Self::ProspectiveMessages(MessageSelector::Vault) => out.write_all(&[5, 1]),
        }
    }

    fn read_from(input: &mut impl Read) -> io::Result<Self> {
        match read_array::<1>(input)?[0] {
            1 => Ok(Self::AllClaimFreeGateDecisions),
            2 => {
                let count = u64::from_be_bytes(read_array(input)?);
                let mut ids = Vec::new();
                for _ in 0..count {
                    let id = read_array(input)?;
                    if ids.last().is_some_and(|previous| previous >= &id) {
                        return Err(invalid("legal capture decision order"));
                    }
                    ids.try_reserve(1).map_err(io::Error::other)?;
                    ids.push(id);
                }
                Ok(Self::GateDecisions(ids))
            }
            3 => {
                let count = usize::try_from(u64::from_be_bytes(read_array(input)?))
                    .map_err(|_| invalid("legal live session ref length"))?;
                let mut bytes = Vec::new();
                bytes.try_reserve_exact(count).map_err(io::Error::other)?;
                bytes.resize(count, 0);
                input.read_exact(&mut bytes)?;
                let session_ref = String::from_utf8(bytes)
                    .map_err(|_| invalid("legal live session ref UTF-8"))?;
                Ok(Self::LiveSession(LiveSessionTarget {
                    session_ref,
                    instance: read_array(input)?,
                }))
            }
            4 => {
                let count = u64::from_be_bytes(read_array(input)?);
                let mut ids = Vec::new();
                for _ in 0..count {
                    let id = read_array(input)?;
                    if ids.last().is_some_and(|previous| previous >= &id) {
                        return Err(invalid("legal capture message order"));
                    }
                    ids.try_reserve(1).map_err(io::Error::other)?;
                    ids.push(id);
                }
                Ok(Self::Messages(ids))
            }
            5 => match read_array::<1>(input)?[0] {
                1 => Ok(Self::ProspectiveMessages(MessageSelector::Vault)),
                _ => Err(invalid("legal capture message selector")),
            },
            _ => Err(invalid("legal capture scope")),
        }
    }
}

/// One exact HOST-admitted capture. A live-session request waits for that
/// entry's covered close; registration alone is not a captured source.
/// Recipient bytes are a per-order PUBLIC hybrid key, never a private seed.
#[derive(Clone, PartialEq, Eq)]
pub struct CaptureRequest {
    pub order: [u8; 16],
    pub capture: [u8; 16],
    pub source_vault: [u8; 32],
    pub generation: u64,
    pub ends_at: u64,
    pub scope: CaptureScope,
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
        self.scope.write_to(out)?;
        out.write_all(&(self.recipient.len() as u32).to_be_bytes())?;
        out.write_all(&self.recipient)
    }

    pub fn read_from(input: &mut impl Read) -> io::Result<Self> {
        if read_array::<6>(input)? != MAGIC {
            return Err(invalid("legal capture protocol"));
        }
        Self::read_body(input)
    }

    fn read_body(input: &mut impl Read) -> io::Result<Self> {
        let order = read_array(input)?;
        let capture = read_array(input)?;
        let source_vault = read_array(input)?;
        let generation = u64::from_be_bytes(read_array(input)?);
        let ends_at = u64::from_be_bytes(read_array(input)?);
        let scope = CaptureScope::read_from(input)?;
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
            scope,
            recipient,
        })
    }

    pub fn digest(&self) -> io::Result<[u8; 32]> {
        let mut sink = DigestSink(blake3::Hasher::new());
        self.write_to(&mut sink)?;
        Ok(*sink.0.finalize().as_bytes())
    }
}

/// Only this HOST order generation is ended. The receipt is not a claim
/// that HOST clone keys or ciphertext have been destroyed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseLiveOrder {
    pub order: [u8; 16],
    pub source_vault: [u8; 32],
    pub generation: u64,
}

impl ReleaseLiveOrder {
    pub fn write_to(&self, out: &mut impl Write) -> io::Result<()> {
        out.write_all(&RELEASE_MAGIC)?;
        out.write_all(&self.order)?;
        out.write_all(&self.source_vault)?;
        out.write_all(&self.generation.to_be_bytes())
    }

    fn read_body(input: &mut impl Read) -> io::Result<Self> {
        Ok(Self {
            order: read_array(input)?,
            source_vault: read_array(input)?,
            generation: u64::from_be_bytes(read_array(input)?),
        })
    }

    pub fn digest(&self) -> io::Result<[u8; 32]> {
        let mut sink = DigestSink(blake3::Hasher::new());
        self.write_to(&mut sink)?;
        Ok(*sink.0.finalize().as_bytes())
    }
}

/// Accepted only over the manager's kernel-authenticated native connection.
/// This enum is framing, not an authorization token.
pub enum HostLegalRequest {
    Capture(CaptureRequest),
    ReleaseLiveOrder(ReleaseLiveOrder),
}

impl HostLegalRequest {
    pub fn read_from(input: &mut impl Read) -> io::Result<Self> {
        match read_array::<6>(input)? {
            MAGIC => CaptureRequest::read_body(input).map(Self::Capture),
            RELEASE_MAGIC => ReleaseLiveOrder::read_body(input).map(Self::ReleaseLiveOrder),
            _ => Err(invalid("legal request protocol")),
        }
    }
}

struct DigestSink(blake3::Hasher);

impl Write for DigestSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
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
    /// Exact live order registered, but no source snapshot has been pinned.
    Pending = 6,
    /// Exact native order standing ended; not HOST key destruction.
    Released = 7,
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
            6 => FrameKind::Pending,
            7 => FrameKind::Released,
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
    pub source: CaptureSource,
    pub source_key: Vec<u8>,
    pub source_key_digest: [u8; 32],
    pub revision: [u8; 32],
    pub plaintext_fingerprint: [u8; 32],
    pub plaintext_len: u64,
    pub chunk_count: u64,
}

/// Actual source facts encrypted as a live metadata component. A native file
/// is not a producer occurrence or a fabricated published RAW_OUTPUTS row.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LiveSpillMetadata {
    Published {
        raw_key: Vec<u8>,
        raw_file_row: Vec<u8>,
    },
    NativeFile {
        name: String,
        /// Whether the native spill finished, not whether its producer completed.
        finished: bool,
        physical_len: u64,
    },
}

impl LiveSpillMetadata {
    pub fn source_key(&self) -> &[u8] {
        match self {
            Self::Published { raw_key, .. } => raw_key,
            Self::NativeFile { name, .. } => name.as_bytes(),
        }
    }

    pub fn metadata_family(&self) -> &'static str {
        match self {
            Self::Published { .. } => "off-record.raw-output.file",
            Self::NativeFile { .. } => "off-record.native-spill.file",
        }
    }

    pub fn body_family(&self) -> &'static str {
        match self {
            Self::Published { .. } => "off-record.raw-output.body",
            Self::NativeFile { .. } => "off-record.native-spill.body",
        }
    }
}

/// The native source extent actually copied. Written spill covers the final
/// published rows AND frozen native files of the exact live session instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureExtent {
    GateDecisions,
    WrittenLiveSessionSpill,
    /// The selected stored MESSAGE rows with their document and outgoing edge
    /// rows and the result body each still holds, in one source snapshot.
    Messages,
    /// One batch of a prospective order: the exact MESSAGE rows sealed when
    /// they landed, in ordinal order. Rows only: no document or edge rows.
    ProspectiveMessages,
}

/// Immutable completion manifest for its declared extent, encrypted to the
/// SAME order recipient. The descriptor hash covers exact encoded descriptors.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureSummary {
    pub order: [u8; 16],
    pub capture: [u8; 16],
    pub source_vault: [u8; 32],
    pub generation: u64,
    pub ends_at: u64,
    pub decisions: u64,
    pub live_sessions: u64,
    pub live_bodies: u64,
    /// Selected messages copied; zero for gate and live-session captures.
    /// In a prospective batch, the sealed message rows it carries.
    pub messages: u64,
    /// A prospective batch's first outbox ordinal; zero otherwise.
    pub batch_first_ordinal: u64,
    /// A prospective batch's ordinal count (sealed plus missed); zero
    /// otherwise. Ordinals `batch_first_ordinal..+batch_entries` are exactly
    /// the batch, so one acknowledgement never covers another batch.
    pub batch_entries: u64,
    /// New messages of a prospective batch that landed but could not be
    /// sealed: a truthful coverage gap, never claimed as captured.
    pub missed_messages: Vec<[u8; 16]>,
    /// Selected messages whose result attachment names a body the message
    /// no longer holds, or that no row holds: their rows are captured, the
    /// body is not and is never claimed. A held body is component 11
    /// (`MessageResultBody`), revision the BLAKE3 of that message's full
    /// stored entity row. Empty for every other capture.
    pub absent_result_bodies: Vec<[u8; 16]>,
    pub extent: CaptureExtent,
    pub components: u64,
    pub plaintext_bytes: u64,
    /// BLAKE3 over the exact encoded descriptors in stream order. In a
    /// prospective batch, BLAKE3 over each component's descriptor digest
    /// (BLAKE3 of its exact encoded descriptor) in stream order, since those
    /// descriptors were sealed when their messages landed.
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
