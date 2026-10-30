//! The window pad envelope (KS-5, FIX 7107): the one wire form of every frame
//! that carries a window's bytes, an `UPDATE`, a `RESIDENCE_UPDATE` or a
//! `REPLACEMENT`, a nonempty bulk state and a promotion's snapshot.
//!
//! The payload is the window blob with its pad rows as bare references
//! (`world_keys::project_window_pad_refs`); the pads they reference ride
//! beside it in one capsule sealed to the one machine the frame goes to,
//! never another's (`store::seal_world_pad_compartment`). A payload that
//! holds no pad goes alone ([`WindowPadForm::PadFree`]); one a sender could
//! not project or seal goes as today's carrier, marked so
//! ([`WindowPadForm::Carrier`], KEEP TODAY).
//!
//! `header ‖ payload ‖ refs ‖ capsule`, the header [`WINDOW_PAD_HEADER_BYTES`]
//! long. A payload that fits rides the first frame whole, so a frame's
//! release judges all of it; what does not fit after the header follows in
//! order on the same socket as `WINDOW_PAD_PART` frames
//! (`[envelope id:32][offset:8 BE][bytes]`, the id the header's BLAKE3, the
//! offset counted from the header's end): the refs and capsule, and the rest
//! of a payload past one frame, such as a replacement or a catch-up whose
//! window outgrew the floor (FIX 8247). Its receiver joins every part and
//! checks the payload against the header's digest before it reads any of it.
//! The header has its own allowance over the frame floor, so an update that
//! fit one frame before still does.
//!
//! A receiver answers with its receipt ([`WindowPadReceipt`]): the digests,
//! recipient and position the envelope bound, and whether the pads it owed
//! are installed there.

mod parts;

pub use parts::{WindowPadArrival, WindowPadAssembly};

use super::{
    MAX_ENCODED_FRAME_BYTES, TAG_WINDOW_SYNC, TransportError, validate_window_key, window_sub_tags,
};

const MAGIC: &[u8; 4] = b"OWP1";
const RECEIPT_MAGIC: &[u8; 4] = b"OWR1";
/// The derive-key context of a reference list's digest.
const REFS_CONTEXT: &str = "oneiron/window-pads/refs/v1";

/// magic (4) ‖ kind (1) ‖ form (1) ‖ queue seq (8) ‖ payload length (4) ‖
/// payload digest (32) ‖ reference count (4) ‖ recipient (16) ‖ source
/// position (96) ‖ capsule digest (32) ‖ capsule length (4); every integer
/// big-endian, every absent field zero.
pub const WINDOW_PAD_HEADER_BYTES: usize = 4 + 1 + 1 + 8 + 4 + 32 + 4 + 16 + 96 + 32 + 4;
/// One reference: the pad's full id, world (16) ‖ generation (8) ‖ mint (16).
const REF_BYTES: usize = 40;
/// magic (4) ‖ kind (1) ‖ readiness (1) ‖ queue seq (8) ‖ payload digest (32)
/// ‖ references digest (32) ‖ recipient (16) ‖ source position (96) ‖
/// capsule digest (32).
const RECEIPT_BYTES: usize = 4 + 1 + 1 + 8 + 32 + 32 + 16 + 96 + 32;
/// A part frame's lead: its envelope's id and the offset of its bytes past
/// the payload.
const PART_LEAD: usize = 32 + 8;

/// What an envelope's payload is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowPadKind {
    Update,
    ResidenceUpdate,
    Replacement,
    BulkState,
    Promotion,
}

impl WindowPadKind {
    /// The kind a window frame's sub-tag carries; `None` for a notice.
    pub fn of_sub_tag(sub_tag: u8) -> Option<Self> {
        match sub_tag {
            window_sub_tags::UPDATE => Some(Self::Update),
            window_sub_tags::RESIDENCE_UPDATE => Some(Self::ResidenceUpdate),
            window_sub_tags::REPLACEMENT => Some(Self::Replacement),
            _ => None,
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::Update => 0,
            Self::ResidenceUpdate => 1,
            Self::Replacement => 2,
            Self::BulkState => 3,
            Self::Promotion => 4,
        }
    }

    fn from_tag(tag: u8) -> Option<Self> {
        [
            Self::Update,
            Self::ResidenceUpdate,
            Self::Replacement,
            Self::BulkState,
            Self::Promotion,
        ]
        .into_iter()
        .find(|kind| kind.tag() == tag)
    }
}

/// How an envelope's payload carries its pads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowPadForm {
    /// No pad: nothing is owed.
    PadFree,
    /// Bare references, their pads in the capsule sealed to the recipient.
    Sealed,
    /// Today's carrier, as the sender holds it: a projection, recipient or
    /// custody fault, or a machine the world's pads do not go to.
    Carrier,
}

impl WindowPadForm {
    fn tag(self) -> u8 {
        match self {
            Self::PadFree => 0,
            Self::Sealed => 1,
            Self::Carrier => 2,
        }
    }

    fn from_tag(tag: u8) -> Option<Self> {
        [Self::PadFree, Self::Sealed, Self::Carrier]
            .into_iter()
            .find(|form| form.tag() == tag)
    }
}

/// The capsule beside a sealed payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowPadSidecar {
    /// The one machine it is sealed to.
    pub recipient: [u8; 16],
    /// The sender's custody position it is bound to; its first 32 bytes name
    /// the vault.
    pub source_position: [u8; 96],
    /// BLAKE3 of [`Self::capsule`].
    pub digest: [u8; 32],
    pub capsule: Vec<u8>,
}

/// One window frame's bytes and the pads they owe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowPadEnvelope {
    pub kind: WindowPadKind,
    pub form: WindowPadForm,
    /// A residence update's durable queue sequence; none for any other kind.
    pub queue_seq: Option<u64>,
    pub payload: Vec<u8>,
    /// The full id of each pad the payload references, ascending; none
    /// unless sealed.
    pub refs: Vec<[u8; 40]>,
    pub sidecar: Option<WindowPadSidecar>,
}

/// What an envelope bound: what its receipt must name to answer it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowPadBinding {
    pub kind: WindowPadKind,
    pub queue_seq: Option<u64>,
    /// BLAKE3 of the payload as it went: the projected view, never the
    /// envelope or a carrier the sender keeps.
    pub payload_digest: [u8; 32],
    /// The digest of the reference list ([`window_pad_refs_digest`]).
    pub refs_digest: [u8; 32],
    pub recipient: Option<[u8; 16]>,
    pub source_position: Option<[u8; 96]>,
    pub sidecar_digest: Option<[u8; 32]>,
}

/// What a receiver did with an envelope's pads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowPadReadiness {
    /// The payload owed no pad.
    PadFree,
    /// Every pad it owed is installed in current custody here and read back.
    Ready,
    /// It came as today's carrier: its pads land as its rows do.
    KeptCarrier,
    /// Its pads are not installed here, and nothing of it was imported: its
    /// sender sends the same bytes again as the carrier.
    NotReady,
}

impl WindowPadReadiness {
    fn tag(self) -> u8 {
        match self {
            Self::PadFree => 0,
            Self::Ready => 1,
            Self::KeptCarrier => 2,
            Self::NotReady => 3,
        }
    }

    fn from_tag(tag: u8) -> Option<Self> {
        [
            Self::PadFree,
            Self::Ready,
            Self::KeptCarrier,
            Self::NotReady,
        ]
        .into_iter()
        .find(|readiness| readiness.tag() == tag)
    }
}

/// A receiver's answer to one envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowPadReceipt {
    pub binding: WindowPadBinding,
    pub readiness: WindowPadReadiness,
}

fn invalid(why: &'static str) -> TransportError {
    TransportError::InvalidPayload(why)
}

/// The digest of a reference list: its count and every full id in order.
pub fn window_pad_refs_digest(refs: &[[u8; 40]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(REFS_CONTEXT);
    hasher.update(&(refs.len() as u64).to_be_bytes());
    for item in refs {
        hasher.update(item);
    }
    *hasher.finalize().as_bytes()
}

/// `Some` unless every byte is zero, an absent field's form.
fn present<const N: usize>(bytes: [u8; N]) -> Option<[u8; N]> {
    bytes.iter().any(|byte| *byte != 0).then_some(bytes)
}

fn array<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[at..at + N]);
    out
}

fn u32_len(len: usize) -> Result<u32, TransportError> {
    u32::try_from(len).map_err(|_| invalid("window pad envelope field too large"))
}

/// An envelope's header, read.
struct Header {
    kind: WindowPadKind,
    form: WindowPadForm,
    queue_seq: Option<u64>,
    payload_len: usize,
    payload_digest: [u8; 32],
    refs: usize,
    recipient: Option<[u8; 16]>,
    source_position: Option<[u8; 96]>,
    sidecar_digest: Option<[u8; 32]>,
    capsule_len: usize,
}

impl Header {
    fn read(bytes: &[u8]) -> Result<Self, TransportError> {
        let header = bytes
            .get(..WINDOW_PAD_HEADER_BYTES)
            .filter(|header| header.starts_with(MAGIC))
            .ok_or_else(|| invalid("not a window pad envelope"))?;
        let kind = WindowPadKind::from_tag(header[4]).ok_or_else(|| invalid("window pad kind"))?;
        let form = WindowPadForm::from_tag(header[5]).ok_or_else(|| invalid("window pad form"))?;
        let read = Self {
            kind,
            form,
            queue_seq: Some(u64::from_be_bytes(array(header, 6))).filter(|seq| *seq != 0),
            payload_len: u32::from_be_bytes(array(header, 14)) as usize,
            payload_digest: array(header, 18),
            refs: u32::from_be_bytes(array(header, 50)) as usize,
            recipient: present(array(header, 54)),
            source_position: present(array(header, 70)),
            sidecar_digest: present(array(header, 166)),
            capsule_len: u32::from_be_bytes(array(header, 198)) as usize,
        };
        read.check()?;
        Ok(read)
    }

    /// Whether the fields hold together: a residence update and nothing else
    /// has a sequence and a payload; a sealed envelope and nothing else has
    /// references, a recipient, a position and a capsule.
    fn check(&self) -> Result<(), TransportError> {
        let residence = self.kind == WindowPadKind::ResidenceUpdate;
        if self.queue_seq.is_some() != residence || (residence && self.payload_len == 0) {
            return Err(invalid("invalid residence update"));
        }
        let sealed = self.form == WindowPadForm::Sealed;
        if [
            self.refs > 0,
            self.recipient.is_some(),
            self.source_position.is_some(),
            self.sidecar_digest.is_some(),
            self.capsule_len > 0,
        ]
        .into_iter()
        .any(|field| field != sealed)
        {
            return Err(invalid("window pad sidecar fields"));
        }
        Ok(())
    }

    /// Where the payload ends.
    fn head(&self) -> usize {
        WINDOW_PAD_HEADER_BYTES + self.payload_len
    }

    /// The whole envelope's length.
    fn total(&self) -> Option<usize> {
        self.refs
            .checked_mul(REF_BYTES)?
            .checked_add(self.capsule_len)?
            .checked_add(self.head())
    }
}

impl WindowPadEnvelope {
    /// What this envelope binds.
    pub fn binding(&self) -> WindowPadBinding {
        WindowPadBinding {
            kind: self.kind,
            queue_seq: self.queue_seq,
            payload_digest: *blake3::hash(&self.payload).as_bytes(),
            refs_digest: window_pad_refs_digest(&self.refs),
            recipient: self.sidecar.as_ref().map(|sidecar| sidecar.recipient),
            source_position: self.sidecar.as_ref().map(|sidecar| sidecar.source_position),
            sidecar_digest: self.sidecar.as_ref().map(|sidecar| sidecar.digest),
        }
    }

    fn header(&self) -> Result<[u8; WINDOW_PAD_HEADER_BYTES], TransportError> {
        let mut header = [0u8; WINDOW_PAD_HEADER_BYTES];
        header[..4].copy_from_slice(MAGIC);
        header[4] = self.kind.tag();
        header[5] = self.form.tag();
        header[6..14].copy_from_slice(&self.queue_seq.unwrap_or(0).to_be_bytes());
        header[14..18].copy_from_slice(&u32_len(self.payload.len())?.to_be_bytes());
        header[18..50].copy_from_slice(blake3::hash(&self.payload).as_bytes());
        header[50..54].copy_from_slice(&u32_len(self.refs.len())?.to_be_bytes());
        if let Some(sidecar) = &self.sidecar {
            header[54..70].copy_from_slice(&sidecar.recipient);
            header[70..166].copy_from_slice(&sidecar.source_position);
            header[166..198].copy_from_slice(&sidecar.digest);
            header[198..202].copy_from_slice(&u32_len(sidecar.capsule.len())?.to_be_bytes());
        }
        Header::read(&header)?;
        if self.refs.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(invalid("window pad references out of order"));
        }
        Ok(header)
    }

    /// The references and the capsule, end to end.
    fn tail(&self) -> Vec<u8> {
        let capsule = self
            .sidecar
            .as_ref()
            .map_or(&[][..], |sidecar| &sidecar.capsule);
        let mut tail = Vec::with_capacity(self.refs.len() * REF_BYTES + capsule.len());
        for item in &self.refs {
            tail.extend_from_slice(item);
        }
        tail.extend_from_slice(capsule);
        tail
    }

    /// The whole envelope as one byte string: a promotion's snapshot and a
    /// bulk state carry it so.
    ///
    /// # Errors
    ///
    /// Fields that do not hold together, or past a length field.
    pub fn encode(&self) -> Result<Vec<u8>, TransportError> {
        let mut bytes = self.header()?.to_vec();
        bytes.extend_from_slice(&self.payload);
        bytes.extend_from_slice(&self.tail());
        Ok(bytes)
    }

    /// The frames this envelope goes as under `sub_tag` for `window_key`: the
    /// first holds the header and as much of the payload and the rest as the
    /// frame floor and the header's allowance hold, the whole payload whenever
    /// it fits; each `WINDOW_PAD_PART` after it as much of what is left as a
    /// frame holds, a payload past one frame included (FIX 8247).
    ///
    /// # Errors
    ///
    /// A sub-tag of another kind, an invalid key, or fields that do not hold
    /// together or pass a length field.
    pub fn encode_frames(
        &self,
        window_key: &str,
        sub_tag: u8,
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        if WindowPadKind::of_sub_tag(sub_tag) != Some(self.kind) {
            return Err(invalid("window pad envelope of another kind"));
        }
        let key = validate_window_key(window_key)?;
        let header = self.header()?;
        let tail = self.tail();
        let lead = 3 + key.len();
        // The payload and the tail go end to end after the header.
        let body = self.payload.len() + tail.len();
        let inline = body.min(MAX_ENCODED_FRAME_BYTES - lead);
        let [payload, rest] = body_slices(&self.payload, &tail, 0, inline);
        let mut frames = vec![frame(key, sub_tag, &[&header[..], payload, rest])];
        let id = blake3::hash(&header);
        let step = MAX_ENCODED_FRAME_BYTES - lead - PART_LEAD;
        let mut offset = inline;
        while offset < body {
            let end = body.min(offset + step);
            let [payload, rest] = body_slices(&self.payload, &tail, offset, end);
            frames.push(frame(
                key,
                window_sub_tags::WINDOW_PAD_PART,
                &[
                    &id.as_bytes()[..],
                    &(offset as u64).to_be_bytes()[..],
                    payload,
                    rest,
                ],
            ));
            offset = end;
        }
        Ok(frames)
    }
}

/// The bytes of `payload ‖ tail` from `start` to `end`, as the part of each
/// they hold.
fn body_slices<'a>(payload: &'a [u8], tail: &'a [u8], start: usize, end: usize) -> [&'a [u8]; 2] {
    let split = payload.len();
    [
        &payload[start.min(split)..end.min(split)],
        &tail[start.max(split) - split..end.max(split) - split],
    ]
}

/// `[TAG_WINDOW_SYNC][key length][key][sub_tag]` and `parts`, end to end.
fn frame(key: &[u8], sub_tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    let len = 3 + key.len() + parts.iter().map(|part| part.len()).sum::<usize>();
    let mut frame = Vec::with_capacity(len);
    frame.push(TAG_WINDOW_SYNC);
    frame.push(key.len() as u8);
    frame.extend_from_slice(key);
    frame.push(sub_tag);
    for part in parts {
        frame.extend_from_slice(part);
    }
    frame
}

/// A whole envelope from `bytes`: every field checked against the others,
/// the payload against its digest, the references in order and the capsule
/// against its digest.
///
/// # Errors
///
/// Bytes that are no whole envelope.
pub fn decode_window_pad_envelope(bytes: &[u8]) -> Result<WindowPadEnvelope, TransportError> {
    let header = Header::read(bytes)?;
    if header.total() != Some(bytes.len()) {
        return Err(invalid("window pad envelope length"));
    }
    let payload = bytes[WINDOW_PAD_HEADER_BYTES..header.head()].to_vec();
    if *blake3::hash(&payload).as_bytes() != header.payload_digest {
        return Err(invalid("window pad payload digest"));
    }
    let refs_end = header.head() + header.refs * REF_BYTES;
    let refs: Vec<[u8; 40]> = bytes[header.head()..refs_end]
        .chunks_exact(REF_BYTES)
        .map(|item| array(item, 0))
        .collect();
    if refs.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid("window pad references out of order"));
    }
    let sidecar = match (
        header.recipient,
        header.source_position,
        header.sidecar_digest,
    ) {
        (Some(recipient), Some(source_position), Some(digest)) => {
            let capsule = bytes[refs_end..].to_vec();
            if *blake3::hash(&capsule).as_bytes() != digest {
                return Err(invalid("window pad capsule digest"));
            }
            Some(WindowPadSidecar {
                recipient,
                source_position,
                digest,
                capsule,
            })
        }
        _ => None,
    };
    Ok(WindowPadEnvelope {
        kind: header.kind,
        form: header.form,
        queue_seq: header.queue_seq,
        payload,
        refs,
        sidecar,
    })
}

/// The payload a window frame's envelope carries, read from its first frame
/// alone, with the envelope's id and whether parts follow it: what a frame's
/// release judges.
///
/// # Errors
///
/// A frame payload that is no envelope's first frame, or one whose payload
/// continues in parts: no first frame alone judges that one.
pub fn window_pad_frame_payload(frame: &[u8]) -> Result<([u8; 32], &[u8], bool), TransportError> {
    let header = Header::read(frame)?;
    let total = header
        .total()
        .ok_or_else(|| invalid("window pad envelope length"))?;
    if frame.len() < header.head() || frame.len() > total {
        return Err(invalid("window pad envelope length"));
    }
    Ok((
        *blake3::hash(&frame[..WINDOW_PAD_HEADER_BYTES]).as_bytes(),
        &frame[WINDOW_PAD_HEADER_BYTES..header.head()],
        frame.len() < total,
    ))
}

/// The envelope id a `WINDOW_PAD_PART` frame names.
pub fn window_pad_part_id(part: &[u8]) -> Option<[u8; 32]> {
    (part.len() > PART_LEAD).then(|| array(part, 0))
}

/// Whether a node batch member of `sub_tag` holds what its frame must: an
/// envelope's first frame, or a part.
///
/// # Errors
///
/// A member that does not.
pub fn validate_window_pad_member(sub_tag: u8, payload: &[u8]) -> Result<(), TransportError> {
    if sub_tag == window_sub_tags::WINDOW_PAD_PART {
        return window_pad_part_id(payload)
            .map(|_| ())
            .ok_or_else(|| invalid("short window pad part"));
    }
    let header = Header::read(payload)?;
    if WindowPadKind::of_sub_tag(sub_tag) != Some(header.kind) {
        return Err(invalid("window pad envelope of another kind"));
    }
    if header.payload_len == 0 {
        return Err(invalid("batch requires window writes"));
    }
    window_pad_frame_payload(payload).map(|_| ())
}

impl WindowPadReceipt {
    pub fn encode(&self) -> Vec<u8> {
        let binding = &self.binding;
        let mut bytes = Vec::with_capacity(RECEIPT_BYTES);
        bytes.extend_from_slice(RECEIPT_MAGIC);
        bytes.push(binding.kind.tag());
        bytes.push(self.readiness.tag());
        bytes.extend_from_slice(&binding.queue_seq.unwrap_or(0).to_be_bytes());
        bytes.extend_from_slice(&binding.payload_digest);
        bytes.extend_from_slice(&binding.refs_digest);
        bytes.extend_from_slice(&binding.recipient.unwrap_or_default());
        bytes.extend_from_slice(&binding.source_position.unwrap_or([0; 96]));
        bytes.extend_from_slice(&binding.sidecar_digest.unwrap_or_default());
        bytes
    }

    /// # Errors
    ///
    /// Bytes that are no receipt.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() != RECEIPT_BYTES || !bytes.starts_with(RECEIPT_MAGIC) {
            return Err(invalid("not a window pad receipt"));
        }
        let kind = WindowPadKind::from_tag(bytes[4]).ok_or_else(|| invalid("window pad kind"))?;
        let readiness = WindowPadReadiness::from_tag(bytes[5])
            .ok_or_else(|| invalid("window pad readiness"))?;
        Ok(Self {
            binding: WindowPadBinding {
                kind,
                queue_seq: Some(u64::from_be_bytes(array(bytes, 6))).filter(|seq| *seq != 0),
                payload_digest: array(bytes, 14),
                refs_digest: array(bytes, 46),
                recipient: present(array(bytes, 78)),
                source_position: present(array(bytes, 94)),
                sidecar_digest: present(array(bytes, 190)),
            },
            readiness,
        })
    }
}
