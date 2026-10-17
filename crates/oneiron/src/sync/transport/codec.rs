//! The own-link codec frame (ARCH-0081 §7, OF-604): zstd-3 on our own sockets.
//!
//! A frame of [`CODEC_MIN_FRAME_BYTES`] or more goes as `[TAG_CODEC][codec][compressed inner
//! frame]` when the peer's hello listed that codec and the wrapped frame is smaller. The
//! receiver unwraps it under a cap and handles the inner frame as usual, so every frame kind
//! gets the codec with no per-kind work. Smaller frames, and frames that do not shrink, go as
//! they are. Each link counts raw and sent bytes per inner tag; [`process_link_bytes`] sums
//! every link in this process.

use std::io::Read;
use std::pin::Pin;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, ready};

use futures_util::{Sink, Stream};
use serde::Serialize;
use tokio_tungstenite::tungstenite::error::{CapacityError, Error as WsError};
use tokio_tungstenite::tungstenite::{Bytes, Message};

use super::{MAX_DECODED_PAYLOAD_BYTES, TAG_PROTOCOL_HELLO, TransportError};

/// Codec frame: `[TAG_CODEC:1][codec id:1][compressed inner frame]`. Never nests.
pub const TAG_CODEC: u8 = 40;

/// Codec ids a hello lists after its version byte.
pub mod codec_ids {
    /// zstd, compressed at [`super::CODEC_ZSTD_LEVEL`].
    pub const ZSTD: u8 = 1;
}

/// The smallest frame worth wrapping (ARCH-0081 §7).
pub const CODEC_MIN_FRAME_BYTES: usize = 16 * 1024;
/// zstd level on our own links (ARCH-0081 §7).
pub const CODEC_ZSTD_LEVEL: i32 = 3;
/// The largest inner frame a sender wraps and a receiver unwraps by default: the shared
/// decoded-payload cap. A larger frame goes plain, as it did before the codec.
pub const MAX_CODEC_INNER_BYTES: usize = MAX_DECODED_PAYLOAD_BYTES;
/// The most codec ids one hello may list.
pub const MAX_HELLO_CODECS: usize = 8;

/// The codecs this build decodes, as its hellos list them.
pub const DECODED_CODEC_IDS: &[u8] = &[codec_ids::ZSTD];

/// The codecs one peer decodes, from its hello. Unknown ids are ignored.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WireCodecs {
    zstd: bool,
}

impl WireCodecs {
    /// A peer that listed nothing, such as a light web client: it gets plain frames.
    pub const NONE: Self = Self { zstd: false };
    /// Our own server and clients: every build decodes zstd.
    pub const OURS: Self = Self { zstd: true };

    /// The codecs named by a hello's id list.
    pub fn from_ids(ids: &[u8]) -> Self {
        Self {
            zstd: ids.contains(&codec_ids::ZSTD),
        }
    }

    /// Whether the peer decodes zstd codec frames.
    pub const fn decodes_zstd(self) -> bool {
        self.zstd
    }
}

/// Builds a hello: `[TAG_PROTOCOL_HELLO][version][codec ids…]`.
pub(super) fn hello_frame(version: u8) -> Vec<u8> {
    let mut frame = Vec::with_capacity(2 + DECODED_CODEC_IDS.len());
    frame.extend_from_slice(&[TAG_PROTOCOL_HELLO, version]);
    frame.extend_from_slice(DECODED_CODEC_IDS);
    frame
}

/// The codecs a hello lists (the FULL frame, tag included).
pub fn decode_protocol_hello_codecs(frame: &[u8]) -> Result<WireCodecs, TransportError> {
    super::decode_protocol_hello(frame)?;
    Ok(WireCodecs::from_ids(&frame[2..]))
}

/// Wraps `frame` for a peer that decodes `peer`, or `None` when it should go plain: the
/// peer decodes nothing we send, the frame is under [`CODEC_MIN_FRAME_BYTES`] or over
/// [`MAX_CODEC_INNER_BYTES`], or the wrapped frame would not be smaller.
pub fn encode_codec_frame(frame: &[u8], peer: WireCodecs) -> Option<Vec<u8>> {
    if !peer.decodes_zstd()
        || frame.len() < CODEC_MIN_FRAME_BYTES
        || frame.len() > MAX_CODEC_INNER_BYTES
        || frame.first() == Some(&TAG_CODEC)
    {
        return None;
    }
    let mut wrapped = Vec::with_capacity(frame.len() / 2);
    wrapped.extend_from_slice(&[TAG_CODEC, codec_ids::ZSTD]);
    let mut encoder = zstd::stream::Encoder::new(wrapped, CODEC_ZSTD_LEVEL).ok()?;
    std::io::Write::write_all(&mut encoder, frame).ok()?;
    let wrapped = encoder.finish().ok()?;
    (wrapped.len() < frame.len()).then_some(wrapped)
}

/// Unwraps a codec frame (the FULL frame, tag included), refusing an inner frame larger
/// than `max_inner` before it is held, an unknown codec, and a nested codec frame.
pub fn decode_codec_frame(frame: &[u8], max_inner: usize) -> Result<Vec<u8>, TransportError> {
    let [TAG_CODEC, codec, compressed @ ..] = frame else {
        return Err(TransportError::InvalidPayload("not a codec frame"));
    };
    if *codec != codec_ids::ZSTD {
        return Err(TransportError::InvalidPayload("unknown codec"));
    }
    let mut decoder = zstd::stream::Decoder::new(compressed)
        .map_err(|_| TransportError::InvalidPayload("zstd decoder init failed"))?;
    let mut inner = Vec::with_capacity(compressed.len().saturating_mul(4).min(max_inner));
    let mut chunk = [0u8; 8192];
    loop {
        let n = decoder
            .read(&mut chunk)
            .map_err(|_| TransportError::InvalidPayload("zstd decompress failed"))?;
        if n == 0 {
            break;
        }
        if inner.len() + n > max_inner {
            return Err(TransportError::FrameTooLarge {
                size: inner.len() + n,
                max: max_inner,
            });
        }
        inner.extend_from_slice(&chunk[..n]);
    }
    match inner.first() {
        None => Err(TransportError::InvalidPayload("empty codec frame")),
        Some(&TAG_CODEC) => Err(TransportError::InvalidPayload("nested codec frame")),
        Some(_) => Ok(inner),
    }
}

/// Inner tags at or past this slot share the last one.
const TAG_SLOTS: usize = 64;

#[derive(Debug, Default)]
struct TagBytes {
    out_frames: AtomicU64,
    out_raw: AtomicU64,
    out_sent: AtomicU64,
    in_frames: AtomicU64,
    in_raw: AtomicU64,
    in_received: AtomicU64,
}

/// Raw and wire bytes per inner frame tag on one link, each way.
#[derive(Debug)]
pub struct LinkBytes {
    tags: [TagBytes; TAG_SLOTS],
}

impl Default for LinkBytes {
    fn default() -> Self {
        Self {
            tags: std::array::from_fn(|_| TagBytes::default()),
        }
    }
}

static PROCESS_LINK_BYTES: LazyLock<LinkBytes> = LazyLock::new(LinkBytes::default);

impl LinkBytes {
    fn slot(&self, tag: u8) -> &TagBytes {
        &self.tags[usize::from(tag).min(TAG_SLOTS - 1)]
    }

    /// Counts one frame sent: `raw` inner bytes went as `sent` bytes on the wire.
    pub fn record_sent(&self, tag: u8, raw: usize, sent: usize) {
        for bytes in [self, &*PROCESS_LINK_BYTES] {
            let slot = bytes.slot(tag);
            slot.out_frames.fetch_add(1, Ordering::Relaxed);
            slot.out_raw.fetch_add(raw as u64, Ordering::Relaxed);
            slot.out_sent.fetch_add(sent as u64, Ordering::Relaxed);
        }
    }

    /// Counts one frame read: `received` wire bytes held `raw` inner bytes.
    pub fn record_received(&self, tag: u8, raw: usize, received: usize) {
        for bytes in [self, &*PROCESS_LINK_BYTES] {
            let slot = bytes.slot(tag);
            slot.in_frames.fetch_add(1, Ordering::Relaxed);
            slot.in_raw.fetch_add(raw as u64, Ordering::Relaxed);
            slot.in_received.fetch_add(received as u64, Ordering::Relaxed);
        }
    }

    /// The tags this link has carried, in tag order.
    pub fn snapshot(&self) -> Vec<TagBytesRow> {
        self.tags
            .iter()
            .enumerate()
            .filter_map(|(tag, bytes)| {
                let row = TagBytesRow {
                    tag: tag as u8,
                    out_frames: bytes.out_frames.load(Ordering::Relaxed),
                    out_raw: bytes.out_raw.load(Ordering::Relaxed),
                    out_sent: bytes.out_sent.load(Ordering::Relaxed),
                    in_frames: bytes.in_frames.load(Ordering::Relaxed),
                    in_raw: bytes.in_raw.load(Ordering::Relaxed),
                    in_received: bytes.in_received.load(Ordering::Relaxed),
                };
                (row.out_frames != 0 || row.in_frames != 0).then_some(row)
            })
            .collect()
    }

    /// Raw and wire bytes over every tag: `(raw, wire)` sent and received.
    pub fn totals(&self) -> ((u64, u64), (u64, u64)) {
        self.snapshot()
            .iter()
            .fold(((0, 0), (0, 0)), |((or, os), (ir, iw)), row| {
                (
                    (or + row.out_raw, os + row.out_sent),
                    (ir + row.in_raw, iw + row.in_received),
                )
            })
    }
}

/// One inner tag's counts. `tag` 63 also holds every higher tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct TagBytesRow {
    pub tag: u8,
    pub out_frames: u64,
    pub out_raw: u64,
    pub out_sent: u64,
    pub in_frames: u64,
    pub in_raw: u64,
    pub in_received: u64,
}

/// Every link in this process, summed per inner tag.
pub fn process_link_bytes() -> Vec<TagBytesRow> {
    PROCESS_LINK_BYTES.snapshot()
}

/// A tungstenite WebSocket that speaks the codec frame: a binary send is wrapped when the
/// peer decodes it, a binary read is unwrapped under the cap, and both are counted. Control
/// and text frames pass untouched.
#[derive(Debug)]
pub struct WireSocket<S> {
    socket: S,
    peer: WireCodecs,
    max_inner: usize,
    bytes: LinkBytes,
}

impl<S> WireSocket<S> {
    /// Wraps `socket` toward a peer that decodes `peer`, unwrapping at most `max_inner` bytes.
    pub fn new(socket: S, peer: WireCodecs, max_inner: usize) -> Self {
        Self {
            socket,
            peer,
            max_inner,
            bytes: LinkBytes::default(),
        }
    }

    /// A socket to our own server. Its hello gate reads the codec list every hello of ours
    /// carries, so it always decodes, and no reply needs to confirm it.
    pub fn to_our_server(socket: S, max_inner: usize) -> Self {
        Self::new(socket, WireCodecs::OURS, max_inner)
    }

    /// This link's counts.
    pub fn link_bytes(&self) -> &LinkBytes {
        &self.bytes
    }

    pub fn get_ref(&self) -> &S {
        &self.socket
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.socket
    }

    fn unwrap_read(&self, frame: Bytes) -> Result<Bytes, WsError> {
        let Some(&tag) = frame.first() else {
            return Ok(frame);
        };
        if tag != TAG_CODEC {
            self.bytes.record_received(tag, frame.len(), frame.len());
            return Ok(frame);
        }
        let inner = decode_codec_frame(&frame, self.max_inner).map_err(|error| match error {
            TransportError::FrameTooLarge { size, max } => {
                WsError::Capacity(CapacityError::MessageTooLong {
                    size,
                    max_size: max,
                })
            }
            other => WsError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                other.to_string(),
            )),
        })?;
        self.bytes
            .record_received(inner[0], inner.len(), frame.len());
        Ok(inner.into())
    }

    fn wrap_send(&self, frame: Bytes) -> Bytes {
        let Some(&tag) = frame.first() else {
            return frame;
        };
        match encode_codec_frame(&frame, self.peer) {
            Some(wrapped) => {
                self.bytes.record_sent(tag, frame.len(), wrapped.len());
                wrapped.into()
            }
            None => {
                self.bytes.record_sent(tag, frame.len(), frame.len());
                frame
            }
        }
    }
}

impl<S> Stream for WireSocket<S>
where
    S: Stream<Item = Result<Message, WsError>> + Unpin,
{
    type Item = Result<Message, WsError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        Poll::Ready(match ready!(Pin::new(&mut this.socket).poll_next(cx)) {
            Some(Ok(Message::Binary(frame))) => Some(this.unwrap_read(frame).map(Message::Binary)),
            other => other,
        })
    }
}

impl<S> Sink<Message> for WireSocket<S>
where
    S: Sink<Message, Error = WsError> + Unpin,
{
    type Error = WsError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), WsError>> {
        Pin::new(&mut self.get_mut().socket).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), WsError> {
        let this = self.get_mut();
        let item = match item {
            Message::Binary(frame) => Message::Binary(this.wrap_send(frame)),
            other => other,
        };
        Pin::new(&mut this.socket).start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), WsError>> {
        Pin::new(&mut self.get_mut().socket).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), WsError>> {
        Pin::new(&mut self.get_mut().socket).poll_close(cx)
    }
}
