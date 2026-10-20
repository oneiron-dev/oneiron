//! The self-host shipper's requests, planned to the intake's bounds (TL-6):
//! a window per piece packed into batches, and the withdrawal and receipt
//! asks, each counted as reqwest encodes it before it is sent.
//!
//! A piece's window starts where the intake's last signed receipt says it
//! resumes: the head while the intake lacks it, the next items of each list
//! (up to the page bound), then the next bytes of the sealed stream, cut
//! into parts of at most the part bound (a part may cut a chunk), and the
//! final once the window reaches every total. Windows join a batch while it
//! holds fewer entries than the batch bound and its encoded size stays
//! within the request bound: the JSON part, every part's multipart framing
//! as reqwest writes it, and the bytes. Nothing is capped or skipped (Rule
//! 5): a window that does not fit goes in the next request, and what a
//! window leaves goes in the piece's next one.
//!
//! The bounds start at LC's recommended codec numbers ([`START`], CALLS
//! TL6_WINDOW_START) and only ever tighten, for this process. A `413`'s
//! advertised bounds are taken where they are stricter, and a `413` that
//! advertises none (or none stricter) halves the dimension it names, the
//! request bytes when it names none. A request whose time ran out halves
//! the request and part bytes (CALLS TL6_UPLOAD_TIMEOUT). When not even the
//! smallest request fits a bound, it is sent as it is: there is none
//! smaller.

use std::io::Read as _;
use std::time::Duration;

use oneiron_vault_contract::conversation_training::{
    PIECE_WIRE_VERSION, PieceBatchV1, PieceCursorV1, PieceEntryV1, PieceErrorBodyV1,
    PieceMetaPageV1, PiecePartV1, PieceReceiptAskV1, PieceWithdrawalV1,
};
use reqwest::blocking::multipart::{Form, Part};
use serde::Serialize;

use super::super::http::REQUEST_TIMEOUT;
use super::Shipment;

/// One mebibyte.
const MIB: u64 = 1024 * 1024;

/// CALLS TL6_WINDOW_START: LC's recommended codec numbers, where this
/// process's bounds start.
pub(super) const START: Bounds = Bounds {
    request_bytes: 19 * MIB,
    part_bytes: 18 * MIB,
    items_per_page: 128,
    pieces_per_batch: 16,
};
/// CALLS TL6_UPLOAD_TIMEOUT (Engine, 10-21): the slowest uplink a `POST`'s
/// time allows for, in bytes a second. A `POST` has the client's 30 s, plus
/// a second for each this many bytes of its body.
pub(super) const UPLINK_FLOOR: u64 = 64 * 1024;
/// CALLS TL6_STATUS_PACE (Engine, 10-21): a process asks the intake for
/// owed receipts at most this often, since the intake allows an address
/// about 120 attempts an hour. Uploads and unacknowledged withdrawals keep
/// the 30 s pass.
pub(super) const STATUS_PACE: Duration = Duration::from_secs(15 * 60);

/// Where a piece the intake has signed nothing for starts.
pub(super) const FROM_START: PieceCursorV1 = PieceCursorV1 {
    next_index: 0,
    next_offset: 0,
    persons_next: 0,
    worlds_next: 0,
    chunks_next: 0,
    head_received: false,
};

/// The type of every JSON body and part.
pub(super) const JSON: &str = "application/json";
/// The multipart part that carries a batch's JSON.
const BATCH_PART: &str = "batch";
/// Lower-case hex characters of a BLAKE3 digest.
const DIGEST_HEX: usize = 64;
/// The JSON of an absent final, which a final replaces.
const NULL: &str = "null";

/// The intake's bounds on one request, as this process knows them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Bounds {
    /// The most bytes one request carries, encoded whole.
    pub(super) request_bytes: u64,
    /// The most bytes one sealed part carries.
    pub(super) part_bytes: u64,
    /// The most items one list of one facts page carries.
    pub(super) items_per_page: u64,
    /// The most piece entries, withdrawals or receipt asks one request
    /// carries.
    pub(super) pieces_per_batch: u64,
}

impl Bounds {
    /// Learns from a `413` and its `refusal`: each bound it advertises is
    /// taken where it is stricter, and when that tightens nothing, the
    /// dimension it names halves (the request bytes when it names none).
    /// Whether any bound tightened; `false` once the request is cut as
    /// small as it goes.
    pub(super) fn split(&mut self, refusal: Option<&PieceErrorBodyV1>) -> bool {
        let before = *self;
        if let Some(advertised) = refusal.and_then(|refusal| refusal.bounds.as_ref()) {
            self.request_bytes = stricter(self.request_bytes, advertised.max_request_bytes);
            self.part_bytes = stricter(self.part_bytes, advertised.max_part_bytes);
            self.items_per_page = stricter(self.items_per_page, advertised.max_items_per_page);
            self.pieces_per_batch =
                stricter(self.pieces_per_batch, advertised.max_pieces_per_batch);
        }
        if *self == before {
            let named = refusal.and_then(|refusal| refusal.dimension.as_deref());
            let dimension = match named.map(|name| name.strip_prefix("max_").unwrap_or(name)) {
                Some("part_bytes") => &mut self.part_bytes,
                Some("items_per_page") => &mut self.items_per_page,
                Some("pieces_per_batch") => &mut self.pieces_per_batch,
                _ => &mut self.request_bytes,
            };
            *dimension = half(*dimension);
        }
        *self != before
    }

    /// Learns from a request whose time ran out (CALLS TL6_UPLOAD_TIMEOUT):
    /// the request and part bytes halve. Whether either tightened.
    pub(super) fn slow(&mut self) -> bool {
        let before = *self;
        self.request_bytes = half(self.request_bytes);
        self.part_bytes = half(self.part_bytes);
        *self != before
    }
}

/// The stricter of a bound held and one advertised; never below 1.
fn stricter(held: u64, advertised: u64) -> u64 {
    held.min(advertised).max(1)
}

/// Half a bound; never below 1.
fn half(bound: u64) -> u64 {
    (bound / 2).max(1)
}

/// A `POST`'s whole time for a body of `len` bytes (CALLS
/// TL6_UPLOAD_TIMEOUT): the client's 30 s, plus a second for each
/// [`UPLINK_FLOOR`] bytes.
pub(super) fn post_timeout(len: usize) -> Duration {
    let len = u64::try_from(len).unwrap_or(u64::MAX);
    REQUEST_TIMEOUT.saturating_add(Duration::from_secs(len.div_ceil(UPLINK_FLOOR)))
}

/// One planned window of one piece.
pub(super) struct Window {
    /// Its entry. Its parts' digests are placeholders of the same length
    /// until [`Window::seal`] reads them.
    pub(super) entry: PieceEntryV1,
    /// The stream offset its parts start at.
    pub(super) start: u64,
    /// The stream offset its parts end at.
    pub(super) end: u64,
    /// Whether its facts reach every list's total, so a final may close it.
    facts_whole: bool,
}

impl Window {
    /// Whether the window carries anything: a facts page, a part or a final.
    fn carries(&self) -> bool {
        self.entry.meta.is_some() || !self.entry.parts.is_empty() || self.entry.finish.is_some()
    }

    /// Cuts `bytes`, the window's stream range read whole, into its parts,
    /// and writes each part's digest into its entry: each part's name and
    /// bytes, in order.
    ///
    /// # Errors
    /// `bytes` that are not the window's range.
    pub(super) fn seal(&mut self, mut bytes: Vec<u8>) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
        if u64::try_from(bytes.len())? != self.end.saturating_sub(self.start) {
            anyhow::bail!("a window's bytes are not its range");
        }
        let mut sealed = Vec::with_capacity(self.entry.parts.len());
        for part in self.entry.parts.iter_mut().rev() {
            let at = usize::try_from(part.offset.saturating_sub(self.start))?;
            if at > bytes.len() {
                anyhow::bail!("a window's part starts outside its range");
            }
            let range = bytes.split_off(at);
            part.digest = oneiron_vault_contract::hex(blake3::hash(&range).as_bytes());
            sealed.push((part.part_name.clone(), range));
        }
        sealed.reverse();
        Ok(sealed)
    }
}

/// The windows of one request, planned from the first of `shipments`: one
/// each for as many of them, in order, as fit `bounds`; at least the first
/// one's, the smallest there is when not even it fits.
///
/// # Errors
/// A window that does not encode.
pub(super) fn plan(shipments: &[Shipment], bounds: Bounds) -> anyhow::Result<Vec<Window>> {
    let base = framing(None)?;
    let mut sizer = Sizer {
        size: base.saturating_add(json_len(&batch(Vec::new(), Vec::new()))?),
        entries: 0,
        parts: 0,
    };
    let mut windows = Vec::new();
    for shipment in shipments {
        if u64::try_from(windows.len())? >= bounds.pieces_per_batch {
            break;
        }
        let Some(window) = fit(shipment, bounds, &mut sizer, base)? else {
            break;
        };
        windows.push(window);
    }
    if windows.is_empty()
        && let Some(shipment) = shipments.first()
    {
        windows.push(smallest(shipment));
    }
    Ok(windows)
}

/// A request's encoded size as it is planned, as reqwest writes it: the
/// JSON part's bytes, every part's multipart framing, and the sealed bytes.
struct Sizer {
    /// The bytes counted so far.
    size: u64,
    /// The piece entries so far.
    entries: usize,
    /// The sealed parts so far, which number the next part's name.
    parts: usize,
}

/// The window of `shipment` that fits what is left of the request `sizer`
/// counts, counted into it; `None` when none would carry anything there.
/// A window alone in its request halves its items until its facts fit.
fn fit(
    shipment: &Shipment,
    bounds: Bounds,
    sizer: &mut Sizer,
    base: u64,
) -> anyhow::Result<Option<Window>> {
    let Some(room) = bounds.request_bytes.checked_sub(sizer.size) else {
        return Ok(None);
    };
    let alone = sizer.entries == 0;
    let mut items = bounds.items_per_page;
    let (mut window, mut cost) = loop {
        let window = facts(shipment, items);
        let cost = json_len(&window.entry)?.saturating_add(u64::from(!alone));
        if cost <= room {
            break (window, cost);
        }
        if !alone || items <= 1 {
            return Ok(None);
        }
        items /= 2;
    };
    let piece = &shipment.piece;
    let finish = piece.finish();
    let finish_cost = json_len(&finish)?.saturating_sub(len_u64(NULL.len()));
    // A window whose facts are whole keeps the final's room back from its
    // bytes, so the window that sends the last byte closes the piece.
    let reserve = if window.facts_whole { finish_cost } else { 0 };
    while window.end < piece.total_bytes {
        let name = format!(
            "part-{}",
            sizer.parts.saturating_add(window.entry.parts.len())
        );
        let frame = framing(Some(&name))?.saturating_sub(base);
        let comma = u64::from(!window.entry.parts.is_empty());
        let largest = bounds.part_bytes.min(piece.total_bytes - window.end);
        let index = shipment
            .cursor
            .next_index
            .saturating_add(len_u64(window.entry.parts.len()));
        let mut part = unread_part(index, window.end, largest, name);
        let overhead = json_len(&part)?.saturating_add(comma).saturating_add(frame);
        let spent = cost.saturating_add(reserve).saturating_add(overhead);
        let left = room.saturating_sub(spent);
        if left == 0 {
            break;
        }
        part.bytes = largest.min(left);
        let bytes = part.bytes;
        cost = cost
            .saturating_add(json_len(&part)?)
            .saturating_add(comma)
            .saturating_add(frame)
            .saturating_add(bytes);
        window.end = window.end.saturating_add(bytes);
        window.entry.parts.push(part);
        if bytes < largest {
            break;
        }
    }
    if window.facts_whole
        && window.end == piece.total_bytes
        && cost.saturating_add(finish_cost) <= room
    {
        window.entry.finish = Some(finish);
        cost = cost.saturating_add(finish_cost);
    }
    if !window.carries() {
        return Ok(None);
    }
    sizer.size = sizer.size.saturating_add(cost);
    sizer.entries += 1;
    sizer.parts = sizer.parts.saturating_add(window.entry.parts.len());
    Ok(Some(window))
}

/// The smallest window of `shipment`: its facts one item a list (and its
/// head while the intake lacks it), else its next byte, else its final.
fn smallest(shipment: &Shipment) -> Window {
    let piece = &shipment.piece;
    let mut window = facts(shipment, 1);
    if window.entry.meta.is_none() && window.end < piece.total_bytes {
        let first = unread_part(
            shipment.cursor.next_index,
            window.end,
            1,
            "part-0".to_owned(),
        );
        window.entry.parts.push(first);
        window.end = window.end.saturating_add(1);
    }
    if window.facts_whole && window.end == piece.total_bytes {
        window.entry.finish = Some(piece.finish());
    }
    window
}

/// The facts of `shipment`'s next window, with no bytes yet: the head
/// while the intake lacks it, and up to `items` of each list from where it
/// resumes.
fn facts(shipment: &Shipment, items: u64) -> Window {
    let piece = &shipment.piece;
    let cursor = &shipment.cursor;
    let head = (!cursor.head_received).then(|| piece.head.clone());
    let persons = page(&piece.persons, cursor.persons_next, items);
    let worlds = page(&piece.worlds, cursor.worlds_next, items);
    let chunks = page(&piece.chunks, cursor.chunks_next, items);
    let facts_whole = reaches(cursor.persons_next, persons.len(), piece.persons.len())
        && reaches(cursor.worlds_next, worlds.len(), piece.worlds.len())
        && reaches(cursor.chunks_next, chunks.len(), piece.chunks.len());
    let carries = head.is_some() || !persons.is_empty() || !worlds.is_empty() || !chunks.is_empty();
    let meta = carries.then(|| PieceMetaPageV1 {
        head,
        persons_from: cursor.persons_next,
        persons,
        worlds_from: cursor.worlds_next,
        worlds,
        chunks_from: cursor.chunks_next,
        chunks,
    });
    let start = cursor.next_offset.min(piece.total_bytes);
    Window {
        entry: PieceEntryV1 {
            code: shipment.code.clone(),
            meta,
            parts: Vec::new(),
            finish: None,
        },
        start,
        end: start,
        facts_whole,
    }
}

/// Up to `items` of `list`, from its index `from`.
fn page<T: Clone>(list: &[T], from: u64, items: u64) -> Vec<T> {
    let from = usize::try_from(from).unwrap_or(usize::MAX);
    let items = usize::try_from(items).unwrap_or(usize::MAX);
    list.iter().skip(from).take(items).cloned().collect()
}

/// Whether `sent` items from index `next` reach a list of `total`.
fn reaches(next: u64, sent: usize, total: usize) -> bool {
    next.saturating_add(len_u64(sent)) >= len_u64(total)
}

/// A sealed part, its digest a placeholder of a digest's length.
fn unread_part(index: u64, offset: u64, bytes: u64, part_name: String) -> PiecePartV1 {
    PiecePartV1 {
        index,
        offset,
        bytes,
        digest: "0".repeat(DIGEST_HEX),
        part_name,
    }
}

/// A batch of `pieces` and `withdrawals`, with no install check (the
/// engine sends none).
pub(super) fn batch(
    pieces: Vec<PieceEntryV1>,
    withdrawals: Vec<PieceWithdrawalV1>,
) -> PieceBatchV1 {
    PieceBatchV1 {
        version: PIECE_WIRE_VERSION,
        pieces,
        withdrawals,
        install_check: None,
    }
}

/// How many of `items`, from the first, one request carries: at most the
/// batch bound, and no more than the request bound once `base` (the
/// request's size with none) and each item's JSON and comma are counted.
/// At least one: the first alone, over a bound, is the smallest request
/// there is.
///
/// # Errors
/// An item that does not encode.
pub(super) fn fitting<T: Serialize>(
    items: &[T],
    bounds: Bounds,
    base: u64,
) -> anyhow::Result<usize> {
    let mut size = base;
    let mut taken = 0;
    for item in items {
        if len_u64(taken) >= bounds.pieces_per_batch {
            break;
        }
        let next = size
            .saturating_add(json_len(item)?)
            .saturating_add(u64::from(taken > 0));
        if next > bounds.request_bytes {
            break;
        }
        size = next;
        taken += 1;
    }
    Ok(taken.max(1).min(items.len()))
}

/// The encoded size of a withdrawals batch with no withdrawal: its one
/// JSON part, framed.
///
/// # Errors
/// A form that does not encode.
pub(super) fn withdrawals_base() -> anyhow::Result<u64> {
    Ok(framing(None)?.saturating_add(json_len(&batch(Vec::new(), Vec::new()))?))
}

/// The size of a receipts ask with no code.
///
/// # Errors
/// An ask that does not encode.
pub(super) fn receipts_base() -> anyhow::Result<u64> {
    json_len(&PieceReceiptAskV1 { codes: Vec::new() })
}

/// One request, encoded.
pub(super) struct Encoded {
    /// Its type, naming its multipart boundary.
    pub(super) content_type: String,
    /// Its body, as reqwest writes it.
    pub(super) body: Vec<u8>,
}

/// Encodes `batch` and its sealed `parts` as one multipart request, as
/// reqwest writes it: the batch's JSON part, then a part per name.
///
/// # Errors
/// A batch or a form that does not encode.
pub(super) fn encode(
    batch: &PieceBatchV1,
    parts: Vec<(String, Vec<u8>)>,
) -> anyhow::Result<Encoded> {
    let json = Part::bytes(serde_json::to_vec(batch)?).mime_str(JSON)?;
    let mut form = Form::new().part(BATCH_PART, json);
    for (name, bytes) in parts {
        form = form.part(name, Part::bytes(bytes));
    }
    let content_type = format!("multipart/form-data; boundary={}", form.boundary());
    let mut body = Vec::new();
    form.into_reader().read_to_end(&mut body)?;
    Ok(Encoded { content_type, body })
}

/// The multipart framing reqwest writes around a batch's JSON part and, if
/// named, one sealed part: a form of those parts with empty bodies, counted
/// as it encodes. The framing never depends on a body, only on its part's
/// name and type, and the boundary's length is fixed.
fn framing(name: Option<&str>) -> anyhow::Result<u64> {
    let mut form = Form::new().part(BATCH_PART, Part::bytes(Vec::new()).mime_str(JSON)?);
    if let Some(name) = name {
        form = form.part(name.to_owned(), Part::bytes(Vec::new()));
    }
    let mut counted = Vec::new();
    form.into_reader().read_to_end(&mut counted)?;
    Ok(len_u64(counted.len()))
}

/// The length of `value`'s compact JSON, as serde_json writes it.
fn json_len<T: Serialize>(value: &T) -> anyhow::Result<u64> {
    Ok(len_u64(serde_json::to_vec(value)?.len()))
}

/// A length as a `u64`.
fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}
