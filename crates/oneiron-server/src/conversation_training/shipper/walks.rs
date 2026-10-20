//! The self-host shipper's three walks over the vault's anonymous custody
//! (TL-6): the withdrawals, the uploads and the receipts, the last at most
//! once every [`STATUS_PACE`]. Each walks its pages from where its last
//! walk stopped to the end, sends what a page names in as many requests as
//! the bounds take, and applies each answer before the next request. A
//! walk that stops (its endpoint waits, a request's time ran out, or the
//! shipper is stopping) resumes from the start of the page it was on.

use std::path::Path;
use std::time::Instant;

use oneiron::feedback::{ANONYMOUS_PAGE, AnonymousUploadWork};
use oneiron_vault_contract::conversation_training::{
    PIECE_BATCHES_PATH, PIECE_RECEIPTS_PATH, PieceBatchResultV1, PieceEntryV1, PieceReceiptAskV1,
    PieceReceiptCursorAskV1, PieceWithdrawalV1, decode_piece_receipt_page,
};

use super::stream::Piece;
use super::tally::Unread;
use super::window::{self, FROM_START, JSON, STATUS_PACE, Window};
use super::{Pass, Sent, Shipment};

impl Pass<'_> {
    /// The withdrawals: each page of codes to withdraw, from where the last
    /// walk stopped to the end, in batches of codes alone.
    pub(super) fn withdrawals(&mut self) -> anyhow::Result<()> {
        let mut after = self.state.withdrawals_after;
        loop {
            if self.stopping() || !self.state.batches.ready(Instant::now()) {
                return Ok(());
            }
            let Some(page) =
                self.admitted(|| self.vault.anonymous_withdrawal_page(after, ANONYMOUS_PAGE))
            else {
                return Ok(());
            };
            let (work, next) = page?;
            let now = Instant::now();
            let codes: Vec<PieceWithdrawalV1> = work
                .into_iter()
                .filter(|work| self.state.ready(work.id, now))
                .map(|work| PieceWithdrawalV1 { code: work.code })
                .collect();
            if !self.withdraw(&codes)? {
                return Ok(());
            }
            self.state.withdrawals_after = next;
            if next.is_none() {
                return Ok(());
            }
            after = next;
        }
    }

    /// Sends `codes` for withdrawal in as many batches as they take, each
    /// batch's results applied before the next. Whether all were answered;
    /// `false` stops the walk where it is.
    fn withdraw(&mut self, mut codes: &[PieceWithdrawalV1]) -> anyhow::Result<bool> {
        let base = window::withdrawals_base()?;
        while !codes.is_empty() {
            let count = window::fitting(codes, self.state.bounds, base)?;
            let (sent, rest) = codes.split_at(count.min(codes.len()));
            let batch = window::batch(Vec::new(), sent.to_vec());
            let encoded = window::encode(&batch, Vec::new())?;
            let route = PIECE_BATCHES_PATH;
            match self.send(route, &encoded.content_type, encoded.body, decode_results) {
                Sent::Answered(results) => {
                    self.tally.withdrawals += sent.len();
                    if !self.apply_results(&results)? {
                        return Ok(false);
                    }
                    codes = rest;
                }
                Sent::Again => {}
                Sent::Stop => return Ok(false),
            }
        }
        Ok(true)
    }

    /// The uploads: each page of pieces to upload, from where the last walk
    /// stopped to the end, a window each, read from their released files.
    pub(super) fn uploads(&mut self) -> anyhow::Result<()> {
        let mut after = self.state.uploads_after;
        loop {
            if self.stopping() || !self.state.batches.ready(Instant::now()) {
                return Ok(());
            }
            let Some(page) =
                self.admitted(|| self.vault.anonymous_upload_page(after, ANONYMOUS_PAGE))
            else {
                return Ok(());
            };
            let (work, next) = page?;
            let now = Instant::now();
            let due: Vec<AnonymousUploadWork> = work
                .into_iter()
                .filter(|work| self.state.ready(work.id, now))
                .collect();
            let offers = self.shipper.offers.as_path();
            let Some((shipments, unread)) = self.admitted(|| read_pieces(offers, due)) else {
                return Ok(());
            };
            self.tally.unread(unread);
            if !self.ship(&shipments)? {
                return Ok(());
            }
            self.state.uploads_after = next;
            if next.is_none() {
                return Ok(());
            }
            after = next;
        }
    }

    /// Sends a window of each of `shipments` in as many batches as they
    /// take, each batch's results applied before the next. Whether all were
    /// answered; `false` stops the walk where it is.
    fn ship(&mut self, shipments: &[Shipment]) -> anyhow::Result<bool> {
        let mut rest = shipments;
        while !rest.is_empty() {
            let windows = window::plan(rest, self.state.bounds)?;
            let following = rest.get(windows.len()..).unwrap_or_default();
            let offers = self.shipper.offers.as_path();
            let Some(sealed) = self.admitted(|| seal(offers, rest, windows)) else {
                return Ok(false);
            };
            let sealed = sealed?;
            self.tally.unread(sealed.unread);
            if sealed.entries.is_empty() {
                rest = following;
                continue;
            }
            let entries = sealed.entries.len();
            let batch = window::batch(sealed.entries, Vec::new());
            let encoded = window::encode(&batch, sealed.parts)?;
            let route = PIECE_BATCHES_PATH;
            match self.send(route, &encoded.content_type, encoded.body, decode_results) {
                Sent::Answered(results) => {
                    self.tally.windows += entries;
                    if !self.apply_results(&results)? {
                        return Ok(false);
                    }
                    rest = following;
                }
                Sent::Again => {}
                Sent::Stop => return Ok(false),
            }
        }
        Ok(true)
    }

    /// The receipts, at most once every [`STATUS_PACE`] (CALLS
    /// TL6_STATUS_PACE): each page of codes whose next signed state is
    /// owed, from where the last walk stopped to the end, each asked past
    /// the revision applied.
    pub(super) fn receipts(&mut self) -> anyhow::Result<()> {
        let now = Instant::now();
        let paced = self
            .state
            .receipts_at
            .is_some_and(|at| now.saturating_duration_since(at) < STATUS_PACE);
        if paced || self.stopping() || !self.state.receipts.ready(now) {
            return Ok(());
        }
        self.state.receipts_at = Some(now);
        let mut after = self.state.receipts_after;
        loop {
            if self.stopping() || !self.state.receipts.ready(Instant::now()) {
                return Ok(());
            }
            let Some(page) =
                self.admitted(|| self.vault.anonymous_status_page(after, ANONYMOUS_PAGE))
            else {
                return Ok(());
            };
            let (work, next) = page?;
            let asks: Vec<PieceReceiptCursorAskV1> = work
                .into_iter()
                .map(|work| PieceReceiptCursorAskV1 {
                    code: work.code,
                    after_revision: work.revision,
                })
                .collect();
            if !self.ask(&asks)? {
                return Ok(());
            }
            self.state.receipts_after = next;
            if next.is_none() {
                return Ok(());
            }
            after = next;
        }
    }

    /// Asks for the receipts of `asks` in as many requests as they take,
    /// each page applied before the next request. Whether all were
    /// answered; `false` stops the walk where it is.
    fn ask(&mut self, mut asks: &[PieceReceiptCursorAskV1]) -> anyhow::Result<bool> {
        let base = window::receipts_base()?;
        while !asks.is_empty() {
            let count = window::fitting(asks, self.state.bounds, base)?;
            let (sent, rest) = asks.split_at(count.min(asks.len()));
            let body = serde_json::to_vec(&PieceReceiptAskV1 {
                codes: sent.to_vec(),
            })?;
            let decode = |body: &[u8]| decode_piece_receipt_page(body).ok();
            match self.send(PIECE_RECEIPTS_PATH, JSON, body, decode) {
                Sent::Answered(page) => {
                    self.tally.asked += sent.len();
                    let applied = self
                        .admitted(|| self.vault.apply_anonymous_receipt_page(&page, &self.ring));
                    let Some(applied) = applied else {
                        return Ok(false);
                    };
                    if !self.settle(applied?)? {
                        return Ok(false);
                    }
                    asks = rest;
                }
                Sent::Again => {}
                Sent::Stop => return Ok(false),
            }
        }
        Ok(true)
    }
}

/// A batch's answer, when it decodes.
fn decode_results(body: &[u8]) -> Option<PieceBatchResultV1> {
    serde_json::from_slice(body).ok()
}

/// The pieces of `due` whose manifests in `offers` read, each with where
/// it resumes; the rest counted, and read again next pass.
fn read_pieces(offers: &Path, due: Vec<AnonymousUploadWork>) -> (Vec<Shipment>, Unread) {
    let mut shipments = Vec::with_capacity(due.len());
    let mut unread = Unread::default();
    for work in due {
        match Piece::read(offers, work.id) {
            Ok(piece) => shipments.push(Shipment {
                code: work.code,
                piece,
                cursor: work.cursor.unwrap_or(FROM_START),
            }),
            Err(unreadable) => unread.add(unreadable),
        }
    }
    (shipments, unread)
}

/// One batch's windows, their bytes read and sealed.
struct Sealed {
    /// The entries that read whole, in order.
    entries: Vec<PieceEntryV1>,
    /// Their sealed parts: each part's name and bytes.
    parts: Vec<(String, Vec<u8>)>,
    /// The windows whose files did not read, left out.
    unread: Unread,
}

/// Reads the bytes of each of `windows` (the windows of `shipments`, in
/// order) from its piece's files in `offers`, and seals its parts. A window
/// whose files do not read is left out, and its piece read again next pass.
fn seal(offers: &Path, shipments: &[Shipment], windows: Vec<Window>) -> anyhow::Result<Sealed> {
    let mut sealed = Sealed {
        entries: Vec::with_capacity(windows.len()),
        parts: Vec::new(),
        unread: Unread::default(),
    };
    for (mut window, shipment) in windows.into_iter().zip(shipments) {
        if window.end > window.start {
            match shipment.piece.read_range(offers, window.start, window.end) {
                Ok(bytes) => sealed.parts.extend(window.seal(bytes)?),
                Err(unreadable) => {
                    sealed.unread.add(unreadable);
                    continue;
                }
            }
        }
        sealed.entries.push(window.entry);
    }
    Ok(sealed)
}
