//! The anonymous training window (TL-6, FIX 5813): the wire a self-host
//! engine ships its released offers and its withdrawals over to the
//! publisher's intake, piece by piece, with no account, install key, vault
//! id, cookie or identifying header. The intake parses its batches with
//! these same types, so every name and byte here is the contract.
//!
//! One logical piece is one engine submission. Its code, C, is 32 bytes the
//! engine derives once, at the submission's first preparation, under its
//! training link key (kind `piece`), and keeps in the submission's custody;
//! the wire spells it as 64 lower-case hex. C is the piece's only handle:
//! the scope, submission id and event sequence its facts carry give no
//! retrieval or withdrawal authority. One C names one byte set for good:
//! the engine never seals again under a C, and on
//! [`PIECE_ERROR_RECIPIENT_REFRESH_REQUIRED`] it drops the piece and offers
//! its source anew, as a new submission under a new C.
//!
//! The routes sit under [`PIECE_ROUTE_PREFIX`]:
//!
//! - `POST` [`PIECE_BATCHES_PATH`]: one multipart request, a JSON part (a
//!   [`PieceBatchV1`]) and the sealed parts it names by `part_name`. A batch
//!   carries windows of pieces (facts pages, sealed byte ranges, a final)
//!   and withdrawals, and every entry gets its own result
//!   ([`PieceBatchResultV1`]).
//! - `POST` [`PIECE_RECEIPTS_PATH`]: a [`PieceReceiptAskV1`] naming codes,
//!   answered by a [`PieceReceiptPageV1`] of signed receipts.
//! - `GET` [`PIECE_KEYS_PATH`]: the intake's public descriptor, a
//!   [`TrainingKeysV1`], with no auth.
//! - [`PIECE_CHALLENGE_PATH`]: the intake's optional install check. The
//!   engine calls none in v1.
//!
//! A piece's facts travel in metadata pages ([`PieceMetaPageV1`]): the
//! scalar head once, then its persons, worlds and chunk table at absolute
//! item indexes. Its sealed stream is its ONEV chunk files concatenated in
//! part order, and travels as byte ranges ([`PiecePartV1`]) that may cut a
//! chunk, so a split never needs a new seal. An item or a range is
//! immutable at its index: an exact repeat is a duplicate, a changed one a
//! conflict. The final ([`PieceFinalV1`]) closes a piece: the intake takes
//! it once every list is complete to its total, the ranges run contiguous
//! from 0 to `total_bytes`, and both digests recompute (the facts digest,
//! [`PieceFactsDigest`](super::PieceFactsDigest), and the stream's BLAKE3).
//!
//! Nothing here caps a count or a size (Rule 5). A conversation, a list or a
//! stream goes whole, in as many pages, ranges and batches as it takes. The
//! intake's bounds are its deployment numbers, which a 413 advertises
//! ([`PieceBoundsV1`]); a client that meets them splits and sends again.

use serde::{Deserialize, Serialize};

use super::{TrainingFilterV2, TrainingSettingV2};

/// The version every [`PieceBatchV1`] carries.
pub const PIECE_WIRE_VERSION: u32 = 1;
/// The public prefix of every window route.
pub const PIECE_ROUTE_PREFIX: &str = "/feedback/training/v1";
/// `POST`, under [`PIECE_ROUTE_PREFIX`]: one multipart batch, answered by a
/// [`PieceBatchResultV1`].
pub const PIECE_BATCHES_PATH: &str = "/batches";
/// `POST`, under [`PIECE_ROUTE_PREFIX`]: a [`PieceReceiptAskV1`], answered by
/// a [`PieceReceiptPageV1`].
pub const PIECE_RECEIPTS_PATH: &str = "/receipts";
/// `GET`, under [`PIECE_ROUTE_PREFIX`]: the [`TrainingKeysV1`] descriptor.
pub const PIECE_KEYS_PATH: &str = "/keys";
/// Under [`PIECE_ROUTE_PREFIX`]: the intake's optional install check
/// challenge ([`PieceInstallCheckV1`]).
pub const PIECE_CHALLENGE_PATH: &str = "/challenge";
/// The domain a [`PieceFactsDigest`](super::PieceFactsDigest) starts with.
pub const PIECE_FACTS_DOMAIN: &str = "oneiron.training.piece.facts.v1";
/// The domain [`piece_receipt_signed_message`] starts with.
pub const PIECE_RECEIPT_DOMAIN: &str = "oneiron.training.piece.receipt.v1";
/// The intake is busy: `429` before the body, or one entry's refusal mid
/// batch. The client waits `retry_after_secs` and tries again.
pub const PIECE_ERROR_CAPACITY_BUSY: &str = "capacity_busy";
/// `413`: the request does not fit the intake's bounds, which it carries
/// ([`PieceBoundsV1`]). Never terminal: the client splits and sends again.
pub const PIECE_ERROR_SPLIT_REQUIRED: &str = "split_required";
/// The piece's sealed bytes are under a recipient the intake no longer
/// opens, and it holds no accepted facts for the piece's C. The engine drops
/// that piece and offers its source anew under the current descriptor.
pub const PIECE_ERROR_RECIPIENT_REFRESH_REQUIRED: &str = "recipient_refresh_required";
/// A supplied install check failed. The client may send again without one.
pub const PIECE_ERROR_INVALID_INSTALL_CHECK: &str = "invalid_install_check";
/// `503`, or one entry's refusal: the intake cannot take it now. The client
/// waits `retry_after_secs` and tries again.
pub const PIECE_ERROR_UNAVAILABLE: &str = "unavailable";

/// The JSON part of one `POST` to [`PIECE_BATCHES_PATH`]. The request's other
/// parts are the sealed byte ranges its pieces name by `part_name`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PieceBatchV1 {
    /// [`PIECE_WIRE_VERSION`].
    pub version: u32,
    /// The piece windows, at most one entry per code.
    pub pieces: Vec<PieceEntryV1>,
    /// The withdrawals, at most one per code.
    pub withdrawals: Vec<PieceWithdrawalV1>,
    /// The intake's optional install check. The engine sends none.
    pub install_check: Option<PieceInstallCheckV1>,
}

/// One window of one piece: any of a facts page, sealed ranges and the
/// final.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PieceEntryV1 {
    /// The piece's code, C, 64 hex.
    pub code: String,
    /// A page of the piece's facts.
    pub meta: Option<PieceMetaPageV1>,
    /// Byte ranges of the piece's sealed stream, consecutive by index and
    /// contiguous by offset; empty when the window carries none.
    pub parts: Vec<PiecePartV1>,
    /// The piece's final, closing it.
    #[serde(rename = "final")]
    pub finish: Option<PieceFinalV1>,
}

/// One page of a piece's facts. Every list item sits at its absolute index,
/// the list's `*_from` plus its place in the page, and is immutable there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PieceMetaPageV1 {
    /// The scalar facts: sent once, then immutable.
    pub head: Option<PieceFactsHeadV1>,
    /// The index of `persons`' first item.
    pub persons_from: u64,
    /// Person codes, 64 hex each: V2's `persons`.
    pub persons: Vec<String>,
    /// The index of `worlds`' first item.
    pub worlds_from: u64,
    /// World codes, 64 hex each: V2's `worlds`.
    pub worlds: Vec<String>,
    /// The index of `chunks`' first item.
    pub chunks_from: u64,
    /// Rows of the piece's ONEV chunk table, in part order.
    pub chunks: Vec<PieceChunkV1>,
}

/// A piece's scalar facts: V2's offer body less its signature, its lists and
/// its chunk file names. Its JSON, fields in this order, is the second
/// element of the facts digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PieceFactsHeadV1 {
    /// The submission's random id, 32 hex. No authority: C is the handle.
    pub submission_id: String,
    /// The scope S of the month the piece was first prepared in, 64 hex.
    pub scope: String,
    /// The piece's ordinal within its scope, from 1.
    pub event_seq: u64,
    /// The code of the conversation the text was selected from, 64 hex.
    pub source: String,
    /// The vault's training setting when the piece was prepared.
    pub training: TrainingSettingV2,
    /// [`TRAINING_PRIVACY_EVERYWHERE`](super::TRAINING_PRIVACY_EVERYWHERE).
    pub privacy: String,
    /// The in-vault filter that made the text: provenance, not a safety
    /// claim.
    pub filter: TrainingFilterV2,
    /// [`TRAINING_TEXT_ENCODING`](super::TRAINING_TEXT_ENCODING).
    pub encoding: String,
    /// The BLAKE3 of the intake recipient's bytes the chunks are sealed to,
    /// 64 hex.
    pub key_id: String,
    /// The plaintext's length in bytes, all chunks together.
    pub text_bytes: u64,
    /// Unix seconds, of the piece's first preparation.
    pub prepared_at: u64,
}

/// One ONEV chunk file of a piece, so the intake can split its sealed stream
/// back into chunks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PieceChunkV1 {
    /// The chunk file's length in bytes.
    pub bytes: u64,
    /// The BLAKE3 of the chunk file's bytes, 64 hex.
    pub digest: String,
}

/// One byte range of a piece's sealed stream: its chunk files concatenated in
/// part order. A range may start or end inside a chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PiecePartV1 {
    /// The range's number in the piece, from 0, consecutive.
    pub index: u64,
    /// The stream offset the range starts at: 0 for index 0, else where the
    /// range before it ends.
    pub offset: u64,
    /// The range's length in bytes.
    pub bytes: u64,
    /// The BLAKE3 of the range's bytes, 64 hex.
    pub digest: String,
    /// The multipart part of the request that carries the bytes.
    pub part_name: String,
}

/// A piece's final: its totals and both digests. The intake takes it once
/// every list is complete to its total and the ranges run contiguous from 0
/// to `total_bytes`, and recomputes both digests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PieceFinalV1 {
    /// How many person codes the piece has.
    pub persons_total: u64,
    /// How many world codes the piece has.
    pub worlds_total: u64,
    /// How many chunks the piece's table has.
    pub chunks_total: u64,
    /// The sealed stream's length in bytes.
    pub total_bytes: u64,
    /// The BLAKE3 of the whole sealed stream, 64 hex: V2's
    /// `ciphertext_digest`.
    pub total_digest: String,
    /// The piece's [`PieceFactsDigest`](super::PieceFactsDigest), 64 hex.
    pub facts_digest: String,
}

/// Withdraw one piece. The intake fences C for good before it answers,
/// whether it holds the piece or not, and removes what it holds; the
/// piece's receipts then read `removal_pending`, then `removed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PieceWithdrawalV1 {
    /// The piece's code, C, 64 hex.
    pub code: String,
}

/// The intake's optional install check. The engine never sends one: without
/// a trust anchor it proves possession of a key, not a genuine or unique
/// install, and the window works fully without it. A supplied check that
/// fails is [`PIECE_ERROR_INVALID_INSTALL_CHECK`]. LC may amend this type in
/// its PT PR, before PT pins this crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PieceInstallCheckV1 {
    /// The nonce [`PIECE_CHALLENGE_PATH`] issued.
    pub nonce: String,
    /// The install's Ed25519 public key, 64 hex.
    pub public_key: String,
    /// Its signature, 128 hex.
    pub signature: String,
}

/// The answer to a batch: one result per entry, the pieces first in request
/// order, then the withdrawals in request order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PieceBatchResultV1 {
    /// The results.
    pub results: Vec<PieceResultV1>,
}

/// One entry's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PieceResultV1 {
    /// The entry's code, C, 64 hex.
    pub code: String,
    /// What the intake did with it.
    pub outcome: PieceOutcomeV1,
}

/// What the intake did with one entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PieceOutcomeV1 {
    /// It took the entry, and signed where the piece now stands.
    Receipt {
        /// The entry repeated exactly what the intake held; `receipt` is its
        /// current one.
        duplicate: bool,
        /// The piece's receipt.
        receipt: PieceReceiptV1,
    },
    /// An unsigned refusal of this entry alone, changing nothing at the
    /// intake. The client sends it again on its next pass, except on
    /// [`PIECE_ERROR_RECIPIENT_REFRESH_REQUIRED`].
    Refused {
        /// One of the `PIECE_ERROR_*` codes.
        error: String,
        /// How long to wait first, in seconds.
        retry_after_secs: Option<u64>,
    },
}

/// One signed receipt for one piece.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PieceReceiptV1 {
    /// What the receipt says.
    pub body: PieceReceiptBodyV1,
    /// The intake's Ed25519 signature over [`piece_receipt_signed_message`]
    /// of `body`, 128 hex, by its current receipt key or the one before it
    /// ([`TrainingKeysV1::receipt_keys`]).
    pub signature: String,
}

/// What one receipt says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PieceReceiptBodyV1 {
    /// The piece's code, C, 64 hex.
    pub code: String,
    /// The receipt's revision, rising per piece.
    pub revision: u64,
    /// Where the piece stands.
    pub state: PieceStateV1,
    /// Unix seconds.
    pub at: u64,
}

/// Where a piece stands at the intake. Tagged as V2's receipt status is: a
/// state with no fields is its name alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PieceStateV1 {
    /// The intake holds part of the piece.
    Uploading {
        /// Where the piece resumes.
        cursor: PieceCursorV1,
    },
    /// The piece is complete in quarantined custody: custody only, never
    /// eligibility.
    Accepted,
    /// The intake refused the piece.
    Rejected {
        /// Why.
        reason: String,
    },
    /// A window changed an item or a range the intake already held.
    Conflict,
    /// The piece's facts or bytes do not make a valid submission.
    InvalidSubmission,
    /// The re-filter passed the piece: it may be trained on.
    Eligible,
    /// The re-filter refused the piece.
    Refused {
        /// Why.
        reason: String,
    },
    /// Withdrawn; the intake is removing every copy.
    RemovalPending,
    /// Withdrawn, and every copy removed.
    Removed,
    /// The generic answer for a code the intake holds nothing for. It never
    /// says whether a code was seen.
    Unknown,
}

/// Where an uploading piece resumes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PieceCursorV1 {
    /// The next part index the intake expects.
    pub next_index: u64,
    /// The stream offset the next part starts at.
    pub next_offset: u64,
    /// The next person index.
    pub persons_next: u64,
    /// The next world index.
    pub worlds_next: u64,
    /// The next chunk table index.
    pub chunks_next: u64,
    /// Whether the intake holds the head.
    pub head_received: bool,
}

/// The body of a `POST` to [`PIECE_RECEIPTS_PATH`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PieceReceiptAskV1 {
    /// The pieces asked about.
    pub codes: Vec<PieceReceiptCursorAskV1>,
}

/// One piece asked about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PieceReceiptCursorAskV1 {
    /// The piece's code, C, 64 hex.
    pub code: String,
    /// Only receipts past this revision; 0 for all.
    pub after_revision: u64,
}

/// The answer to a [`PieceReceiptAskV1`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PieceReceiptPageV1 {
    /// One entry per piece answered.
    pub entries: Vec<PieceReceiptEntryV1>,
}

/// One piece's receipts in a page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PieceReceiptEntryV1 {
    /// The piece's code, C, 64 hex.
    pub code: String,
    /// Its receipts past the asked revision, rising by revision.
    pub receipts: Vec<PieceReceiptV1>,
    /// More receipts follow: ask again past the last revision here.
    pub more: bool,
}

/// The body of a refused request, answered before any entry was read. The
/// rules:
///
/// - `429` [`PIECE_ERROR_CAPACITY_BUSY`] and `503` [`PIECE_ERROR_UNAVAILABLE`]
///   carry `retry_after_secs` and a matching `Retry-After` header. The
///   client waits that long and tries again; it never gives up.
/// - `413` [`PIECE_ERROR_SPLIT_REQUIRED`] carries `bounds`. The client
///   splits its windows to fit and sends them again without loss: a 413 is
///   never terminal for a client.
/// - There is no file, page or conversation cap. Nothing is refused for
///   being large, only for not fitting one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PieceErrorV1 {
    /// The refusal.
    pub error: PieceErrorBodyV1,
}

/// What a refused request says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PieceErrorBodyV1 {
    /// One of the `PIECE_ERROR_*` codes.
    pub code: String,
    /// The bound that refused, such as `capacity`.
    pub bound: Option<String>,
    /// The dimension of that bound it refused on.
    pub dimension: Option<String>,
    /// How long to wait, in seconds: present on a `429` and a `503`.
    pub retry_after_secs: Option<u64>,
    /// The intake's bounds: present on a `413`.
    pub bounds: Option<PieceBoundsV1>,
}

/// The intake's bounds on one request: its deployment numbers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PieceBoundsV1 {
    /// The most bytes one request may carry, every part together.
    pub max_request_bytes: u64,
    /// The most bytes one sealed part may carry.
    pub max_part_bytes: u64,
    /// The most items one list of one facts page may carry.
    pub max_items_per_page: u64,
    /// The most piece entries one batch may carry.
    pub max_pieces_per_batch: u64,
}

/// The intake's public descriptor, served at `GET` [`PIECE_ROUTE_PREFIX`]
/// then [`PIECE_KEYS_PATH`] with no auth or account, and cacheable. It lists
/// only a recipient a worker is ready to open. Trust comes from HTTPS to the
/// intake's origin; v1 adds no signing root. A self-host engine writes
/// [`INTAKE_RECIPIENT_FILE`](super::INTAKE_RECIPIENT_FILE) and
/// [`INTAKE_RECEIPT_KEY_FILE`](super::INTAKE_RECEIPT_KEY_FILE) from it, so
/// one reader serves both; a managed vault keeps its supervisor's push into
/// those files. Every field is a string: this crate decodes no base64, and
/// the consumer checks the decoded lengths and `recipient_blake3`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingKeysV1 {
    /// The intake's key generation.
    pub generation: u64,
    /// The hybrid (X25519 + ML-KEM-1024) public key, 1,600 bytes, standard
    /// base64.
    pub recipient: String,
    /// The BLAKE3 of the recipient's bytes, 64 hex: every piece's `key_id`
    /// under it.
    pub recipient_blake3: String,
    /// The Ed25519 receipt keys, 32 bytes each, standard base64: the current
    /// one first, then at most the one before it.
    pub receipt_keys: Vec<String>,
}

/// The bytes a receipt's signature covers: [`PIECE_RECEIPT_DOMAIN`], a zero
/// byte, then the body's JSON. The intake signs exactly these with its
/// Ed25519 receipt key.
pub fn piece_receipt_signed_message(body: &PieceReceiptBodyV1) -> anyhow::Result<Vec<u8>> {
    let mut message = Vec::from(PIECE_RECEIPT_DOMAIN.as_bytes());
    message.push(0);
    serde_json::to_writer(&mut message, body)?;
    Ok(message)
}
