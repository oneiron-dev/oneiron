//! The publisher training outbox (OF-420, "Learn from my conversations";
//! TRAINING-LINK = C): the files a vault hands toward training the models
//! Oneiron ships, and the receipts the intake writes back. The vault process
//! and its consumer (the node supervisor in managed mode, a self-host
//! uploader otherwise) build against these shapes, so neither side spells
//! them twice. This is version 2; it replaces version 1 whole, and nothing
//! reads or writes a version 1 file.
//!
//! The vault writes into the directory named by
//! `--publisher-training-outbox-dir`. It holds three protocol subdirectories,
//! the vault's scopes file and the intake's two key files:
//!
//! - [`OFFERS_DIR`]: released offers. One offer is its manifest,
//!   `training-offer-<submission>.v2.json` (a [`TrainingOfferV2`]), and its
//!   chunks, `training-offer-<submission>.part-<part>.v2.onev`, each one
//!   sealed envelope of filtered text. Release is publication: the vault
//!   prepares an offer in local custody, rechecks its source, persons,
//!   worlds, the vault's training setting and the opt-outs at release, and
//!   only an offer the release lets through is renamed in, chunks first
//!   and the manifest last. Every manifest in `offers/` is a released offer.
//!   A chunk with no manifest is an interrupted publication: it is not
//!   shipped, and the vault removes it.
//! - [`CONTROLS_DIR`]: `training-control-<scope>-<event_seq>-<control>.v2.json`
//!   (a [`TrainingControlV2`]): withdrawals and the purge, naming codes and
//!   ids only, so the files sort by scope, then in event order within it.
//!   They are written whatever the learning state, and stay shippable from a
//!   vault that is not running.
//! - [`RECEIPTS_DIR`]: `training-receipt-<receipt>.v2.json` (a
//!   [`TrainingReceiptV2`]), written by the intake's side. The vault applies
//!   each one its intake signed for one of its own scopes, and removes it; a
//!   receipt for a scope it never used stays where it is, unapplied.
//! - [`TRAINING_SCOPES_FILE`], in [`SCOPES_DIR`]: the vault's scopes (a
//!   [`TrainingScopesV2`]), unsigned and local: every scope it ever used,
//!   each with the highest publisher sequence it applied there. The vault
//!   rewrites it whole whenever its list of months or a cursor changes; the
//!   consumer pulls receipts by these scopes. [`SCOPES_DIR`] is the vault
//!   user's own directory, so the outbox root, which holds the intake's
//!   keys, never has to be writable by the vault.
//! - [`INTAKE_RECIPIENT_FILE`]: the intake's hybrid (X25519 + ML-KEM-1024)
//!   public key, as raw bytes, that every chunk is sealed to. Without it no
//!   offer is written; controls still are.
//! - [`INTAKE_RECEIPT_KEY_FILE`]: the intake's Ed25519 receipt key, 32 raw
//!   bytes. Without it no receipt is applied, so nothing retires.
//!
//! # The vault holds the link
//!
//! Nothing a vault writes here names a vault, an install's vault id, a
//! source, a person or a world; the publisher's training store keeps only
//! opaque codes. The vault holds a 32-byte random key, K, in its own key
//! custody, made on its first training use. K never leaves the vault: no
//! file here, log, control-plane call or intake call carries it. In place of
//! every name a file carries keyed BLAKE3 digests, each under a key derived
//! from K for its one purpose (`blake3::derive_key`):
//!
//! - the scope, S = keyed BLAKE3 under derive_key(`oneiron.training.scope.v2`,
//!   K) of the month, where month is the UTC calendar month (`YYYY-MM`) of an
//!   offer's first preparation, so S rotates monthly; a retry keeps its
//!   month, its S, its ordinal and its first preparation time;
//! - codes, keyed BLAKE3 under derive_key(`oneiron.training.code.v2`, K) of
//!   kind, id and month, kind `source`, `person` or `world`: one source,
//!   person or world reads as an unrelated code in another month.
//!
//! Each digest input part is framed as its length, a big-endian `u32`, then
//! its bytes. S and every code are 32 bytes, written as 64 lower-case hex.
//!
//! Events are numbered per scope: within one scope, offers and controls are
//! totally ordered by `event_seq`, counted from 1; across scopes nothing is
//! ordered, and nothing here continues a vault-wide counter. A withdrawal
//! that reaches submissions of several months is one control per month, each
//! under its own scope, naming that month's codes and taking that scope's
//! next number. An erase purges scope by scope ([`TrainingPurgeScopeV2`]):
//! one control per scope the vault ever used, each riding its own scope at
//! its next number and naming no other, so no control links two months. Once
//! the intake's `removed` receipt for every one of them is in, the vault
//! retires K. A withdrawal applies to training runs that start after the
//! intake receives it ([`TRAINING_WITHDRAWAL_NOTE`]); a vault that is offline
//! sends it when it next reaches the outbox, never instantly.
//!
//! Offers and controls are signed with the vault install's machine key over
//! [`training_signed_message`]. The signature is for the intake's
//! authentication of the install and nothing else: the intake checks it,
//! then discards the signature and the key, and keeps no install identity
//! beside the codes. The uploader binds its own account outside these files.
//! Each chunk is an `ONEV` envelope sealed to the intake recipient under
//! purpose `PublisherTrainingOffer` (19), recipient
//! [`TRAINING_SEAL_RECIPIENT`], key id the submission id's 16 bytes then the
//! part as a big-endian `u32`, and vault id the offer's scope, S's 32 bytes:
//! the envelope's clear header names no vault. The text is the chunks'
//! plaintexts joined in part order, then decoded as UTF-8
//! ([`TRAINING_TEXT_ENCODING`]). Chunks split transport only: a long
//! conversation goes whole, in as many chunks as it takes.
//!
//! Every file is written whole: a private temporary sibling (a name starting
//! with `.`, never a protocol file), synced, renamed, then the directory
//! synced ([`spool_training_file`]). Every id is lower-case hex: a
//! submission, control or receipt id 32 characters; a scope, a code or a
//! digest 64.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The anonymous training window (TL-6): the per-piece wire a self-host
/// engine ships its offers and withdrawals over, keyed by each piece's C.
mod piece;
/// The window's shape checks and decoders.
mod piece_check;
/// The window's paging-invariant facts digest.
mod piece_facts;

pub use self::piece::{
    PIECE_BATCHES_PATH, PIECE_CHALLENGE_PATH, PIECE_ERROR_CAPACITY_BUSY,
    PIECE_ERROR_INVALID_INSTALL_CHECK, PIECE_ERROR_RECIPIENT_REFRESH_REQUIRED,
    PIECE_ERROR_SPLIT_REQUIRED, PIECE_ERROR_UNAVAILABLE, PIECE_FACTS_DOMAIN, PIECE_KEYS_PATH,
    PIECE_RECEIPT_DOMAIN, PIECE_RECEIPTS_PATH, PIECE_ROUTE_PREFIX, PIECE_WIRE_VERSION,
    PieceBatchResultV1, PieceBatchV1, PieceBoundsV1, PieceChunkV1, PieceCursorV1, PieceEntryV1,
    PieceErrorBodyV1, PieceErrorV1, PieceFactsHeadV1, PieceFinalV1, PieceInstallCheckV1,
    PieceMetaPageV1, PieceOutcomeV1, PiecePartV1, PieceReceiptAskV1, PieceReceiptBodyV1,
    PieceReceiptCursorAskV1, PieceReceiptEntryV1, PieceReceiptPageV1, PieceReceiptV1,
    PieceResultV1, PieceStateV1, PieceWithdrawalV1, TrainingKeysV1, piece_receipt_signed_message,
};
pub use self::piece_check::{decode_piece_batch, decode_piece_receipt_page, decode_training_keys};
pub use self::piece_facts::{PieceFactsDigest, piece_facts_digest};

/// The wire schema version of every file below.
pub const TRAINING_SCHEMA_VERSION: u32 = 2;
/// The type tag of a [`TrainingOfferV2`].
pub const TRAINING_OFFER_TYPE: &str = "publisher_training_offer";
/// The type tag of a [`TrainingControlV2`].
pub const TRAINING_CONTROL_TYPE: &str = "publisher_training_control";
/// The type tag of a [`TrainingReceiptV2`].
pub const TRAINING_RECEIPT_TYPE: &str = "publisher_training_receipt";
/// The type tag of a [`TrainingScopesV2`].
pub const TRAINING_SCOPES_TYPE: &str = "publisher_training_scopes";
/// The subdirectory of released offers.
pub const OFFERS_DIR: &str = "offers";
/// The subdirectory of controls.
pub const CONTROLS_DIR: &str = "controls";
/// The subdirectory the intake's receipts arrive in.
pub const RECEIPTS_DIR: &str = "receipts";
/// The subdirectory holding [`TRAINING_SCOPES_FILE`], owned by the vault's
/// own user. The outbox directory itself may not be writable by it (a
/// managed node keeps it root-owned because it holds the intake's keys), and
/// it must never be made so: the vault could then replace those keys.
pub const SCOPES_DIR: &str = "scopes";
/// The vault's scopes, in [`SCOPES_DIR`]: unsigned and local.
pub const TRAINING_SCOPES_FILE: &str = "training-scopes.v2.json";
/// The intake's hybrid public key, in the outbox directory.
pub const INTAKE_RECIPIENT_FILE: &str = "intake-recipient.v1";
/// The intake's Ed25519 receipt key, in the outbox directory.
pub const INTAKE_RECEIPT_KEY_FILE: &str = "intake-receipt-key.v1";
/// The serve setting naming the outbox: argv only, and the supervisor's in
/// managed mode.
pub const OUTBOX_DIR_SETTING: &str = "publisher_training_outbox_dir";
/// How an offer's text is encoded: UTF-8, each selected message as a line
/// naming its speaker (`### person` or `### agent`), its filtered text, and
/// an empty line.
pub const TRAINING_TEXT_ENCODING: &str = "filtered-text-utf8-v1";
/// The privacy every world an offer names reads.
pub const TRAINING_PRIVACY_EVERYWHERE: &str = "everywhere";
/// The signature suite of every signed file.
pub const TRAINING_SIGNATURE_SUITE: &str = "ed25519";
/// The recipient every chunk envelope is sealed to.
pub const TRAINING_SEAL_RECIPIENT: &[u8] = b"oneiron.publisher_training.offer.v2";
/// What every control says, and every removal receipt must say, about when
/// a withdrawal takes effect (C6).
pub const TRAINING_WITHDRAWAL_NOTE: &str = "A withdrawal applies to training runs that start \
                                            after the intake receives it. A run already in \
                                            progress finishes, and a model already trained is \
                                            not unlearned.";

/// The domain every signed message starts with.
const SIGNATURE_DOMAIN: &[u8] = b"oneiron.publisher_training.signature.v2";
const OFFER_PREFIX: &str = "training-offer-";
const CONTROL_PREFIX: &str = "training-control-";
const RECEIPT_PREFIX: &str = "training-receipt-";
const JSON_SUFFIX: &str = ".v2.json";
const CHUNK_SUFFIX: &str = ".v2.onev";
const PART_INFIX: &str = ".part-";
/// Lower-case hex characters of a 16-byte id.
const ID_HEX: usize = 32;
/// Lower-case hex characters of a 32-byte scope, code or digest.
const DIGEST_HEX: usize = 64;

/// A signature over [`training_signed_message`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingSignatureV2 {
    /// [`TRAINING_SIGNATURE_SUITE`].
    pub suite: String,
    /// The signer's Ed25519 public key, 64 hex.
    pub public_key: String,
    /// The signature, 128 hex.
    pub signature: String,
}

/// One released offer's manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingOfferV2 {
    pub schema_version: u32,
    /// [`TRAINING_OFFER_TYPE`].
    pub file_type: String,
    pub body: TrainingOfferBodyV2,
    /// The vault install's signature over `body`, for the intake's
    /// authentication only.
    pub signature: TrainingSignatureV2,
}

/// What one offer says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingOfferBodyV2 {
    /// The submission's random id; a retry keeps it.
    pub submission_id: String,
    /// The scope S of the month the offer was first prepared in, 64 hex.
    pub scope: String,
    /// The offer's ordinal within its scope, from 1.
    pub event_seq: u64,
    /// The code, for its month, of the conversation the text was selected
    /// from, 64 hex. A changed source is a new offer, and the vault forgets
    /// the older ones by controls naming their ids.
    pub source: String,
    /// The codes, for its month, of every person whose words the text
    /// carries, members and guests alike, 64 hex each. Never an agent's;
    /// empty when the text carries only agents' words.
    pub persons: Vec<String>,
    /// The codes, for its month, of every world the text came from, 64 hex
    /// each; never empty.
    pub worlds: Vec<String>,
    /// The vault's "Learn from my conversations" setting in force when the
    /// offer was prepared (FIX 5502): on, for every offer the vault released.
    pub training: TrainingSettingV2,
    /// [`TRAINING_PRIVACY_EVERYWHERE`].
    pub privacy: String,
    /// The in-vault filter that made the text: provenance, not a safety
    /// claim.
    pub filter: TrainingFilterV2,
    pub payload: TrainingPayloadV2,
    /// Unix seconds, of the offer's first preparation; a retry keeps it.
    pub prepared_at: u64,
}

/// The vault's training setting, as an offer names it. Its revision, who set
/// it and its authority act stay in the vault, where the release rechecks
/// them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingSettingV2 {
    /// Whether it was on: true for every offer the vault released.
    pub on: bool,
}

/// The filter that made an offer's text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingFilterV2 {
    pub model: String,
    pub stack_sha16: Option<String>,
}

/// Where an offer's sealed text is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingPayloadV2 {
    /// [`TRAINING_TEXT_ENCODING`].
    pub encoding: String,
    /// The BLAKE3 of the intake recipient file's bytes, 64 hex.
    pub key_id: String,
    /// The plaintext's length in bytes, all chunks together.
    pub text_bytes: u64,
    /// The BLAKE3 of every chunk file's bytes in part order, 64 hex.
    pub ciphertext_digest: String,
    pub chunks: Vec<TrainingChunkV2>,
}

/// One chunk file of an offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingChunkV2 {
    /// From 0, consecutive.
    pub part: u32,
    /// The chunk file's length in bytes.
    pub bytes: u64,
    /// The BLAKE3 of the chunk file's bytes, 64 hex.
    pub digest: String,
    /// The chunk's file in [`OFFERS_DIR`]: exactly
    /// [`offer_chunk_file_name`] of the submission and part.
    pub file: String,
}

/// One control: a withdrawal or the purge, codes and ids only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingControlV2 {
    pub schema_version: u32,
    /// [`TRAINING_CONTROL_TYPE`].
    pub file_type: String,
    pub body: TrainingControlBodyV2,
    /// The vault install's signature over `body`, for the intake's
    /// authentication only.
    pub signature: TrainingSignatureV2,
}

/// What one control says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingControlBodyV2 {
    pub control_id: String,
    /// The scope the control rides, 64 hex: the month of the submissions it
    /// reaches, or for a purge the scope it purges.
    pub scope: String,
    /// The control's ordinal within its scope, from 1.
    pub event_seq: u64,
    pub change: TrainingControlChangeV2,
    /// Unix seconds.
    pub recorded_at: u64,
    /// [`TRAINING_WITHDRAWAL_NOTE`].
    pub note: String,
}

/// The change a control carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrainingControlChangeV2 {
    /// Remove these submissions of one source.
    ForgetSource(TrainingForgetSourceV2),
    /// A world no longer reads everywhere, or no longer exists.
    WorldEligibility(TrainingWorldEligibilityV2),
    /// Purge everything held under the control's own scope: an erase.
    PurgeScope(TrainingPurgeScopeV2),
}

/// Remove these submissions of one source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingForgetSourceV2 {
    /// The source's code for the control's month, 64 hex.
    pub source: String,
    /// The submissions, 32 hex each, all of the control's month.
    pub submissions: Vec<String>,
}

/// A world's eligibility now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingWorldEligibilityV2 {
    /// The world's code for the control's month, 64 hex.
    pub world: String,
    pub everywhere: bool,
}

/// Purge everything held under the control's own scope (an erase). It
/// names no other scope: a vault that used several sends one per scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingPurgeScopeV2 {}

/// One receipt from the intake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingReceiptV2 {
    pub schema_version: u32,
    /// [`TRAINING_RECEIPT_TYPE`].
    pub file_type: String,
    pub body: TrainingReceiptBodyV2,
    /// The intake's signature over `body`, by the key in
    /// [`INTAKE_RECEIPT_KEY_FILE`].
    pub signature: TrainingSignatureV2,
}

/// What one receipt says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingReceiptBodyV2 {
    pub receipt_id: String,
    /// The scope the receipt answers in, 64 hex: its subject's.
    pub scope: String,
    pub subject: TrainingReceiptSubjectV2,
    pub status: TrainingReceiptStatusV2,
    /// The intake's sequence for this scope, rising: the vault applies a
    /// receipt only past the highest it applied in the same scope, and never
    /// compares one scope's sequence with another's.
    pub publisher_sequence: u64,
    /// The runs that used submissions (C3).
    pub used_runs: Vec<TrainingUsedRunV2>,
    /// The intake's no-human-read attestation (C5); absent when it makes
    /// none.
    pub no_human_read: Option<TrainingNoHumanReadV2>,
    /// [`TRAINING_WITHDRAWAL_NOTE`], required on a removal.
    pub note: Option<String>,
    /// Unix seconds.
    pub issued_at: u64,
}

/// What a receipt answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrainingReceiptSubjectV2 {
    /// A submission id.
    Submission(String),
    /// A control id.
    Control(String),
}

/// The intake's custody of a subject. `Stored` is committed intake custody;
/// `Removed` is verified purge completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrainingReceiptStatusV2 {
    Stored,
    Excluded,
    RemovalPending,
    Removed,
    Rejected,
}

/// One training run that used submissions (C3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingUsedRunV2 {
    pub run_id: String,
    /// The model or checkpoint the run made.
    pub model: String,
    /// The submissions it used.
    pub submissions: Vec<String>,
    /// Unix seconds.
    pub used_at: u64,
}

/// The intake's attestation that no person reads what it holds (C5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingNoHumanReadV2 {
    /// Unix seconds.
    pub attested_at: u64,
    /// The intake policy the attestation is made under.
    pub policy: String,
}

/// The vault's scopes ([`TRAINING_SCOPES_FILE`]): unsigned and local, for
/// its consumer to pull receipts by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingScopesV2 {
    pub schema_version: u32,
    /// [`TRAINING_SCOPES_TYPE`].
    pub file_type: String,
    /// Every scope the vault ever used, sorted by scope.
    pub scopes: Vec<TrainingScopeCursorV2>,
}

/// One scope the vault used, and where its receipts resume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingScopeCursorV2 {
    /// The scope, 64 hex.
    pub scope: String,
    /// The highest publisher sequence the vault applied in it; 0 before any.
    pub receipt_cursor: u64,
}

/// A protocol file, by its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrainingFileName {
    OfferManifest {
        submission: String,
    },
    OfferChunk {
        submission: String,
        part: u32,
    },
    Control {
        scope: String,
        event_seq: u64,
        control: String,
    },
    Receipt {
        receipt: String,
    },
    /// [`TRAINING_SCOPES_FILE`].
    Scopes,
}

/// The bytes a signature in a file of `file_type` covers: the domain, the
/// type and the body's JSON, each separated by a zero byte.
pub fn training_signed_message<T: Serialize>(file_type: &str, body: &T) -> anyhow::Result<Vec<u8>> {
    let mut message = Vec::from(SIGNATURE_DOMAIN);
    message.push(0);
    message.extend_from_slice(file_type.as_bytes());
    message.push(0);
    serde_json::to_writer(&mut message, body)?;
    Ok(message)
}

/// Whether `text` is `chars` lower-case hex characters.
#[must_use]
pub fn is_lower_hex(text: &str, chars: usize) -> bool {
    text.len() == chars && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// An offer's manifest file, or `None` for an id that cannot name one.
#[must_use]
pub fn offer_manifest_file_name(submission: &str) -> Option<String> {
    is_lower_hex(submission, ID_HEX).then(|| format!("{OFFER_PREFIX}{submission}{JSON_SUFFIX}"))
}

/// An offer chunk's file, or `None` for an id that cannot name one.
#[must_use]
pub fn offer_chunk_file_name(submission: &str, part: u32) -> Option<String> {
    is_lower_hex(submission, ID_HEX)
        .then(|| format!("{OFFER_PREFIX}{submission}{PART_INFIX}{part:08}{CHUNK_SUFFIX}"))
}

/// A control's file, or `None` for a scope or id that cannot name one. The
/// scope, then the zero padded sequence, sort the files by scope and in
/// event order within it.
#[must_use]
pub fn control_file_name(scope: &str, event_seq: u64, control: &str) -> Option<String> {
    (is_lower_hex(scope, DIGEST_HEX) && is_lower_hex(control, ID_HEX))
        .then(|| format!("{CONTROL_PREFIX}{scope}-{event_seq:020}-{control}{JSON_SUFFIX}"))
}

/// A receipt's file, or `None` for an id that cannot name one.
#[must_use]
pub fn receipt_file_name(receipt: &str) -> Option<String> {
    is_lower_hex(receipt, ID_HEX).then(|| format!("{RECEIPT_PREFIX}{receipt}{JSON_SUFFIX}"))
}

/// The protocol file `name` spells, or `None` for any other name (a
/// temporary sibling included).
#[must_use]
pub fn parse_training_file_name(name: &str) -> Option<TrainingFileName> {
    if name == TRAINING_SCOPES_FILE {
        return Some(TrainingFileName::Scopes);
    }
    if let Some(rest) = name.strip_prefix(OFFER_PREFIX) {
        if let Some(submission) = rest.strip_suffix(JSON_SUFFIX) {
            return is_lower_hex(submission, ID_HEX).then(|| TrainingFileName::OfferManifest {
                submission: submission.to_owned(),
            });
        }
        let (submission, part) = rest.strip_suffix(CHUNK_SUFFIX)?.split_once(PART_INFIX)?;
        let parsed = (part.len() == 8 && part.bytes().all(|b| b.is_ascii_digit()))
            .then(|| part.parse().ok())
            .flatten()?;
        return is_lower_hex(submission, ID_HEX).then(|| TrainingFileName::OfferChunk {
            submission: submission.to_owned(),
            part: parsed,
        });
    }
    if let Some(rest) = name.strip_prefix(CONTROL_PREFIX) {
        let mut fields = rest.strip_suffix(JSON_SUFFIX)?.splitn(3, '-');
        let (scope, seq, control) = (fields.next()?, fields.next()?, fields.next()?);
        let event_seq = (seq.len() == 20 && seq.bytes().all(|b| b.is_ascii_digit()))
            .then(|| seq.parse().ok())
            .flatten()?;
        return (is_lower_hex(scope, DIGEST_HEX) && is_lower_hex(control, ID_HEX)).then(|| {
            TrainingFileName::Control {
                scope: scope.to_owned(),
                event_seq,
                control: control.to_owned(),
            }
        });
    }
    let receipt = name
        .strip_prefix(RECEIPT_PREFIX)?
        .strip_suffix(JSON_SUFFIX)?;
    is_lower_hex(receipt, ID_HEX).then(|| TrainingFileName::Receipt {
        receipt: receipt.to_owned(),
    })
}

/// Decodes one receipt strictly: the exact shape, version and type, its
/// scope and hex ids, a well-formed signature, and the note on a removal.
/// Its signature is checked against the intake's key by the vault, not here.
pub fn decode_training_receipt(bytes: &[u8]) -> anyhow::Result<TrainingReceiptV2> {
    let receipt: TrainingReceiptV2 = serde_json::from_slice(bytes)?;
    check_header(
        receipt.schema_version,
        &receipt.file_type,
        TRAINING_RECEIPT_TYPE,
    )?;
    check_signature(&receipt.signature)?;
    let body = &receipt.body;
    check_hex("receipt_id", &body.receipt_id, ID_HEX)?;
    check_hex("scope", &body.scope, DIGEST_HEX)?;
    match &body.subject {
        TrainingReceiptSubjectV2::Submission(id) | TrainingReceiptSubjectV2::Control(id) => {
            check_hex("subject", id, ID_HEX)?;
        }
    }
    for run in &body.used_runs {
        if run.run_id.trim().is_empty() || run.model.trim().is_empty() {
            anyhow::bail!("a used run names no run or no model");
        }
        for submission in &run.submissions {
            check_hex("used run submission", submission, ID_HEX)?;
        }
    }
    let removal = matches!(
        body.status,
        TrainingReceiptStatusV2::Removed | TrainingReceiptStatusV2::RemovalPending
    );
    if removal && body.note.as_deref() != Some(TRAINING_WITHDRAWAL_NOTE) {
        anyhow::bail!("a removal receipt must carry the withdrawal note");
    }
    Ok(receipt)
}

/// Decodes one control strictly, for a consumer: its scope, its codes and
/// its submission ids.
pub fn decode_training_control(bytes: &[u8]) -> anyhow::Result<TrainingControlV2> {
    let control: TrainingControlV2 = serde_json::from_slice(bytes)?;
    check_header(
        control.schema_version,
        &control.file_type,
        TRAINING_CONTROL_TYPE,
    )?;
    check_signature(&control.signature)?;
    let body = &control.body;
    check_hex("control_id", &body.control_id, ID_HEX)?;
    check_hex("scope", &body.scope, DIGEST_HEX)?;
    match &body.change {
        TrainingControlChangeV2::ForgetSource(forget) => {
            check_hex("source", &forget.source, DIGEST_HEX)?;
            for submission in &forget.submissions {
                check_hex("submission", submission, ID_HEX)?;
            }
        }
        TrainingControlChangeV2::WorldEligibility(world) => {
            check_hex("world", &world.world, DIGEST_HEX)?;
        }
        TrainingControlChangeV2::PurgeScope(TrainingPurgeScopeV2 {}) => {}
    }
    Ok(control)
}

/// Decodes one offer manifest strictly, for a consumer: its scope and codes,
/// at least one world, and chunks numbered from 0, each naming exactly its
/// own file.
pub fn decode_training_offer(bytes: &[u8]) -> anyhow::Result<TrainingOfferV2> {
    let offer: TrainingOfferV2 = serde_json::from_slice(bytes)?;
    check_header(offer.schema_version, &offer.file_type, TRAINING_OFFER_TYPE)?;
    check_signature(&offer.signature)?;
    let body = &offer.body;
    check_hex("submission_id", &body.submission_id, ID_HEX)?;
    check_hex("scope", &body.scope, DIGEST_HEX)?;
    check_hex("source", &body.source, DIGEST_HEX)?;
    check_codes("person", &body.persons)?;
    if body.worlds.is_empty() {
        anyhow::bail!("an offer names no world");
    }
    check_codes("world", &body.worlds)?;
    check_hex("key_id", &body.payload.key_id, DIGEST_HEX)?;
    for (index, chunk) in body.payload.chunks.iter().enumerate() {
        let expected = offer_chunk_file_name(&body.submission_id, chunk.part);
        if u32::try_from(index).ok() != Some(chunk.part) || expected.as_ref() != Some(&chunk.file) {
            anyhow::bail!("an offer chunk is out of order or names another file");
        }
        check_hex("chunk digest", &chunk.digest, DIGEST_HEX)?;
    }
    Ok(offer)
}

/// Decodes the vault's scopes file strictly, for a consumer: the exact
/// shape, version and type, and every scope 64 hex.
pub fn decode_training_scopes(bytes: &[u8]) -> anyhow::Result<TrainingScopesV2> {
    let scopes: TrainingScopesV2 = serde_json::from_slice(bytes)?;
    check_header(
        scopes.schema_version,
        &scopes.file_type,
        TRAINING_SCOPES_TYPE,
    )?;
    for cursor in &scopes.scopes {
        check_hex("scope", &cursor.scope, DIGEST_HEX)?;
    }
    Ok(scopes)
}

/// Writes `bytes` to `dir/name` whole: a private temporary sibling, synced,
/// renamed over the file, then the directory synced. A crash leaves either
/// the whole file or none of it. `dir` must exist.
pub fn spool_training_file(dir: &Path, name: &str, bytes: &[u8]) -> anyhow::Result<PathBuf> {
    if parse_training_file_name(name).is_none() {
        anyhow::bail!("a training outbox file must have a protocol name");
    }
    let target = dir.join(name);
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let written = options.open(&tmp).and_then(|mut file| {
        file.write_all(bytes)?;
        file.sync_all()
    });
    if let Err(error) = written.and_then(|()| std::fs::rename(&tmp, &target)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(error.into());
    }
    std::fs::File::open(dir)?.sync_all()?;
    Ok(target)
}

fn check_header(version: u32, file_type: &str, expected: &str) -> anyhow::Result<()> {
    if version != TRAINING_SCHEMA_VERSION || file_type != expected {
        anyhow::bail!("not a version {TRAINING_SCHEMA_VERSION} {expected} file");
    }
    Ok(())
}

fn check_signature(signature: &TrainingSignatureV2) -> anyhow::Result<()> {
    if signature.suite != TRAINING_SIGNATURE_SUITE {
        anyhow::bail!("unknown signature suite");
    }
    check_hex("public_key", &signature.public_key, DIGEST_HEX)?;
    check_hex("signature", &signature.signature, 2 * DIGEST_HEX)
}

fn check_hex(field: &str, text: &str, chars: usize) -> anyhow::Result<()> {
    if !is_lower_hex(text, chars) {
        anyhow::bail!("{field} is not {chars} lower-case hex characters");
    }
    Ok(())
}

/// Each of `codes` is 64 lower-case hex.
fn check_codes(field: &str, codes: &[String]) -> anyhow::Result<()> {
    for code in codes {
        check_hex(field, code, DIGEST_HEX)?;
    }
    Ok(())
}
