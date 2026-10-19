//! The publisher training outbox (OF-420, "Learn from my conversations"):
//! the files a vault hands toward training the models Oneiron ships, and the
//! receipts the intake writes back. The vault process and its consumer (the
//! node supervisor in managed mode, a self-host uploader otherwise) build
//! against these shapes, so neither side spells them twice.
//!
//! The vault writes into the directory named by
//! `--publisher-training-outbox-dir`. It holds three protocol subdirectories
//! and the intake's two key files:
//!
//! - [`OFFERS_DIR`]: released offers. One offer is its manifest,
//!   `training-offer-<submission>.v1.json` (a [`TrainingOfferV1`]), and its
//!   chunks, `training-offer-<submission>.part-<part>.v1.onev`, each one
//!   sealed envelope of filtered text. Release is publication: the vault
//!   prepares an offer in local custody, rechecks its source, persons,
//!   worlds, the vault's training setting and the opt-outs at release, and
//!   only an offer the release lets through is renamed in, chunks first
//!   and the manifest last. Every manifest in `offers/` is a released offer.
//!   A chunk with no manifest is an interrupted publication: it is not
//!   shipped, and the vault removes it.
//! - [`CONTROLS_DIR`]: `training-control-<event_seq>-<control>.v1.json` (a
//!   [`TrainingControlV1`]), withdrawals naming ids only. They are written
//!   whatever the learning state, and stay shippable from a vault that is
//!   not running.
//! - [`RECEIPTS_DIR`]: `training-receipt-<receipt>.v1.json` (a
//!   [`TrainingReceiptV1`]), written by the intake's side. The vault applies
//!   each one its intake signed and removes it.
//! - [`INTAKE_RECIPIENT_FILE`]: the intake's hybrid (X25519 + ML-KEM-1024)
//!   public key, as raw bytes, that every chunk is sealed to. Without it no
//!   offer is written; controls still are.
//! - [`INTAKE_RECEIPT_KEY_FILE`]: the intake's Ed25519 receipt key, 32 raw
//!   bytes. Without it no receipt is applied, so nothing retires.
//!
//! Every event the vault writes takes the next `event_seq` of one counter,
//! so offers and controls are totally ordered. A withdrawal applies to
//! training runs that start after the intake receives it
//! ([`TRAINING_WITHDRAWAL_NOTE`]); a vault that is offline sends it when it
//! next reaches the outbox, never instantly.
//!
//! Offers and controls are signed with the vault install's machine key over
//! [`training_signed_message`]. That binds a payload to the vault install
//! that wrote it, not to a person's cloud account: the account binding is
//! the uploader's (managed mode binds the registry vault id and the node's
//! bearer outside these files). Each chunk is an `ONEV` envelope sealed to
//! the intake recipient under purpose `PublisherTrainingOffer` (19), recipient
//! [`TRAINING_SEAL_RECIPIENT`], key id the submission id's 16 bytes then the
//! part as a big-endian `u32`, and vault id the engine vault id's 32 bytes.
//! The text is the chunks' plaintexts joined in part order, then decoded as
//! UTF-8 ([`TRAINING_TEXT_ENCODING`]). Chunks split transport only: a long
//! conversation goes whole, in as many chunks as it takes.
//!
//! Every file is written whole: a private temporary sibling (a name starting
//! with `.`, never a protocol file), synced, renamed, then the directory
//! synced ([`spool_training_file`]). Every id is lower-case hex: a
//! submission, control or receipt id and an entity id 32 characters, an
//! engine vault id, digest or revision 64.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The wire schema version of every file below.
pub const TRAINING_SCHEMA_VERSION: u32 = 1;
/// The type tag of a [`TrainingOfferV1`].
pub const TRAINING_OFFER_TYPE: &str = "publisher_training_offer";
/// The type tag of a [`TrainingControlV1`].
pub const TRAINING_CONTROL_TYPE: &str = "publisher_training_control";
/// The type tag of a [`TrainingReceiptV1`].
pub const TRAINING_RECEIPT_TYPE: &str = "publisher_training_receipt";
/// The subdirectory of released offers.
pub const OFFERS_DIR: &str = "offers";
/// The subdirectory of controls.
pub const CONTROLS_DIR: &str = "controls";
/// The subdirectory the intake's receipts arrive in.
pub const RECEIPTS_DIR: &str = "receipts";
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
pub const TRAINING_SEAL_RECIPIENT: &[u8] = b"oneiron.publisher_training.offer.v1";
/// What every control says, and every removal receipt must say, about when
/// a withdrawal takes effect (C6).
pub const TRAINING_WITHDRAWAL_NOTE: &str = "A withdrawal applies to training runs that start \
                                            after the intake receives it. A run already in \
                                            progress finishes, and a model already trained is \
                                            not unlearned.";

/// The domain every signed message starts with.
const SIGNATURE_DOMAIN: &[u8] = b"oneiron.publisher_training.signature.v1";
const OFFER_PREFIX: &str = "training-offer-";
const CONTROL_PREFIX: &str = "training-control-";
const RECEIPT_PREFIX: &str = "training-receipt-";
const JSON_SUFFIX: &str = ".v1.json";
const CHUNK_SUFFIX: &str = ".v1.onev";
const PART_INFIX: &str = ".part-";
/// Lower-case hex characters of a 16-byte id.
const ID_HEX: usize = 32;
/// Lower-case hex characters of a 32-byte vault id, digest or revision.
const DIGEST_HEX: usize = 64;

/// A signature over [`training_signed_message`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingSignatureV1 {
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
pub struct TrainingOfferV1 {
    pub schema_version: u32,
    /// [`TRAINING_OFFER_TYPE`].
    pub file_type: String,
    pub body: TrainingOfferBodyV1,
    /// The vault install's signature over `body`.
    pub signature: TrainingSignatureV1,
}

/// What one offer says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingOfferBodyV1 {
    /// The submission's random id; a retry keeps it.
    pub submission_id: String,
    pub event_seq: u64,
    pub engine_vault_id: String,
    /// The conversation the text was selected from.
    pub source: String,
    /// The digest of the exact selected snapshot: a changed source is a new
    /// offer, and the vault forgets this one by a control naming its id.
    pub source_revision: String,
    /// Every person whose words the text carries, members and guests alike.
    /// Never an agent; empty when the text carries only agents' words.
    pub persons: Vec<String>,
    /// Every world the text came from, never empty.
    pub worlds: Vec<String>,
    /// The vault's "Learn from my conversations" setting in force when the
    /// offer was prepared (FIX 5502): the vault admin's.
    pub training: TrainingSettingV1,
    /// The digest of the worlds' settings revisions.
    pub world_policy_revision: String,
    /// [`TRAINING_PRIVACY_EVERYWHERE`].
    pub privacy: String,
    /// The in-vault filter that made the text: provenance, not a safety
    /// claim.
    pub filter: TrainingFilterV1,
    pub payload: TrainingPayloadV1,
    /// Unix seconds.
    pub prepared_at: u64,
}

/// The vault's training setting, as an offer names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingSettingV1 {
    /// Whether it was on: true for every offer the vault released.
    pub on: bool,
    /// The vault's setting revision, 64 hex.
    pub revision: String,
    /// The vault admin's PERSON who set it, 32 hex; null when the vault
    /// cannot read it.
    pub set_by: Option<String>,
    /// The authority entry of the setting choice in force, 64 hex.
    pub act: Option<String>,
}

/// The filter that made an offer's text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingFilterV1 {
    pub model: String,
    pub stack_sha16: Option<String>,
}

/// Where an offer's sealed text is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingPayloadV1 {
    /// [`TRAINING_TEXT_ENCODING`].
    pub encoding: String,
    /// The BLAKE3 of the intake recipient file's bytes, 64 hex.
    pub key_id: String,
    /// The plaintext's length in bytes, all chunks together.
    pub text_bytes: u64,
    /// The BLAKE3 of every chunk file's bytes in part order, 64 hex.
    pub ciphertext_digest: String,
    pub chunks: Vec<TrainingChunkV1>,
}

/// One chunk file of an offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingChunkV1 {
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

/// One control: a withdrawal, ids only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingControlV1 {
    pub schema_version: u32,
    /// [`TRAINING_CONTROL_TYPE`].
    pub file_type: String,
    pub body: TrainingControlBodyV1,
    /// The vault install's signature over `body`.
    pub signature: TrainingSignatureV1,
}

/// What one control says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingControlBodyV1 {
    pub control_id: String,
    pub event_seq: u64,
    pub engine_vault_id: String,
    pub change: TrainingControlChangeV1,
    /// Unix seconds.
    pub recorded_at: u64,
    /// [`TRAINING_WITHDRAWAL_NOTE`].
    pub note: String,
}

/// The change a control carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrainingControlChangeV1 {
    /// Remove these submissions of one source.
    ForgetSource(TrainingForgetSourceV1),
    /// A world no longer reads everywhere, or no longer exists.
    WorldEligibility(TrainingWorldEligibilityV1),
}

/// Remove these submissions of one source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingForgetSourceV1 {
    pub source: String,
    pub submissions: Vec<String>,
}

/// A world's eligibility now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingWorldEligibilityV1 {
    pub world: String,
    pub everywhere: bool,
}

/// One receipt from the intake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingReceiptV1 {
    pub schema_version: u32,
    /// [`TRAINING_RECEIPT_TYPE`].
    pub file_type: String,
    pub body: TrainingReceiptBodyV1,
    /// The intake's signature over `body`, by the key in
    /// [`INTAKE_RECEIPT_KEY_FILE`].
    pub signature: TrainingSignatureV1,
}

/// What one receipt says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingReceiptBodyV1 {
    pub receipt_id: String,
    pub engine_vault_id: String,
    pub subject: TrainingReceiptSubjectV1,
    pub status: TrainingReceiptStatusV1,
    /// The intake's sequence for this vault, rising: the vault applies a
    /// receipt only past the highest it applied.
    pub publisher_sequence: u64,
    /// The runs that used submissions (C3).
    pub used_runs: Vec<TrainingUsedRunV1>,
    /// The intake's no-human-read attestation (C5); absent when it makes
    /// none.
    pub no_human_read: Option<TrainingNoHumanReadV1>,
    /// [`TRAINING_WITHDRAWAL_NOTE`], required on a removal.
    pub note: Option<String>,
    /// Unix seconds.
    pub issued_at: u64,
}

/// What a receipt answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrainingReceiptSubjectV1 {
    /// A submission id.
    Submission(String),
    /// A control id.
    Control(String),
}

/// The intake's custody of a subject. `Stored` is committed intake custody;
/// `Removed` is verified purge completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrainingReceiptStatusV1 {
    Stored,
    Excluded,
    RemovalPending,
    Removed,
    Rejected,
}

/// One training run that used submissions (C3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingUsedRunV1 {
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
pub struct TrainingNoHumanReadV1 {
    /// Unix seconds.
    pub attested_at: u64,
    /// The intake policy the attestation is made under.
    pub policy: String,
}

/// A protocol file, by its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrainingFileName {
    OfferManifest { submission: String },
    OfferChunk { submission: String, part: u32 },
    Control { event_seq: u64, control: String },
    Receipt { receipt: String },
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

/// A control's file, or `None` for an id that cannot name one. The zero
/// padded sequence sorts the files in event order.
#[must_use]
pub fn control_file_name(event_seq: u64, control: &str) -> Option<String> {
    is_lower_hex(control, ID_HEX)
        .then(|| format!("{CONTROL_PREFIX}{event_seq:020}-{control}{JSON_SUFFIX}"))
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
        let (seq, control) = rest.strip_suffix(JSON_SUFFIX)?.split_once('-')?;
        let event_seq = (seq.len() == 20 && seq.bytes().all(|b| b.is_ascii_digit()))
            .then(|| seq.parse().ok())
            .flatten()?;
        return is_lower_hex(control, ID_HEX).then(|| TrainingFileName::Control {
            event_seq,
            control: control.to_owned(),
        });
    }
    let receipt = name
        .strip_prefix(RECEIPT_PREFIX)?
        .strip_suffix(JSON_SUFFIX)?;
    is_lower_hex(receipt, ID_HEX).then(|| TrainingFileName::Receipt {
        receipt: receipt.to_owned(),
    })
}

/// Decodes one receipt strictly: the exact shape, version and type, hex
/// ids, a well-formed signature, and the note on a removal. Its signature
/// is checked against the intake's key by the vault, not here.
pub fn decode_training_receipt(bytes: &[u8]) -> anyhow::Result<TrainingReceiptV1> {
    let receipt: TrainingReceiptV1 = serde_json::from_slice(bytes)?;
    check_header(
        receipt.schema_version,
        &receipt.file_type,
        TRAINING_RECEIPT_TYPE,
    )?;
    check_signature(&receipt.signature)?;
    let body = &receipt.body;
    check_hex("receipt_id", &body.receipt_id, ID_HEX)?;
    check_hex("engine_vault_id", &body.engine_vault_id, DIGEST_HEX)?;
    match &body.subject {
        TrainingReceiptSubjectV1::Submission(id) | TrainingReceiptSubjectV1::Control(id) => {
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
        TrainingReceiptStatusV1::Removed | TrainingReceiptStatusV1::RemovalPending
    );
    if removal && body.note.as_deref() != Some(TRAINING_WITHDRAWAL_NOTE) {
        anyhow::bail!("a removal receipt must carry the withdrawal note");
    }
    Ok(receipt)
}

/// Decodes one control strictly, for a consumer.
pub fn decode_training_control(bytes: &[u8]) -> anyhow::Result<TrainingControlV1> {
    let control: TrainingControlV1 = serde_json::from_slice(bytes)?;
    check_header(
        control.schema_version,
        &control.file_type,
        TRAINING_CONTROL_TYPE,
    )?;
    check_signature(&control.signature)?;
    check_hex("control_id", &control.body.control_id, ID_HEX)?;
    check_hex("engine_vault_id", &control.body.engine_vault_id, DIGEST_HEX)?;
    Ok(control)
}

/// Decodes one offer manifest strictly, for a consumer: its chunks must be
/// numbered from 0 and each name exactly its own file.
pub fn decode_training_offer(bytes: &[u8]) -> anyhow::Result<TrainingOfferV1> {
    let offer: TrainingOfferV1 = serde_json::from_slice(bytes)?;
    check_header(offer.schema_version, &offer.file_type, TRAINING_OFFER_TYPE)?;
    check_signature(&offer.signature)?;
    let body = &offer.body;
    check_hex("submission_id", &body.submission_id, ID_HEX)?;
    check_hex("engine_vault_id", &body.engine_vault_id, DIGEST_HEX)?;
    check_hex("source", &body.source, ID_HEX)?;
    check_hex("source_revision", &body.source_revision, DIGEST_HEX)?;
    check_hex("key_id", &body.payload.key_id, DIGEST_HEX)?;
    if body.worlds.is_empty() {
        anyhow::bail!("an offer names no world");
    }
    for (index, chunk) in body.payload.chunks.iter().enumerate() {
        let expected = offer_chunk_file_name(&body.submission_id, chunk.part);
        if u32::try_from(index).ok() != Some(chunk.part) || expected.as_ref() != Some(&chunk.file) {
            anyhow::bail!("an offer chunk is out of order or names another file");
        }
        check_hex("chunk digest", &chunk.digest, DIGEST_HEX)?;
    }
    Ok(offer)
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

fn check_signature(signature: &TrainingSignatureV1) -> anyhow::Result<()> {
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
