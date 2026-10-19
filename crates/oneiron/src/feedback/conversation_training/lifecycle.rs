//! The publisher training lifecycle (OF-420 A2): what an outbox takes, and
//! what the engine decides about it.
//!
//! [`PublisherTrainingLifecycle`] sits beside [`super::PublisherTrainingSink`]
//! and leaves it as it is. An implementation is a transport: it stages,
//! publishes and purges bytes the engine sealed and signed, writes controls
//! the engine signed, and reads back the intake's receipts. It decides
//! nothing. [`TrainingQueued`] means local durable custody only: never that
//! the intake took anything, and never that a run used it. A `stored`
//! receipt means the intake's committed custody; `removed`, a verified
//! purge; a used run is a fact of its own.
//!
//! Release is publication. An offer is prepared and held in local custody;
//! [`crate::Vault::release_training_submission`] rechecks its source,
//! persons, worlds, the vault's training setting and the opt-outs
//! immediately before the transport publishes it, and only a
//! [`ReleaseDecision::Release`] publishes.

use oneiron_vault_contract::conversation_training::{
    INTAKE_RECEIPT_KEY_FILE, INTAKE_RECIPIENT_FILE, TrainingReceiptV1,
};

use crate::error::Result;

use super::Withheld;

/// One offer's random id; a retry of the same prepared offer keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrainingSubmissionId(pub [u8; 16]);

impl TrainingSubmissionId {
    /// The id as 32 lower-case hex characters, as files name it.
    #[must_use]
    pub fn to_hex(&self) -> String {
        oneiron_vault_contract::hex(&self.0)
    }

    /// The id `text` spells, as files name it.
    #[must_use]
    pub fn from_hex(text: &str) -> Option<Self> {
        hex_id(text).map(Self)
    }
}

/// One control's random id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrainingControlId(pub [u8; 16]);

impl TrainingControlId {
    /// The id as 32 lower-case hex characters, as files name it.
    #[must_use]
    pub fn to_hex(&self) -> String {
        oneiron_vault_contract::hex(&self.0)
    }

    /// The id `text` spells, as files name it.
    #[must_use]
    pub fn from_hex(text: &str) -> Option<Self> {
        hex_id(text).map(Self)
    }
}

/// A 16-byte id from its lower-case hex.
fn hex_id(text: &str) -> Option<[u8; 16]> {
    if !oneiron_vault_contract::conversation_training::is_lower_hex(text, 32) {
        return None;
    }
    oneiron_vault_contract::from_hex(text)?.try_into().ok()
}

/// What a transport took into local durable custody: one offer or one
/// control, at its place in the event order. Nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrainingQueued {
    /// The submission or control id.
    pub id: [u8; 16],
    /// Its place in the one event order offers and controls share.
    pub event_seq: u64,
}

/// One offer, sealed and signed, for a transport to stage. The text inside
/// is the in-vault filter's output, sealed to the intake: the transport
/// never holds it in the clear.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedTrainingOffer {
    /// The submission.
    pub submission: TrainingSubmissionId,
    /// Its place in the event order.
    pub event_seq: u64,
    /// The manifest file's name and bytes.
    pub manifest: (String, Vec<u8>),
    /// Each chunk file's name and bytes, in part order.
    pub chunks: Vec<(String, Vec<u8>)>,
}

impl std::fmt::Debug for SealedTrainingOffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedTrainingOffer")
            .field("submission", &self.submission.to_hex())
            .field("event_seq", &self.event_seq)
            .field("chunks", &self.chunks.len())
            .finish_non_exhaustive()
    }
}

/// One control, signed, for a transport to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTrainingControl {
    /// The control.
    pub control: TrainingControlId,
    /// Its place in the event order.
    pub event_seq: u64,
    /// The control file's name.
    pub file: String,
    /// The control file's bytes.
    pub bytes: Vec<u8>,
}

/// Where a receipt read resumes: the highest publisher sequence this vault
/// applied.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReceiptCursor(pub u64);

/// One receipt a transport read, with the file it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedTrainingReceipt {
    /// The receipt file's name.
    pub file: String,
    /// The receipt, decoded strictly; its signature is not yet checked.
    pub receipt: TrainingReceiptV1,
}

/// The receipts a transport read past a cursor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrainingReceiptPage {
    /// Receipts past the cursor, in no promised order.
    pub receipts: Vec<ReceivedTrainingReceipt>,
    /// Receipt files at or before the cursor: replays, applied already.
    pub stale: Vec<String>,
}

/// A transport for conversation text toward training the models Oneiron
/// ships: an outbox the intake's side reads.
///
/// It holds no authority. Every byte it stages was sealed and signed by the
/// engine, every publish follows a release the engine decided, and every
/// receipt it reads is applied only once the engine checked the intake's
/// signature.
pub trait PublisherTrainingLifecycle {
    /// Stages one offer in local durable custody, unpublished.
    ///
    /// # Errors
    /// The bytes could not be staged; nothing is published.
    fn accept(&self, offer: &SealedTrainingOffer) -> Result<TrainingQueued>;

    /// Publishes a staged offer a release let through: chunks first, the
    /// manifest last, each renamed whole.
    ///
    /// # Errors
    /// The offer could not be published whole; the next pass retries it.
    fn publish(&self, queued: &TrainingQueued) -> Result<()>;

    /// Removes an offer's bytes, staged or published.
    ///
    /// # Errors
    /// A file could not be removed; the next pass retries it.
    fn purge(&self, submission: TrainingSubmissionId) -> Result<()>;

    /// Writes one control whole.
    ///
    /// # Errors
    /// The control could not be written; the next pass retries it.
    fn control(&self, control: &SignedTrainingControl) -> Result<TrainingQueued>;

    /// The receipts past `after`.
    ///
    /// # Errors
    /// The receipt directory could not be read.
    fn receipts(&self, after: ReceiptCursor) -> Result<TrainingReceiptPage>;

    /// Removes one receipt file the engine applied.
    ///
    /// # Errors
    /// The file could not be removed; it is read again next pass.
    fn retire_receipt(&self, file: &str) -> Result<()>;
}

/// Whether a prepared offer may be published now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseDecision {
    /// Publish it: everything it was prepared on holds now.
    Release {
        /// The source's revision, recomputed now and matching.
        source_revision: [u8; 32],
        /// The vault's training setting revision now.
        setting_revision: [u8; 32],
        /// The worlds' settings revision digest now.
        policy_revision: [u8; 32],
        /// The offer's place in the event order.
        event_seq: u64,
    },
    /// Hold it back: it is purged, never published.
    Withheld(TrainingWithheld),
}

/// Why a release held an offer back. Each names state, never text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrainingWithheld {
    /// No offer of that id is held for release.
    NotHeld,
    /// The source has nothing left that counts.
    SourceGone,
    /// The source changed since the offer was prepared: a changed source
    /// needs a new offer.
    SourceChanged,
    /// The vault's training setting changed since.
    ChoiceChanged,
    /// A world's settings changed since.
    PolicyChanged,
    /// The source does not pass the egress check now.
    Ineligible(Withheld),
}

/// Why no offer is written. Controls still flow in every case.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrainingUnavailable {
    /// The intake's recipient key is not in the outbox (CALLS-5).
    #[error(
        "no intake recipient key: the outbox holds no {}",
        INTAKE_RECIPIENT_FILE
    )]
    MissingIntakeKey,
    /// The recipient file holds no hybrid public key.
    #[error("the outbox's {} is not a hybrid public key", INTAKE_RECIPIENT_FILE)]
    UnusableIntakeKey,
    /// The intake's receipt key is not in the outbox: receipts are not
    /// applied.
    #[error(
        "no intake receipt key: the outbox holds no {}",
        INTAKE_RECEIPT_KEY_FILE
    )]
    MissingReceiptKey,
    /// The receipt key file holds no Ed25519 public key.
    #[error(
        "the outbox's {} is not an Ed25519 public key",
        INTAKE_RECEIPT_KEY_FILE
    )]
    UnusableReceiptKey,
    /// A self-hosted vault has no account binding to the intake yet (C1).
    #[error("no account binding to the publisher's intake (no device-code client in-tree)")]
    NoAccountBinding,
    /// This install has no signing key to sign an offer with.
    #[error("this install has no machine signing key to sign training files with")]
    NoInstallKey,
    /// The in-vault filter could not run; no text was offered.
    #[error("the in-vault text filter is unavailable: {0}")]
    FilterUnavailable(String),
}
