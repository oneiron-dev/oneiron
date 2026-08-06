//! ED-08 (ONE-1764, ARCH-0056 §9 · OF-401): the publisher loop's engine
//! substrate — content-free issue signatures UP, an ordinary comm channel as
//! the transport, and interview digests that ride ED-00/ED-01's doors.
//!
//! # Content-freedom is structural, not a naming convention
//!
//! ARCH-0056 §9's rung-1 row is safe to default on "because the leak is
//! structurally impossible, not checkbox-prevented". That claim only holds if
//! free text has nowhere to sit. [`IssueSignature`] therefore has PRIVATE
//! fields and exactly one door — [`IssueSignature::new`] — and every one of
//! its arguments is a shape that cannot carry a message:
//!
//! | field | why text cannot enter |
//! |---|---|
//! | `category` | [`IssueCategory`], a closed enum — not a string |
//! | `artifact` | [`EntityId`], 16 opaque bytes |
//! | `version` | `u32` |
//! | `model_id` | must parse as a [`ModelStackId`] AND be registered in the caller's [`ModelStackRegistry`]; an unknown id is refused, so "model id" is not a smuggling channel |
//! | `counts` | keys are [`CountKey`], a closed enum; values are `u32` |
//! | `content_hash` | exactly [`CONTENT_HASH_LEN`] lowercase hex characters |
//!
//! The honest bound: `content_hash` is caller-supplied, so an in-vault caller
//! that wanted to could stuff 32 bytes into it. That is a fixed-width opaque
//! field, not a text channel, and a caller who can call this door is already
//! inside the vault — the guarantee this door makes is that no free-form,
//! variable-length content can cross, which is what the rung-1 consent posture
//! was ratified against. Stating the bound beats implying a stronger one.
//!
//! # Counts are tallies, never deltas
//!
//! Rung 1 carries "counts, pattern hashes. NEVER text, NEVER deltas". So
//! [`CountKey`] is the three-arm tally of [`ProposalOutcome`] — how many judged
//! outcomes, how many the human had to amend, how many the human threw away —
//! and deliberately NOT the edit mass in [`OpsSummary`](super::delta::OpsSummary)
//! (`ins`/`del`/`kept`/`d_norm`). Those numbers ARE the delta; they stay home.
//!
//! # The channel is nothing new
//!
//! ARCH-0056 r7: "publisher ↔ user channel = a normal comm channel with the
//! publisher ACTOR as counterparty — zero new primitives". This module calls
//! [`resolve_or_create_comm_party`] and [`record_comm_send_receipt`] and owns
//! nothing about send or retry; SPINE-COMM owns those internals. The DOWN
//! direction (platform-voice notices, EC-7) is ordinary channel content and
//! needs no engine surface at all.
//!
//! # The dial is a dial
//!
//! Dial off means signatures are still computed and stored locally and nothing
//! is sent — the local ledger keeps working, only the outbound hop stops. The
//! withheld fact is durable ([`SignatureSendState::Withheld`]) rather than
//! merely returned, because a skip nobody can read afterwards is not a skip
//! anyone can audit.
//!
//! Outbound consent rails already ride the comm send path (`disclosure.rs`),
//! so this module adds no second consent check.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::comm::{CommError, record_comm_send_receipt, resolve_or_create_comm_party};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::identity_topology::ProposalOutcome;
use crate::receipt::ReceiptRecord;
use crate::settings::model_versioning::{ModelStackId, ModelStackRegistry};
use crate::skill_attribution::AttributionVerdict;

#[cfg(feature = "sync")]
use super::proposal_text::ProposalTextArtifact;
#[cfg(feature = "sync")]
use crate::write_envelope::WriteActor;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Typed error for the publisher loop's doors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PublisherError {
    /// Underlying vault operation failed.
    #[error(transparent)]
    Engine(#[from] Error),
    /// The comm doors this module rides refused.
    #[error(transparent)]
    Comm(#[from] CommError),
    /// The offered model id is not a stack the caller's registry serves —
    /// either it is not a well-formed [`ModelStackId`] at all, or it names no
    /// registered stack. One fact, one error: it is not a model this vault
    /// knows, and an unknown model id is how free text would get out.
    #[error("issue signature model id is not a registered model stack")]
    UnknownModelStack,
    /// The same [`CountKey`] was offered twice. The keys are closed, so a
    /// repeat is the only shape left for smuggling a second value under one
    /// name.
    #[error("issue signature repeats a count key")]
    DuplicateCountKey,
    /// `content_hash` was not exactly [`CONTENT_HASH_LEN`] lowercase hex
    /// characters.
    #[error("issue signature content hash is not fixed-length lowercase hex")]
    MalformedContentHash,
    /// A signature id was offered to the send door with no stored record
    /// behind it.
    #[error("issue signature not found")]
    SignatureNotFound,
}

/// Result alias for the publisher loop's doors.
pub type PublisherResult<T> = std::result::Result<T, PublisherError>;

// ---------------------------------------------------------------------------
// Closed vocabularies
// ---------------------------------------------------------------------------

/// The defect class an issue signature reports (ARCH-0056 §5 routing, §9 UP
/// rung 1).
///
/// Pinned to [`AttributionVerdict`] arm-for-arm and token-for-token via
/// [`IssueCategory::from_verdict`] — the attribution judge's verdict IS the
/// category, and the tests assert the two vocabularies cannot drift apart. It
/// is a distinct type only because `AttributionVerdict` carries skill-routing
/// semantics (which entity a verdict writes against) that the publisher's
/// wire vocabulary must not inherit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IssueCategory {
    /// The shipped artifact's own content was wrong.
    SkillDefect,
    /// The executor fumbled an artifact that was correct.
    ExecutionLapse,
    /// The artifact was missing content the attempt needed.
    Discovery,
    /// An external fact moved under an artifact that was right when made.
    Environment,
    /// The decider's taste moved; the artifact was not wrong.
    PreferenceShift,
}

impl IssueCategory {
    /// Every arm — the closed enum made iterable, so a sixth category cannot
    /// be added without every site here seeing it.
    pub const ALL: [Self; 5] = [
        Self::SkillDefect,
        Self::ExecutionLapse,
        Self::Discovery,
        Self::Environment,
        Self::PreferenceShift,
    ];

    /// The pinned on-disk/wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SkillDefect => "skill_defect",
            Self::ExecutionLapse => "execution_lapse",
            Self::Discovery => "discovery",
            Self::Environment => "environment",
            Self::PreferenceShift => "preference_shift",
        }
    }

    /// Parses a pinned token; `None` for one this engine never wrote.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|arm| arm.as_str() == value)
    }

    /// The category behind an attribution verdict — the no-fork bridge.
    #[must_use]
    pub const fn from_verdict(verdict: AttributionVerdict) -> Self {
        match verdict {
            AttributionVerdict::SkillDefect => Self::SkillDefect,
            AttributionVerdict::ExecutionLapse => Self::ExecutionLapse,
            AttributionVerdict::Discovery => Self::Discovery,
            AttributionVerdict::Environment => Self::Environment,
            AttributionVerdict::PreferenceShift => Self::PreferenceShift,
        }
    }
}

/// The closed set of count names a signature may carry.
///
/// Each arm is one-to-one with a landed [`ProposalOutcome`] fact, so the whole
/// vocabulary is derivable from judged receipts and nothing here needs a
/// consumer to invent a number. `ApprovedUntouched` has no arm on purpose: it
/// is `Judged - Amended - Rejected`, and a redundant count is a second place
/// for the two to disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CountKey {
    /// Judged outcomes behind this signature — the denominator.
    Judged,
    /// Of those, approved only after the human amended the body.
    Amended,
    /// Of those, rejected outright.
    Rejected,
}

impl CountKey {
    /// Every arm.
    pub const ALL: [Self; 3] = [Self::Judged, Self::Amended, Self::Rejected];

    /// The pinned on-disk/wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Judged => "judged",
            Self::Amended => "amended",
            Self::Rejected => "rejected",
        }
    }

    /// Parses a pinned token; `None` for one this engine never wrote.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|arm| arm.as_str() == value)
    }
}

/// Length of a signature's `content_hash` — blake3 rendered as lowercase hex,
/// the same shape ED-01's Δ refs carry.
pub const CONTENT_HASH_LEN: usize = 64;

// ---------------------------------------------------------------------------
// The signature record
// ---------------------------------------------------------------------------

/// A content-free issue signature (ARCH-0056 §9, UP rung 1).
///
/// Fields are private and [`IssueSignature::new`] is the only door; see the
/// module docs for why that is what makes the leak structural.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueSignature {
    category: IssueCategory,
    artifact: EntityId,
    version: u32,
    model_id: ModelStackId,
    counts: BTreeMap<CountKey, u32>,
    content_hash: String,
}

impl IssueSignature {
    /// The only door.
    ///
    /// `registry` is the authority `model_id` is checked against — see the
    /// worklog's D1: membership cannot be tested without it, and an unchecked
    /// model id is precisely the smuggling channel this door exists to close.
    ///
    /// # Errors
    ///
    /// [`PublisherError::UnknownModelStack`] for a model id the registry does
    /// not serve, [`PublisherError::DuplicateCountKey`] for a repeated count
    /// name, [`PublisherError::MalformedContentHash`] for a hash that is not
    /// exactly [`CONTENT_HASH_LEN`] lowercase hex characters.
    pub fn new(
        category: IssueCategory,
        artifact: EntityId,
        version: u32,
        registry: &ModelStackRegistry,
        model_id: &str,
        counts: &[(CountKey, u32)],
        content_hash: &str,
    ) -> PublisherResult<Self> {
        let model_id: ModelStackId = model_id
            .parse()
            .map_err(|_| PublisherError::UnknownModelStack)?;
        if registry.get(&model_id).is_none() {
            return Err(PublisherError::UnknownModelStack);
        }
        if !is_content_hash(content_hash) {
            return Err(PublisherError::MalformedContentHash);
        }
        let mut tallies = BTreeMap::new();
        for (key, value) in counts {
            if tallies.insert(*key, *value).is_some() {
                return Err(PublisherError::DuplicateCountKey);
            }
        }
        Ok(Self {
            category,
            artifact,
            version,
            model_id,
            counts: tallies,
            content_hash: content_hash.to_owned(),
        })
    }

    /// The defect class.
    #[must_use]
    pub const fn category(&self) -> IssueCategory {
        self.category
    }

    /// The shipped artifact this is about.
    #[must_use]
    pub const fn artifact(&self) -> EntityId {
        self.artifact
    }

    /// That artifact's version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// The registered model stack behind the judged work.
    #[must_use]
    pub fn model_id(&self) -> &ModelStackId {
        &self.model_id
    }

    /// The pattern hash.
    #[must_use]
    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }

    /// One tally; `None` when this signature carries no count under `key`.
    #[must_use]
    pub fn count(&self, key: CountKey) -> Option<u32> {
        self.counts.get(&key).copied()
    }

    /// Every tally, in [`CountKey`] order.
    pub fn counts(&self) -> impl Iterator<Item = (CountKey, u32)> + '_ {
        self.counts.iter().map(|(key, value)| (*key, *value))
    }
}

/// Whether `value` is exactly [`CONTENT_HASH_LEN`] lowercase hex characters.
fn is_content_hash(value: &str) -> bool {
    value.len() == CONTENT_HASH_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Tallies the closed count set over judged proposal-outcome receipts.
///
/// This is the judged-cluster inlet. ED-03/ED-04's clusters do not exist yet,
/// so the door binds the surface that does: `outcome` on a [`ReceiptRecord`],
/// parsed through [`ProposalOutcome`] (ARCH-0055 r7's ratified three states).
/// When the cluster types land they pass their own members' receipts through
/// this same door and nothing here changes.
///
/// Records whose outcome is not a proposal outcome are skipped rather than
/// raised — a mixed receipt slice is the normal case for a caller that queried
/// by artifact, not by kind.
#[must_use]
pub fn tally_judged_outcomes(receipts: &[ReceiptRecord]) -> [(CountKey, u32); 3] {
    let mut judged = 0_u32;
    let mut amended = 0_u32;
    let mut rejected = 0_u32;
    for outcome in receipts
        .iter()
        .filter_map(|record| ProposalOutcome::parse(&record.outcome))
    {
        judged = judged.saturating_add(1);
        match outcome {
            ProposalOutcome::ApprovedAmended => amended = amended.saturating_add(1),
            ProposalOutcome::Rejected => rejected = rejected.saturating_add(1),
            ProposalOutcome::ApprovedUntouched => {}
        }
    }
    [
        (CountKey::Judged, judged),
        (CountKey::Amended, amended),
        (CountKey::Rejected, rejected),
    ]
}

// ---------------------------------------------------------------------------
// Signature storage
// ---------------------------------------------------------------------------

const SIGNATURE_KEY_PREFIX: &[u8] = b"edit_distance/issue_signature/v1\0";
const SEND_STATE_KEY_PREFIX: &[u8] = b"edit_distance/issue_signature_send/v1\0";

/// On-disk shape of a stored signature.
///
/// Separate from [`IssueSignature`] on purpose: deriving `Deserialize` on the
/// public type would hand every caller a second constructor that skips every
/// check `new` makes. Readback re-validates the closed vocabularies and the
/// hash shape through [`IssueSignature`]'s own invariants below.
#[derive(Serialize, Deserialize)]
struct SignatureRow {
    schema_version: u8,
    category: String,
    artifact: String,
    version: u32,
    model_id: String,
    counts: BTreeMap<String, u32>,
    content_hash: String,
}

const SIGNATURE_SCHEMA_VERSION: u8 = 1;

fn corrupt() -> Error {
    Error::CorruptedIndex("issue signature record")
}

fn signature_key(id: EntityId) -> Vec<u8> {
    let mut key = SIGNATURE_KEY_PREFIX.to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}

fn send_state_key(id: EntityId) -> Vec<u8> {
    let mut key = SEND_STATE_KEY_PREFIX.to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}

fn put_meta(vault: &Vault, key: &[u8], value: &[u8]) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, key, value)?;
        Ok(())
    })
}

fn encode_signature(sig: &IssueSignature) -> Result<Vec<u8>> {
    let row = SignatureRow {
        schema_version: SIGNATURE_SCHEMA_VERSION,
        category: sig.category.as_str().to_owned(),
        artifact: sig.artifact.to_hex(),
        version: sig.version,
        model_id: sig.model_id.as_str().to_owned(),
        counts: sig
            .counts
            .iter()
            .map(|(key, value)| (key.as_str().to_owned(), *value))
            .collect(),
        content_hash: sig.content_hash.clone(),
    };
    crate::llm::canonical_json_bytes(&row)
        .map_err(|_| Error::InvariantViolation("issue signature encode"))
}

fn decode_signature(bytes: &[u8]) -> Result<IssueSignature> {
    let row: SignatureRow = serde_json::from_slice(bytes).map_err(|_| corrupt())?;
    if row.schema_version != SIGNATURE_SCHEMA_VERSION || !is_content_hash(&row.content_hash) {
        return Err(corrupt());
    }
    let mut counts = BTreeMap::new();
    for (key, value) in row.counts {
        let key = CountKey::parse(&key).ok_or_else(corrupt)?;
        if counts.insert(key, value).is_some() {
            return Err(corrupt());
        }
    }
    Ok(IssueSignature {
        category: IssueCategory::parse(&row.category).ok_or_else(corrupt)?,
        artifact: EntityId::from_hex(&row.artifact).map_err(|_| corrupt())?,
        version: row.version,
        model_id: row.model_id.parse().map_err(|_| corrupt())?,
        counts,
        content_hash: row.content_hash,
    })
}

/// Stores a signature and returns the id it landed under.
///
/// # Errors
///
/// Storage errors.
pub fn emit_issue_signature(vault: &Vault, sig: IssueSignature) -> PublisherResult<EntityId> {
    let id = EntityId::now();
    let value = encode_signature(&sig)?;
    put_meta(vault, &signature_key(id), &value)?;
    Ok(id)
}

/// Reads back the signature stored under `id`.
///
/// # Errors
///
/// Storage errors, and [`Error::CorruptedIndex`] on a row this engine did not
/// write.
pub fn issue_signature(vault: &Vault, id: EntityId) -> PublisherResult<Option<IssueSignature>> {
    let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, &signature_key(id))? else {
        return Ok(None);
    };
    Ok(Some(decode_signature(&raw)?))
}

// ---------------------------------------------------------------------------
// The dial
// ---------------------------------------------------------------------------

/// The publisher share dial, over `vault_meta` — house pattern is a per-feature
/// byte-key const in the owning module (`INBOX_REVIEW_DIAL_KEY`, `inbox.rs:73`).
/// `settings.rs` is UI-customization only and is not touched.
pub const PUBLISHER_ENABLED_KEY: &[u8] = b"settings:publisher:v1:enabled";

/// The install profile's default for [`PUBLISHER_ENABLED_KEY`], written at
/// provisioning. This is where the cloud posture's default-ON (ARCH-0056 §9
/// rung 1, owner ruling r6) lands; a self-host install writes its own answer,
/// and a build that never provisioned falls through to
/// [`PUBLISHER_ENABLED_COMPILED_DEFAULT`].
pub const PUBLISHER_INSTALL_DEFAULT_KEY: &[u8] = b"settings:publisher:v1:install_default";

/// The compiled fallback: disabled.
///
/// The engine cannot know its own posture, and it is the OSS/self-hostable
/// artifact — "self-host picks posture at install" (§9) means a build that
/// never picked must not send to a publisher nobody chose. This is posture
/// resolution, not a wall: one write to either key above flips it.
pub const PUBLISHER_ENABLED_COMPILED_DEFAULT: bool = false;

const DIAL_ENABLED: &str = "enabled";
const DIAL_DISABLED: &str = "disabled";

fn read_dial_key(vault: &Vault, key: &[u8]) -> Result<Option<bool>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, key)? else {
        return Ok(None);
    };
    match std::str::from_utf8(&raw) {
        Ok(DIAL_ENABLED) => Ok(Some(true)),
        Ok(DIAL_DISABLED) => Ok(Some(false)),
        _ => Err(Error::CorruptedIndex("publisher dial")),
    }
}

fn write_dial_key(vault: &Vault, key: &[u8], enabled: bool) -> Result<()> {
    let token = if enabled { DIAL_ENABLED } else { DIAL_DISABLED };
    put_meta(vault, key, token.as_bytes())
}

/// Resolves the effective publisher dial.
///
/// Order: the owner's explicit dial, then the install profile, then the
/// compiled default. The explicit dial sits on top deliberately — an install
/// profile that overrode a dial the owner set would make it a wall, and this
/// is ratified as a dial (worklog D4).
///
/// # Errors
///
/// Storage errors, and [`Error::CorruptedIndex`] on a dial token this engine
/// never wrote.
pub fn publisher_enabled(vault: &Vault) -> PublisherResult<bool> {
    if let Some(explicit) = read_dial_key(vault, PUBLISHER_ENABLED_KEY)? {
        return Ok(explicit);
    }
    if let Some(profile) = read_dial_key(vault, PUBLISHER_INSTALL_DEFAULT_KEY)? {
        return Ok(profile);
    }
    Ok(PUBLISHER_ENABLED_COMPILED_DEFAULT)
}

/// Sets the owner's explicit dial position.
///
/// # Errors
///
/// Storage errors.
pub fn set_publisher_enabled(vault: &Vault, enabled: bool) -> PublisherResult<()> {
    write_dial_key(vault, PUBLISHER_ENABLED_KEY, enabled)?;
    Ok(())
}

/// Writes the install profile's default. Provisioning-time door; it never
/// overrides an explicit dial.
///
/// # Errors
///
/// Storage errors.
pub fn set_publisher_install_default(vault: &Vault, enabled: bool) -> PublisherResult<()> {
    write_dial_key(vault, PUBLISHER_INSTALL_DEFAULT_KEY, enabled)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Transport — the publisher is an ordinary comm party
// ---------------------------------------------------------------------------

/// The comm party key the publisher counterparty resolves under.
pub const PUBLISHER_PARTY_KEY: &str = "publisher";

/// The comm channel class publisher sends ride.
pub const PUBLISHER_CHANNEL_CLASS: &str = "publisher";

/// Resolves — creating on first use — the PERSON entity the publisher channel
/// hangs off.
///
/// # Errors
///
/// Whatever `comm.rs`'s party door raises.
pub fn publisher_party(vault: &Vault) -> PublisherResult<EntityId> {
    Ok(resolve_or_create_comm_party(vault, PUBLISHER_PARTY_KEY)?)
}

/// Where a stored signature stands with respect to the outbound hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignatureSendState {
    /// Computed and stored; never offered to the send door.
    #[default]
    Pending,
    /// Offered while the dial was off — stored, deliberately not sent.
    Withheld,
    /// Handed to `comm.rs`'s send-receipt door.
    Sent,
}

impl SignatureSendState {
    /// Every arm.
    pub const ALL: [Self; 3] = [Self::Pending, Self::Withheld, Self::Sent];

    /// The pinned on-disk token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Withheld => "withheld",
            Self::Sent => "sent",
        }
    }

    /// Parses a pinned token.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|arm| arm.as_str() == value)
    }
}

/// What one [`send_signatures_if_enabled`] batch did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SendOutcome {
    /// Signatures handed to the comm send door.
    pub sent: usize,
    /// Signatures held locally because the dial is off.
    pub withheld: usize,
    /// The counterparty this batch rode, resolved once for the whole batch.
    /// `None` when the dial was off — a withheld batch mints no party.
    pub party: Option<EntityId>,
}

/// Reads a signature's send state; [`SignatureSendState::Pending`] until the
/// send door has ruled on it.
///
/// # Errors
///
/// Storage errors, and [`Error::CorruptedIndex`] on a token this engine never
/// wrote.
pub fn signature_send_state(vault: &Vault, id: EntityId) -> PublisherResult<SignatureSendState> {
    let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, &send_state_key(id))? else {
        return Ok(SignatureSendState::Pending);
    };
    let token = std::str::from_utf8(&raw)
        .ok()
        .and_then(SignatureSendState::parse)
        .ok_or_else(|| Error::CorruptedIndex("issue signature send state"))?;
    Ok(token)
}

fn put_send_state(vault: &Vault, id: EntityId, state: SignatureSendState) -> Result<()> {
    put_meta(vault, &send_state_key(id), state.as_str().as_bytes())
}

fn require_signature(vault: &Vault, id: EntityId) -> PublisherResult<()> {
    let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
    if vault
        .store
        .vault_meta
        .get(&rtxn, &signature_key(id))?
        .is_none()
    {
        return Err(PublisherError::SignatureNotFound);
    }
    Ok(())
}

/// Offers a batch of stored signatures to the publisher channel, honoring the
/// dial.
///
/// Dial ON: the counterparty is resolved once, then each signature rides
/// `comm.rs`'s send-receipt door. Dial OFF: nothing is sent and nothing is
/// resolved; each signature is durably marked
/// [`SignatureSendState::Withheld`], which is what makes a skip auditable
/// afterwards.
///
/// The projector is NOT run here — `comm.rs` owns when its pass runs, and
/// coupling a send door to a projector pass is exactly the kind of internal
/// this lane is not allowed to reach into.
///
/// # Errors
///
/// [`PublisherError::SignatureNotFound`] when an id has no stored record,
/// plus storage and comm errors.
pub fn send_signatures_if_enabled(
    vault: &Vault,
    sigs: &[EntityId],
) -> PublisherResult<SendOutcome> {
    // An empty batch resolves nothing: minting the counterparty for a send that
    // carries no signatures would leave a PERSON row behind for a caller that
    // asked for no work.
    if sigs.is_empty() {
        return Ok(SendOutcome::default());
    }
    for id in sigs {
        require_signature(vault, *id)?;
    }
    if !publisher_enabled(vault)? {
        for id in sigs {
            put_send_state(vault, *id, SignatureSendState::Withheld)?;
        }
        return Ok(SendOutcome {
            sent: 0,
            withheld: sigs.len(),
            party: None,
        });
    }
    let party = publisher_party(vault)?;
    let now = crate::unix_seconds_now();
    for id in sigs {
        record_comm_send_receipt(vault, PUBLISHER_PARTY_KEY, PUBLISHER_CHANNEL_CLASS, now)?;
        put_send_state(vault, *id, SignatureSendState::Sent)?;
    }
    Ok(SendOutcome {
        sent: sigs.len(),
        withheld: 0,
        party: Some(party),
    })
}

// ---------------------------------------------------------------------------
// UP rung 3 — agent-conducted interviews
// ---------------------------------------------------------------------------

/// Where an interview digest stands (ARCH-0056 §9 rung 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InterviewState {
    /// The user's own agent is still drafting the digest.
    #[default]
    Drafting,
    /// Surfaced to the user, who may edit it before it settles.
    UserReview,
    /// Frozen — the digest's edit window is closed and its Δ is measurable.
    Settled,
}

impl InterviewState {
    /// Every arm.
    pub const ALL: [Self; 3] = [Self::Drafting, Self::UserReview, Self::Settled];

    /// The pinned on-disk token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Drafting => "drafting",
            Self::UserReview => "user_review",
            Self::Settled => "settled",
        }
    }

    /// Parses a pinned token.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|arm| arm.as_str() == value)
    }
}

/// One interview: the publisher-sourced topic, the digest artifact the user's
/// agent drafts against it, and where that digest stands.
///
/// The digest is an ORDINARY proposal-text artifact. That is the whole point of
/// rung 3's "the edit loop applies to the digest itself — free": the user's
/// edits are recorded by ED-00's window and measured by ED-01's Δ lanes, so
/// this module computes no edit distance of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterviewSession {
    /// The publisher-sourced topic this interview answers.
    pub topic_ref: EntityId,
    /// The proposal-text artifact holding the digest body.
    pub digest_artifact: EntityId,
    /// Where the digest stands.
    pub state: InterviewState,
}

const INTERVIEW_KEY_PREFIX: &[u8] = b"edit_distance/interview_session/v1\0";

/// On-disk shape of a session, keyed by its digest artifact.
#[derive(Serialize, Deserialize)]
struct InterviewRow {
    schema_version: u8,
    topic_ref: String,
    state: String,
}

const INTERVIEW_SCHEMA_VERSION: u8 = 1;

fn interview_corrupt() -> Error {
    Error::CorruptedIndex("interview session record")
}

fn interview_key(digest_artifact: EntityId) -> Vec<u8> {
    let mut key = INTERVIEW_KEY_PREFIX.to_vec();
    key.extend_from_slice(digest_artifact.as_bytes());
    key
}

fn put_interview(vault: &Vault, session: InterviewSession) -> Result<()> {
    let row = InterviewRow {
        schema_version: INTERVIEW_SCHEMA_VERSION,
        topic_ref: session.topic_ref.to_hex(),
        state: session.state.as_str().to_owned(),
    };
    let value = crate::llm::canonical_json_bytes(&row)
        .map_err(|_| Error::InvariantViolation("interview session encode"))?;
    put_meta(vault, &interview_key(session.digest_artifact), &value)
}

/// Reads the session recorded against `digest_artifact`.
///
/// # Errors
///
/// Storage errors, and [`Error::CorruptedIndex`] on a row this engine did not
/// write.
pub fn interview_session(
    vault: &Vault,
    digest_artifact: EntityId,
) -> PublisherResult<Option<InterviewSession>> {
    let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
    let Some(raw) = vault
        .store
        .vault_meta
        .get(&rtxn, &interview_key(digest_artifact))?
    else {
        return Ok(None);
    };
    let row: InterviewRow = serde_json::from_slice(&raw).map_err(|_| interview_corrupt())?;
    if row.schema_version != INTERVIEW_SCHEMA_VERSION {
        return Err(interview_corrupt().into());
    }
    Ok(Some(InterviewSession {
        topic_ref: EntityId::from_hex(&row.topic_ref).map_err(|_| interview_corrupt())?,
        digest_artifact,
        state: InterviewState::parse(&row.state).ok_or_else(interview_corrupt)?,
    }))
}

/// Moves a drafted digest in front of the user.
///
/// # Errors
///
/// Storage errors; [`PublisherError::SignatureNotFound`] is not raised here —
/// an unknown digest simply has no session, which surfaces as `Ok(None)` from
/// [`interview_session`].
pub fn submit_interview_for_review(
    vault: &Vault,
    session: InterviewSession,
) -> PublisherResult<InterviewSession> {
    let session = InterviewSession {
        state: InterviewState::UserReview,
        ..session
    };
    put_interview(vault, session)?;
    Ok(session)
}

/// Opens an interview: mints the digest as an ordinary proposal-text artifact
/// through ED-00's public door, binds `actor` to the artifact's Loro peer so
/// the user's later edits attribute to them, and records the session.
///
/// Returns the artifact alongside the session because ED-00's edit door lives
/// on the artifact value — the caller cannot reach the edit loop without it
/// (worklog D2).
///
/// # Errors
///
/// Whatever ED-00's door raises, plus storage errors.
#[cfg(feature = "sync")]
pub fn open_interview(
    vault: &Vault,
    topic: &EntityId,
    actor: &WriteActor,
    draft: &str,
) -> PublisherResult<(InterviewSession, ProposalTextArtifact)> {
    let digest = ProposalTextArtifact::open(draft, actor, Some(*topic))?;
    // Without the binding ED-00 refuses the stamp and every later edit
    // attributes to the device peer instead of the human doing the reviewing.
    super::register_peer_actor(vault, digest.peer_id(), actor)?;
    let session = InterviewSession {
        topic_ref: *topic,
        digest_artifact: digest.artifact_ref().entity_id(),
        state: InterviewState::Drafting,
    };
    put_interview(vault, session)?;
    Ok((session, digest))
}

/// Settles the digest: closes ED-00's edit window through
/// [`ProposalTextArtifact::finalize`] and records the session as
/// [`InterviewState::Settled`].
///
/// The user's amendments become a Δ the ordinary way — the finalized record is
/// persisted by `finalize`, so
/// [`delta_from_recorded_ops`](super::delta::delta_from_recorded_ops) over
/// [`finalized_proposal_text`](super::finalized_proposal_text) yields it. No
/// edit distance is computed here; that is ED-01's job and reusing it is the
/// point of rung 3.
///
/// The FINALIZED artifact's own ref keys the settled row — the session records
/// what was actually frozen, not what the caller believed it was holding. In
/// every flow through [`open_interview`] the two are the same value.
///
/// # Errors
///
/// Whatever ED-00's finalize raises, plus storage errors.
#[cfg(feature = "sync")]
pub fn settle_interview_digest(
    vault: &Vault,
    session: InterviewSession,
    digest: ProposalTextArtifact,
) -> PublisherResult<EntityId> {
    let finalized = digest.finalize(vault)?;
    let digest_artifact = finalized.artifact_ref.entity_id();
    put_interview(
        vault,
        InterviewSession {
            digest_artifact,
            state: InterviewState::Settled,
            ..session
        },
    )?;
    Ok(digest_artifact)
}

#[cfg(test)]
mod tests;
