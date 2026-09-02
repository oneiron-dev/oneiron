//! Email thread passports and the sticky per-thread mask (OF-347 INB-02).
//!
//! Every inbound email message that touches an agent [`ChannelIdentity`] lands
//! in exactly one durable thread identity. That landing is recorded as
//! ordinary CLAIM rows behind the checked typed [`Vault`] doors at the bottom
//! of this file:
//!
//! * [`PREDICATE_THREAD_PASSPORT`] — one active row per
//!   `(identity_ref × canonical Message-ID)` carrying the resolved
//!   `thread_ref` and the [`ThreadMask`] the receiving identity wore.
//! * [`PREDICATE_THREAD_ALIAS`] — one row per previously separate thread root
//!   that a later bridging message converged onto a surviving root.
//!
//! Threading follows provider `References` / `In-Reply-To` physics and nothing
//! else. Resolution is deterministic and order-independent:
//!
//! 1. Canonicalize the current `Message-ID` and every reference with the SAME
//!    [`canonical_message_id`] function.
//! 2. Look up active passport rows for every normalized reference and
//!    canonicalize each hit's `thread_ref` through the alias graph.
//! 3. No known reference mints
//!    `"mail:v1:" + hex(sha256(canonical current Message-ID bytes))`.
//! 4. Exactly one known thread reuses it.
//! 5. Several known roots converge on the LEXICOGRAPHICALLY SMALLEST
//!    `thread_ref`, with an alias row from every other root. Because the
//!    surviving root is chosen by value and not by arrival, replaying the two
//!    roots in either order converges identically.
//!
//! Deliberate non-goals, pinned so later tickets do not reopen this file:
//!
//! * The mask is an identity/facet CONTINUITY pin, not a disclosure decision.
//!   Nothing here consults or extends an `admits()` path; the S-DISC facet and
//!   mask admit zones stay read-only.
//! * The module never flips a mask. [`Vault::sticky_thread_mask`] answers
//!   [`StickyMaskDecision::Unset`], [`StickyMaskDecision::Keep`], or a typed
//!   [`StickyMaskDecision::Conflict`]; choosing what to do about a conflict is
//!   the composer's business, and an explicit human handoff stays ordinary
//!   message content rather than a new engine verb.
//! * Thread membership is NOT stored here. Parties join a resolved thread
//!   through the existing public [`crate::comm::record_comm_thread_event`]
//!   surface, wrapped by [`Vault::join_thread_party`] only so the caller joins
//!   the CANONICAL thread. `comm.thread_member` keeps its own value shape.
//! * Message-IDs are opaque provider tokens. Canonicalization is conservative
//!   — trim, unwrap one `<...>` pair, reject the malformed — and LOWERCASING
//!   IS FORBIDDEN, because two identifiers a provider treats as distinct must
//!   never be merged into one thread.
//!
//! [`ChannelIdentity`]: crate::channel_identity::ChannelIdentity

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::channel_identity_selection::ChannelIdentityThreadPin;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::comm::{CommError, record_comm_thread_event};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY;
use crate::temporal::TimeRange;

/// Current schema version for both `channel_identity.thread_*` claim values.
pub const THREAD_PASSPORT_SCHEMA_VERSION: u64 = 1;

/// One `(identity_ref × canonical Message-ID)` landing.
pub const PREDICATE_THREAD_PASSPORT: &str = "channel_identity.thread_passport";

/// One converged thread root: `from_thread_ref` now reads as `to_thread_ref`.
pub const PREDICATE_THREAD_ALIAS: &str = "channel_identity.thread_alias";

/// Maximum canonical Message-ID length in bytes.
///
/// RFC 5322 caps a header line at 998 octets excluding CRLF, so a canonical
/// Message-ID can never legitimately exceed it.
pub const MAX_MESSAGE_ID_BYTES: usize = 998;

/// Versioned prefix of every minted email thread reference.
///
/// The version rides the ref itself so a future derivation change mints a
/// visibly different namespace instead of silently re-threading stored mail.
pub const THREAD_REF_PREFIX: &str = "mail:v1:";

/// Maximum thread-reference length in bytes.
///
/// Matched to the comm key bound so a canonical thread ref is always a legal
/// [`crate::comm::record_comm_thread_event`] key.
pub const MAX_THREAD_REF_BYTES: usize = 512;

/// Maximum alias hops a read will follow before declaring corruption.
///
/// Convergence writes aliases only from roots that are already fixed points to
/// a root that is also a fixed point, so a healthy graph is a forest of depth
/// well under this bound. Exceeding it means the alias rows were not written
/// by this module.
pub const MAX_THREAD_ALIAS_HOPS: usize = 32;

/// Pinned on-disk MessagePack key set for a `thread_passport` claim value.
pub const THREAD_PASSPORT_BODY_KEYS: [&str; 7] = [
    "schema_version",
    "identity_ref",
    "message_id",
    "thread_ref",
    "actor_ref",
    "facet_ref",
    "observed_at",
];

/// Pinned on-disk MessagePack key set for a `thread_alias` claim value.
pub const THREAD_ALIAS_BODY_KEYS: [&str; 5] = [
    "schema_version",
    "identity_ref",
    "from_thread_ref",
    "to_thread_ref",
    "observed_at",
];

const KEY_SCHEMA_VERSION: &str = THREAD_PASSPORT_BODY_KEYS[0];
const KEY_IDENTITY_REF: &str = THREAD_PASSPORT_BODY_KEYS[1];
const KEY_MESSAGE_ID: &str = THREAD_PASSPORT_BODY_KEYS[2];
const KEY_THREAD_REF: &str = THREAD_PASSPORT_BODY_KEYS[3];
const KEY_ACTOR_REF: &str = THREAD_PASSPORT_BODY_KEYS[4];
const KEY_FACET_REF: &str = THREAD_PASSPORT_BODY_KEYS[5];
const KEY_OBSERVED_AT: &str = THREAD_PASSPORT_BODY_KEYS[6];
const KEY_FROM_THREAD_REF: &str = THREAD_ALIAS_BODY_KEYS[2];
const KEY_TO_THREAD_REF: &str = THREAD_ALIAS_BODY_KEYS[3];

// ---------------------------------------------------------------------------
// Message-ID canonicalization
// ---------------------------------------------------------------------------

/// A validated, case-PRESERVING canonical `Message-ID`.
///
/// The only constructor is [`canonical_message_id`], so holding one of these
/// is proof the token already survived the conservative gate.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalMessageId(String);

impl CanonicalMessageId {
    /// The canonical token, exactly as it will be stored and hashed.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper, yielding the canonical token.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }

    /// The thread reference this Message-ID mints when nothing it references
    /// is known yet.
    ///
    /// Derived from the canonical PRESERVED-CASE bytes, so the ref is stable
    /// across vaults and replicas without merging identifiers a provider keeps
    /// distinct.
    #[must_use]
    pub fn minted_thread_ref(&self) -> String {
        let digest = bytes_to_hex_lower(&Sha256::digest(self.0.as_bytes()));
        format!("{THREAD_REF_PREFIX}{digest}")
    }
}

impl std::fmt::Display for CanonicalMessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Canonicalizes one raw provider `Message-ID`, `In-Reply-To`, or `References`
/// token.
///
/// Deliberately conservative, in this order:
///
/// 1. Trim outer ASCII whitespace.
/// 2. Remove ONE surrounding `<...>` pair, if present.
/// 3. Reject empty, over [`MAX_MESSAGE_ID_BYTES`], any control or whitespace
///    character, and any residual angle bracket (which means the raw value was
///    not a single well-formed `msg-id`).
///
/// Case is preserved. Lowercasing is forbidden: a Message-ID is an opaque
/// token and folding case would merge threads a provider treats as separate.
///
/// # Errors
///
/// Returns [`Error::InvalidClaimBody`] when the token fails any rule above.
pub fn canonical_message_id(raw: &str) -> Result<CanonicalMessageId> {
    let trimmed = raw.trim_matches(|c: char| c.is_ascii_whitespace());
    let unwrapped = trimmed
        .strip_prefix('<')
        .and_then(|rest| rest.strip_suffix('>'))
        .unwrap_or(trimmed);
    validate_canonical_message_id(unwrapped)?;
    Ok(CanonicalMessageId(unwrapped.to_owned()))
}

/// Canonicalizes a provider reference list with [`canonical_message_id`],
/// de-duplicating while PRESERVING provider order.
///
/// `References` and `In-Reply-To` normalize through this one path so a parent
/// named by both cannot resolve two different ways.
///
/// # Errors
///
/// Returns [`Error::InvalidClaimBody`] as soon as any entry fails
/// canonicalization; a malformed reference is never silently dropped.
pub fn canonical_message_id_list<S: AsRef<str>>(raw: &[S]) -> Result<Vec<CanonicalMessageId>> {
    let mut out: Vec<CanonicalMessageId> = Vec::with_capacity(raw.len());
    for value in raw {
        let canonical = canonical_message_id(value.as_ref())?;
        if !out.contains(&canonical) {
            out.push(canonical);
        }
    }
    Ok(out)
}

fn validate_canonical_message_id(value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::InvalidClaimBody(
            "message id is empty after canonicalization",
        ));
    }
    if value.len() > MAX_MESSAGE_ID_BYTES {
        return Err(Error::InvalidClaimBody(
            "message id exceeds the 998-byte header bound",
        ));
    }
    if value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(Error::InvalidClaimBody(
            "message id carries a control or whitespace character",
        ));
    }
    if value.contains(['<', '>']) {
        return Err(Error::InvalidClaimBody(
            "message id carries a residual angle bracket",
        ));
    }
    Ok(())
}

fn validate_thread_ref(thread_ref: &str) -> Result<()> {
    if thread_ref.is_empty() {
        return Err(Error::InvalidClaimBody("thread ref is empty"));
    }
    if thread_ref.len() > MAX_THREAD_REF_BYTES {
        return Err(Error::InvalidClaimBody("thread ref exceeds the key bound"));
    }
    if thread_ref
        .chars()
        .any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(Error::InvalidClaimBody(
            "thread ref carries a control or whitespace character",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Mask, input, and outcome shapes
// ---------------------------------------------------------------------------

/// The face a thread wears: exactly one `(identity × actor × facet)` triple.
///
/// This is the whole mask. Nothing else may be added without re-deciding the
/// continuity rule, because every field here is something a client, a
/// reply-history scorer, and an allow-list all key on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ThreadMask {
    /// `ChannelIdentity` record the thread is pinned to.
    pub identity_ref: EntityId,
    /// Actor speaking behind that identity.
    pub actor_ref: EntityId,
    /// Facet worn on the thread, when the caller has one.
    pub facet_ref: Option<EntityId>,
}

impl ThreadMask {
    /// Builds a mask with no facet.
    #[must_use]
    pub const fn new(identity_ref: EntityId, actor_ref: EntityId) -> Self {
        Self {
            identity_ref,
            actor_ref,
            facet_ref: None,
        }
    }

    /// Attaches a facet to the mask.
    #[must_use]
    pub const fn with_facet(mut self, facet_ref: EntityId) -> Self {
        self.facet_ref = Some(facet_ref);
        self
    }

    /// The selection-law input this mask stands for.
    ///
    /// The composer feeds this straight to
    /// [`crate::channel_identity_selection::ChannelIdentitySelectionRequest::with_thread_pin`];
    /// the actor is continuity state that selection deliberately does not see.
    #[must_use]
    pub const fn thread_pin(self) -> ChannelIdentityThreadPin {
        ChannelIdentityThreadPin {
            identity_ref: self.identity_ref,
            facet_ref: self.facet_ref,
        }
    }
}

/// One inbound message, already canonicalized, waiting for a thread.
///
/// The provider payload parsing that produces these strings belongs to the
/// adapter; canonicalization belongs to this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadPassportInput {
    /// Receiving `ChannelIdentity` record.
    pub identity_ref: EntityId,
    /// Actor behind the receiving identity.
    pub actor_ref: EntityId,
    /// Facet the receiving identity wears, when it has one.
    pub facet_ref: Option<EntityId>,
    /// This message's canonical `Message-ID`.
    pub message_id: CanonicalMessageId,
    /// Canonical `References`, de-duplicated in provider order.
    pub references: Vec<CanonicalMessageId>,
    /// Canonical `In-Reply-To`, when the provider supplied one.
    pub in_reply_to: Option<CanonicalMessageId>,
    /// When the provider event was observed (Unix seconds).
    pub observed_at: u64,
}

impl ThreadPassportInput {
    /// Builds a reference-free input; chain the builders for the rest.
    #[must_use]
    pub const fn new(
        identity_ref: EntityId,
        actor_ref: EntityId,
        message_id: CanonicalMessageId,
        observed_at: u64,
    ) -> Self {
        Self {
            identity_ref,
            actor_ref,
            facet_ref: None,
            message_id,
            references: Vec::new(),
            in_reply_to: None,
            observed_at,
        }
    }

    /// Sets the facet the receiving identity wears.
    #[must_use]
    pub fn with_facet(mut self, facet_ref: EntityId) -> Self {
        self.facet_ref = Some(facet_ref);
        self
    }

    /// Sets the canonical `References` list.
    #[must_use]
    pub fn with_references(mut self, references: Vec<CanonicalMessageId>) -> Self {
        self.references = references;
        self
    }

    /// Sets the canonical `In-Reply-To` parent.
    #[must_use]
    pub fn with_in_reply_to(mut self, in_reply_to: CanonicalMessageId) -> Self {
        self.in_reply_to = Some(in_reply_to);
        self
    }

    /// The mask this message would pin were it the thread's first passport.
    #[must_use]
    pub const fn mask(&self) -> ThreadMask {
        ThreadMask {
            identity_ref: self.identity_ref,
            actor_ref: self.actor_ref,
            facet_ref: self.facet_ref,
        }
    }

    /// `References` followed by `In-Reply-To`, de-duplicated in provider
    /// order.
    ///
    /// Order only decides which rows are LOOKED UP, never which root survives:
    /// convergence picks the smallest ref by value, so this ordering cannot
    /// leak arrival order into the outcome.
    fn reference_chain(&self) -> Vec<&CanonicalMessageId> {
        let mut chain: Vec<&CanonicalMessageId> = Vec::with_capacity(self.references.len() + 1);
        for reference in &self.references {
            if !chain.contains(&reference) {
                chain.push(reference);
            }
        }
        if let Some(parent) = self.in_reply_to.as_ref()
            && !chain.contains(&parent)
        {
            chain.push(parent);
        }
        chain
    }
}

/// One stored `(identity × Message-ID)` landing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadPassport {
    /// Receiving `ChannelIdentity` record.
    pub identity_ref: EntityId,
    /// Canonical `Message-ID` this row is filed under.
    pub message_id: CanonicalMessageId,
    /// Thread reference AS WRITTEN. A later convergence may alias it; read
    /// [`ThreadPassportResolution::canonical_thread_ref`] or
    /// [`Vault::canonical_thread_ref`] for where it resolves today.
    pub thread_ref: String,
    /// Mask the receiving identity wore for this message.
    pub mask: ThreadMask,
    /// When the provider event was observed (Unix seconds).
    pub observed_at: u64,
}

/// What one [`Vault::record_thread_passport`] call decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadPassportResolution {
    /// The stored passport — freshly written, or the pre-existing row a replay
    /// resolved to.
    pub passport: ThreadPassport,
    /// Where `passport.thread_ref` resolves after following aliases.
    pub canonical_thread_ref: String,
    /// Roots THIS call converged onto `canonical_thread_ref`, ascending.
    /// Empty for a mint, a single-root join, and every replay.
    pub aliased_thread_refs: Vec<String>,
}

/// The sticky-mask answer for one thread.
///
/// There is deliberately no "flip" arm: a thread that already wears a mask
/// keeps it, and disagreement is reported rather than resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StickyMaskDecision {
    /// No passport has landed on this thread yet; the caller is free.
    Unset,
    /// The thread's pinned mask, which the caller must wear.
    Keep(ThreadMask),
    /// The request disagrees with the pin. Never an automatic From/facet flip.
    Conflict {
        /// Mask the thread's first passport pinned.
        pinned: ThreadMask,
        /// Mask the caller asked for.
        requested: ThreadMask,
    },
}

// ---------------------------------------------------------------------------
// Claim value codec
// ---------------------------------------------------------------------------

fn encode_passport_value(passport: &ThreadPassport) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(THREAD_PASSPORT_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_IDENTITY_REF),
            Value::from(passport.identity_ref.to_hex()),
        ),
        (
            Value::from(KEY_MESSAGE_ID),
            Value::from(passport.message_id.as_str()),
        ),
        (
            Value::from(KEY_THREAD_REF),
            Value::from(passport.thread_ref.as_str()),
        ),
        (
            Value::from(KEY_ACTOR_REF),
            Value::from(passport.mask.actor_ref.to_hex()),
        ),
        (
            Value::from(KEY_FACET_REF),
            encode_optional_ref(passport.mask.facet_ref),
        ),
        (
            Value::from(KEY_OBSERVED_AT),
            Value::from(passport.observed_at),
        ),
    ])
}

fn encode_alias_value(
    identity_ref: EntityId,
    from_thread_ref: &str,
    to_thread_ref: &str,
    observed_at: u64,
) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(THREAD_PASSPORT_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_IDENTITY_REF),
            Value::from(identity_ref.to_hex()),
        ),
        (
            Value::from(KEY_FROM_THREAD_REF),
            Value::from(from_thread_ref),
        ),
        (Value::from(KEY_TO_THREAD_REF), Value::from(to_thread_ref)),
        (Value::from(KEY_OBSERVED_AT), Value::from(observed_at)),
    ])
}

fn encode_optional_ref(id: Option<EntityId>) -> Value {
    id.map_or(Value::Nil, |id| Value::from(id.to_hex()))
}

/// Every decode failure below is [`Error::CorruptedIndex`] on purpose: these
/// bytes came out of the store, so a shape the typed doors cannot have written
/// is a corrupt row, not a bad argument.
fn corrupt(reason: &'static str) -> Error {
    Error::CorruptedIndex(reason)
}

fn map_entries<'a>(value: &'a Value, reason: &'static str) -> Result<&'a [(Value, Value)]> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(corrupt(reason)),
    }
}

fn map_entry<'a>(
    entries: &'a [(Value, Value)],
    key: &str,
    reason: &'static str,
) -> Result<&'a Value> {
    entries
        .iter()
        .find(|(entry_key, _)| entry_key.as_str() == Some(key))
        .map(|(_, value)| value)
        .ok_or_else(|| corrupt(reason))
}

fn decode_ref(value: &Value, reason: &'static str) -> Result<EntityId> {
    value
        .as_str()
        .and_then(|hex| EntityId::from_hex(hex).ok())
        .ok_or_else(|| corrupt(reason))
}

fn decode_optional_ref(value: &Value, reason: &'static str) -> Result<Option<EntityId>> {
    if matches!(value, Value::Nil) {
        Ok(None)
    } else {
        decode_ref(value, reason).map(Some)
    }
}

fn decode_thread_ref(value: &Value, reason: &'static str) -> Result<String> {
    let raw = value.as_str().ok_or_else(|| corrupt(reason))?;
    validate_thread_ref(raw).map_err(|_| corrupt(reason))?;
    Ok(raw.to_owned())
}

fn decode_schema_version(entries: &[(Value, Value)], reason: &'static str) -> Result<()> {
    let version = map_entry(entries, KEY_SCHEMA_VERSION, reason)?
        .as_u64()
        .ok_or_else(|| corrupt(reason))?;
    if version == THREAD_PASSPORT_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(corrupt(reason))
    }
}

fn decode_passport_value(subject: EntityId, value: &Value) -> Result<ThreadPassport> {
    const REASON: &str = "thread passport claim value is malformed";
    let entries = map_entries(value, REASON)?;
    decode_schema_version(entries, "thread passport claim schema version is unknown")?;
    let identity_ref = decode_ref(map_entry(entries, KEY_IDENTITY_REF, REASON)?, REASON)?;
    if identity_ref != subject {
        return Err(corrupt(
            "thread passport identity_ref disagrees with its claim subject",
        ));
    }
    let raw_message_id = map_entry(entries, KEY_MESSAGE_ID, REASON)?
        .as_str()
        .ok_or_else(|| corrupt(REASON))?;
    validate_canonical_message_id(raw_message_id)
        .map_err(|_| corrupt("stored thread passport message id is not canonical"))?;
    Ok(ThreadPassport {
        identity_ref,
        message_id: CanonicalMessageId(raw_message_id.to_owned()),
        thread_ref: decode_thread_ref(map_entry(entries, KEY_THREAD_REF, REASON)?, REASON)?,
        mask: ThreadMask {
            identity_ref,
            actor_ref: decode_ref(map_entry(entries, KEY_ACTOR_REF, REASON)?, REASON)?,
            facet_ref: decode_optional_ref(map_entry(entries, KEY_FACET_REF, REASON)?, REASON)?,
        },
        observed_at: map_entry(entries, KEY_OBSERVED_AT, REASON)?
            .as_u64()
            .ok_or_else(|| corrupt(REASON))?,
    })
}

fn decode_alias_value(value: &Value) -> Result<(String, String)> {
    const REASON: &str = "thread alias claim value is malformed";
    let entries = map_entries(value, REASON)?;
    decode_schema_version(entries, "thread alias claim schema version is unknown")?;
    let from = decode_thread_ref(map_entry(entries, KEY_FROM_THREAD_REF, REASON)?, REASON)?;
    let to = decode_thread_ref(map_entry(entries, KEY_TO_THREAD_REF, REASON)?, REASON)?;
    Ok((from, to))
}

// ---------------------------------------------------------------------------
// Row readers and alias resolution
// ---------------------------------------------------------------------------

/// One active passport CLAIM as read back out of the store.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PassportRow {
    claim_id: EntityId,
    passport: ThreadPassport,
}

/// Total order deciding which passport PINS a thread's mask.
///
/// Earliest observation wins; the canonical Message-ID and then the claim id
/// break ties so two rows stamped the same second still pin deterministically
/// on every replica.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PassportPinKey {
    observed_at: u64,
    message_id: String,
    claim_id: EntityId,
}

impl PassportRow {
    fn pin_key(&self) -> PassportPinKey {
        PassportPinKey {
            observed_at: self.passport.observed_at,
            message_id: self.passport.message_id.0.clone(),
            claim_id: self.claim_id,
        }
    }
}

fn active_passport_rows(vault: &Vault, rtxn: &heed::RoTxn<'_>) -> Result<Vec<PassportRow>> {
    let mut rows = Vec::new();
    for (claim_id, body) in vault.claims_with_predicate_in_txn(rtxn, PREDICATE_THREAD_PASSPORT)? {
        if body.lifecycle != ClaimLifecycleStatus::Active {
            continue;
        }
        let ClaimSubject::Entity(subject) = body.subject else {
            return Err(corrupt("thread passport subject must be an entity"));
        };
        rows.push(PassportRow {
            claim_id,
            passport: decode_passport_value(subject, &body.value)?,
        });
    }
    Ok(rows)
}

/// The alias graph as `from_thread_ref -> to_thread_ref`.
///
/// Two active rows naming the same `from` must agree; a fork means two reads
/// of the same thread could answer differently, which is corruption.
fn thread_alias_edges(vault: &Vault, rtxn: &heed::RoTxn<'_>) -> Result<BTreeMap<String, String>> {
    let mut edges: BTreeMap<String, String> = BTreeMap::new();
    for (_, body) in vault.claims_with_predicate_in_txn(rtxn, PREDICATE_THREAD_ALIAS)? {
        if body.lifecycle != ClaimLifecycleStatus::Active {
            continue;
        }
        let (from, to) = decode_alias_value(&body.value)?;
        match edges.entry(from) {
            Entry::Vacant(slot) => {
                slot.insert(to);
            }
            Entry::Occupied(slot) => {
                if *slot.get() != to {
                    return Err(corrupt("thread alias forks to two different threads"));
                }
            }
        }
    }
    Ok(edges)
}

/// Follows `start` through the alias graph to its fixed point.
///
/// Bounded twice over — a visited set and [`MAX_THREAD_ALIAS_HOPS`] — so a
/// cycle or an absurdly long chain fails typed instead of spinning.
fn resolve_thread_alias<'a>(edges: &'a BTreeMap<String, String>, start: &'a str) -> Result<String> {
    let mut seen: Vec<&str> = Vec::new();
    let mut current = start;
    loop {
        if seen.contains(&current) {
            return Err(corrupt("thread alias chain contains a cycle"));
        }
        seen.push(current);
        let Some(next) = edges.get(current) else {
            return Ok(current.to_owned());
        };
        if seen.len() > MAX_THREAD_ALIAS_HOPS {
            return Err(corrupt("thread alias chain exceeds the hop bound"));
        }
        current = next.as_str();
    }
}

/// Every active passport resolving to `canonical`, in pin order.
fn passports_on_thread(
    rows: Vec<PassportRow>,
    edges: &BTreeMap<String, String>,
    canonical: &str,
) -> Result<BTreeMap<PassportPinKey, ThreadPassport>> {
    let mut ordered = BTreeMap::new();
    for row in rows {
        if resolve_thread_alias(edges, &row.passport.thread_ref)? != canonical {
            continue;
        }
        ordered.insert(row.pin_key(), row.passport);
    }
    Ok(ordered)
}

// ---------------------------------------------------------------------------
// Claim writers
// ---------------------------------------------------------------------------

/// Refuses a passport whose subject is not a live `ChannelIdentity` record.
///
/// `put_claim_in_txn` already refuses a missing subject; this adds the TYPE
/// check, so a passport can never be filed against an arbitrary entity that
/// merely happens to exist.
fn require_channel_identity(vault: &Vault, wtxn: &heed::RwTxn<'_>, id: EntityId) -> Result<()> {
    let raw = vault
        .store
        .entities
        .get(wtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or_else(|| corrupt("entity header"))?;
    if header.entity_type == ENTITY_TYPE_CHANNEL_IDENTITY {
        Ok(())
    } else {
        Err(Error::InvalidEntityType(header.entity_type))
    }
}

fn put_passport_claim(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    passport: &ThreadPassport,
) -> Result<()> {
    let mut body = ClaimBody::new(
        PREDICATE_THREAD_PASSPORT,
        ClaimSubject::Entity(passport.identity_ref),
        encode_passport_value(passport),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.valid_from = Some(passport.observed_at);
    // Observed: a passport records what a provider event did, not a belief the
    // engine inferred.
    body.source = Some(ClaimSource::Observed);
    vault.put_claim_in_txn(
        wtxn,
        &EntityId::now(),
        &body,
        TimeRange {
            start: passport.observed_at,
            end: passport.observed_at,
        },
        passport.observed_at,
    )
}

fn put_alias_claim(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    identity_ref: EntityId,
    from_thread_ref: &str,
    to_thread_ref: &str,
    observed_at: u64,
) -> Result<()> {
    let mut body = ClaimBody::new(
        PREDICATE_THREAD_ALIAS,
        ClaimSubject::Entity(identity_ref),
        encode_alias_value(identity_ref, from_thread_ref, to_thread_ref, observed_at),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.valid_from = Some(observed_at);
    body.source = Some(ClaimSource::Observed);
    vault.put_claim_in_txn(
        wtxn,
        &EntityId::now(),
        &body,
        TimeRange {
            start: observed_at,
            end: observed_at,
        },
        observed_at,
    )
}

// ---------------------------------------------------------------------------
// Typed Vault doors
// ---------------------------------------------------------------------------

impl Vault {
    /// Lands one inbound message in exactly one durable thread.
    ///
    /// The passport row, and every alias row the same message's references
    /// force, are written in ONE transaction: a bridging message that
    /// converges two roots must never leave a vault where the passport exists
    /// but the convergence does not.
    ///
    /// Idempotent by construction. Replaying the same provider event finds the
    /// active `(identity_ref × Message-ID)` row, returns it with its thread
    /// re-resolved through today's aliases, and writes nothing — so a replay
    /// can neither duplicate the active row nor restamp the mask.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EntityNotFound`] or [`Error::InvalidEntityType`] when
    /// `identity_ref` is not a live `ChannelIdentity` record, and
    /// [`Error::CorruptedIndex`] when a stored passport or alias row cannot be
    /// decoded or the alias graph cycles.
    pub fn record_thread_passport(
        &self,
        input: ThreadPassportInput,
    ) -> Result<ThreadPassportResolution> {
        self.with_write_txn(|wtxn| {
            require_channel_identity(self, wtxn, input.identity_ref)?;
            let edges = thread_alias_edges(self, wtxn)?;
            let rows = active_passport_rows(self, wtxn)?;

            if let Some(existing) = rows.iter().find(|row| {
                row.passport.identity_ref == input.identity_ref
                    && row.passport.message_id == input.message_id
            }) {
                return Ok(ThreadPassportResolution {
                    canonical_thread_ref: resolve_thread_alias(
                        &edges,
                        &existing.passport.thread_ref,
                    )?,
                    passport: existing.passport.clone(),
                    aliased_thread_refs: Vec::new(),
                });
            }

            // A BTreeSet would do, but the map is already ordered and the
            // ascending first key IS the lexicographically smallest root —
            // which is what makes convergence independent of arrival order.
            let mut roots: BTreeMap<String, ()> = BTreeMap::new();
            for reference in input.reference_chain() {
                for row in &rows {
                    if row.passport.message_id == *reference {
                        roots.insert(resolve_thread_alias(&edges, &row.passport.thread_ref)?, ());
                    }
                }
            }

            let mut roots_iter = roots.into_keys();
            let (canonical_thread_ref, aliased_thread_refs) = match roots_iter.next() {
                None => (input.message_id.minted_thread_ref(), Vec::new()),
                Some(smallest) => (smallest, roots_iter.collect::<Vec<_>>()),
            };

            for from in &aliased_thread_refs {
                put_alias_claim(
                    self,
                    wtxn,
                    input.identity_ref,
                    from,
                    &canonical_thread_ref,
                    input.observed_at,
                )?;
            }

            let passport = ThreadPassport {
                identity_ref: input.identity_ref,
                message_id: input.message_id.clone(),
                thread_ref: canonical_thread_ref.clone(),
                mask: input.mask(),
                observed_at: input.observed_at,
            };
            put_passport_claim(self, wtxn, &passport)?;
            Ok(ThreadPassportResolution {
                passport,
                canonical_thread_ref,
                aliased_thread_refs,
            })
        })
    }

    /// The active passport for one `(identity_ref × Message-ID)`, if any.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CorruptedIndex`] when a stored passport row cannot be
    /// decoded.
    pub fn thread_passport(
        &self,
        identity_ref: &EntityId,
        message_id: &CanonicalMessageId,
    ) -> Result<Option<ThreadPassport>> {
        let rtxn = self.store.env.read_txn()?;
        Ok(active_passport_rows(self, &rtxn)?
            .into_iter()
            .find(|row| {
                row.passport.identity_ref == *identity_ref && row.passport.message_id == *message_id
            })
            .map(|row| row.passport))
    }

    /// Follows `thread_ref` through the alias graph to its fixed point.
    ///
    /// An unknown ref is its own fixed point: aliases record convergence, not
    /// existence.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidClaimBody`] for a malformed `thread_ref` and
    /// [`Error::CorruptedIndex`] when the alias graph cycles, forks, or
    /// exceeds [`MAX_THREAD_ALIAS_HOPS`].
    pub fn canonical_thread_ref(&self, thread_ref: &str) -> Result<String> {
        validate_thread_ref(thread_ref)?;
        let rtxn = self.store.env.read_txn()?;
        let edges = thread_alias_edges(self, &rtxn)?;
        resolve_thread_alias(&edges, thread_ref)
    }

    /// Every active passport on `thread_ref`'s canonical thread, in pin order.
    ///
    /// The first element is the row whose mask the thread wears.
    ///
    /// # Errors
    ///
    /// As [`Vault::canonical_thread_ref`], plus decode failures on stored
    /// passport rows.
    pub fn thread_passports(&self, thread_ref: &str) -> Result<Vec<ThreadPassport>> {
        validate_thread_ref(thread_ref)?;
        let rtxn = self.store.env.read_txn()?;
        let edges = thread_alias_edges(self, &rtxn)?;
        let canonical = resolve_thread_alias(&edges, thread_ref)?;
        let rows = active_passport_rows(self, &rtxn)?;
        Ok(passports_on_thread(rows, &edges, &canonical)?
            .into_values()
            .collect())
    }

    /// The mask a thread already wears, judged against what a caller wants.
    ///
    /// The thread's FIRST passport pins the mask and nothing later moves it.
    /// A `requested` mask that disagrees comes back as
    /// [`StickyMaskDecision::Conflict`] carrying both sides — the composer
    /// decides what to say about it, and a human handoff stays message
    /// content. There is no arm that changes the pin, because changing the
    /// From address mid-thread breaks client threading, reply-history scoring,
    /// and allow-list continuity all at once.
    ///
    /// # Errors
    ///
    /// As [`Vault::canonical_thread_ref`], plus decode failures on stored
    /// passport rows.
    pub fn sticky_thread_mask(
        &self,
        thread_ref: &str,
        requested: Option<ThreadMask>,
    ) -> Result<StickyMaskDecision> {
        validate_thread_ref(thread_ref)?;
        let rtxn = self.store.env.read_txn()?;
        let edges = thread_alias_edges(self, &rtxn)?;
        let canonical = resolve_thread_alias(&edges, thread_ref)?;
        let rows = active_passport_rows(self, &rtxn)?;
        let ordered = passports_on_thread(rows, &edges, &canonical)?;
        let Some(pinning) = ordered.into_values().next() else {
            return Ok(StickyMaskDecision::Unset);
        };
        let pinned = pinning.mask;
        Ok(match requested {
            None => StickyMaskDecision::Keep(pinned),
            Some(requested) if requested == pinned => StickyMaskDecision::Keep(pinned),
            Some(requested) => StickyMaskDecision::Conflict { pinned, requested },
        })
    }

    /// Joins (or parts) `party` on `thread_ref`'s CANONICAL thread.
    ///
    /// A thin, alias-aware wrapper over the existing public
    /// [`crate::comm::record_comm_thread_event`]: membership stays a
    /// `comm.thread_member` claim with comm's own value shape, and this module
    /// adds only the guarantee that a party never lands on a thread ref that
    /// has since been converged away.
    ///
    /// # Errors
    ///
    /// As [`Vault::canonical_thread_ref`], plus
    /// [`Error::InvalidClaimBody`] when comm rejects the party or thread key.
    pub fn join_thread_party(
        &self,
        thread_ref: &str,
        party: &str,
        joined: bool,
        occurred_at: u64,
    ) -> Result<()> {
        let canonical = self.canonical_thread_ref(thread_ref)?;
        record_comm_thread_event(self, &canonical, party, joined, occurred_at).map_err(|err| {
            match err {
                CommError::Engine(inner) => inner,
                _ => Error::InvalidClaimBody("comm rejected the thread membership event"),
            }
        })
    }
}

#[cfg(test)]
mod tests;
