//! Email thread passports and the sticky per-thread mask (ONE-1827, OF-347
//! INB-02).
//!
//! Every inbound email message that touches an agent [`ChannelIdentity`] lands
//! in exactly one durable thread identity. That landing is recorded as
//! ordinary CLAIM rows behind the checked typed [`Vault`] doors at the bottom
//! of this file:
//!
//! * [`PREDICATE_THREAD_PASSPORT`] — one active row per
//!   `(identity_ref × canonical Message-ID)` carrying the resolved
//!   `thread_ref` and the [`ThreadMask`] the receiving identity wore.
//! * [`PREDICATE_THREAD_ALIAS`] — observed convergence receipts. Offline forks
//!   are valid. An alias affects resolution only with independent passport
//!   reference evidence connecting its endpoints; it cannot redirect a thread
//!   merely by asserting two root strings.
//!
//! Threading follows provider `References` / `In-Reply-To` physics and nothing
//! else. Resolution is deterministic and order-independent:
//!
//! 1. Canonicalize the current `Message-ID` and every reference with the SAME
//!    [`canonical_message_id`] function.
//! 2. Read passport evidence through the ChannelIdentity and ClaimOf indexes.
//!    Persist References and In-Reply-To, including unknown tokens. Their
//!    connected components support both forward and reverse arrival lookup.
//!    Duplicate logical passports share one deterministic winner; every row's
//!    reference evidence still participates in convergence.
//! 3. Nothing known mints
//!    `"mail:v1:" + hex(sha256(canonical current Message-ID bytes))`.
//! 4. Exactly one known thread reuses it.
//! 5. Several known roots converge on the LEXICOGRAPHICALLY SMALLEST
//!    `thread_ref`, with an alias row from every other root. Because the
//!    surviving root is chosen by value and not by arrival, replaying the two
//!    roots in either order converges identically.
//! 6. Whatever step 3–5 chose is resolved through the alias graph one last
//!    time before it is stored or returned, so the ref this module hands a
//!    composer is always a fixed point.
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
//! * Selection law (ONE-1826) stays where it is. This module MINTS the
//!   canonical `thread_ref` and reports the pinned mask; the composer builds a
//!   [`ChannelIdentityThreadPin`] out of the two — see
//!   [`ThreadMask::thread_pin`] — and hands it to the selection resolver
//!   BORROWED. Nothing here resolves a face or writes a selection rule.
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
use std::collections::BTreeSet;

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
/// [`crate::comm::record_comm_thread_event`] key. A MINTED ref is always
/// `THREAD_REF_PREFIX` plus 64 lowercase hex digits — 72 bytes of
/// `[a-z0-9:]` — so it is also always inside the tighter alphabet and length
/// the selection resolver accepts for a [`ChannelIdentityThreadPin`].
pub const MAX_THREAD_REF_BYTES: usize = 512;

/// Historical alias-hop bound, retained for source compatibility.
///
/// Reads now flatten evidenced components. Valid long offline histories do not
/// fail at this bound; cycle protection is independent of component size.
pub const MAX_THREAD_ALIAS_HOPS: usize = 32;

/// Pinned on-disk MessagePack key set for a `thread_passport` claim value.
pub const THREAD_PASSPORT_BODY_KEYS: [&str; 9] = [
    "schema_version",
    "identity_ref",
    "message_id",
    "thread_ref",
    "actor_ref",
    "facet_ref",
    "observed_at",
    "references",
    "in_reply_to",
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
const KEY_REFERENCES: &str = THREAD_PASSPORT_BODY_KEYS[7];
const KEY_IN_REPLY_TO: &str = THREAD_PASSPORT_BODY_KEYS[8];
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

    /// The selection-law pin this mask stands for ON `thread_ref`.
    ///
    /// The composer resolves a thread here first, then feeds the result to
    /// selection: build the pin from the mask and the CANONICAL thread ref
    /// this module returned ([`ThreadPassportResolution::canonical_thread_ref`]
    /// or [`Vault::canonical_thread_ref`]), set it as the `thread_pin` field of
    /// a [`ChannelIdentitySelectionQuery`] — which borrows it — and call
    /// [`resolve_channel_identity_selection`].
    ///
    /// Two deliberate omissions. The actor is continuity state that selection
    /// never sees. And a NON-canonical ref must not be pinned: selection
    /// honours the pin verbatim, so pinning a ref that has since been
    /// converged away would strand the reply on a dead thread.
    ///
    /// Not `const`: the upstream pin owns its `thread_ref` [`String`], which is
    /// not const-constructible.
    ///
    /// [`ChannelIdentitySelectionQuery`]: crate::channel_identity_selection::ChannelIdentitySelectionQuery
    /// [`resolve_channel_identity_selection`]: crate::channel_identity_selection::resolve_channel_identity_selection
    #[must_use]
    pub fn thread_pin(self, thread_ref: impl Into<String>) -> ChannelIdentityThreadPin {
        ChannelIdentityThreadPin {
            thread_ref: thread_ref.into(),
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
    ///
    /// This is the ref a [`ChannelIdentityThreadPin`] must carry; see
    /// [`ThreadMask::thread_pin`].
    pub canonical_thread_ref: String,
    /// Roots THIS call converged onto `canonical_thread_ref`, ascending.
    /// Empty for a mint or a single-root join. A replay with new reference
    /// evidence can converge previously separate roots.
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

mod codec;
mod graph;
mod storage;
mod vault_doors;

pub(crate) use codec::validate_thread_claim_structure;
use codec::*;
use graph::*;
pub(crate) use graph::{canonical_thread_ref_in_txn, thread_aliases_in_txn};
use storage::*;
pub(crate) use storage::{is_thread_claim_predicate, validate_thread_claim_in_txn};

#[cfg(test)]
mod tests;
