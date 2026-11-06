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
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY;
use crate::temporal::TimeRange;
use crate::write_envelope::communication::CommError;

pub use crate::channel_identity_selection::ThreadMaskSelectionExt;
use crate::write_envelope::thread_claim::*;
pub use crate::write_envelope::thread_claim::{
    CanonicalMessageId, MAX_MESSAGE_ID_BYTES, MAX_THREAD_ALIAS_HOPS, MAX_THREAD_REF_BYTES,
    PREDICATE_THREAD_ALIAS, PREDICATE_THREAD_PASSPORT, StickyMaskDecision, THREAD_ALIAS_BODY_KEYS,
    THREAD_PASSPORT_BODY_KEYS, THREAD_PASSPORT_SCHEMA_VERSION, THREAD_REF_PREFIX, ThreadMask,
    ThreadPassport, ThreadPassportInput, ThreadPassportResolution, canonical_message_id,
    canonical_message_id_list,
};

mod codec;
mod graph;
mod storage;
mod vault_doors;

pub(crate) use crate::write_envelope::thread_claim::is_thread_claim_predicate;
pub(crate) use codec::validate_thread_claim_structure;
use codec::*;
use graph::*;
pub(crate) use graph::{canonical_thread_ref_in_txn, thread_aliases_in_txn};
pub(crate) use storage::validate_thread_claim_in_txn;
use storage::*;

#[cfg(test)]
mod tests;
