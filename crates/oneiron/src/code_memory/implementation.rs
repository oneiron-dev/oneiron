//! Symbol-anchored memory keeps five include fragments in one privacy scope.
//! The read entry is `pull_code_memory`; the fragments define the implementation items.
//! Keep fragments: types/storage alone share 31 private names plus an inferred private type.
//!
//! ARCH-0050 R6 L2 memory-over-code attachment mechanics (ONE-1608).
//!
//! Five cohesive sections, in this order:
//!
//! 1. dual-anchor and opaque-note reference types;
//! 2. multi-writer slot types and union/dedupe logic;
//! 3. explicit anchor-transfer persistence;
//! 4. [`EdgeKind::Blocks`] validation and traversal policy;
//! 5. `ScopedRead`-clamped pull.
//!
//! The load-bearing rules, all enforced here:
//!
//! * IDENTITY IS THE SYMBOL. A durable note is keyed by a `CODE_SYMBOL`
//!   entity id, itself keyed by its file document (FIX 7809). The locator, a
//!   cursor-anchored span on that document at a version, and the validity
//!   interval are history and display, never identity. There is
//!   deliberately no `find_attachment_by_path`, no `attach_to_path`, and no
//!   path-derived key: path resemblance can never move an attachment.
//! * A RENAME CARRIES ITS NOTES. A file rename is an op on its document, so
//!   the symbol keeps its id and its notes with no transfer (FIX 7810). An
//!   [`AnchorTransfer`] a caller has reviewed moves or copies notes between
//!   two distinct symbols. Nothing in this module infers a target from a
//!   path or a fingerprint.
//! * SLOTS ARE MULTI-WRITER. Every value keeps its own actor and time. The
//!   content hash is an ACTOR-SCOPED dedupe index, never value identity, so
//!   two actors writing byte-identical content stay two values with conflict
//!   visible. Merge is a canonical-minimum union: associative, commutative,
//!   idempotent, and with NO last-write-wins path anywhere.
//! * READINESS EDGES ARE GATED. [`EdgeKind::Blocks`] (u8 24) is closed,
//!   authority-gated, `CODE_SYMBOL`-typed on BOTH endpoints, acyclic,
//!   non-decaying, never traversed by PPR, and local-only. Both generic
//!   public edge doors reject it.
//! * PULL, NOT PUSH. L2 reads are `ScopedRead`-clamped and return
//!   provenance-labelled DATA. There is no unlabelled read surface, no
//!   instruction material kind, and no injection callback.
//!
//! STORAGE. Everything rides namespaced `vault_meta` key-prefix row families,
//! the pattern documented in `store/short_id_alias.rs`: no new LMDB database,
//! no `Store` field, no storage-ABI change. NOTE/L2 payload bodies stay
//! opaque — this module stores refs and hashes and decodes neither.

use crate::ports::EntityStoreRead;
// Private implementation fragments are included in one module so their original
// private names, visibility, and cross-section behavior remain unchanged.
include!("parts/types-and-slots.rs");
include!("parts/transfer-and-blocks.rs");
include!("parts/pull.rs");
include!("parts/storage.rs");
include!("parts/lifecycle-and-tests.rs");
