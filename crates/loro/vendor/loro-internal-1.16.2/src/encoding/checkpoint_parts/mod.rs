//! Root-map checkpoint split and join (Oneiron vendor patch).
//!
//! A checkpoint copy of a document whose only containers are allowlisted root
//! maps can be split into a payload-free [`Skeleton`] and one [`Atom`] per
//! value or commit message, each naming its rightful holders. The skeleton
//! keeps the causal graph (ids, deps, lamports, timestamps), the plaintext
//! keys (the caller proves them opaque ids or fixed schema names), the map
//! winners of the shallow root and the latest state, and the version vectors
//! and frontiers. It holds no values and no messages.
//!
//! [`LoroDoc::join_root_map_checkpoint`] rebuilds a native document from the
//! skeleton after an arbitrary set of atoms was erased. An erased value
//! becomes a map delete at the same op id and lamport, so it still wins or
//! loses exactly where the original write did, and an erased message becomes
//! no message. The join proves the result against the skeleton before it
//! returns, and the bytes open with [`LoroDoc::from_snapshot`].
//!
//! Live documents, the update and snapshot formats and every reader are
//! unchanged. Anything outside the admitted shape is
//! [`Capture::Unclassified`], never an error.
//!
//! [`LoroDoc::join_root_map_checkpoint`]: crate::LoroDoc::join_root_map_checkpoint
//! [`LoroDoc::from_snapshot`]: crate::LoroDoc::from_snapshot

mod capture;
mod join;
mod types;

pub use types::*;
