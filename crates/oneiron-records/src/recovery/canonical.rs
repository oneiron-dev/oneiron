//! Moved from `crates/oneiron/src/recovery/canonical.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::recovery::canonical::asset_body_refs::CanonicalAssetBodyRef;
pub use crate::recovery::canonical::peer_origins::CanonicalPeerOrigin;
pub use crate::recovery::canonical::row_births::CanonicalRowBirth;
pub use crate::recovery::canonical::source_audiences::CanonicalSourceAudience;
pub use crate::recovery::canonical::vocabulary::CanonicalContainerManifest;
pub use crate::recovery::canonical::vocabulary::CanonicalCustodyTransition;
pub use crate::recovery::canonical::vocabulary::CanonicalEntity;
pub use crate::recovery::canonical::vocabulary::CanonicalPinCarrier;
pub use crate::recovery::canonical::vocabulary::CanonicalRoomFact;
pub use crate::recovery::canonical::vocabulary::CanonicalRoomTurn;
pub use crate::recovery::canonical::vocabulary::CanonicalSchemaManifest;
pub use crate::recovery::canonical::vocabulary::CanonicalShellWorld;
pub use crate::recovery::canonical::vocabulary::CanonicalTombstone;
pub use crate::store::canonical_document::CanonicalDocumentFork;
pub use crate::store::canonical_document::CanonicalDocumentPin;
pub use crate::store::canonical_document::CanonicalDocumentPurge;
pub use crate::store::canonical_document::CanonicalDocumentReceipt;
pub use crate::store::canonical_document::CanonicalDocumentVersion;
pub use crate::store::canonical_document::CanonicalForkStatus;
pub use crate::store::canonical_document::CanonicalSettleVerb;
pub(super) use crate::store::canonical_document::invalid;
use loro::LoroDoc;
use loro::LoroValue;
use loro::ValueOrContainer;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// Maximum decoded artifact size. Recovery is off the hot path but remains bounded.
pub const CANONICAL_SNAPSHOT_MAX_BYTES: usize = 64 * 1024 * 1024;
pub mod asset_body_refs;
pub mod peer_origins;
pub mod row_births;
pub mod source_audiences;
pub mod vocabulary;
pub mod withdrawn_cutoffs;
