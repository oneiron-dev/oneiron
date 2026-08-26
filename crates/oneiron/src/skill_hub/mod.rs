//! Skill-hub records, provenance aliases, adapter contracts, and update gates.

mod adapter;
mod doors;
mod index;
mod package;
mod record;
mod support;
mod verdict;

#[cfg(test)]
mod tests;

pub use self::adapter::{
    GitSkillHubAdapter, HttpIndexSkillHubAdapter, LocalDirSkillHubAdapter, SkillHubAdapter,
};
pub use self::doors::{
    HubDependencyResolution, HubSyncDisposition, PREDICATE_SKILL_HUB_UPDATE_PROPOSAL,
};
pub use self::index::PREDICATE_SKILL_HUB_PROVENANCE;
pub use self::package::{HubFile, HubIndexEntry, HubPackage, SkillCapabilitySurface};
pub use self::record::{
    HUB_PIN_KEYS, HUB_REF_KEYS, HubPin, HubRef, HubSyncPolicy, SKILL_HUB_BODY_KEYS, SkillHubKind,
    SkillHubRecord, SkillHubTrustTier, TrackedHubRef, decode_skill_hub_record,
    encode_skill_hub_record,
};
pub use self::verdict::{
    PREDICATE_SKILL_SCAN_VERDICT, ScanCompleteness, ScanRiskLevel, ScanVerdict, SkillGovernance,
    SkillScanReceipt,
};

pub(crate) use self::index::{
    backfill_content_hash_index_if_needed, maintain_skill_content_hash_index_for_delete,
    maintain_skill_content_hash_index_for_put,
};
pub(crate) use self::package::{MAX_HUB_FILE_BYTES, MAX_HUB_PACKAGE_TOTAL_BYTES};
pub(crate) use self::verdict::{
    scan_verdict_row_risk, skill_scan_verdicts_for_content_hash_in_store,
};

// The flat skill_hub.rs module used to provide these names to the test module
// through `use super::*`; after the directory split the seam re-imports them so
// the extracted sibling `tests.rs` resolves exactly as it did inline.
#[cfg(test)]
use self::index::{
    CONTENT_HASH_INDEX_SCHEMA_VERSION, CONTENT_HASH_INDEX_SCHEMA_VERSION_KEY,
    MAX_HUB_SKILL_SCAN_ENTRIES, content_hash_index_key, same_hub_alias,
};
#[cfg(test)]
use self::package::MAX_HUB_PACKAGE_FILES;
#[cfg(test)]
use self::support::{map_text, map_value};
#[cfg(test)]
use self::verdict::skill_content_anchor_entity_id;
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::batch::ENTITY_METADATA_HEADER_LEN;
#[cfg(test)]
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, ErrorKind, Result};
#[cfg(test)]
use crate::registry::{ENTITY_TYPE_SKILL, ENTITY_TYPE_SKILL_CONTENT_ANCHOR};
#[cfg(test)]
use crate::skill::{
    SkillContentHash, SkillLifecycle, SkillRecord, canonical_skill_tree_hash, encode_skill_record,
};
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use rmpv::Value;
#[cfg(test)]
use std::collections::BTreeSet;
