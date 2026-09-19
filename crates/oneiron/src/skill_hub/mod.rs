//! Skill-hub records, provenance aliases, adapter contracts, and update gates.

mod adapter;
mod admission;
mod admission_guard;
mod admission_view;
mod doors;
mod folder;
mod git_fetch;
mod git_process;
mod http_fetch;
mod import_receipt;
mod package_codec;
mod publisher;
pub use import_receipt::HubImportReceipt;
mod shared_delta;
mod shared_gate;

pub use admission::{HubAdmissionDisposition, HubAdmissionReceipt};
pub(crate) use admission_guard::check_hub_skill_put;
pub use admission_view::{HubActivationAsk, HubAskSurface, hub_ask_surface};
pub use git_fetch::GitEndpointSkillHubAdapter;
pub use http_fetch::HttpEndpointSkillHubAdapter;
pub(crate) use package_codec::remove_hub_package_in_txn;
pub use package_codec::{decode_hub_package, encode_hub_package};
pub use publisher::ForeignSkillPublisher;
pub use shared_delta::{SharedSkillDelta, SharedSkillLane};
pub use shared_gate::{
    SharedSkillMergeAsk, SharedSkillMergeDisposition, SharedSkillMergeReceipt, UsefulUpstreamJudge,
};

#[cfg(test)]
mod admission_tests;
#[cfg(test)]
mod transport_tests;

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
pub use self::package::{
    HubFile, HubIndexEntry, HubPackage, SkillCapabilitySurface, SkillPackageFormat,
};
pub(crate) use folder::package_from_source;
mod fork_source;
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
pub(crate) use self::package::{
    MAX_HUB_FILE_BYTES, MAX_HUB_PACKAGE_FILES, MAX_HUB_PACKAGE_TOTAL_BYTES,
};
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

mod archive;

#[cfg(test)]
#[path = "tests/support.rs"]
pub(crate) mod test_support;

#[cfg(test)]
mod source_birth_tests;

pub mod pack_catalog;

mod source_carrier;
mod source_custody;
pub(crate) use source_carrier::encode_source_carrier;
pub(crate) use source_carrier::{decode_source_carrier, validate_hub_source_carrier_put};
#[cfg(feature = "sync")]
pub(crate) use source_carrier::{source_carrier_holder, source_carrier_matches_id};
pub(crate) use source_custody::{
    retire_source_holder_in_txn, source_carriers_for_holder_in_txn, source_custody_exists_in_txn,
    stage_source_custody_put,
};
#[cfg(test)]
mod source_replication_tests;

#[cfg(test)]
mod source_custody_tests;
