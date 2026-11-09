//! Doors for `crates/oneiron-agent-runtime/tests/callable_wait_park.rs`
//! (ENGINE CALL SANDBOX-WAIT-PARK-SEMANTICS): a first-party callable skill,
//! stored and active, for the public `skill::execute_callable_skill` door to
//! run. The skill store calls it needs are crate-private. Compiled only under
//! `--cfg oneiron_test_support`; never API.

use crate::Result;
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::entity_id::EntityId;
use crate::skill::{
    SkillCallContract, SkillLifecycle, SkillRecord, SkillRole, canonical_skill_tree_hash,
};
use crate::skill_hub::{HubFile, HubPackage, SkillCapabilitySurface, SkillPackageFormat};
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// The stored file a door callable's call runs.
const CALL_REFERENCE: &str = "scripts/call.js";
/// A door callable's description, in its record and its frontmatter.
const DESCRIPTION: &str = "A test door callable";

/// Stores `source` as the generated first-party callable `name`, approved
/// and active, whose call takes `arguments` and returns `returns` (shapes as
/// `skill::matches_shape` reads them), and answers its id. The record and
/// its native package are written as a local callable's first revision is,
/// then activated.
///
/// # Errors
/// The skill store's.
#[doc(hidden)]
pub fn put_active_callable(
    vault: &Vault,
    name: &str,
    source: &str,
    arguments: &serde_json::Value,
    returns: &serde_json::Value,
) -> Result<EntityId> {
    let id = EntityId::now();
    // A native callable's frontmatter names the call contract its record
    // holds (`package_from_source`).
    let manifest = format!(
        "---\nname: {name}\ndescription: {DESCRIPTION}\nversion: 1\nrole: callable\ncall:\n  \
         reference: {CALL_REFERENCE}\n  arguments: {arguments}\n  returns: {returns}\n---\n\
         {DESCRIPTION}.\n"
    );
    let files = vec![
        HubFile::new("SKILL.md", manifest.into_bytes()),
        HubFile::new(CALL_REFERENCE, source.as_bytes().to_vec()),
    ];
    let hash = canonical_skill_tree_hash(
        files
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice())),
    )?;
    let record = SkillRecord::new(
        name,
        DESCRIPTION,
        "1",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::Generated,
        0.5,
        true,
        false,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("fixture"),
        )]),
    )
    .with_role(
        SkillRole::Callable,
        Some(SkillCallContract {
            reference: CALL_REFERENCE.to_owned(),
            arguments: arguments.clone(),
            returns: returns.clone(),
        }),
    )
    .with_content_hash(hash);
    let mut package = HubPackage::new(record.clone(), files, SkillCapabilitySurface::default());
    package.format = SkillPackageFormat::Native;
    vault.with_write_txn(|txn| {
        vault.put_skill_record_in_txn(txn, &id, &record, TimeRange { start: 1, end: 1 }, 1)?;
        vault.persist_hub_package_in_txn(txn, &id, &package)
    })?;
    let mut active = record;
    active.lifecycle_status = SkillLifecycle::Active;
    vault.update_skill_record(&id, &active, TimeRange { start: 2, end: 2 }, 2)?;
    Ok(id)
}
