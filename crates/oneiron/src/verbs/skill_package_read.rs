//! `self.skills.package`: one admitted skill's record and runtime package.

use crate::EntityId;
use crate::claim::ScopedReadResult;
use crate::memory::{Memory, MemoryResult};
use crate::skill_hub::HubPackage;

use super::{
    HubSkillRequest, SkillCapabilityView, SkillLibraryCall, SkillLibraryDependency,
    SkillLibraryFile,
};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::skill_package_read::{
    SkillPackageFormatView, SkillPackageRecordView, SkillPackageView,
};

/// The view of skill `entity` built from its runtime `package`: the package's
/// stored record, files, capabilities and format. The native current record
/// validated the load (admission) before this; where the two differ, the stored
/// package record is what the output preserves.
fn skill_package_view_from(entity: EntityId, package: HubPackage) -> SkillPackageView {
    let HubPackage {
        record: stored,
        files,
        capabilities,
        format,
    } = package;
    let provenance = crate::msgpack_value_to_json(&stored.provenance);
    SkillPackageView {
        entity,
        record: SkillPackageRecordView {
            skill_id: stored.skill_id,
            desc: stored.desc,
            version: stored.version,
            approval_status: stored.approval_status,
            lifecycle_status: stored.lifecycle_status.into(),
            source: stored.source,
            confidence: stored.confidence,
            generated: stored.generated,
            human_authored: stored.human_authored,
            dependencies: stored
                .dependencies
                .into_iter()
                .map(|dependency| SkillLibraryDependency {
                    skill_id: dependency.skill_id,
                    min_version: dependency.min_version,
                })
                .collect(),
            provenance,
            content_hash: stored.content_hash.map(|hash| hash.to_hex()),
            forked_from: stored.forked_from,
            governance_tier: stored.governance_tier.map(|tier| tier.as_str().to_owned()),
            role: stored.role.as_str().to_owned(),
            call: stored.call.map(|call| SkillLibraryCall {
                reference: call.reference,
                arguments: call.arguments,
                returns: call.returns,
            }),
        },
        files: files
            .into_iter()
            .map(|file| SkillLibraryFile {
                path: file.path,
                content: file.content,
            })
            .collect(),
        capabilities: SkillCapabilityView {
            bins: capabilities.bins.into_iter().collect(),
            env: capabilities.env.into_iter().collect(),
            mcp: capabilities.mcp.into_iter().collect(),
            allowed_tools: capabilities.allowed_tools.into_iter().collect(),
        },
        format: SkillPackageFormatView::from(format),
    }
}

/// `self.skills.package` on a handle: `input.entity` as its record with its
/// runtime package's files, capabilities and format, under the caller's lane.
/// The lane read refuses a caller with no live owner Grant naming the verb, in
/// the serving snapshot itself; a missing, withheld, non-skill or unloadable
/// skill answers `None`, never an error.
pub fn self_skills_package_embedded(
    memory: &Memory<'_>,
    input: HubSkillRequest,
) -> MemoryResult<ScopedReadResult<Option<SkillPackageView>>> {
    let read = memory.skill_package_read(&input.entity)?;
    Ok(read.map(|slot| slot.map(|package| skill_package_view_from(input.entity, package))))
}
