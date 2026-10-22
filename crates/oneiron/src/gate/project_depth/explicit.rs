//! Whether a project's live depth is a setting the owner made or the seeded
//! default alone (FIX 9560). Dispatch spends depth, and refuses once it is
//! spent, only under an explicit, authorized owner setting; the shipped
//! default bounds nothing. An unresolved policy is neither: its zero is never
//! read as unlimited.

use crate::HostingPrivacyPosture;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::store::Store;

use super::codec::{ProjectDepthContribution, decode_contribution, seeded_default_carrier};
use super::fold::{ProjectDepthDisposition, resolve_project_depth};

/// What a project's live depth policy says about dispatch depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProjectDepthSetting {
    /// An authorized owner setting binds the live depth: an edit, a birth
    /// from an owner-edited creation default, or a holder-set vault maximum
    /// below the seeded depth. Each spawn spends one level of it.
    Explicit(u64),
    /// Only the shipped default speaks: no owner set a depth, so none is
    /// spent.
    Seeded,
    /// Pending, quarantined or fail-closed: no depth is resolved, and its
    /// zero holds as zero.
    Unresolved,
}

/// The depth setting `project` lives under, from the same fold
/// [`resolve_project_depth`] reads, in `txn`.
///
/// # Errors
///
/// When the fold, the policy manifest or a frontier row does not read.
pub(crate) fn resolve_explicit_project_depth(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    posture: HostingPrivacyPosture,
    project: EntityId,
) -> Result<ProjectDepthSetting> {
    let resolution = resolve_project_depth(store, txn, posture, project)?;
    if resolution.disposition != ProjectDepthDisposition::Authorized {
        return Ok(ProjectDepthSetting::Unresolved);
    }
    let policy = crate::gate::resolve_policy_manifest(store, txn)?;
    if policy.diagnostics.loaded_manifest_forces_fail_closed() {
        return Ok(ProjectDepthSetting::Unresolved);
    }
    let seeded_source = seeded_default_carrier()?.0.to_hex();
    let mut explicit_head = false;
    let mut head_depth = u64::MAX;
    for id in &resolution.frontier {
        // The implicit canonical birth is derived on every replica and never
        // stored: it is the seeded default's.
        let Some(raw) = store.port_entity_raw(txn, id)? else {
            head_depth =
                head_depth.min(crate::gate::default_manifest::SEEDED_PROJECT_DEPTH_DEFAULT);
            continue;
        };
        let Some(body) = raw.get(ENTITY_METADATA_HEADER_LEN..) else {
            continue;
        };
        match decode_contribution(body)? {
            ProjectDepthContribution::Edit(edit) => {
                explicit_head = true;
                head_depth = head_depth.min(edit.depth);
            }
            ProjectDepthContribution::Birth(birth) => {
                explicit_head |= birth.source_manifest != seeded_source;
                head_depth = head_depth.min(birth.depth);
            }
            ProjectDepthContribution::Default(_) | ProjectDepthContribution::DefaultEdit(_) => {}
        }
    }
    let maximum_binds = policy
        .project_depth_max
        .is_some_and(|maximum| maximum < head_depth);
    Ok(if explicit_head || maximum_binds {
        ProjectDepthSetting::Explicit(resolution.depth)
    } else {
        ProjectDepthSetting::Seeded
    })
}
