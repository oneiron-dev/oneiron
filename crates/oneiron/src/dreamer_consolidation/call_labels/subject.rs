//! A claim subject as a call names it, by that call's labels. One copy,
//! shared by the nightly merge, its link pairs and the Arc's claims.

use super::{CallLabel, CallLabelMap, LabelKind};
use crate::EntityId;
use crate::claim::ClaimSubject;

/// A proposal's subject as its narrative call names it: an entity by its
/// label (a proposal's own `C<n>` when it is one, else `P<n>`), an edge as
/// `<kind>(<source>,<target>)` over its endpoints' labels.
pub(in crate::dreamer_consolidation) fn subject_label(
    labels: &mut CallLabelMap,
    subject: &ClaimSubject,
) -> String {
    let mut label = |id: EntityId| -> CallLabel {
        labels
            .label(LabelKind::Claim, id)
            .unwrap_or_else(|| labels.assign(LabelKind::Entity, id))
    };
    match *subject {
        ClaimSubject::Entity(id) => label(id).to_string(),
        ClaimSubject::Edge {
            source,
            kind,
            target,
        } => {
            let (source, target) = (label(source), label(target));
            format!("{}({source},{target})", kind.name())
        }
    }
}
