//! The listing as a call shows it (FIX 7506): each entity and claim by its
//! call-local label, never its id. The listing's byte budget still measures
//! each line at the width it had with a full id, so a listing selects
//! exactly the entities and claims it selected before labels.

use super::{KnownClaim, Neighbourhood};
use crate::EntityId;
use crate::dreamer_consolidation::call_labels::{CallLabel, CallLabelMap, LabelKind};

impl Neighbourhood {
    /// The listing as transcript lines, each entity and claim by the label
    /// `labels` assigns it here, in this order; each claim only while
    /// `admitted` holds it as a prior head.
    pub(in crate::dreamer_consolidation) fn render(
        &self,
        labels: &mut CallLabelMap,
        admitted: impl Fn(&EntityId) -> bool,
    ) -> String {
        let mut out = String::new();
        for entity in &self.entities {
            let label = labels.assign(LabelKind::Entity, entity.id);
            out.push_str(&entity_line(label, entity.label.as_deref()));
            for claim in entity.claims.iter().filter(|claim| admitted(&claim.id)) {
                let label = labels.assign(LabelKind::Claim, claim.id);
                out.push_str(&claim_line(label, claim));
            }
        }
        out
    }
}

fn entity_line(label: CallLabel, name: Option<&str>) -> String {
    match name {
        Some(name) => format!("entity {label} {}\n", serde_json::json!(name)),
        None => format!("entity {label}\n"),
    }
}

fn claim_line(label: CallLabel, claim: &KnownClaim) -> String {
    format!("  claim {label} {} = {}\n", claim.predicate, claim.value)
}

/// What an entity line counts against the listing's byte budget: its
/// length with the entity's full id, as the budget measured it before
/// labels.
pub(super) fn entity_line_bytes(id: EntityId, label: Option<&str>) -> usize {
    match label {
        Some(label) => format!("entity {} {}\n", id.to_hex(), serde_json::json!(label)).len(),
        None => format!("entity {}\n", id.to_hex()).len(),
    }
}

/// What a claim line counts against the listing's byte budget, measured
/// as [`entity_line_bytes`] is.
pub(super) fn claim_line_bytes(claim: &KnownClaim) -> usize {
    format!(
        "  claim {} {} = {}\n",
        claim.id.to_hex(),
        claim.predicate,
        claim.value
    )
    .len()
}
