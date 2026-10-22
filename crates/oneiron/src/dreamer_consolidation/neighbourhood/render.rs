//! The listing as a call shows it (FIX 7506): each entity, claim and
//! relationship by its call-local label, never its id. A page's room still
//! measures each line at the width it had with a full id ([`super::pages`]).

use super::pages::ListingPage;
use super::{KnownClaim, Neighbourhood};
use crate::EntityId;
use crate::dreamer_consolidation::call_labels::{
    CallLabel, CallLabelMap, LabelKind, relationship_lines,
};

impl Neighbourhood {
    /// The whole listing as transcript lines, every page in order, each
    /// entity and claim by the label `labels` assigns it here; each claim
    /// only while `admitted` holds it as a prior head. A NOTE review packs
    /// its whole listing (entities only) into its one call this way.
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
                out.push_str(&claim_line(label, claim, None));
            }
        }
        out
    }
}

impl ListingPage<'_> {
    /// The page as transcript lines (FIX 7575): first each relationship a
    /// candidate may name, the branch's `bound` one first, then each one
    /// the page's heads hold within; then each entity and claim, a claim
    /// within a relationship ending in that relationship's label. Labels
    /// are assigned in this order.
    pub(in crate::dreamer_consolidation) fn render(
        &self,
        labels: &mut CallLabelMap,
        bound: Option<EntityId>,
    ) -> String {
        let mut out = relationship_lines(labels, bound.into_iter().chain(self.relationships()));
        for (entity, claims) in self.entities() {
            let label = labels.assign(LabelKind::Entity, entity.id);
            out.push_str(&entity_line(label, entity.label.as_deref()));
            for claim in claims {
                let label = labels.assign(LabelKind::Claim, claim.id);
                let rel = claim
                    .rel
                    .map(|rel| labels.assign(LabelKind::Relationship, rel));
                out.push_str(&claim_line(label, claim, rel));
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

fn claim_line(label: CallLabel, claim: &KnownClaim, rel: Option<CallLabel>) -> String {
    match rel {
        Some(rel) => format!(
            "  claim {label} {} = {} [{rel}]\n",
            claim.predicate, claim.value
        ),
        None => format!("  claim {label} {} = {}\n", claim.predicate, claim.value),
    }
}

/// What an entity line counts against a page's room: its length with the
/// entity's full id, as the listing's budget measured it before labels.
pub(super) fn entity_line_bytes(id: EntityId, label: Option<&str>) -> usize {
    match label {
        Some(label) => format!("entity {} {}\n", id.to_hex(), serde_json::json!(label)).len(),
        None => format!("entity {}\n", id.to_hex()).len(),
    }
}

/// What a claim line counts against a page's room, measured as
/// [`entity_line_bytes`] is, its relationship at a full id's width.
pub(super) fn claim_line_bytes(claim: &KnownClaim) -> usize {
    let line = format!(
        "  claim {} {} = {}\n",
        claim.id.to_hex(),
        claim.predicate,
        claim.value
    )
    .len();
    match claim.rel {
        Some(rel) => line + format!(" [{}]", rel.to_hex()).len(),
        None => line,
    }
}
