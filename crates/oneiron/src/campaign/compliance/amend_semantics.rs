//! What an amendment does to the law a dispatch runs under: rows, lanes, bindings and dials.
//!
//! Classification compares what EXECUTES (FIX 9659, 9660), not which rows or
//! bindings are listed: the rows each `(jurisdiction, channel)` lane selects,
//! whether a consent-class row covers the lane, each row's executable consent
//! requirement, the first binding per jurisdiction, and the dials. Only a
//! proven absence of any new allow is a tightening; whatever cannot be ordered
//! goes to the owner stamp as loosening or ambiguous.

use std::collections::BTreeSet;

use super::evaluate::{matching_rows, normalize_token};
use super::rules::{
    CHANNEL_WILDCARD, CompliancePack, ComplianceRuleKind, ComplianceRuleRow, JURISDICTION_NONE,
};

#[derive(Debug, Default)]
pub(super) struct AmendmentDelta {
    pub(super) loosened: bool,
    pub(super) tightened: bool,
}

/// Orders `proposed` against `current` on every axis that decides a verdict.
pub(super) fn classify_semantic_delta(
    current: &CompliancePack,
    proposed: &CompliancePack,
) -> AmendmentDelta {
    let mut delta = AmendmentDelta::default();
    classify_row_survival(current, proposed, &mut delta);
    classify_lane_delta(current, proposed, &mut delta);
    classify_binding_delta(current, proposed, &mut delta);
    classify_dial_delta(current, proposed, &mut delta);
    delta
}

/// How one surviving row's demand compares to the row it replaces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RowOrder {
    Same,
    Stricter,
    Unordered,
}

/// Every current row must survive on its key and demand no less. A deleted
/// row, a widened exemption and any requirement-text edit are unorderable; an
/// executable consent requirement that provably admits only sends the old one
/// admitted is stricter.
fn classify_row_survival(
    current: &CompliancePack,
    proposed: &CompliancePack,
    delta: &mut AmendmentDelta,
) {
    for row in &current.rows {
        let order = proposed
            .rows
            .iter()
            .find(|candidate| candidate.key() == row.key())
            .map_or(RowOrder::Unordered, |candidate| row_order(row, candidate));
        match order {
            RowOrder::Same => {}
            RowOrder::Stricter => delta.tightened = true,
            RowOrder::Unordered => delta.loosened = true,
        }
    }
}

fn row_order(current: &ComplianceRuleRow, proposed: &ComplianceRuleRow) -> RowOrder {
    if current.semantics() != proposed.semantics() {
        return RowOrder::Unordered;
    }
    match (&current.consent, &proposed.consent) {
        (None, None) => RowOrder::Same,
        (Some(held), Some(next)) if held == next => RowOrder::Same,
        (Some(held), Some(next)) if next.implies(held) => RowOrder::Stricter,
        _ => RowOrder::Unordered,
    }
}

/// What one `(jurisdiction, channel)` lane runs under a pack: the rows it
/// selects, exactly as the evaluator selects them, and whether a consent-class
/// row covers it. An uncovered lane blocks every dispatch on it.
pub(super) struct EffectiveLaneRequirements<'a> {
    pub(super) rows: Vec<&'a ComplianceRuleRow>,
    pub(super) consent_covered: bool,
}

pub(super) fn effective_lane_requirements<'a>(
    pack: &'a CompliancePack,
    jurisdiction: &str,
    channel: &str,
) -> EffectiveLaneRequirements<'a> {
    let rows = matching_rows(pack, jurisdiction, channel);
    let consent_covered = rows
        .iter()
        .any(|row| row.rule_kind == ComplianceRuleKind::ConsentClass);
    EffectiveLaneRequirements {
        rows,
        consent_covered,
    }
}

/// Compares every lane both packs induce: each jurisdiction either one seeds,
/// each channel either one names, and one channel neither names (the lanes
/// only wildcard rows reach). An observation no pack seeds routes to the
/// strict pole, which is one of the seeded jurisdictions, so it needs no lane
/// of its own.
///
/// Seeding a jurisdiction the current pack does not seed is not additive:
/// the evaluator trusts any token the pack holds a row for, so the addition
/// takes that token OUT of the strict pole and hands it to exactly the rows
/// the proposal supplied. A lane the current pack leaves uncovered blocks
/// every send; a proposal that covers it can allow one. A row added to a
/// covered, already-seeded lane only adds a requirement.
fn classify_lane_delta(
    current: &CompliancePack,
    proposed: &CompliancePack,
    delta: &mut AmendmentDelta,
) {
    let seeded_now = seeded_jurisdictions(current);
    let seeded_next = seeded_jurisdictions(proposed);
    let channels = lane_channels(current, proposed);
    for jurisdiction in seeded_now.union(&seeded_next) {
        if seeded_now.contains(jurisdiction) != seeded_next.contains(jurisdiction) {
            delta.loosened = true;
            continue;
        }
        for channel in &channels {
            let held = effective_lane_requirements(current, jurisdiction, channel);
            let next = effective_lane_requirements(proposed, jurisdiction, channel);
            if !held.consent_covered && next.consent_covered {
                delta.loosened = true;
            }
            if next
                .rows
                .iter()
                .any(|row| !held.rows.iter().any(|old| old.key() == row.key()))
            {
                delta.tightened = true;
            }
        }
    }
}

fn seeded_jurisdictions(pack: &CompliancePack) -> BTreeSet<&str> {
    pack.rows
        .iter()
        .map(|row| row.jurisdiction.as_str())
        .filter(|jurisdiction| *jurisdiction != JURISDICTION_NONE)
        .collect()
}

/// Every channel token either pack names, normalized as the evaluator
/// normalizes a dispatch's, plus one token neither names.
fn lane_channels(current: &CompliancePack, proposed: &CompliancePack) -> BTreeSet<String> {
    let mut channels: BTreeSet<String> = current
        .rows
        .iter()
        .chain(&proposed.rows)
        .filter(|row| row.channel != CHANNEL_WILDCARD)
        .map(|row| normalize_token(&row.channel))
        .collect();
    let mut unnamed = String::from("unnamed_channel");
    while channels.contains(&unnamed) {
        unnamed.push('_');
    }
    channels.insert(unnamed);
    channels
}

/// The bindings evaluation runs, one per jurisdiction, must match exactly. A
/// changed or removed binding changes what a conditional row demands, and a
/// new one can enable a conditional row that blocked before; none is ordered,
/// so each waits for the owner stamp. An appended duplicate that changes no
/// effective binding is not a change at all.
fn classify_binding_delta(
    current: &CompliancePack,
    proposed: &CompliancePack,
    delta: &mut AmendmentDelta,
) {
    if current.effective_exemption_bindings() != proposed.effective_exemption_bindings() {
        delta.loosened = true;
    }
}

fn classify_dial_delta(
    current: &CompliancePack,
    proposed: &CompliancePack,
    delta: &mut AmendmentDelta,
) {
    // A longer trust window and a lower confidence floor both admit sends the
    // current pack refuses.
    delta.loosened |= proposed.verified_at_max_age_secs > current.verified_at_max_age_secs;
    delta.loosened |= proposed.jurisdiction_confidence_floor_millis
        < current.jurisdiction_confidence_floor_millis;
    delta.loosened |= proposed.strict_pole_jurisdiction != current.strict_pole_jurisdiction;
    delta.loosened |= current
        .prohibited_list_provenance_classes
        .iter()
        .any(|class| !proposed.prohibited_list_provenance_classes.contains(class));
    delta.tightened |= proposed.verified_at_max_age_secs < current.verified_at_max_age_secs;
    delta.tightened |= proposed.jurisdiction_confidence_floor_millis
        > current.jurisdiction_confidence_floor_millis;
    delta.tightened |= proposed
        .prohibited_list_provenance_classes
        .iter()
        .any(|class| !current.prohibited_list_provenance_classes.contains(class));
}
