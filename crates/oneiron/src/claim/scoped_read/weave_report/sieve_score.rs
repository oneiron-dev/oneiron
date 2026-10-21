//! A weave report's SieveScore section reads the sampled sieve audits
//! (OF-499, ARCH-0063 §6). The score is the audits' own agreement: of the
//! sampled audits the section shows, how many agree with the expensive
//! path, each audit a row of its own. No weighting, model or scorer: a
//! section that shows no audit reads no samples, never a success.
use std::collections::{BTreeMap, BTreeSet};

use super::super::{ScopedRead, WeaveItemView, WeaveSieveScoreView};
use super::{WeaveItem, WeaveSection, WeaveSectionKind};
use crate::EntityId;
use crate::attempt_queue::AttemptId;
use crate::dreamer_wake::{SieveAudit, SpanKind};
use crate::entity_id::bytes_to_hex_lower;
use crate::gate::{PolicyManifestResolution, ResolvedRetrievalFilter};

impl ScopedRead<'_> {
    /// Every sampled audit whose rows this reader's floor admits, in
    /// attempt order, read whole (rule 5). Its turn, its source and each
    /// entity it names pass the floor's own admission,
    /// [`Self::is_entity_retrievable_with_policy_in`], unchanged. A row the
    /// floor refuses or cannot answer for (a storage or decode error)
    /// withholds the audit, as an audit row that does not decode is
    /// withheld; neither fails the report, and neither widens it.
    pub(super) fn weave_sieve_audits_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
    ) -> Vec<WeaveItem> {
        if filter.deny_all {
            return Vec::new();
        }
        let rows = match crate::dreamer_wake::sieve::sieve_audits_in_txn(self.vault, txn) {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!(?error, "the sampled sieve audits did not read; none shown");
                return Vec::new();
            }
        };
        let mut floor: BTreeMap<EntityId, bool> = BTreeMap::new();
        let mut items = Vec::new();
        for row in rows {
            let (attempt, audit) = match row {
                Ok(row) => row,
                Err(error) => {
                    tracing::warn!(?error, "a sieve audit row did not decode; withheld");
                    continue;
                }
            };
            let mut admitted = true;
            for id in sieve_audit_rows(&audit) {
                let readable = if let Some(&readable) = floor.get(&id) {
                    readable
                } else {
                    let readable = match self
                        .is_entity_retrievable_with_policy_in(txn, policy, filter, &id)
                    {
                        Ok(readable) => readable,
                        Err(error) => {
                            tracing::warn!(
                                ?error,
                                "the read floor did not answer for a sieve audit's row; withheld"
                            );
                            false
                        }
                    };
                    floor.insert(id, readable);
                    readable
                };
                if !readable {
                    admitted = false;
                    break;
                }
            }
            if admitted {
                items.push(WeaveItem::SieveAudit { attempt, audit });
            }
        }
        items
    }
}

/// The rows a sampled audit stands on, each once: its turn, its source and
/// each entity it names.
pub(crate) fn sieve_audit_rows(audit: &SieveAudit) -> BTreeSet<EntityId> {
    [
        Some(audit.turn),
        Some(audit.source),
        audit.expected_entity,
        audit.actual_entity,
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// Whether a saved audit still reads exactly as it was saved. Its own facts
/// are compared, never today's total, so a newer sample moves no older
/// period; a gone, changed or unreadable row withholds the period.
pub(crate) fn sieve_audit_unchanged_in(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    attempt: &AttemptId,
    audit: &SieveAudit,
) -> bool {
    match crate::dreamer_wake::sieve::sieve_audit_in_txn(store, txn, attempt) {
        Ok(current) => current.as_ref() == Some(audit),
        Err(error) => {
            tracing::warn!(
                ?error,
                "a saved sieve audit did not read; its period is withheld"
            );
            false
        }
    }
}

/// A SieveScore section's counts, derived from the audit items it shows;
/// `None` for every other section.
pub(crate) fn sieve_score_view(section: &WeaveSection) -> Option<WeaveSieveScoreView> {
    if section.kind != WeaveSectionKind::SieveScore {
        return None;
    }
    let mut score = WeaveSieveScoreView {
        sampled: 0,
        agreeing: 0,
    };
    for item in &section.items {
        if let WeaveItem::SieveAudit { audit, .. } = item {
            score.sampled = score.sampled.saturating_add(1);
            score.agreeing = score.agreeing.saturating_add(u64::from(audit.agrees));
        }
    }
    Some(score)
}

/// A sampled audit as a report serves it: hex refs and named kinds.
pub(crate) fn sieve_audit_view(attempt: AttemptId, audit: &SieveAudit) -> WeaveItemView {
    WeaveItemView::SieveAudit {
        attempt_ref: bytes_to_hex_lower(attempt.as_bytes()),
        span_ref: bytes_to_hex_lower(&audit.span),
        turn_ref: audit.turn.to_hex(),
        source_ref: audit.source.to_hex(),
        expected_kind: span_kind_name(audit.expected_kind).to_owned(),
        actual_kind: span_kind_name(audit.actual_kind).to_owned(),
        expected_entity_ref: audit.expected_entity.map(|id| id.to_hex()),
        actual_entity_ref: audit.actual_entity.map(|id| id.to_hex()),
        novel: audit.novel,
        confidence: audit.confidence,
        agrees: audit.agrees,
        audited_at: audit.at,
    }
}

/// A sampled audit's lens cells, each a label and its value.
pub(crate) fn sieve_audit_cells(
    attempt: AttemptId,
    audit: &SieveAudit,
) -> Vec<(&'static str, String)> {
    let mut cells = vec![
        ("attempt_ref", bytes_to_hex_lower(attempt.as_bytes())),
        ("turn_ref", audit.turn.to_hex()),
        ("source_ref", audit.source.to_hex()),
        (
            "expected_kind",
            span_kind_name(audit.expected_kind).to_owned(),
        ),
        ("actual_kind", span_kind_name(audit.actual_kind).to_owned()),
    ];
    if let Some(id) = audit.expected_entity {
        cells.push(("expected_entity_ref", id.to_hex()));
    }
    if let Some(id) = audit.actual_entity {
        cells.push(("actual_entity_ref", id.to_hex()));
    }
    cells.push(("agrees", audit.agrees.to_string()));
    cells.push(("confidence", audit.confidence.to_string()));
    cells.push(("audited_at", audit.at.to_string()));
    cells
}

/// A span kind's name, as the sieve doors serve it.
fn span_kind_name(kind: SpanKind) -> &'static str {
    match kind {
        SpanKind::Date => "date",
        SpanKind::Name => "name",
    }
}
