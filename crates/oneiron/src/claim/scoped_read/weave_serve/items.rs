//! The served weave items (FIX 7904): each report item lowered into its
//! wire view, and a saved period's view with its lens beside it.
use super::super::{ScopedRead, StoredWeaveDigest, WeaveItem, WeaveReader, WeaveReport};
use super::{WeaveDigestFramed, WeaveDigestView, WeaveItemView, WeaveSectionView};
use crate::memory::{Memory, MemoryError, MemoryResult};

impl Memory<'_> {
    /// A saved period's view. Its render composes under `read`, the
    /// opener's own read; a render that no longer composes is left out and
    /// the period's data still serves.
    pub(super) fn weave_digest_view(
        &self,
        read: &ScopedRead<'_>,
        reader: WeaveReader<'_>,
        stored: StoredWeaveDigest,
    ) -> MemoryResult<WeaveDigestFramed> {
        // A saved period serves the rows its report was read from.
        self.produced_from(stored.report.value.source_rows());
        // Its lens composes over the rows its render was written over.
        let lens = stored.lens.as_ref().and_then(|render| {
            read.saved_weave_lens_rows(stored.reader, &stored.report.value)
                .and_then(|rows| {
                    super::super::weave_lens::compose_weave_lens_framed(read, reader, &rows, render)
                })
                .inspect_err(|error| tracing::warn!(?error, "weave lens did not compose"))
                .ok()
        });
        Ok(WeaveDigestFramed {
            view: WeaveDigestView {
                scheduled_for: stored.scheduled_for,
                rendered_at: stored.rendered_at,
                sections: self.weave_sections(&stored.report.value)?,
                narrowing: stored.report.receipt,
                lens: None,
                lens_refused: stored.lens_refused,
            },
            lens,
        })
    }

    pub(crate) fn weave_sections(
        &self,
        report: &WeaveReport,
    ) -> MemoryResult<Vec<WeaveSectionView>> {
        report
            .sections
            .iter()
            .map(|section| {
                Ok(WeaveSectionView {
                    kind: section.kind,
                    sieve_score: super::super::weave_report::sieve_score::sieve_score_view(section),
                    items: section
                        .items
                        .iter()
                        .map(|item| {
                            Ok(match item {
                                WeaveItem::Claim { id, body } => WeaveItemView::Claim {
                                    claim: self.served_claim_view(id, body)?,
                                },
                                WeaveItem::Project { id, goal } => WeaveItemView::Project {
                                    project_ref: id.to_hex(),
                                    goal_ref: goal.clone(),
                                },
                                WeaveItem::Budget {
                                    project,
                                    budget_ref,
                                } => WeaveItemView::Budget {
                                    project_ref: project.to_hex(),
                                    budget_ref: budget_ref.to_hex(),
                                },
                                WeaveItem::Link {
                                    source,
                                    kind,
                                    target,
                                } => WeaveItemView::Link {
                                    source_ref: source.to_hex(),
                                    kind: kind.name().to_owned(),
                                    target_ref: target.to_hex(),
                                },
                                WeaveItem::DreamProgress {
                                    resident,
                                    dreamed_at,
                                    entries,
                                } => WeaveItemView::DreamProgress {
                                    resident_ref: resident.to_hex(),
                                    dreamed_at: *dreamed_at,
                                    entries: *entries,
                                },
                                WeaveItem::AgentHealth { card, draft_erased } => {
                                    WeaveItemView::AgentHealth {
                                        card_ref: card.card_ref(),
                                        card: card.clone(),
                                        draft_erased: *draft_erased,
                                    }
                                }
                                WeaveItem::SieveAudit { attempt, audit, .. } => {
                                    super::super::weave_report::sieve_score::sieve_audit_view(
                                        *attempt, audit,
                                    )
                                }
                                WeaveItem::LoopDecision { .. } => {
                                    super::super::weave_report::admissions::loop_decision_view(item)
                                        .map_err(MemoryError::from)?
                                }
                            })
                        })
                        .collect::<MemoryResult<Vec<_>>>()?,
                })
            })
            .collect()
    }
}
