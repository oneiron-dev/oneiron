//! A saved schedule's and period's stored JSON rows, their conversions to
//! and from the live types, and the sources a saved period's copies index.
//! Private to the digest: the parent binds each name at its old path.

use super::super::weave_lens::{WeaveLensRefusal, WeaveLensRender};
use super::super::{
    ScopedReadReceipt, ScopedReadResult, WeaveItem, WeaveReport, WeaveSection, WeaveSectionKind,
    WeaveSectionSpec,
};
use super::{
    SOURCE_PREFIX, WeaveDigestCadence, WeaveDigestReader, WeaveDigestSchedule, invalid,
    loop_decisions,
};
use crate::claim::{ClaimSubject, decode_claim_body, encode_claim_body};
use crate::error::Result;
use crate::{EdgeKind, EntityId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireSectionSpec {
    pub(super) kind: WeaveSectionKind,
    pub(super) predicates: Vec<String>,
    pub(super) edge_kinds: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireSchedule {
    pub(super) cadence: WeaveDigestCadence,
    pub(super) next_due_at: u64,
    pub(super) recipe: Vec<WireSectionSpec>,
    /// The timer leaves this row until then: an owner's notice went out, or
    /// its render failed. The next render or schedule write clears it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) held_until: Option<u64>,
    /// The refused render that set `held_until`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) held_because: Option<String>,
}

impl WireSchedule {
    /// When the timer next serves this row.
    pub(super) fn serve_at(&self) -> u64 {
        self.held_until
            .map_or(self.next_due_at, |held| held.max(self.next_due_at))
    }

    /// The first cadence boundary after `now`, counted from `next_due_at`.
    pub(super) fn next_boundary_after(&self, now: u64) -> Result<u64> {
        let periods = now.saturating_sub(self.next_due_at) / self.cadence.seconds() + 1;
        self.next_due_at
            .checked_add(
                periods
                    .checked_mul(self.cadence.seconds())
                    .ok_or_else(invalid)?,
            )
            .ok_or_else(invalid)
    }

    pub(super) fn from_row(row: &WeaveDigestSchedule) -> Self {
        Self {
            cadence: row.cadence,
            next_due_at: row.next_due_at,
            held_until: None,
            held_because: None,
            recipe: row
                .recipe
                .iter()
                .map(|s| WireSectionSpec {
                    kind: s.kind,
                    predicates: s.predicates.clone(),
                    edge_kinds: s.edge_kinds.iter().map(|k| *k as u8).collect(),
                })
                .collect(),
        }
    }
    pub(super) fn into_row(self, reader: WeaveDigestReader) -> Result<WeaveDigestSchedule> {
        Ok(WeaveDigestSchedule {
            reader,
            cadence: self.cadence,
            next_due_at: self.next_due_at,
            recipe: self
                .recipe
                .into_iter()
                .map(|s| {
                    Ok(WeaveSectionSpec {
                        kind: s.kind,
                        predicates: s.predicates,
                        edge_kinds: s
                            .edge_kinds
                            .into_iter()
                            .map(|k| EdgeKind::try_from_u8(k).ok_or_else(invalid))
                            .collect::<Result<Vec<_>>>()?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireDigest {
    pub(super) rendered_at: u64,
    pub(super) receipt: ScopedReadReceipt,
    pub(super) sections: Vec<WireSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) lens: Option<WeaveLensRender>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) lens_refused: Option<WeaveLensRefusal>,
    /// A due Owner schedule's publication (FIX 1259): the schedule basis it
    /// rendered from, rechecked before the period reaches a model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) scheduled_basis: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireSection {
    pub(super) kind: WeaveSectionKind,
    pub(super) items: Vec<WireItem>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) enum WireItem {
    Claim {
        id: String,
        body: Vec<u8>,
    },
    Project {
        id: String,
        goal: Option<String>,
    },
    Budget {
        project: String,
        budget_ref: String,
    },
    Link {
        source: String,
        kind: u8,
        target: String,
    },
    DreamProgress {
        resident: String,
        dreamed_at: u64,
        entries: u64,
    },
    AgentHealth {
        card: crate::dreamer_runner::maintenance::agent_health::AgentHealthCard,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        draft_erased: bool,
    },
    SieveAudit {
        attempt: crate::attempt_queue::AttemptId,
        audit: crate::dreamer_wake::SieveAuditRecord,
    },
    LoopDecision(loop_decisions::WireLoopDecision),
}

impl WireDigest {
    pub(super) fn from_report(
        rendered_at: u64,
        report: &ScopedReadResult<WeaveReport>,
    ) -> Result<Self> {
        Ok(Self {
            rendered_at,
            receipt: report.receipt.clone(),
            sections: report
                .value
                .sections
                .iter()
                .map(|s| {
                    Ok(WireSection {
                        kind: s.kind,
                        items: s
                            .items
                            .iter()
                            .map(|i| {
                                Ok(match i {
                                    WeaveItem::Claim { id, body } => WireItem::Claim {
                                        id: id.to_hex(),
                                        body: encode_claim_body(body)?,
                                    },
                                    WeaveItem::Project { id, goal } => WireItem::Project {
                                        id: id.to_hex(),
                                        goal: goal.clone(),
                                    },
                                    WeaveItem::Budget {
                                        project,
                                        budget_ref,
                                    } => WireItem::Budget {
                                        project: project.to_hex(),
                                        budget_ref: budget_ref.to_hex(),
                                    },
                                    WeaveItem::Link {
                                        source,
                                        kind,
                                        target,
                                    } => WireItem::Link {
                                        source: source.to_hex(),
                                        kind: *kind as u8,
                                        target: target.to_hex(),
                                    },
                                    WeaveItem::DreamProgress {
                                        resident,
                                        dreamed_at,
                                        entries,
                                    } => WireItem::DreamProgress {
                                        resident: resident.to_hex(),
                                        dreamed_at: *dreamed_at,
                                        entries: *entries,
                                    },
                                    WeaveItem::AgentHealth { card, draft_erased } => {
                                        WireItem::AgentHealth {
                                            card: card.clone(),
                                            draft_erased: *draft_erased,
                                        }
                                    }
                                    WeaveItem::SieveAudit { attempt, audit, .. } => {
                                        WireItem::SieveAudit {
                                            attempt: *attempt,
                                            audit: audit.clone(),
                                        }
                                    }
                                    WeaveItem::LoopDecision { .. } => WireItem::LoopDecision(
                                        loop_decisions::WireLoopDecision::of(i)?,
                                    ),
                                })
                            })
                            .collect::<Result<Vec<_>>>()?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            lens: None,
            lens_refused: None,
            scheduled_basis: None,
        })
    }
    pub(super) fn into_report(self) -> Result<ScopedReadResult<WeaveReport>> {
        Ok(ScopedReadResult {
            receipt: self.receipt,
            value: WeaveReport {
                sections: self
                    .sections
                    .into_iter()
                    .map(|s| {
                        Ok(WeaveSection {
                            kind: s.kind,
                            items: s
                                .items
                                .into_iter()
                                .map(|i| {
                                    Ok(match i {
                                        WireItem::Claim { id, body } => WeaveItem::Claim {
                                            id: EntityId::from_hex(&id).map_err(|_| invalid())?,
                                            body: Box::new(
                                                decode_claim_body(&body, true)
                                                    .map_err(|_| invalid())?,
                                            ),
                                        },
                                        WireItem::Project { id, goal } => WeaveItem::Project {
                                            id: EntityId::from_hex(&id).map_err(|_| invalid())?,
                                            goal,
                                        },
                                        WireItem::Budget {
                                            project,
                                            budget_ref,
                                        } => WeaveItem::Budget {
                                            project: EntityId::from_hex(&project)
                                                .map_err(|_| invalid())?,
                                            budget_ref: EntityId::from_hex(&budget_ref)
                                                .map_err(|_| invalid())?,
                                        },
                                        WireItem::Link {
                                            source,
                                            kind,
                                            target,
                                        } => WeaveItem::Link {
                                            source: EntityId::from_hex(&source)
                                                .map_err(|_| invalid())?,
                                            kind: EdgeKind::try_from_u8(kind)
                                                .ok_or_else(invalid)?,
                                            target: EntityId::from_hex(&target)
                                                .map_err(|_| invalid())?,
                                        },
                                        WireItem::DreamProgress {
                                            resident,
                                            dreamed_at,
                                            entries,
                                        } => WeaveItem::DreamProgress {
                                            resident: EntityId::from_hex(&resident)
                                                .map_err(|_| invalid())?,
                                            dreamed_at,
                                            entries,
                                        },
                                        WireItem::AgentHealth { card, draft_erased } => {
                                            WeaveItem::AgentHealth { card, draft_erased }
                                        }
                                        WireItem::SieveAudit { attempt, audit } => {
                                            WeaveItem::SieveAudit {
                                                attempt,
                                                audit,
                                                redacted: Vec::new(),
                                            }
                                        }
                                        WireItem::LoopDecision(row) => row.into_item(),
                                    })
                                })
                                .collect::<Result<Vec<_>>>()?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
            },
        })
    }
}

/// Include the copied claim and every typed reference carried by its saved
/// projection. This is an index over byte carriers, not a read authorization.
/// A loop row's refs and a card's draft sources join only the erase index
/// (`dependencies::indexed_sources`), never the period's gates.
pub(super) fn report_sources(report: &WeaveReport) -> Result<BTreeSet<EntityId>> {
    let mut sources = BTreeSet::new();
    for section in &report.sections {
        for item in &section.items {
            match item {
                WeaveItem::Claim { id, body } => {
                    sources.insert(*id);
                    match body.subject {
                        ClaimSubject::Entity(subject) => {
                            sources.insert(subject);
                        }
                        ClaimSubject::Edge { source, target, .. } => {
                            sources.insert(source);
                            sources.insert(target);
                        }
                    }
                }
                WeaveItem::Project { id, goal } => {
                    sources.insert(*id);
                    if let Some(goal) = goal {
                        sources.insert(EntityId::from_hex(goal).map_err(|_| invalid())?);
                    }
                }
                WeaveItem::Budget {
                    project,
                    budget_ref,
                } => {
                    sources.insert(*project);
                    sources.insert(*budget_ref);
                }
                WeaveItem::Link { source, target, .. } => {
                    sources.insert(*source);
                    sources.insert(*target);
                }
                // The reader's own dreaming time and entry count: no copied
                // body, and no diary entry's id or text.
                WeaveItem::DreamProgress { .. } => {}
                // A card is a side-table row, not a record: a saved period
                // reads the current card again before it serves one. Its
                // draft's sources index it apart (`dependencies`).
                WeaveItem::AgentHealth { .. } => {}
                // An audit is a side-table row too, read again the same way;
                // the rows it stands on are records.
                WeaveItem::SieveAudit { audit, .. } => {
                    sources.extend(super::super::weave_report::sieve_score::sieve_audit_rows(
                        audit,
                    ));
                }
                // A loop row's refs index its period for erasure apart
                // (`dependencies::indexed_sources`): the row is rechecked
                // whole on its own, so its refs never gate the period.
                WeaveItem::LoopDecision { .. } => {}
            }
        }
    }
    Ok(sources)
}

pub(super) fn source_key(source: &EntityId, digest_key: &[u8]) -> Vec<u8> {
    [SOURCE_PREFIX, source.as_bytes(), digest_key].concat()
}
