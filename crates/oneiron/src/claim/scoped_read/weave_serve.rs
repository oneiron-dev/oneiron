//! The served weave lens (OF-499): the per-reader report and its saved
//! digests as wire views, for the `vault.weave.*` verbs and the owner's
//! routes. The reader is the bound actor, never a request field: a person
//! reads the person lens, an agent the agent lens, and only a live owner
//! proof reads the owner lens.
use super::{
    ClaimReadStatus, ScopedRead, ScopedReadReceipt, StoredWeaveDigest, WeaveDigestCadence,
    WeaveDigestReader, WeaveDigestSchedule, WeaveItem, WeaveLensPlan, WeaveLensRender,
    WeaveLinkCorrection, WeaveLiveLens, WeaveReader, WeaveReport, WeaveSectionKind,
    WeaveSectionSpec,
};
use crate::EntityId;
use crate::consent::AuthenticatedOwner;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::lens::GeneratedLens;
use crate::memory::{ClaimView, Memory, MemoryError, MemoryResult};
use crate::provenance::EdgeRef;
use serde::{Deserialize, Serialize};

/// One section a weave report asks for, in the reader's own recipe.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveSectionInput {
    pub kind: WeaveSectionKind,
    /// Exact claim predicates the section reads.
    #[serde(default)]
    pub predicates: Vec<String>,
    /// Direct graph kinds, by name, for a `links` section.
    #[serde(default)]
    pub edge_kinds: Vec<String>,
}

impl WeaveSectionInput {
    fn spec(&self) -> MemoryResult<WeaveSectionSpec> {
        Ok(WeaveSectionSpec {
            kind: self.kind,
            predicates: self.predicates.clone(),
            edge_kinds: self
                .edge_kinds
                .iter()
                .map(|name| {
                    EdgeKind::from_name(name)
                        .ok_or_else(|| MemoryError::bad_request("unknown weave edge kind"))
                })
                .collect::<MemoryResult<Vec<_>>>()?,
        })
    }

    fn from_spec(spec: &WeaveSectionSpec) -> Self {
        Self {
            kind: spec.kind,
            predicates: spec.predicates.clone(),
            edge_kinds: spec
                .edge_kinds
                .iter()
                .map(|kind| kind.name().to_owned())
                .collect(),
        }
    }
}

/// `vault.weave.report`'s input: the sections, in order.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveReportRequest {
    pub sections: Vec<WeaveSectionInput>,
}

/// `vault.weave.digest`'s input: one saved period, or the newest.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveDigestRequest {
    /// The period's due Unix second, as its inbox notice names it.
    #[serde(default)]
    pub scheduled_for: Option<u64>,
}

/// `vault.weave.link.wrong`'s input: one link, as the reader's report
/// serves it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveWrongLinkRequest {
    pub source_ref: String,
    pub kind: String,
    pub target_ref: String,
}

impl WeaveWrongLinkRequest {
    fn link(&self) -> MemoryResult<EdgeRef> {
        let entity = |hex: &str| {
            EntityId::from_hex(hex)
                .map_err(|_| MemoryError::bad_request("a weave link names entity ids"))
        };
        Ok(EdgeRef::new(
            entity(&self.source_ref)?,
            EdgeKind::from_name(&self.kind)
                .ok_or_else(|| MemoryError::bad_request("unknown weave edge kind"))?,
            entity(&self.target_ref)?,
        ))
    }
}

/// One filed wrong-link label. It labels the link for the loops; the link
/// itself stays.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WeaveLinkCorrectionView {
    pub label_ref: String,
    pub source_ref: String,
    pub kind: String,
    pub target_ref: String,
    pub actor_ref: String,
    pub recorded_at: u64,
}

impl WeaveLinkCorrectionView {
    fn from_correction(correction: &WeaveLinkCorrection) -> Self {
        Self {
            label_ref: correction.id.to_hex(),
            source_ref: correction.link.source.to_hex(),
            kind: correction.link.kind.name().to_owned(),
            target_ref: correction.link.target.to_hex(),
            actor_ref: correction.actor.to_hex(),
            recorded_at: correction.recorded_at,
        }
    }
}

/// One served item. A claim comes through the same served claim view as
/// every other read; the rest are refs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "item", rename_all = "snake_case")]
pub enum WeaveItemView {
    Claim {
        claim: ClaimView,
    },
    Project {
        project_ref: String,
        goal_ref: Option<String>,
    },
    Budget {
        project_ref: String,
        budget_ref: String,
    },
    Link {
        source_ref: String,
        kind: String,
        target_ref: String,
    },
    DreamProgress {
        resident_ref: String,
        dreamed_at: u64,
        entries: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WeaveSectionView {
    pub kind: WeaveSectionKind,
    pub items: Vec<WeaveItemView>,
}

/// A live weave report, with its narrowing receipt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WeaveReportView {
    pub sections: Vec<WeaveSectionView>,
    pub narrowing: ScopedReadReceipt,
}

/// One saved digest period, with the receipt saved with it, and its lens
/// once the generate step has rendered the period.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WeaveDigestView {
    pub scheduled_for: u64,
    pub rendered_at: u64,
    pub sections: Vec<WeaveSectionView>,
    pub narrowing: ScopedReadReceipt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lens: Option<GeneratedLens>,
}

/// Who a schedule is for, on the owner's wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WeaveReaderKind {
    Person,
    Owner,
    Agent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeaveReaderRef {
    pub kind: WeaveReaderKind,
    /// The reader, as 32 hex.
    pub reader_ref: String,
}

impl WeaveReaderRef {
    pub fn reader(&self) -> MemoryResult<WeaveDigestReader> {
        let id = EntityId::from_hex(&self.reader_ref)
            .map_err(|_| MemoryError::bad_request("reader_ref is not an entity id"))?;
        Ok(match self.kind {
            WeaveReaderKind::Person => WeaveDigestReader::Person(id),
            WeaveReaderKind::Owner => WeaveDigestReader::Owner(id),
            WeaveReaderKind::Agent => WeaveDigestReader::Agent(id),
        })
    }

    fn from_reader(reader: WeaveDigestReader) -> Self {
        let (kind, id) = match reader {
            WeaveDigestReader::Person(id) => (WeaveReaderKind::Person, id),
            WeaveDigestReader::Owner(id) => (WeaveReaderKind::Owner, id),
            WeaveDigestReader::Agent(id) => (WeaveReaderKind::Agent, id),
        };
        Self {
            kind,
            reader_ref: id.to_hex(),
        }
    }
}

/// One reader's schedule row on the owner's wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeaveScheduleView {
    pub reader: WeaveReaderRef,
    pub cadence: WeaveDigestCadence,
    /// The first due Unix second.
    pub next_due_at: u64,
    pub sections: Vec<WeaveSectionInput>,
}

impl WeaveScheduleView {
    pub fn into_schedule(self) -> MemoryResult<WeaveDigestSchedule> {
        Ok(WeaveDigestSchedule {
            reader: self.reader.reader()?,
            cadence: self.cadence,
            next_due_at: self.next_due_at,
            recipe: self
                .sections
                .iter()
                .map(WeaveSectionInput::spec)
                .collect::<MemoryResult<Vec<_>>>()?,
        })
    }

    #[must_use]
    pub fn from_schedule(row: &WeaveDigestSchedule) -> Self {
        Self {
            reader: WeaveReaderRef::from_reader(row.reader),
            cadence: row.cadence,
            next_due_at: row.next_due_at,
            sections: row
                .recipe
                .iter()
                .map(WeaveSectionInput::from_spec)
                .collect(),
        }
    }
}

impl Memory<'_> {
    /// The bound actor's lens: an owner proof reads the owner lens, a
    /// person the person lens, an agent its own.
    fn weave_reader<'a>(
        &self,
        owner: Option<&'a AuthenticatedOwner>,
    ) -> MemoryResult<WeaveReader<'a>> {
        Ok(match (owner, self.actor_class()) {
            (Some(owner), _) => WeaveReader::Owner(owner),
            (None, EdgeActorClass::Human) => WeaveReader::Person(self.actor()),
            (None, EdgeActorClass::Agent) => WeaveReader::Agent(self.actor()),
            (None, EdgeActorClass::System) => {
                return Err(MemoryError::bad_request(
                    "a system actor reads no weave lens",
                ));
            }
        })
    }

    /// `vault.weave.report`: the live weave report for the bound actor,
    /// through its own read and the vault's weave policy for its role.
    pub fn weave_report(
        &self,
        owner: Option<&AuthenticatedOwner>,
        request: &WeaveReportRequest,
    ) -> MemoryResult<WeaveReportView> {
        let reader = self.weave_reader(owner)?;
        let recipe = request
            .sections
            .iter()
            .map(WeaveSectionInput::spec)
            .collect::<MemoryResult<Vec<_>>>()?;
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let report = read.weave_report(reader, &recipe)?;
        Ok(WeaveReportView {
            sections: self.weave_sections(&report.value)?,
            narrowing: report.receipt,
        })
    }

    /// `vault.weave.lens`, before its generate step: the bound actor's live
    /// report, read as [`Self::weave_report`] reads it and keyed for the
    /// weave-report skill. `None` when the skill does not load (retired,
    /// unapproved or deleted).
    pub fn weave_lens_prepare(
        &self,
        owner: Option<&AuthenticatedOwner>,
        request: &WeaveReportRequest,
    ) -> MemoryResult<Option<WeaveLiveLens>> {
        let reader = self.weave_reader(owner)?;
        let role = match reader {
            WeaveReader::Person(_) => "person",
            WeaveReader::Owner(_) => "owner",
            WeaveReader::Agent(_) => "agent",
        };
        let report = self.live_weave_report(reader, request)?;
        let sections = self.weave_sections(&report)?;
        Ok(WeaveLiveLens::prepare(self.vault(), role, report, &sections)?)
    }

    /// `vault.weave.lens`, after its generate step: re-reads the live report
    /// under the bound actor's current read and composes `answer`, the
    /// step's plan, over it. The plan was written over what the first read
    /// admitted, so a report that changed meanwhile is refused, as is a plan
    /// that does not cite each of its items exactly once.
    pub fn weave_lens_finish(
        &self,
        owner: Option<&AuthenticatedOwner>,
        request: &WeaveReportRequest,
        live: WeaveLiveLens,
        answer: &str,
        model: &str,
    ) -> MemoryResult<GeneratedLens> {
        let reader = self.weave_reader(owner)?;
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let report = read.weave_report(reader, &Self::weave_recipe(request)?)?.value;
        if report != live.report {
            return Err(MemoryError::new(
                crate::memory::MEMORY_CODE_INVALID_STATE,
                "the weave report changed while its lens rendered",
                &["Ask for the lens again."],
            ));
        }
        let plan: WeaveLensPlan = serde_json::from_str(answer.trim()).map_err(|_| {
            MemoryError::new(
                crate::memory::MEMORY_CODE_MODEL_UNAVAILABLE,
                "the model's answer is not a weave lens plan",
                &["Ask for the lens again."],
            )
        })?;
        if plan.validate(&report).is_err() {
            return Err(MemoryError::new(
                crate::memory::MEMORY_CODE_MODEL_UNAVAILABLE,
                "the model's plan does not cite each report item exactly once",
                &["Ask for the lens again."],
            ));
        }
        let render = WeaveLensRender {
            plan,
            skill_ref: live.skill_ref,
            skill_version: live.skill_version,
            model: model.to_owned(),
            rendered_at: self.vault().store.clock.now_recorded_at(),
        };
        Ok(super::weave_lens::compose_weave_lens(&read, &report, &render)?)
    }

    /// The live report for `reader` under the bound actor's read.
    fn live_weave_report(
        &self,
        reader: WeaveReader<'_>,
        request: &WeaveReportRequest,
    ) -> MemoryResult<WeaveReport> {
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        Ok(read.weave_report(reader, &Self::weave_recipe(request)?)?.value)
    }

    fn weave_recipe(request: &WeaveReportRequest) -> MemoryResult<Vec<WeaveSectionSpec>> {
        request
            .sections
            .iter()
            .map(WeaveSectionInput::spec)
            .collect()
    }

    /// `vault.weave.digest`: one of the bound actor's saved digests, under
    /// the current read policy. An owner opening its digest renders the due
    /// period first: the timer cannot, holding no owner proof.
    pub fn weave_digest(
        &self,
        owner: Option<&AuthenticatedOwner>,
        request: &WeaveDigestRequest,
    ) -> MemoryResult<Option<WeaveDigestView>> {
        let reader = self.weave_reader(owner)?;
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        if owner.is_some() {
            read.render_due_weave_digest(reader, self.vault().store.clock.now_recorded_at())?;
        }
        let stored = match request.scheduled_for {
            Some(at) => read.read_weave_digest(reader, at)?,
            None => read.read_latest_weave_digest(reader)?,
        };
        stored
            .map(|stored| self.weave_digest_view(&read, stored))
            .transpose()
    }

    /// `vault.weave.link.wrong`: the one-tap wrong control on a link the
    /// bound human sees in its own lens, filed as a label under `proof`. An
    /// owner proof in `owner` files from the owner lens; an agent files
    /// nothing.
    pub fn weave_wrong_link(
        &self,
        owner: Option<&AuthenticatedOwner>,
        proof: &AuthenticatedOwner,
        request: &WeaveWrongLinkRequest,
    ) -> MemoryResult<WeaveLinkCorrectionView> {
        let reader = self.weave_reader(owner)?;
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let filed = read.report_wrong_link(proof, reader, request.link()?)?;
        Ok(WeaveLinkCorrectionView::from_correction(&filed))
    }

    /// A saved period's view. Its render composes under `read`, the
    /// opener's own read; a render that no longer composes is left out and
    /// the period's data still serves.
    fn weave_digest_view(
        &self,
        read: &ScopedRead<'_>,
        stored: StoredWeaveDigest,
    ) -> MemoryResult<WeaveDigestView> {
        let lens = stored.lens.as_ref().and_then(|render| {
            super::weave_lens::compose_weave_lens(read, &stored.report.value, render)
                .inspect_err(|error| tracing::warn!(?error, "weave lens did not compose"))
                .ok()
        });
        Ok(WeaveDigestView {
            scheduled_for: stored.scheduled_for,
            rendered_at: stored.rendered_at,
            sections: self.weave_sections(&stored.report.value)?,
            narrowing: stored.report.receipt,
            lens,
        })
    }

    pub(super) fn weave_sections(&self, report: &WeaveReport) -> MemoryResult<Vec<WeaveSectionView>> {
        report
            .sections
            .iter()
            .map(|section| {
                Ok(WeaveSectionView {
                    kind: section.kind,
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
                            })
                        })
                        .collect::<MemoryResult<Vec<_>>>()?,
                })
            })
            .collect()
    }
}
