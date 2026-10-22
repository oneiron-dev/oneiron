//! The served weave lens (OF-499): the per-reader report and its saved
//! digests as wire views, for the `vault.weave.*` verbs and the owner's
//! routes. The reader is the bound actor, never a request field: a person
//! reads the person lens, an agent the agent lens, and only a live owner
//! proof reads the owner lens.
use super::{
    ClaimReadStatus, ScopedReadReceipt, WeaveDigestCadence, WeaveDigestReader, WeaveDigestSchedule,
    WeaveItemCorrection, WeaveItemTarget, WeaveLensRefusal, WeaveLensRender, WeaveLinkCorrection,
    WeaveLiveLens, WeaveReader, WeaveReport, WeaveScheduleHold, WeaveSectionKind, WeaveSectionSpec,
};
use crate::EntityId;
use crate::consent::AuthenticatedOwner;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::lens::{
    GeneratedUiSurfaceCapabilities, HostedLensRender, LensFrameCard, LensRenderFrame,
};
use crate::memory::{ClaimView, Memory, MemoryError, MemoryResult};
use crate::provenance::EdgeRef;
use serde::{Deserialize, Serialize};

// The weave Admin's reads and labels under its proof (OF-499 A3).
mod admin;
// Each served item's lowering, and a saved period's view (FIX 7904).
mod items;
pub(super) mod sieve_audit;

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
    pub(super) fn link(&self) -> MemoryResult<EdgeRef> {
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WeaveLinkCorrectionView {
    pub label_ref: String,
    pub source_ref: String,
    pub kind: String,
    pub target_ref: String,
    pub actor_ref: String,
    pub recorded_at: u64,
}

impl WeaveLinkCorrectionView {
    pub(super) fn from_correction(correction: &WeaveLinkCorrection) -> Self {
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

/// `vault.weave.item.wrong`'s input: one claim, project, budget or sieve
/// audit row, as the reader's report serves it (`item` is its `item` tag; an
/// audit's `item_ref` is its `attempt_ref`). A budget names the project it
/// shows under; no other item does.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveWrongItemRequest {
    pub item: String,
    pub item_ref: String,
    #[serde(default)]
    pub project_ref: Option<String>,
}

impl WeaveWrongItemRequest {
    /// The input a lens row's wrong control sends for `target`.
    pub(super) fn of(target: WeaveItemTarget) -> Self {
        let (item, id, project) = match target {
            WeaveItemTarget::Claim(id) => ("claim", id, None),
            WeaveItemTarget::Project(id) => ("project", id, None),
            WeaveItemTarget::Budget { project, budget } => ("budget", budget, Some(project)),
            WeaveItemTarget::SieveAudit { attempt } => ("sieve_audit", attempt, None),
        };
        Self {
            item: item.to_owned(),
            item_ref: id.to_hex(),
            project_ref: project.map(|project| project.to_hex()),
        }
    }

    fn target(&self) -> MemoryResult<WeaveItemTarget> {
        let entity = |hex: &str| {
            EntityId::from_hex(hex)
                .map_err(|_| MemoryError::bad_request("a weave item names entity ids"))
        };
        let id = entity(&self.item_ref)?;
        match (self.item.as_str(), &self.project_ref) {
            ("claim", None) => Ok(WeaveItemTarget::Claim(id)),
            ("project", None) => Ok(WeaveItemTarget::Project(id)),
            ("budget", Some(project)) => Ok(WeaveItemTarget::Budget {
                project: entity(project)?,
                budget: id,
            }),
            ("sieve_audit", None) => Ok(WeaveItemTarget::SieveAudit { attempt: id }),
            ("budget", None) => Err(MemoryError::bad_request(
                "a weave budget item names its project_ref",
            )),
            ("claim" | "project" | "sieve_audit", Some(_)) => Err(MemoryError::bad_request(
                "only a weave budget item names a project_ref",
            )),
            _ => Err(MemoryError::bad_request(
                "a wrong weave item is a claim, project, budget or sieve audit",
            )),
        }
    }
}

/// One filed wrong-item label. It labels the item for the loops; the
/// record itself stays.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WeaveItemCorrectionView {
    pub label_ref: String,
    pub item: String,
    pub item_ref: String,
    pub project_ref: Option<String>,
    pub actor_ref: String,
    pub recorded_at: u64,
}

impl WeaveItemCorrectionView {
    fn from_correction(correction: &WeaveItemCorrection) -> Self {
        let item = WeaveWrongItemRequest::of(correction.item);
        Self {
            label_ref: correction.id.to_hex(),
            item: item.item,
            item_ref: item.item_ref,
            project_ref: item.project_ref,
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
    /// An agent-health card and its `health:` handle, the input the concern
    /// door (`self.inbox.concern.outcome`) takes.
    AgentHealth {
        card_ref: String,
        card: crate::dreamer_runner::maintenance::agent_health::AgentHealthCard,
        /// A saved copy's Coach draft lost its diagnosis and proposal: a row
        /// they were drafted from was erased (FIX 8672). The rest stays.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        draft_erased: bool,
    },
    /// One sampled sieve audit (OF-499): the attempt that wrote it, the
    /// span's turn and source, the rule's kind and entity beside the
    /// expensive path's, and whether they agree. Its wrong control sends
    /// `attempt_ref` as a `sieve_audit` item's `item_ref`.
    SieveAudit {
        attempt_ref: String,
        span_ref: String,
        turn_ref: String,
        source_ref: String,
        expected_kind: String,
        actual_kind: String,
        expected_entity_ref: Option<String>,
        actual_entity_ref: Option<String>,
        novel: bool,
        confidence: u8,
        agrees: bool,
        audited_at: u64,
    },
    /// One unflagged window's sieve audit (OF-498f); its wrong control is a
    /// `sieve_audit` item's, by `attempt_ref`.
    SieveWindowAudit {
        attempt_ref: String,
        finding: sieve_audit::WeaveSieveFindingView,
    },
    /// One loop decision (OF-499 A2), its refs as hex: its outcome and kind
    /// exactly as stored, its family, each reason, and whether it is an
    /// erasure skeleton. It carries no wrong control (FIX 7598).
    LoopDecision {
        decision_ref: String,
        created_at: u64,
        family: String,
        kind: String,
        outcome: String,
        reason_codes: Vec<String>,
        redacted: bool,
        claim_ref: Option<String>,
        actor_ref: Option<String>,
        evidence_refs: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WeaveSectionView {
    pub kind: WeaveSectionKind,
    pub items: Vec<WeaveItemView>,
    /// A SieveScore section's score, derived from its audit items; absent
    /// on every other section.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sieve_score: Option<WeaveSieveScoreView>,
}

/// A SieveScore section's score (OF-499): of the sampled sieve audits the
/// section shows, how many agree with the expensive path. It is counted
/// from those items, never kept apart. `sampled: 0` is no samples: no
/// score, never a success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeaveSieveScoreView {
    pub sampled: u64,
    pub agreeing: u64,
    /// How many distinct discoveries the section's window audits found
    /// (FIX 7903): one found again by another audit counts once here, and
    /// each audit still lists its own occurrence.
    pub discoveries: u64,
}

/// A live weave report, with its narrowing receipt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WeaveReportView {
    pub sections: Vec<WeaveSectionView>,
    pub narrowing: ScopedReadReceipt,
}

/// One saved digest period, with the receipt saved with it, and its lens
/// once the generate step has rendered the period, or why it rendered none.
/// The lens is a card lowered for the whole atom kit; a server holds its
/// frame for the opener's events on it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WeaveDigestView {
    pub scheduled_for: u64,
    pub rendered_at: u64,
    pub sections: Vec<WeaveSectionView>,
    pub narrowing: ScopedReadReceipt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lens: Option<LensFrameCard>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lens_refused: Option<WeaveLensRefusal>,
}

/// One saved period as its host serves it: the view, and its render as a
/// card beside the frame that minted its rows' backing refs (OF-181).
/// Host-only: a caller is handed the view [`Self::lower`] makes.
#[derive(Debug)]
pub struct WeaveDigestFramed {
    /// The period with no lens yet.
    pub view: WeaveDigestView,
    pub lens: Option<HostedLensRender>,
}

impl WeaveDigestFramed {
    /// The view with its lens lowered once for the whole atom kit, and the
    /// lens's frame for a host to hold. A lens that does not lower is left
    /// out, as one that no longer composes is; the period still serves.
    #[must_use]
    pub fn lower(self) -> (WeaveDigestView, Option<LensRenderFrame>) {
        let mut view = self.view;
        let frame = self.lens.and_then(|hosted| {
            match hosted.lower(&GeneratedUiSurfaceCapabilities::all_atom_kit()) {
                Ok((frame, card)) => {
                    view.lens = Some(card);
                    Some(frame)
                }
                Err(error) => {
                    tracing::warn!(?error, "weave lens did not lower");
                    None
                }
            }
        });
        (view, frame)
    }
}

/// Who a schedule is for, on the owner's wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WeaveReaderKind {
    Person,
    Owner,
    Agent,
    /// A weave Admin's namespace (OF-499 A3): `reader_ref` is its exact
    /// Admin membership grant. Answer only: an Admin reader comes from its
    /// proof, never from a reader ref.
    Admin,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
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
            WeaveReaderKind::Admin => {
                return Err(MemoryError::bad_request(
                    "an admin reader comes from its admin proof, never a reader_ref",
                ));
            }
        })
    }

    fn from_reader(reader: WeaveDigestReader) -> Self {
        let (kind, id) = match reader {
            WeaveDigestReader::Person(id) => (WeaveReaderKind::Person, id),
            WeaveDigestReader::Owner(id) => (WeaveReaderKind::Owner, id),
            WeaveDigestReader::Agent(id) => (WeaveReaderKind::Agent, id),
            WeaveDigestReader::Admin(key) => (WeaveReaderKind::Admin, key.membership_grant()),
        };
        Self {
            kind,
            reader_ref: id.to_hex(),
        }
    }
}

/// One reader's schedule row on the owner's wire.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveScheduleView {
    pub reader: WeaveReaderRef,
    pub cadence: WeaveDigestCadence,
    /// The first due Unix second.
    pub next_due_at: u64,
    pub sections: Vec<WeaveSectionInput>,
    /// Answer only: the timer left this row until `held.until`, after an
    /// owner's due notice or a refused render. A write ignores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<WeaveScheduleHold>,
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
    pub fn from_schedule(row: &WeaveDigestSchedule, held: Option<WeaveScheduleHold>) -> Self {
        Self {
            held,
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
    pub(super) fn weave_reader<'a>(
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
        self.produced_from(report.value.source_rows());
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
            WeaveReader::Admin(_) => crate::gate::weave_policy::ADMIN_ROLE,
        };
        let report = self.live_weave_report(reader, request)?;
        let sections = self.weave_sections(&report)?;
        Ok(WeaveLiveLens::prepare(
            self.vault(),
            role,
            report,
            &sections,
        )?)
    }

    /// `vault.weave.lens`, after its generate step: re-reads the live report
    /// under the bound actor's current read and composes `answer`, the
    /// step's plan, over it, as a card beside the frame that minted its
    /// backing refs; its host keeps the frame for the card's events. The
    /// plan was written over the rows the first read admitted: it composes
    /// over those rows while the re-read still serves each of them, a loop
    /// decision appended since left for the next read (FIX 7694); else it
    /// answers `None` and the host asks again from a fresh read. A plan that
    /// does not cite each item exactly once is refused.
    pub fn weave_lens_finish_framed(
        &self,
        owner: Option<&AuthenticatedOwner>,
        request: &WeaveReportRequest,
        live: WeaveLiveLens,
        answer: &str,
        model: &str,
    ) -> MemoryResult<Option<HostedLensRender>> {
        let reader = self.weave_reader(owner)?;
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let fresh = read
            .weave_report(reader, &Self::weave_recipe(request)?)?
            .value;
        if !super::weave_lens::snapshot_still_served(&live.report, &fresh) {
            return Ok(None);
        }
        let report = live.report;
        self.produced_from(report.source_rows());
        let plan =
            super::weave_lens::weave_lens_answer_plan(answer, &report).map_err(|reason| {
                MemoryError::new(
                    crate::memory::MEMORY_CODE_MODEL_UNAVAILABLE,
                    format!("the model's weave lens plan was refused: {reason}"),
                    &["Ask for the lens again."],
                )
            })?;
        let render = WeaveLensRender {
            plan,
            skill_ref: live.skill_ref,
            skill_version: live.skill_version,
            model: model.to_owned(),
            rendered_at: self.vault().store.clock.now_recorded_at(),
        };
        let lens = super::weave_lens::compose_weave_lens_framed(&read, reader, &report, &render)?;
        // The render is kept, and the one before it settles on the skill's
        // corrections axis; neither gates the lens.
        if let Err(error) = self.vault().keep_live_weave_lens(reader, &report, &render) {
            tracing::warn!(?error, "the live weave lens render was not kept");
        }
        Ok(Some(lens))
    }

    /// The live report for `reader` under the bound actor's read, its rows
    /// listed.
    fn live_weave_report(
        &self,
        reader: WeaveReader<'_>,
        request: &WeaveReportRequest,
    ) -> MemoryResult<WeaveReport> {
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let report = read
            .weave_report(reader, &Self::weave_recipe(request)?)?
            .value;
        self.produced_from(report.source_rows());
        Ok(report)
    }

    fn weave_recipe(request: &WeaveReportRequest) -> MemoryResult<Vec<WeaveSectionSpec>> {
        request
            .sections
            .iter()
            .map(WeaveSectionInput::spec)
            .collect()
    }

    /// `vault.weave.digest` where no host keeps the frame: the period of
    /// [`Self::weave_digest_framed`], its lens lowered for the whole atom
    /// kit. The lens card's events need a server, which holds its frame.
    pub fn weave_digest(
        &self,
        owner: Option<&AuthenticatedOwner>,
        request: &WeaveDigestRequest,
    ) -> MemoryResult<Option<WeaveDigestView>> {
        Ok(self
            .weave_digest_framed(owner, request)?
            .map(|framed| framed.lower().0))
    }

    /// One of the bound actor's saved digests, under the current read
    /// policy, with its lens as a card beside its frame. An owner opening
    /// its digest renders the due period first: the timer cannot, holding
    /// no owner proof.
    pub fn weave_digest_framed(
        &self,
        owner: Option<&AuthenticatedOwner>,
        request: &WeaveDigestRequest,
    ) -> MemoryResult<Option<WeaveDigestFramed>> {
        let reader = self.weave_reader(owner)?;
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        if owner.is_some() {
            read.render_due_weave_digest(reader, self.vault().store.clock.now_recorded_at())?;
        }
        let stored = match request.scheduled_for {
            Some(at) => read.read_weave_digest(reader, at)?,
            None => read.read_latest_weave_digest(reader)?,
        };
        let Some(stored) = stored else {
            return Ok(None);
        };
        let period = (stored.reader, stored.scheduled_for);
        let framed = self.weave_digest_view(&read, reader, stored)?;
        // The owner's own open of his period, for the Coach (FIX 5495):
        // evidence, never a gate on this read. Person and agent reads never
        // count.
        if let Some(owner) = owner {
            self.vault().note_owner_weave_digest_open(
                owner,
                period.0,
                period.1,
                request.scheduled_for.is_none(),
            );
        }
        Ok(Some(framed))
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
        let link = request.link()?;
        // The label is filed on the link the reader's own report shows.
        self.produced_from([link.source, link.target]);
        let filed = read.report_wrong_link(proof, reader, link)?;
        Ok(WeaveLinkCorrectionView::from_correction(&filed))
    }

    /// `vault.weave.owner.link.wrong`: the owner lens card's wrong control,
    /// filed under the owner reader with `owner` as its proof.
    pub fn weave_owner_wrong_link(
        &self,
        owner: &AuthenticatedOwner,
        request: &WeaveWrongLinkRequest,
    ) -> MemoryResult<WeaveLinkCorrectionView> {
        self.weave_wrong_link(Some(owner), owner, request)
    }

    /// `vault.weave.item.wrong`: the one-tap wrong control on a claim,
    /// project, budget or sieve audit row the bound human sees in its own
    /// lens, filed as a link's is: under `proof`, from the owner lens when
    /// `owner` is given; an agent files nothing.
    pub fn weave_wrong_item(
        &self,
        owner: Option<&AuthenticatedOwner>,
        proof: &AuthenticatedOwner,
        request: &WeaveWrongItemRequest,
    ) -> MemoryResult<WeaveItemCorrectionView> {
        let reader = self.weave_reader(owner)?;
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let target = request.target()?;
        // The label is filed on the row the reader's own report shows. An
        // audit is a side-table row; its records passed that report's floor.
        if !matches!(target, WeaveItemTarget::SieveAudit { .. }) {
            self.produced_from([target.id()]);
        }
        let filed = read.report_wrong_item(proof, reader, target)?;
        Ok(WeaveItemCorrectionView::from_correction(&filed))
    }

    /// `vault.weave.owner.item.wrong`: the owner lens card's wrong control
    /// on an item, filed under the owner reader with `owner` as its proof.
    pub fn weave_owner_wrong_item(
        &self,
        owner: &AuthenticatedOwner,
        request: &WeaveWrongItemRequest,
    ) -> MemoryResult<WeaveItemCorrectionView> {
        self.weave_wrong_item(Some(owner), owner, request)
    }
}
