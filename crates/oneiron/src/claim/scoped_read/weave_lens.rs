//! The weave lens's generate step (OF-499, ARCH-0063 §6): "Its render is a
//! generate step, a skill with its own axes: read rate and corrections."
//!
//! The Dreamer renders each saved digest period through the shipped
//! `weave-report` skill on a lent model. The model sees the period's admitted
//! items, each under a key, and answers with a [`WeaveLensPlan`]: wording and
//! grouping that cite those keys and nothing else. The plan is saved on the
//! period's row. Opening the digest composes it into a [`GeneratedLens`]
//! under the opener's own read: every row keeps its source refs, and every
//! link carries the one-tap wrong control (`vault.weave.link.wrong`). The
//! model mints no ref, handle or action. When the reader's next period
//! renders, the previous one settles the skill's two axes as evidence.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{PointRead, ScopedRead, StoredWeaveDigest, WeaveDigestReader, WeaveItem, WeaveReport};
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::learning::{Anchor, LearningCell, LearningEvidence, LearningPredicate, Observation};
use crate::lens::{
    ButtonControl, CollectionAtom, GeneratedLens, LedgerCell, LedgerRowAtom, LensAtom, LensAtomId,
    LensBackingTarget, LensHandleName, LensHandleRef, LensHandleRole, LensNode,
    LensPrincipalBinding, LensRenderFrame, LensRenderId, LensText, SectionAtom, SelfUiAction,
    SelfUiActionId, SelfUiControl, SelfUiControlId, SelfUiValue,
};
use crate::provenance::EdgeRef;
use crate::{EntityId, Vault};

/// The shipped skill whose SKILL.md is the render instruction.
pub const WEAVE_REPORT_SKILL_NAME: &str = "weave-report";
/// The skill's axes: the reader opened the period's notice; the reader
/// marked none of the period's links wrong.
pub const WEAVE_LENS_READ_RATE_AXIS: &str = "read_rate";
pub const WEAVE_LENS_CORRECTIONS_AXIS: &str = "corrections";
/// The verb a link's wrong control calls.
const WRONG_LINK_VERB: &str = "vault.weave.link.wrong";
/// The most sections a plan holds, and summary lines per section.
const MAX_PLAN_SECTIONS: usize = 64;
const MAX_SUMMARY_LINES: usize = 16;

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("weave lens: {reason}"))
}

/// The shipped `weave-report` skill: its bootstrap seed id.
pub fn weave_report_skill_id() -> Result<EntityId> {
    EntityId::derive(
        crate::entity_id::derived_domains::BOOTSTRAP_SKILL,
        &[WEAVE_REPORT_SKILL_NAME.as_bytes()],
    )
}

/// The model's answer: a title, the wrong control's label, and sections
/// that cite every admitted item exactly once by its key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveLensPlan {
    pub title: String,
    pub wrong_label: String,
    pub sections: Vec<WeaveLensPlanSection>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveLensPlanSection {
    pub heading: String,
    #[serde(default)]
    pub summary: Vec<String>,
    pub items: Vec<WeaveLensPlanLine>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveLensPlanLine {
    pub key: String,
    pub line: String,
}

/// One period's render, saved on its digest row: the plan and what made it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeaveLensRender {
    pub plan: WeaveLensPlan,
    pub skill_ref: String,
    pub skill_version: String,
    pub model: String,
    pub rendered_at: u64,
}

fn item_key(section: usize, item: usize) -> String {
    format!("{section}.{item}")
}

fn keyed_items(report: &WeaveReport) -> BTreeMap<String, &WeaveItem> {
    report
        .sections
        .iter()
        .enumerate()
        .flat_map(|(s, section)| {
            section
                .items
                .iter()
                .enumerate()
                .map(move |(i, item)| (item_key(s, i), item))
        })
        .collect()
}

fn required_text(value: &str, what: &str) -> Result<LensText> {
    if value.trim().is_empty() {
        return Err(invalid(&format!("the plan's {what} is empty")));
    }
    LensText::new(value.to_owned())
}

impl WeaveLensPlan {
    /// The plan cites every admitted item of `report` exactly once, by key,
    /// and nothing else; every text is a non-empty lens text.
    pub fn validate(&self, report: &WeaveReport) -> Result<()> {
        if self.sections.len() > MAX_PLAN_SECTIONS
            || self
                .sections
                .iter()
                .any(|section| section.summary.len() > MAX_SUMMARY_LINES)
        {
            return Err(invalid("the plan is too large"));
        }
        required_text(&self.title, "title")?;
        required_text(&self.wrong_label, "wrong label")?;
        let items = keyed_items(report);
        let mut cited = BTreeSet::new();
        for section in &self.sections {
            required_text(&section.heading, "heading")?;
            for line in &section.summary {
                LensText::new(line.clone())?;
            }
            for line in &section.items {
                if !items.contains_key(&line.key) || !cited.insert(line.key.as_str()) {
                    return Err(invalid("the plan cites a key it was not given, or twice"));
                }
                required_text(&line.line, "item line")?;
            }
        }
        if cited.len() != items.len() {
            return Err(invalid("the plan drops an item"));
        }
        Ok(())
    }
}

/// The generate step's input: the period's items as their served views,
/// each under its key, and who reads them.
pub(crate) fn weave_lens_model_input(vault: &Vault, stored: &StoredWeaveDigest) -> Result<String> {
    let (id, class, reader) = match stored.reader {
        WeaveDigestReader::Person(id) => (id, EdgeActorClass::Human, "person"),
        WeaveDigestReader::Owner(id) => (id, EdgeActorClass::Human, "owner"),
        WeaveDigestReader::Agent(id) => (id, EdgeActorClass::Agent, "agent"),
    };
    let sections = vault
        .memory(id, class)
        .weave_sections(&stored.report.value)
        .map_err(|error| invalid(&error.to_string()))?;
    let sections = sections
        .iter()
        .enumerate()
        .map(|(s, section)| {
            let items = section
                .items
                .iter()
                .enumerate()
                .map(|(i, item)| {
                    let mut value =
                        serde_json::to_value(item).map_err(|_| invalid("an item is not JSON"))?;
                    value
                        .as_object_mut()
                        .ok_or_else(|| invalid("an item is not an object"))?
                        .insert("key".to_owned(), item_key(s, i).into());
                    Ok(value)
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(serde_json::json!({ "kind": section.kind, "items": items }))
        })
        .collect::<Result<Vec<_>>>()?;
    serde_json::to_string_pretty(&serde_json::json!({
        "reader": reader,
        "period": stored.scheduled_for,
        "rendered_at": stored.rendered_at,
        "sections": sections,
    }))
    .map_err(|_| invalid("the input is not JSON"))
}

/// The JSON schema the generate step's answer must meet.
pub(crate) fn weave_lens_plan_schema() -> Result<serde_json::Value> {
    serde_json::to_value(schemars::schema_for!(WeaveLensPlan))
        .map_err(|_| invalid("the plan schema is not JSON"))
}

/// A frame for the opener's own key, as the default projection builds one.
fn opener_frame(read: &ScopedRead<'_>) -> Result<LensRenderFrame> {
    let key = read.actor_key().clone();
    let principal_ref = key.actor_ref().to_owned();
    let principal = if key.actor_class() == Some(EdgeActorClass::Agent.gate_actor_class()) {
        LensPrincipalBinding::agent_task(principal_ref, key.clone(), vec![key])?
    } else {
        LensPrincipalBinding::human_view(principal_ref, key.clone(), vec![key])?
    };
    let render_id = LensRenderId::new(format!("weave-lens-{}", EntityId::now().to_hex()))?;
    Ok(LensRenderFrame::new(render_id, principal))
}

fn cells(item: &WeaveItem, line: &str) -> Result<Vec<LedgerCell>> {
    let cell = |label: &str, value: String| -> Result<LedgerCell> {
        Ok(LedgerCell {
            label: LensText::new(label.to_owned())?,
            value: LensText::new(value)?,
        })
    };
    let mut cells = vec![cell("line", line.to_owned())?];
    match item {
        WeaveItem::Claim { id, .. } => cells.push(cell("claim_ref", id.to_hex())?),
        WeaveItem::Project { id, goal } => {
            cells.push(cell("project_ref", id.to_hex())?);
            if let Some(goal) = goal {
                cells.push(cell("goal_ref", goal.clone())?);
            }
        }
        WeaveItem::Budget {
            project,
            budget_ref,
        } => {
            cells.push(cell("project_ref", project.to_hex())?);
            cells.push(cell("budget_ref", budget_ref.to_hex())?);
        }
        WeaveItem::Link {
            source,
            kind,
            target,
        } => {
            cells.push(cell("source_ref", source.to_hex())?);
            cells.push(cell("kind", kind.name().to_owned())?);
            cells.push(cell("target_ref", target.to_hex())?);
        }
        WeaveItem::DreamProgress {
            resident,
            dreamed_at,
            entries,
        } => {
            cells.push(cell("resident_ref", resident.to_hex())?);
            cells.push(cell("dreamed_at", dreamed_at.to_string())?);
            cells.push(cell("entries", entries.to_string())?);
        }
    }
    Ok(cells)
}

/// The records an item stands on, which its row binds when the read admits.
fn item_sources(item: &WeaveItem) -> Option<EntityId> {
    match item {
        WeaveItem::Claim { id, .. } | WeaveItem::Project { id, .. } => Some(*id),
        WeaveItem::Budget { project, .. } => Some(*project),
        WeaveItem::Link { .. } | WeaveItem::DreamProgress { .. } => None,
    }
}

/// Compose a saved render into the lens under `read`, the opener's own read.
/// Every row binds the source its read admits now; every link row carries
/// the wrong control over its exact link.
pub(super) fn compose_weave_lens(
    read: &ScopedRead<'_>,
    report: &WeaveReport,
    render: &WeaveLensRender,
) -> Result<GeneratedLens> {
    let plan = &render.plan;
    plan.validate(report)?;
    let items = keyed_items(report);
    let mut frame = opener_frame(read)?;
    let sources: Vec<EntityId> = items
        .values()
        .filter_map(|item| item_sources(item))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut handles = BTreeMap::new();
    if !sources.is_empty() {
        let reads: Vec<_> = sources.iter().map(|id| PointRead::id(*id)).collect();
        for (index, row) in read.read(&reads, None)?.value.into_iter().enumerate() {
            let Some(row) = row else { continue };
            let (target, role) = if row.entity_type == crate::registry::ENTITY_TYPE_CLAIM {
                (
                    LensBackingTarget::claim(row.id, row.id.to_hex(), row.content_hash)?,
                    LensHandleRole::ClaimSet,
                )
            } else {
                (
                    LensBackingTarget::entity(row.id, row.id.to_hex(), row.content_hash)?,
                    LensHandleRole::EntitySet,
                )
            };
            let name = LensHandleName::new(format!("weave-{index}"))?;
            frame.mint_backing_ref(read, name.clone(), role, target)?;
            handles.insert(row.id, LensHandleRef { name, role });
        }
    }
    let mut root = LensNode::new(
        LensAtomId::new("weave-lens")?,
        LensAtom::Sheet(CollectionAtom {
            title: required_text(&plan.title, "title")?,
            rows: Vec::new(),
        }),
    );
    for (s, section) in plan.sections.iter().enumerate() {
        let mut node = LensNode::new(
            LensAtomId::new(format!("weave-lens-{s}"))?,
            LensAtom::DossierSection(SectionAtom {
                title: required_text(&section.heading, "heading")?,
                lines: section
                    .summary
                    .iter()
                    .map(|line| LensText::new(line.clone()))
                    .collect::<Result<Vec<_>>>()?,
            }),
        );
        for (i, entry) in section.items.iter().enumerate() {
            let item = items
                .get(&entry.key)
                .ok_or_else(|| invalid("the plan cites a key it was not given"))?;
            let id = format!("weave-lens-{s}-{i}");
            let mut row = LensNode::new(
                LensAtomId::new(id.clone())?,
                LensAtom::LedgerRow(LedgerRowAtom {
                    cells: cells(item, &entry.line)?,
                    status: None,
                    seal: None,
                }),
            );
            row.bindings = item_sources(item)
                .and_then(|source| handles.get(&source).cloned())
                .into_iter()
                .collect();
            if let WeaveItem::Link {
                source,
                kind,
                target,
            } = item
            {
                let control = format!("{id}-wrong");
                row.children.push(LensNode::new(
                    LensAtomId::new(control.clone())?,
                    LensAtom::SelfUi(SelfUiControl::Button(ButtonControl {
                        id: SelfUiControlId::new(control)?,
                        label: required_text(&plan.wrong_label, "wrong label")?,
                        action: SelfUiAction {
                            command: SelfUiActionId::new(WRONG_LINK_VERB)?,
                            args: vec![
                                SelfUiValue::Text(LensText::new(source.to_hex())?),
                                SelfUiValue::Text(LensText::new(kind.name().to_owned())?),
                                SelfUiValue::Text(LensText::new(target.to_hex())?),
                            ],
                        },
                    })),
                ));
            }
            node.children.push(row);
        }
        root.children.push(node);
    }
    GeneratedLens::new(root)
}

/// Settle one rendered period on the skill's axes once the reader's next
/// period has rendered: whether the reader opened the period's notice, and
/// whether they marked any of its links wrong since it rendered. Each lands
/// as world-anchored evidence keyed by the period, so a replay replaces its
/// own row.
pub(crate) fn settle_weave_lens_axes(
    vault: &Vault,
    reader: WeaveDigestReader,
    scheduled_for: u64,
    report: &WeaveReport,
    render: &WeaveLensRender,
    now: u64,
) -> Result<()> {
    let skill = EntityId::from_hex(&render.skill_ref).map_err(|_| invalid("skill ref"))?;
    let id = reader.id();
    let source = reader.notification(scheduled_for, now).source;
    let receipt = format!("{}:{}", source.producer, source.event);
    let cell = |axis: &str| {
        LearningCell::new(LearningPredicate::Reliability, skill)
            .executor(render.model.clone())
            .axis(axis)
    };
    vault.with_write_txn_grouped(|txn| {
        if let Some(seen) = vault.notification_seen_in_txn(txn, &source, &id)? {
            crate::learning::record_evidence_in_txn(
                vault,
                txn,
                &cell(WEAVE_LENS_READ_RATE_AXIS),
                &LearningEvidence::anchored(
                    receipt.clone(),
                    now,
                    Anchor::WorldOutcome,
                    Observation::Success(seen),
                ),
                now,
            )?;
        }
        let mut corrected = false;
        for item in report.sections.iter().flat_map(|section| &section.items) {
            if let WeaveItem::Link {
                source,
                kind,
                target,
            } = item
                && vault
                    .weave_link_correction_labels_in_txn(
                        txn,
                        EdgeRef::new(*source, *kind, *target),
                    )?
                    .iter()
                    .any(|label| label.actor == id && label.recorded_at >= render.rendered_at)
            {
                corrected = true;
                break;
            }
        }
        crate::learning::record_evidence_in_txn(
            vault,
            txn,
            &cell(WEAVE_LENS_CORRECTIONS_AXIS),
            &LearningEvidence::anchored(
                receipt.clone(),
                now,
                Anchor::WorldOutcome,
                Observation::Success(!corrected),
            ),
            now,
        )?;
        Ok(())
    })
}

/// The generate step's attempt input: the period it renders, as
/// `[reader tag, reader id hex, scheduled_for, rendered_at]`.
pub(crate) fn weave_lens_attempt_input(
    reader: WeaveDigestReader,
    scheduled_for: u64,
    rendered_at: u64,
) -> rmpv::Value {
    let (tag, id) = reader.tag();
    rmpv::Value::Array(vec![
        tag.into(),
        id.to_hex().into(),
        scheduled_for.into(),
        rendered_at.into(),
    ])
}

/// The period a generate-step attempt renders.
pub(crate) fn weave_lens_attempt_period(
    input: &rmpv::Value,
) -> Result<(WeaveDigestReader, u64, u64)> {
    let fields = input
        .as_array()
        .filter(|fields| fields.len() == 4)
        .ok_or_else(|| invalid("attempt input"))?;
    let id = fields[1]
        .as_str()
        .and_then(|hex| EntityId::from_hex(hex).ok())
        .ok_or_else(|| invalid("attempt reader"))?;
    let reader = fields[0]
        .as_str()
        .and_then(|tag| WeaveDigestReader::from_tag(tag, id))
        .ok_or_else(|| invalid("attempt reader"))?;
    let scheduled_for = fields[2]
        .as_u64()
        .ok_or_else(|| invalid("attempt period"))?;
    let rendered_at = fields[3]
        .as_u64()
        .ok_or_else(|| invalid("attempt period"))?;
    Ok((reader, scheduled_for, rendered_at))
}
