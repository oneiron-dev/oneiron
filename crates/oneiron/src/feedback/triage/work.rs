//! A long revision's durable work graph (FIX 7549). A revision whose whole
//! request the Coach's window cannot take is triaged in parts: its item's
//! canonical text is cut, end to end and on character boundaries, into
//! ordered spans, each answered by its own `coach.feedback_triage_part`
//! child. Ordered batches of those answers that fit the window are then
//! answered by `coach.feedback_triage_synthesis` children, level after
//! level, until one answer stands or no batch joins two. Every node is owed
//! until answered, and every part and synthesis answer is kept on the
//! revision's handoff row. The graph keeps no item text: a part reads its
//! span back from the item its revision names, so nothing here outlives an
//! erase of that item.
//!
//! One generation runs one pinned skill arm on one window. A new generation
//! starts when that arm can no longer load or the owner bound another skill,
//! and the answers of earlier generations stay, retired. When only the
//! window changes, only the unanswered nodes are cut again.
use serde::{Deserialize, Serialize};

use super::FeedbackTriageOutput;
use crate::{EntityId, Error, Result};

/// The domain a part's digest is taken under.
const PART_DOMAIN: &[u8] = b"oneiron:feedback-triage:part:v1";
/// The domain a synthesis node's digest is taken under.
const SYNTHESIS_DOMAIN: &[u8] = b"oneiron:feedback-triage:synthesis:v1";
/// The domain the whole item text's digest is taken under.
const ITEM_DOMAIN: &[u8] = b"oneiron:feedback-triage:item:v1";

/// One revision's part and synthesis graph, kept on its handoff row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageWork {
    /// 1 for the first generation, then one more for each new one.
    pub generation: u32,
    /// The skill arm and window the current generation runs on.
    pub pin: FeedbackTriagePin,
    /// 64 hex: the digest of the item text the parts cut.
    pub item_digest: String,
    /// The item text's length in bytes.
    pub item_bytes: u64,
    /// The current generation's nodes, level by level, each level in order.
    pub nodes: Vec<FeedbackTriageWorkNode>,
    /// Every answered node of an earlier generation, kept.
    pub retired: Vec<FeedbackTriageWorkNode>,
    /// The id the next node takes.
    pub next_node: u32,
    /// Vault seconds the graph last took a new generation.
    pub planned_at: u64,
}

/// The skill arm a generation runs and the window it was cut for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriagePin {
    /// The SKILL entity the owner bound.
    pub skill: EntityId,
    /// The entity that loaded when the generation was planned: the bound
    /// skill, or the open proposal of it an exploration trial routed to.
    pub entity: EntityId,
    /// The version that loaded; every child loads exactly it.
    pub version: String,
    /// The model whose window the generation was cut for.
    pub model: String,
    /// That window less the output it reserves, in tokens.
    pub input_tokens: u64,
}

/// A byte range of the item text, on character boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageSpan {
    /// Its first byte.
    pub start: u64,
    /// One past its last byte.
    pub end: u64,
}

/// One part or synthesis node of a generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageWorkNode {
    /// Its id, unique in the graph across generations.
    pub id: u32,
    /// The generation it belongs to.
    pub generation: u32,
    /// 0 for a part; a synthesis node one above its inputs.
    pub level: u32,
    /// A part's span of the item text; `None` for a synthesis node.
    pub span: Option<FeedbackTriageSpan>,
    /// A synthesis node's inputs, in order: ids of the level below.
    pub inputs: Vec<u32>,
    /// 64 hex: a part's text, or a synthesis node's input answers.
    pub digest: String,
    /// The child job last queued for it.
    pub attempt: Option<EntityId>,
    /// Its answer; `None` while it is owed.
    pub answer: Option<FeedbackTriageNodeAnswer>,
}

/// One node's typed answer and where it came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageNodeAnswer {
    /// The answer.
    pub output: FeedbackTriageOutput,
    /// The child job that answered, or, for an answer carried up a level
    /// unasked, the one that answered it first.
    pub attempt: EntityId,
    /// The model of the rung that answered, fallback included.
    pub served_model: String,
    /// Vault seconds it was recorded.
    pub recorded_at: u64,
}

/// What a revision's job asks of its graph, checked in the writer that parks
/// the job on its children.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeedbackTriageStep {
    /// A new generation on `pin`: the item text cut into `spans`, in order,
    /// from its first byte to its last.
    Generation {
        /// The arm and window the generation runs on.
        pin: FeedbackTriagePin,
        /// The parts.
        spans: Vec<FeedbackTriageSpan>,
    },
    /// The window changed: the pin takes its new size, and each unanswered
    /// node a split names is cut again.
    Repartition {
        /// The same arm, on the new window.
        pin: FeedbackTriagePin,
        /// The nodes cut again.
        splits: Vec<FeedbackTriageSplit>,
    },
    /// The next level: the current answers, in order, in batches of node
    /// ids. A batch of one carries its answer up unasked.
    Synthesis {
        /// The batches, together every current node once, in order.
        batches: Vec<Vec<u32>>,
    },
    /// Nothing changes: the owed children are queued again, and the job
    /// waits on them or on the next sweep.
    Wait,
}

/// One unanswered node cut again for a changed window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedbackTriageSplit {
    /// The node.
    pub node: u32,
    /// A part's new spans, together its span, in order.
    pub spans: Vec<FeedbackTriageSpan>,
    /// A synthesis node's new batches, together its inputs, in order.
    pub batches: Vec<Vec<u32>>,
}

impl FeedbackTriageWork {
    /// The level the current nodes stand at: the highest.
    #[must_use]
    pub fn level(&self) -> u32 {
        self.nodes.iter().map(|node| node.level).max().unwrap_or(0)
    }

    /// The current level's nodes, in order.
    pub fn current(&self) -> impl Iterator<Item = &FeedbackTriageWorkNode> {
        let level = self.level();
        self.nodes.iter().filter(move |node| node.level == level)
    }

    /// Whether a current node is still unanswered.
    #[must_use]
    pub fn owed(&self) -> bool {
        self.current().any(|node| node.answer.is_none())
    }

    /// The current generation's node `id`.
    #[must_use]
    pub fn node(&self, id: u32) -> Option<&FeedbackTriageWorkNode> {
        self.nodes.iter().find(|node| node.id == id)
    }
}

fn invalid_plan() -> Error {
    Error::InvalidConfig("invalid feedback triage work plan".into())
}

fn digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

/// `span` of `text`; `None` off its character boundaries or past its end.
fn slice(text: &str, span: FeedbackTriageSpan) -> Option<&str> {
    let start = usize::try_from(span.start).ok()?;
    let end = usize::try_from(span.end).ok()?;
    text.get(start..end)
}

/// Refuses `spans` unless they cut `within` of `text` whole: in order, each
/// non-empty, each starting where the last ended, all on character
/// boundaries. Nothing is left out.
fn tile(text: &str, within: FeedbackTriageSpan, spans: &[FeedbackTriageSpan]) -> Result<()> {
    let mut at = within.start;
    for span in spans {
        if span.start != at || span.end <= span.start || slice(text, *span).is_none() {
            return Err(invalid_plan());
        }
        at = span.end;
    }
    if spans.is_empty() || at != within.end {
        return Err(invalid_plan());
    }
    Ok(())
}

fn take(next: &mut u32) -> Result<u32> {
    let id = *next;
    *next = id.checked_add(1).ok_or_else(invalid_plan)?;
    Ok(id)
}

fn part(
    text: &str,
    span: FeedbackTriageSpan,
    generation: u32,
    next: &mut u32,
) -> Result<FeedbackTriageWorkNode> {
    let piece = slice(text, span).ok_or_else(invalid_plan)?;
    Ok(FeedbackTriageWorkNode {
        id: take(next)?,
        generation,
        level: 0,
        span: Some(span),
        inputs: Vec::new(),
        digest: digest(PART_DOMAIN, piece.as_bytes()),
        attempt: None,
        answer: None,
    })
}

/// A synthesis node over `inputs`, each answered in `nodes`. A node of one
/// input carries its answer up unasked.
fn batch(
    nodes: &[FeedbackTriageWorkNode],
    inputs: Vec<u32>,
    level: u32,
    generation: u32,
    next: &mut u32,
) -> Result<FeedbackTriageWorkNode> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SYNTHESIS_DOMAIN);
    let mut answers = Vec::with_capacity(inputs.len());
    for id in &inputs {
        let answer = nodes
            .iter()
            .find(|node| node.id == *id)
            .and_then(|node| node.answer.as_ref())
            .ok_or_else(invalid_plan)?;
        let bytes = rmp_serde::to_vec_named(&answer.output).map_err(|_| invalid_plan())?;
        hasher.update(&(bytes.len() as u64).to_be_bytes());
        hasher.update(&bytes);
        answers.push(answer);
    }
    let carried = match answers.as_slice() {
        [only] => Some((*only).clone()),
        _ => None,
    };
    Ok(FeedbackTriageWorkNode {
        id: take(next)?,
        generation,
        level,
        span: None,
        inputs,
        digest: hasher.finalize().to_hex().to_string(),
        attempt: None,
        answer: carried,
    })
}

/// `node`'s span of `text`, checked against the item and part digests the
/// graph keeps.
pub(super) fn span_text<'t>(
    work: &FeedbackTriageWork,
    node: &FeedbackTriageWorkNode,
    text: &'t str,
) -> Result<&'t str> {
    if digest(ITEM_DOMAIN, text.as_bytes()) != work.item_digest {
        return Err(Error::CorruptedIndex("feedback triage item digest"));
    }
    let piece = node
        .span
        .and_then(|span| slice(text, span))
        .ok_or(Error::CorruptedIndex("feedback triage part span"))?;
    if digest(PART_DOMAIN, piece.as_bytes()) != node.digest {
        return Err(Error::CorruptedIndex("feedback triage part digest"));
    }
    Ok(piece)
}

/// `step` applied to `work`, `text` the item text when the step cuts it.
/// Refused unless every span and batch covers what it replaces, whole and
/// in order.
pub(super) fn apply(
    work: Option<FeedbackTriageWork>,
    step: FeedbackTriageStep,
    text: Option<&str>,
    now: u64,
) -> Result<FeedbackTriageWork> {
    match (step, work) {
        (FeedbackTriageStep::Generation { pin, spans }, work) => {
            generation(work, pin, &spans, text.ok_or_else(invalid_plan)?, now)
        }
        (_, None) => Err(invalid_plan()),
        (FeedbackTriageStep::Repartition { pin, splits }, Some(work)) => {
            repartition(work, pin, splits, text)
        }
        (FeedbackTriageStep::Synthesis { batches }, Some(work)) => synthesis(work, batches),
        (FeedbackTriageStep::Wait, Some(work)) => Ok(work),
    }
}

fn generation(
    work: Option<FeedbackTriageWork>,
    pin: FeedbackTriagePin,
    spans: &[FeedbackTriageSpan],
    text: &str,
    now: u64,
) -> Result<FeedbackTriageWork> {
    let item_bytes = text.len() as u64;
    let whole = FeedbackTriageSpan {
        start: 0,
        end: item_bytes,
    };
    tile(text, whole, spans)?;
    let (number, retired, mut next) = match work {
        Some(work) => {
            let mut retired = work.retired;
            retired.extend(work.nodes.into_iter().filter(|node| node.answer.is_some()));
            let number = work.generation.checked_add(1).ok_or_else(invalid_plan)?;
            (number, retired, work.next_node)
        }
        None => (1, Vec::new(), 0),
    };
    let mut nodes = Vec::with_capacity(spans.len());
    for span in spans {
        nodes.push(part(text, *span, number, &mut next)?);
    }
    Ok(FeedbackTriageWork {
        generation: number,
        pin,
        item_digest: digest(ITEM_DOMAIN, text.as_bytes()),
        item_bytes,
        nodes,
        retired,
        next_node: next,
        planned_at: now,
    })
}

fn repartition(
    mut work: FeedbackTriageWork,
    pin: FeedbackTriagePin,
    splits: Vec<FeedbackTriageSplit>,
    text: Option<&str>,
) -> Result<FeedbackTriageWork> {
    if (pin.skill, pin.entity, &pin.version) != (work.pin.skill, work.pin.entity, &work.pin.version)
    {
        return Err(invalid_plan());
    }
    let level = work.level();
    let mut next = work.next_node;
    for split in splits {
        let at = work
            .nodes
            .iter()
            .position(|node| node.id == split.node && node.level == level && node.answer.is_none())
            .ok_or_else(invalid_plan)?;
        let fresh = match work.nodes.get(at).and_then(|node| node.span) {
            Some(span) => {
                let text = text.ok_or_else(invalid_plan)?;
                if !split.batches.is_empty() {
                    return Err(invalid_plan());
                }
                tile(text, span, &split.spans)?;
                let mut fresh = Vec::with_capacity(split.spans.len());
                for span in &split.spans {
                    fresh.push(part(text, *span, work.generation, &mut next)?);
                }
                fresh
            }
            None => {
                let inputs = work.nodes.get(at).map(|node| node.inputs.as_slice());
                if !split.spans.is_empty()
                    || split.batches.iter().any(Vec::is_empty)
                    || !inputs.is_some_and(|inputs| split.batches.iter().flatten().eq(inputs))
                {
                    return Err(invalid_plan());
                }
                let mut fresh = Vec::with_capacity(split.batches.len());
                for inputs in split.batches {
                    fresh.push(batch(
                        &work.nodes,
                        inputs,
                        level,
                        work.generation,
                        &mut next,
                    )?);
                }
                fresh
            }
        };
        let tail = work.nodes.split_off(at + 1);
        work.nodes.truncate(at);
        work.nodes.extend(fresh);
        work.nodes.extend(tail);
    }
    work.pin = pin;
    work.next_node = next;
    Ok(work)
}

fn synthesis(mut work: FeedbackTriageWork, batches: Vec<Vec<u32>>) -> Result<FeedbackTriageWork> {
    if work.owed()
        || !batches.iter().any(|batch| batch.len() > 1)
        || batches.iter().any(Vec::is_empty)
        || !batches
            .iter()
            .flatten()
            .copied()
            .eq(work.current().map(|node| node.id))
    {
        return Err(invalid_plan());
    }
    let level = work.level().checked_add(1).ok_or_else(invalid_plan)?;
    let mut next = work.next_node;
    let mut fresh = Vec::with_capacity(batches.len());
    for inputs in batches {
        fresh.push(batch(
            &work.nodes,
            inputs,
            level,
            work.generation,
            &mut next,
        )?);
    }
    work.nodes.extend(fresh);
    work.next_node = next;
    Ok(work)
}
