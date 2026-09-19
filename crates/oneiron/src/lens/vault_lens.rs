//! Default vault browsing projection over actor-scoped, bounded engine reads.
use super::*;
use crate::claim::{ScopedRead, decode_claim_body};
use crate::edge::EdgeKind;
use crate::{EntityId, Error, Result};
use chrono::{DateTime, Datelike, Utc};
use std::collections::BTreeSet;

pub const VAULT_ON_THIS_DAY_ACTION: &str = "vault.on_this_day";
/// Each section has a conservative bound beneath the aggregate atom-kit budget.
pub const VAULT_LENS_MAX_ROWS: usize = 128;

#[derive(Debug, Clone)]
pub struct VaultLensRequest {
    pub card_id: LensRenderId,
    pub anchor: EntityId,
    /// A TURN (PartOf messages) or CONVERSATION (BelongsTo messages).
    pub thread: Option<EntityId>,
    pub valid_at: u64,
    pub learned_at: u64,
    pub limit: usize,
}
#[derive(Debug, Clone, Copy)]
pub enum VaultLensAction {
    AsOf(u64),
    OnThisDay { today: u64 },
}
#[derive(Debug, Clone)]
pub struct VaultLensProjection {
    pub card: GeneratedUiCard,
    pub valid_at: u64,
    pub claim_refs: Vec<EntityId>,
}

impl ScopedRead<'_> {
    /// Compose the closed atom kit. A hidden anchor never becomes an ungated
    /// graph or dossier read, and collection limits are checked before querying.
    pub fn project_vault_lens(&self, request: &VaultLensRequest) -> Result<VaultLensProjection> {
        if !(1..=VAULT_LENS_MAX_ROWS).contains(&request.limit) {
            return Err(Error::InvalidConfig(
                "vault lens limit must be 1..=128".into(),
            ));
        }
        let Some((kind, _, _)) = self.get_entity_parts(&request.anchor)? else {
            return Err(Error::EntityNotFound);
        };
        let mut root = node(
            "vault",
            LensAtom::Sheet(CollectionAtom {
                title: text("Vault")?,
                rows: Vec::new(),
            }),
        )?;
        root.children.push(node(
            "dossier",
            LensAtom::DossierSection(SectionAtom {
                title: text(request.anchor.to_hex())?,
                lines: vec![text(format!("Entity kind {kind}"))?],
            }),
        )?);
        root.children.push(node(
            "scrubber",
            LensAtom::AsofScrubber(AsofScrubberAtom {
                value: text(date_text(request.valid_at)?)?,
                min: None,
                max: None,
            }),
        )?);
        let mut claim_refs = Vec::new();
        let mut ledger = node(
            "ledger",
            LensAtom::Sheet(CollectionAtom {
                title: text("Claims ledger")?,
                rows: Vec::new(),
            }),
        )?;
        for hit in self.search_claims_as_of(request.valid_at, request.learned_at, request.limit)? {
            let Some(bytes) = self.get(&hit.id)? else {
                continue;
            };
            let claim = decode_claim_body(&bytes, true)?;
            if claim.valid_from.is_some_and(|from| from > request.valid_at)
                || claim.valid_to.is_some_and(|to| to <= request.valid_at)
            {
                continue;
            }
            claim_refs.push(hit.id);
            ledger.children.push(node(
                &format!("claim-{}", hit.id.to_hex()),
                LensAtom::LedgerRow(LedgerRowAtom {
                    cells: vec![
                        cell("predicate", claim.predicate)?,
                        cell(
                            "value",
                            crate::companion::companion_value_to_json(&claim.value).to_string(),
                        )?,
                        cell("valid at", date_text(request.valid_at)?)?,
                    ],
                    status: None,
                    seal: None,
                }),
            )?);
        }
        root.children.push(ledger);
        root.children.push(node(
            "graph",
            LensAtom::NeighborhoodGraph(neighborhood(self, request)?),
        )?);
        root.children.push(thread(self, request)?);
        let action = SelfUiAction {
            command: SelfUiActionId::new(VAULT_ON_THIS_DAY_ACTION)?,
            args: Vec::new(),
        };
        root.children.push(node(
            "on-this-day",
            LensAtom::SelfUi(SelfUiControl::Button(ButtonControl {
                id: SelfUiControlId::new("on-this-day")?,
                label: text("On this day last year")?,
                action: action.clone(),
            })),
        )?);
        let card = GeneratedUiCard::interactive(
            request.card_id.clone(),
            GeneratedLens::new(root)?,
            vec![GeneratedUiActionDeclaration {
                element_id: LensAtomId::new("on-this-day")?,
                action_id: action.command.clone(),
                tier: GeneratedUiActionTier::DeterministicTool,
                action,
            }],
            GeneratedUiStateSnapshot::default(),
        )?;
        Ok(VaultLensProjection {
            card,
            valid_at: request.valid_at,
            claim_refs,
        })
    }

    /// Re-query before committing the scrubber position. Failed reads leave its
    /// last-good position unchanged. The host supplies its clock, not lens text.
    pub fn apply_vault_lens_action(
        &self,
        request: &mut VaultLensRequest,
        action: VaultLensAction,
    ) -> Result<VaultLensProjection> {
        let mut next = request.clone();
        next.valid_at = match action {
            VaultLensAction::AsOf(at) => at,
            VaultLensAction::OnThisDay { today } => today_last_year(today)?,
        };
        let projection = self.project_vault_lens(&next)?;
        *request = next;
        Ok(projection)
    }
}

fn neighborhood(
    read: &ScopedRead<'_>,
    request: &VaultLensRequest,
) -> Result<NeighborhoodGraphAtom> {
    let anchor = request.anchor.to_hex();
    let mut graph = NeighborhoodGraphAtom {
        nodes: vec![GraphNode {
            id: LensHandleName::new(&anchor)?,
            label: text(&anchor)?,
        }],
        edges: Vec::new(),
    };
    let mut seen = BTreeSet::from([anchor.clone()]);
    for outward in [true, false] {
        let remaining = request.limit.saturating_sub(graph.edges.len());
        for edge in
            read.vault()
                .neighbor_edges_bounded(&request.anchor, outward, None, None, remaining)?
        {
            if !read.is_entity_readable(&edge.target)? {
                continue;
            }
            let other = edge.target.to_hex();
            if seen.insert(other.clone()) {
                graph.nodes.push(GraphNode {
                    id: LensHandleName::new(&other)?,
                    label: text(&other)?,
                });
            }
            let (from, to) = if outward {
                (&anchor, &other)
            } else {
                (&other, &anchor)
            };
            graph.edges.push(GraphEdge {
                from: LensHandleName::new(from)?,
                to: LensHandleName::new(to)?,
                label: text(format!("{:?}", edge.kind))?,
            });
        }
    }
    Ok(graph)
}

fn thread(read: &ScopedRead<'_>, request: &VaultLensRequest) -> Result<LensNode> {
    let mut section = node(
        "thread",
        LensAtom::DossierSection(SectionAtom {
            title: text("Thread")?,
            lines: Vec::new(),
        }),
    )?;
    let Some(anchor) = request.thread else {
        return Ok(section);
    };
    let Some((kind, _, _)) = read.get_entity_parts(&anchor)? else {
        return Ok(section);
    };
    let edge = match kind {
        crate::registry::ENTITY_TYPE_TURN => EdgeKind::PartOf,
        crate::registry::ENTITY_TYPE_CONVERSATION => EdgeKind::BelongsTo,
        _ => {
            return Err(Error::InvalidConfig(
                "thread anchor must be a turn or conversation".into(),
            ));
        }
    };
    for edge in
        read.vault()
            .neighbor_edges_bounded(&anchor, false, Some(edge), None, request.limit)?
    {
        let Some((crate::registry::ENTITY_TYPE_MESSAGE, learned, bytes)) =
            read.get_entity_parts(&edge.target)?
        else {
            continue;
        };
        if learned > request.learned_at {
            continue;
        }
        let value = rmpv::decode::read_value(&mut bytes.as_slice())
            .map_err(|_| Error::CorruptedIndex("witness message body"))?;
        let Some(map) = value.as_map() else {
            return Err(Error::CorruptedIndex("witness message map"));
        };
        let get = |key: &str| {
            map.iter()
                .find(|(k, _)| k.as_str() == Some(key))
                .map(|(_, v)| v)
        };
        if get("is_visible").and_then(rmpv::Value::as_bool) != Some(true) {
            continue;
        }
        let author = get("author")
            .and_then(rmpv::Value::as_str)
            .ok_or(Error::CorruptedIndex("witness author"))?;
        let content = get("content")
            .and_then(rmpv::Value::as_str)
            .ok_or(Error::CorruptedIndex("witness content"))?;
        section.children.push(node(
            &format!("message-{}", edge.target.to_hex()),
            LensAtom::ThreadEntry(ThreadEntryAtom {
                author: text(author)?,
                body: text(content)?,
                timestamp: Some(text(date_text(learned)?)?),
                seal: None,
            }),
        )?);
    }
    Ok(section)
}
fn text(value: impl Into<String>) -> Result<LensText> {
    LensText::new(value)
}
fn cell(label: &str, value: impl Into<String>) -> Result<LedgerCell> {
    Ok(LedgerCell {
        label: text(label)?,
        value: text(value)?,
    })
}
fn node(id: &str, atom: LensAtom) -> Result<LensNode> {
    Ok(LensNode::new(LensAtomId::new(id)?, atom))
}
fn timestamp(at: u64) -> Result<DateTime<Utc>> {
    i64::try_from(at)
        .ok()
        .and_then(|at| DateTime::from_timestamp(at, 0))
        .ok_or_else(|| {
            Error::InvalidConfig("vault lens date is outside the supported range".into())
        })
}
fn date_text(at: u64) -> Result<String> {
    Ok(timestamp(at)?.to_rfc3339())
}
/// Calendar-year subtraction, clamping February 29 to February 28, in UTC.
pub fn today_last_year(today: u64) -> Result<u64> {
    let today = timestamp(today)?;
    let prior = today
        .with_year(today.year() - 1)
        .or_else(|| {
            today
                .with_day(28)
                .and_then(|day| day.with_year(today.year() - 1))
        })
        .ok_or_else(|| {
            Error::InvalidConfig("last-year date is outside the supported range".into())
        })?;
    u64::try_from(prior.timestamp())
        .map_err(|_| Error::InvalidConfig("last-year date precedes epoch".into()))
}
