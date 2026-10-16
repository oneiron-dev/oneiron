//! ARCH-0072's memory-informed drafter. It reads two inputs and nothing else:
//! the resolved manifest, and the owner's past grant rulings, which are the
//! rows of the slates he stamped. Every row starts at `auto`; a draft may
//! pre-fill `always ask` or `never allow` where those rulings show he wants
//! them, and never widens. The model answers one typed choice per row, never
//! prose, and the slate is always shown before anything is granted.
use super::slate::{
    ConnectorGrantSlate, SlateDisposition, SlateDraftRow, SlateOwnerOverride, SlateRow,
    SlateToolManifest, declaration_expands, new_slate, read_slate_in_store_txn, scan_slates_in_txn,
};
use crate::error::{Error, Result};
use crate::llm::decision::catalogue::CONNECTOR_SLATE_DRAFT;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBandPolicy, DecisionDial, DecisionLadder, Reversibility,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::store::Store;
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

/// A recommendation needs this many connectors' rulings, and a strict
/// majority of them, before it pre-fills a tighter setting.
const PAST_RULING_MIN_CONNECTORS: u32 = 2;

/// The capability traits the owner's past rulings are counted by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlateTrait {
    Read,
    Destroys,
    Spends,
    SendsOutward,
    Header,
    Elicitation,
    Personal,
    Secret,
}
impl SlateTrait {
    pub fn of(tool: &SlateToolManifest) -> BTreeSet<Self> {
        let mut traits = BTreeSet::new();
        for (on, trait_) in [
            (tool.destroys, Self::Destroys),
            (tool.spends, Self::Spends),
            (tool.sends_outward, Self::SendsOutward),
            (
                tool.row_data_class() == super::SlateDataClass::Header,
                Self::Header,
            ),
            (tool.legacy_ask, Self::Elicitation),
        ] {
            if on {
                traits.insert(trait_);
            }
        }
        if traits.is_empty() {
            traits.insert(Self::Read);
        }
        match tool.data_class {
            super::SlateDataClass::Personal => {
                traits.insert(Self::Personal);
            }
            super::SlateDataClass::Secret => {
                traits.insert(Self::Secret);
            }
            super::SlateDataClass::Public | super::SlateDataClass::Header => {}
        }
        traits
    }
    fn label(self) -> &'static str {
        match self {
            Self::Read => "read-only tools",
            Self::Destroys => "destructive tools",
            Self::Spends => "paying tools",
            Self::SendsOutward => "outward-sending tools",
            Self::Header => "header-bearing tools",
            Self::Elicitation => "elicitation",
            Self::Personal => "tools reaching personal data",
            Self::Secret => "tools reaching secret data",
        }
    }
}

/// The owner's past grant rulings: per trait, how many connectors' stamped
/// slates kept each setting. Evidence for a recommendation, never a settings
/// store, and never a widening on its own.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SlatePastRulings {
    pub by_trait: BTreeMap<SlateTrait, BTreeMap<SlateDisposition, u32>>,
    /// The stamped slates the counts come from.
    pub evidence: Vec<EntityId>,
}
impl SlatePastRulings {
    /// The tightest setting the rulings show the owner wants for this tool,
    /// with the line that says why.
    pub fn recommend(&self, tool: &SlateToolManifest) -> Option<(SlateDisposition, String)> {
        let mut best: Option<(SlateDisposition, String)> = None;
        for trait_ in SlateTrait::of(tool) {
            let Some(counts) = self.by_trait.get(&trait_) else {
                continue;
            };
            let count = |setting| counts.get(&setting).copied().unwrap_or(0);
            let ask = count(SlateDisposition::AlwaysAsk);
            let never = count(SlateDisposition::NeverAllow);
            let strict = ask + never;
            let total =
                strict + count(SlateDisposition::Auto) + count(SlateDisposition::AlwaysAllow);
            if strict < PAST_RULING_MIN_CONNECTORS || strict * 2 <= total {
                continue;
            }
            let (setting, n) = if never > ask {
                (SlateDisposition::NeverAllow, never)
            } else {
                (SlateDisposition::AlwaysAsk, ask)
            };
            if best.as_ref().is_none_or(|(held, _)| setting > *held) {
                best = Some((
                    setting,
                    format!(
                        "you chose {} for {} on {n} of {total} connectors",
                        setting.as_str().replace('_', " "),
                        trait_.label()
                    ),
                ));
            }
        }
        best
    }
}

/// Reads the owner's rulings from every stamped slate, one lineage per
/// connector: a drift delta chains to its prior, and only the newest stamped
/// slate of a lineage counts, so re-stamps never count twice.
pub(super) fn past_rulings_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<SlatePastRulings> {
    let slates: BTreeMap<EntityId, ConnectorGrantSlate> =
        scan_slates_in_txn(store, txn)?.into_iter().collect();
    let root = |mut id: EntityId| {
        for _ in 0..slates.len() {
            match slates.get(&id).and_then(ConnectorGrantSlate::prior) {
                Some(prior) if slates.contains_key(&prior) => id = prior,
                _ => break,
            }
        }
        id
    };
    let mut newest: BTreeMap<EntityId, EntityId> = BTreeMap::new();
    for (id, slate) in &slates {
        if slate.owner_actor().is_some() {
            let lineage = newest.entry(root(*id)).or_insert(*id);
            *lineage = (*lineage).max(*id);
        }
    }
    let mut rulings = SlatePastRulings::default();
    for id in newest.into_values() {
        let slate = &slates[&id];
        let mut seen = BTreeSet::new();
        for row in slate.rows() {
            let Some(tool) = slate.tool(&row.draft.tool) else {
                continue;
            };
            for trait_ in SlateTrait::of(tool) {
                seen.insert((trait_, row.stamped_disposition()));
            }
        }
        for (trait_, setting) in seen {
            *rulings
                .by_trait
                .entry(trait_)
                .or_default()
                .entry(setting)
                .or_default() += 1;
        }
        rulings.evidence.push(id);
    }
    Ok(rulings)
}

/// The rule rung of the drafter: `auto`, or the owner's evident tighter
/// choice. It is also what a row falls back to when no model answers.
pub fn rule_draft_row(tool: &SlateToolManifest, rulings: &SlatePastRulings) -> SlateDraftRow {
    let (disposition, rationale) = rulings.recommend(tool).unwrap_or_else(|| {
        (
            SlateDisposition::Auto,
            if tool.floor() {
                "auto: an irreversible or header-bearing call still asks each time"
            } else {
                "auto: scoped read"
            }
            .to_owned(),
        )
    });
    SlateDraftRow {
        tool: tool.name.clone(),
        disposition,
        data_class: tool.row_data_class(),
        rationale,
    }
}

/// Draft deterministic defaults with no past rulings: every row `auto`.
pub fn draft_connector_slate(manifest: &[SlateToolManifest]) -> Vec<SlateDraftRow> {
    let rulings = SlatePastRulings::default();
    manifest
        .iter()
        .map(|tool| rule_draft_row(tool, &rulings))
        .collect()
}

/// The drafter's model rungs on the shared typed-decision ladder. Hosts
/// supply the provider slots, policy, clock and wording; the engine asks one
/// choice question per row and keeps only the typed setting.
pub struct ConnectorSlateDrafter<'a> {
    pub ladder: DecisionLadder<'a>,
    pub principal: EntityId,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    pub deadline: &'a RetrievalDeadline,
    /// The host's per-row question wording; never engine text.
    pub wording: &'a str,
}
impl ConnectorSlateDrafter<'_> {
    /// One row. An abstention, an answer outside `options` or a ladder
    /// failure keeps the rule row, so drafting never stalls an admission.
    fn draft_row(
        &self,
        door: &str,
        tool: &SlateToolManifest,
        rulings: &SlatePastRulings,
        rule: &SlateDraftRow,
        options: &[SlateDisposition],
        instruction: Option<&str>,
        current: Option<SlateDisposition>,
    ) -> SlateDraftRow {
        let contract = AnswerContract::Choice {
            options: options.iter().map(|o| o.as_str().to_owned()).collect(),
        };
        let Ok(question) = CONNECTOR_SLATE_DRAFT.question(
            &[door.as_bytes(), tool.name.as_bytes()],
            self.wording.to_owned(),
            contract,
        ) else {
            return rule.clone();
        };
        let past: BTreeMap<_, _> = SlateTrait::of(tool)
            .into_iter()
            .filter_map(|t| rulings.by_trait.get(&t).map(|counts| (t, counts)))
            .collect();
        let state = json!({
            "tool": tool,
            "past_rulings": past,
            "rule_draft": rule.disposition,
            "current": current,
            "owner_instruction": instruction,
        });
        let decision = self.ladder.run(
            &question,
            self.principal,
            &rulings.evidence,
            &state,
            self.dial,
            &self.bands,
            Reversibility::ReversibleRead,
            self.deadline,
        );
        let Ok(decision) = decision else {
            return rule.clone();
        };
        let DecisionAnswer::Choice(answer) = decision.answer else {
            return rule.clone();
        };
        match SlateDisposition::parse(&answer).filter(|d| options.contains(d)) {
            Some(disposition) if disposition == rule.disposition => rule.clone(),
            Some(disposition) => SlateDraftRow {
                disposition,
                rationale: format!(
                    "drafted {}; the rule draft was {} ({})",
                    disposition.as_str().replace('_', " "),
                    rule.disposition.as_str().replace('_', " "),
                    rule.rationale
                ),
                ..rule.clone()
            },
            None => rule.clone(),
        }
    }
}

/// What a drift delta changed against its prior slate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorSlateDelta {
    pub slate_id: EntityId,
    /// New or expanded rows: the only ones the owner's tap re-asks.
    pub reask: BTreeSet<String>,
    /// Unchanged or narrowed rows, carried with their settings.
    pub carried: BTreeSet<String>,
    /// Tools the declaration dropped; they drop without an ask.
    pub dropped: BTreeSet<String>,
}

/// An owner-asked re-draft: changed rows only, landed by one tap through
/// `override_connector_slate` at `expected_revision`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorSlateRedraft {
    pub slate_id: EntityId,
    pub expected_revision: u64,
    pub proposed: BTreeMap<String, SlateOwnerOverride>,
    pub rationale: BTreeMap<String, String>,
}

/// Admission and drift drafts never offer `always allow`; only the owner
/// picks it, or asks for it in a re-draft.
const DRAFT_OPTIONS: [SlateDisposition; 3] = [
    SlateDisposition::Auto,
    SlateDisposition::AlwaysAsk,
    SlateDisposition::NeverAllow,
];

fn draft_rows(
    door: &str,
    tools: &[&SlateToolManifest],
    rulings: &SlatePastRulings,
    drafter: Option<&ConnectorSlateDrafter<'_>>,
) -> Vec<SlateDraftRow> {
    tools
        .iter()
        .map(|tool| {
            let rule = rule_draft_row(tool, rulings);
            match drafter {
                Some(drafter) => {
                    drafter.draft_row(door, tool, rulings, &rule, &DRAFT_OPTIONS, None, None)
                }
                None => rule,
            }
        })
        .collect()
}

fn fresh(draft: SlateDraftRow) -> SlateRow {
    SlateRow {
        draft,
        owner_override: None,
        holder_narrow: None,
    }
}

impl Vault {
    pub fn connector_slate_past_rulings(&self) -> Result<SlatePastRulings> {
        let txn = self.store.env.read_txn()?;
        past_rulings_in_txn(&self.store, &txn)
    }

    /// Connector add: draft the slate from the resolved manifest and the
    /// owner's past rulings, and store it unstamped for the one-tap accept.
    /// Without a model drafter the rule rung drafts every row.
    pub fn draft_connector_admission_slate(
        &self,
        manifest: &[SlateToolManifest],
        drafter: Option<&ConnectorSlateDrafter<'_>>,
    ) -> Result<EntityId> {
        let rulings = self.connector_slate_past_rulings()?;
        let tools: Vec<_> = manifest.iter().collect();
        let rows = draft_rows("admission", &tools, &rulings, drafter)
            .into_iter()
            .map(fresh)
            .collect();
        self.put_new_slate(new_slate(manifest, rows, None, None, BTreeSet::new())?)
    }

    /// Drift: a delta slate against `prior`. Unchanged and narrowed rows
    /// carry their settings and overrides; new and expanded rows are drafted
    /// fresh and are the only rows that re-ask; removed tools drop. Bind it
    /// with `revise_connector_protocol`, which re-asks only on expansion.
    pub fn draft_connector_delta_slate(
        &self,
        prior_id: EntityId,
        manifest: &[SlateToolManifest],
        drafter: Option<&ConnectorSlateDrafter<'_>>,
    ) -> Result<ConnectorSlateDelta> {
        let (prior, rulings, carry) = {
            let txn = self.store.env.read_txn()?;
            let prior = read_slate_in_store_txn(&self.store, &txn, prior_id)?
                .ok_or(Error::EntityNotFound)?;
            let policy = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
            (
                prior,
                past_rulings_in_txn(&self.store, &txn)?,
                policy.connector_class_carry(),
            )
        };
        let expanded: Vec<&SlateToolManifest> = manifest
            .iter()
            .filter(|tool| {
                prior
                    .tool(&tool.name)
                    .is_none_or(|old| declaration_expands(old, tool, &carry))
            })
            .collect();
        let mut drafted: BTreeMap<String, SlateDraftRow> =
            draft_rows("drift", &expanded, &rulings, drafter)
                .into_iter()
                .map(|row| (row.tool.clone(), row))
                .collect();
        let mut rows = Vec::with_capacity(manifest.len());
        let (mut reask, mut carried) = (BTreeSet::new(), BTreeSet::new());
        for tool in manifest {
            if let Some(draft) = drafted.remove(&tool.name) {
                reask.insert(tool.name.clone());
                rows.push(fresh(draft));
                continue;
            }
            let mut row = prior
                .row(&tool.name)
                .cloned()
                .ok_or_else(|| Error::InvalidConfig("connector slate row missing".into()))?;
            // A carried class change is a narrow; the row names the new class.
            row.draft.data_class = tool.row_data_class();
            carried.insert(tool.name.clone());
            rows.push(row);
        }
        let names: BTreeSet<&str> = manifest.iter().map(|t| t.name.as_str()).collect();
        let dropped = prior
            .tool_names()
            .into_iter()
            .filter(|name| !names.contains(name))
            .map(str::to_owned)
            .collect();
        let slate = new_slate(manifest, rows, Some(&prior), Some(prior_id), reask.clone())?;
        Ok(ConnectorSlateDelta {
            slate_id: self.put_new_slate(slate)?,
            reask,
            carried,
            dropped,
        })
    }

    /// The owner asks the agent to widen or tighten a connector: the drafter
    /// re-runs with his instruction and his past rulings, and proposes the
    /// changed rows. Nothing lands until his one tap stamps them.
    pub fn redraft_connector_slate(
        &self,
        id: EntityId,
        instruction: &str,
        drafter: &ConnectorSlateDrafter<'_>,
    ) -> Result<ConnectorSlateRedraft> {
        if instruction.trim().is_empty() || instruction.len() > 4096 {
            return Err(Error::InvalidConfig(
                "invalid slate re-draft instruction".into(),
            ));
        }
        let (slate, rulings) = {
            let txn = self.store.env.read_txn()?;
            let slate =
                read_slate_in_store_txn(&self.store, &txn, id)?.ok_or(Error::EntityNotFound)?;
            (slate, past_rulings_in_txn(&self.store, &txn)?)
        };
        let mut proposed = BTreeMap::new();
        let mut rationale = BTreeMap::new();
        for row in slate.rows() {
            let Some(tool) = slate.tool(&row.draft.tool) else {
                continue;
            };
            let current = row.stamped_disposition();
            let rule = rule_draft_row(tool, &rulings);
            let drafted = drafter.draft_row(
                "redraft",
                tool,
                &rulings,
                &rule,
                &SlateDisposition::ALL,
                Some(instruction),
                Some(current),
            );
            if drafted.disposition != current {
                proposed.insert(
                    tool.name.clone(),
                    SlateOwnerOverride {
                        disposition: drafted.disposition,
                    },
                );
                rationale.insert(tool.name.clone(), drafted.rationale);
            }
        }
        Ok(ConnectorSlateRedraft {
            slate_id: id,
            expected_revision: slate.revision(),
            proposed,
            rationale,
        })
    }
}
