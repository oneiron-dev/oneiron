//! Typed turn-one self projection shared by the prefix and mid-run describe call.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::skill_reliability::skill_reliability_with_sources;
use crate::{Vault, write_envelope::skill_record::SkillContentHash};
use oneiron_authority::federation::Scope;
use oneiron_model::llm::BudgetRead;

use super::SessionReadSet;
use super::people::{People, PeoplePrefix};
use std::collections::BTreeSet;

/// A class verdict is a dated description, not authorization. Execution rechecks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassVerdict {
    Allow,
    Deny,
    WouldAsk,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ClassLimit {
    pub class: String,
    pub verdict: ClassVerdict,
}

/// Host-resolved communication restrictions. The six-axis scope is a ceiling,
/// not a grant minted by this projection.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CommunicationLimits {
    pub scope: Scope,
    pub recipients: Vec<EntityId>,
    pub max_messages: Option<u64>,
}

/// The head of the line that names each brief field no host produced.
const UNAVAILABLE_HEAD: &str = "unavailable (no producer yet)";

/// Inputs must be the effective, already-authorized run/session reads. In
/// particular, this renderer cannot decide which classes or worlds are visible.
/// A `None` field is one no host produced: the brief leaves it out and names
/// it unavailable. `Some` of an empty list is a known empty list.
pub struct SelfBriefInput<'a> {
    pub self_ref: EntityId,
    pub principal: Option<EntityId>,
    pub cast: Option<&'a [EntityId]>,
    pub grant_revision: Option<u64>,
    pub effective_scope: Option<&'a Scope>,
    pub communication: Option<&'a CommunicationLimits>,
    pub classes: Option<&'a [ClassLimit]>,
    pub budget_lease_id: Option<&'a str>,
    pub budget: Option<&'a BudgetRead>,
    pub clock_ms: u64,
    pub skill_index: &'a [EntityId],
    pub read_set: &'a SessionReadSet,
    pub working_set: Option<&'a [EntityId]>,
    /// The vault's people as the reader's read admits them, when the host
    /// read them; the prefix holds a budgeted roster of them.
    pub people: Option<&'a People>,
    /// The roster's token budget when the agent's board layout gives
    /// `people` a share (BOARD-LAYOUT); `None` keeps
    /// [`super::PEOPLE_PREFIX_BUDGET_TOK`].
    pub people_budget_tok: Option<usize>,
}

/// A skill index row is resolved from the skill record and reliability claim;
/// the mutable confidence cache is never an authority for this number.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct BriefSkillRow {
    pub id: EntityId,
    pub hash: Option<String>,
    pub reliability: f32,
    pub loaded_hash: Option<String>,
}

/// A field no host produced is `None`: identity leaves it out, and the
/// rendered brief names it on its one unavailable line.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SelfBrief {
    pub self_ref: EntityId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<EntityId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cast: Option<Vec<EntityId>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_scope: Option<Scope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub communication: Option<CommunicationLimits>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classes: Option<Vec<ClassLimit>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_lease_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget: Option<BudgetRead>,
    pub clock_ms: u64,
    pub skills: Vec<BriefSkillRow>,
    #[serde(skip)]
    skill_sources: Vec<EntityId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_set: Option<Vec<EntityId>>,
    /// PEOPLE (ARCH-0067): the vault's `people` roster, chosen at this
    /// epoch boundary. Rendered as its own block, never inside identity.
    #[serde(skip)]
    pub people: Option<PeoplePrefix>,
}

impl SelfBrief {
    /// Read reliability for the skill index at assembly time. Missing records
    /// and malformed claims fail closed instead of inventing a reliability.
    pub fn describe(vault: &Vault, input: SelfBriefInput<'_>) -> Result<Self> {
        let mut skills = Vec::with_capacity(input.skill_index.len());
        let mut skill_sources = Vec::new();
        for id in input.skill_index {
            let record = vault
                .get_skill_record(id)?
                .ok_or(crate::Error::EntityNotFound)?;
            let (posterior, sources) = skill_reliability_with_sources(vault, id)?;
            skill_sources.extend(sources);
            let hash = record.content_hash.map(|h: SkillContentHash| h.to_hex());
            let loaded_hash = input
                .read_set
                .loaded_skills()
                .any(|(loaded_id, version)| loaded_id == id.to_hex() && version == record.version)
                .then(|| hash.clone())
                .flatten();
            skills.push(BriefSkillRow {
                id: *id,
                hash,
                reliability: posterior.mean(),
                loaded_hash,
            });
        }
        // Self, principal and cast are pinned residents; the rest of the
        // roster fills the prefix budget in handle order.
        let people = input.people.map(|people| {
            people.residence_within(
                &pinned_people(input.self_ref, input.principal, input.cast),
                input
                    .people_budget_tok
                    .unwrap_or(super::PEOPLE_PREFIX_BUDGET_TOK),
            )
        });
        Ok(Self {
            self_ref: input.self_ref,
            principal: input.principal,
            cast: input.cast.map(<[EntityId]>::to_vec),
            grant_revision: input.grant_revision,
            effective_scope: input.effective_scope.cloned(),
            communication: input.communication.cloned(),
            classes: input.classes.map(<[ClassLimit]>::to_vec),
            budget_lease_id: input.budget_lease_id.map(str::to_owned),
            budget: input.budget.cloned(),
            clock_ms: input.clock_ms,
            skills,
            skill_sources,
            working_set: input.working_set.map(<[EntityId]>::to_vec),
            people,
        })
    }

    /// The name the unavailable line gives each field no host produced, in
    /// the line's order.
    fn unavailable(&self) -> Vec<&'static str> {
        [
            (self.grant_revision.is_none(), "grant_revision"),
            (self.cast.is_none(), "cast"),
            (self.communication.is_none(), "communication limits"),
            (self.classes.is_none(), "class verdicts"),
            (self.working_set.is_none(), "working set"),
            (self.effective_scope.is_none(), "effective scope"),
            (self.principal.is_none(), "principal"),
            (self.budget_lease_id.is_none(), "budget lease"),
            (self.budget.is_none(), "budget"),
        ]
        .into_iter()
        .filter_map(|(missing, name)| missing.then_some(name))
        .collect()
    }

    /// Single renderer used at session open, keyframe rebuild and describe(self).
    /// Identity leaves out each field no host produced, and one line after
    /// the sections names them all, so no placeholder reads as a fact.
    #[must_use]
    pub fn render(&self) -> String {
        // All text comes from typed fields and JSON escaping; never parse this
        // rendered text back into authority or state.
        let mut identity = serde_json::to_value(self).expect("typed self brief JSON");
        let skills = identity
            .as_object_mut()
            .expect("self brief is a struct")
            .remove("skills")
            .expect("self brief always carries skill index rows");
        // JSON escapes quotes, but not XML delimiters. Encode those as JSON
        // unicode escapes so a class or label cannot close either block.
        let safe = |value: &serde_json::Value| {
            value
                .to_string()
                .replace('&', "\\u0026")
                .replace('<', "\\u003c")
                .replace('>', "\\u003e")
        };
        let mut out = format!(
            "<skills>{}</skills>\n<identity>{}</identity>",
            safe(&skills),
            safe(&identity)
        );
        if let Some(people) = &self.people {
            out.push('\n');
            out.push_str(&people.render());
        }
        let unavailable = self.unavailable();
        if !unavailable.is_empty() {
            out.push_str(&format!("\n{UNAVAILABLE_HEAD}: {}", unavailable.join(", ")));
        }
        out
    }

    /// The persons this brief's `people` roster holds.
    #[must_use]
    pub fn resident_people(&self) -> BTreeSet<EntityId> {
        self.people
            .as_ref()
            .map(|people| people.resident.clone())
            .unwrap_or_default()
    }

    /// The rows this brief is derived from, as a host lists them beside its
    /// rendered text (DEC-0005): the self; the principal and cast it pins and
    /// each recipient and working-set row it names, when a host produced
    /// them; each indexed skill with the rows its reliability stands on; and
    /// every person on `people`, the
    /// roster it was described with, shown or counted, with each actor that
    /// speaks as one and the exact contributors of its selected `about` line. The
    /// run's host-held scope, classes, budget and clock are no rows.
    ///
    /// # Errors
    ///
    /// A read failure.
    pub fn sources(&self, _vault: &Vault, people: Option<&People>) -> Result<Vec<EntityId>> {
        let mut rows = vec![self.self_ref];
        rows.extend(self.principal);
        rows.extend(self.cast.iter().flatten().copied());
        rows.extend(
            self.communication
                .iter()
                .flat_map(|communication| communication.recipients.iter().copied()),
        );
        rows.extend(self.working_set.iter().flatten().copied());
        rows.extend(self.skills.iter().map(|skill| skill.id));
        rows.extend(self.skill_sources.iter().copied());
        if let Some(people) = people {
            for person in people.rows() {
                rows.push(person.person);
                rows.extend(person.actors.iter().copied());
                if person.about.is_some() {
                    rows.extend_from_slice(people.about_sources(person.person));
                }
            }
        }
        rows.sort_unstable_by_key(|id| *id.as_bytes());
        rows.dedup();
        Ok(rows)
    }
}

/// The cached prefix is replaced only at turn one or an epoch fold. A mid-run
/// call returns an append-only tail update without touching the prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BriefPlacement {
    TurnOne,
    Fold,
    MidRun,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PlacedSelfBrief {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tail: Option<String>,
}

impl PlacedSelfBrief {
    #[must_use]
    pub fn assemble(brief: &SelfBrief, placement: BriefPlacement) -> Self {
        let text = brief.render();
        match placement {
            BriefPlacement::TurnOne | BriefPlacement::Fold => Self {
                prefix: Some(text),
                tail: None,
            },
            BriefPlacement::MidRun => Self {
                prefix: None,
                tail: Some(text),
            },
        }
    }
}

/// Host-owned run snapshot. Only the host that resolved the grant and budget
/// can create this state; an HTTP request never supplies any authority fields.
/// A field the host did not produce is `None`, never a placeholder value;
/// `Some` of an empty list is a known empty list.
#[derive(Debug, Clone)]
pub struct SelfBriefState {
    pub self_ref: EntityId,
    pub principal: Option<EntityId>,
    pub cast: Option<Vec<EntityId>>,
    pub grant_revision: Option<u64>,
    pub effective_scope: Option<Scope>,
    pub communication: Option<CommunicationLimits>,
    pub classes: Option<Vec<ClassLimit>>,
    pub budget_lease_id: Option<String>,
    pub budget: Option<BudgetRead>,
    pub clock_ms: u64,
    pub skill_index: Vec<EntityId>,
    pub working_set: Option<Vec<EntityId>>,
}

/// The persons a brief pins resident on its `people` roster, in pin order:
/// the self, then the principal and cast when a host produced them.
fn pinned_people(
    self_ref: EntityId,
    principal: Option<EntityId>,
    cast: Option<&[EntityId]>,
) -> Vec<EntityId> {
    let mut pinned = vec![self_ref];
    pinned.extend(principal);
    pinned.extend(cast.into_iter().flatten().copied());
    pinned
}

impl SelfBriefState {
    /// The persons this state's brief pins resident on its `people` roster
    /// ([`SelfBrief::describe`]), for a host that lays out the roster before
    /// the brief's prefix emits.
    #[must_use]
    pub fn pinned_people(&self) -> Vec<EntityId> {
        pinned_people(self.self_ref, self.principal, self.cast.as_deref())
    }

    /// Resolve skill records and claims afresh for each render, against the
    /// session's read set rather than a previously rendered prompt.
    pub fn describe(
        &self,
        vault: &Vault,
        read_set: &SessionReadSet,
        people: Option<&People>,
    ) -> Result<SelfBrief> {
        self.describe_within(vault, read_set, people, None)
    }

    /// [`Self::describe`] with the prefix roster's token budget, when the
    /// agent's layout gives `people` a share.
    pub fn describe_within(
        &self,
        vault: &Vault,
        read_set: &SessionReadSet,
        people: Option<&People>,
        people_budget_tok: Option<usize>,
    ) -> Result<SelfBrief> {
        SelfBrief::describe(
            vault,
            SelfBriefInput {
                self_ref: self.self_ref,
                principal: self.principal,
                cast: self.cast.as_deref(),
                grant_revision: self.grant_revision,
                effective_scope: self.effective_scope.as_ref(),
                communication: self.communication.as_ref(),
                classes: self.classes.as_deref(),
                budget_lease_id: self.budget_lease_id.as_deref(),
                budget: self.budget.as_ref(),
                clock_ms: self.clock_ms,
                skill_index: &self.skill_index,
                read_set,
                working_set: self.working_set.as_deref(),
                people,
                people_budget_tok,
            },
        )
    }
}

/// Per-run prefix custody. `describe_self` appends to the tail, leaving the
/// cached bytes untouched until `fold` deliberately replaces the prefix.
#[derive(Debug, Clone, Default)]
pub struct SelfBriefSession {
    cached_prefix: Option<String>,
    /// The persons the cached prefix's `people` roster holds; the live board
    /// names them by bare handle.
    resident_people: BTreeSet<EntityId>,
    /// The prefix roster's token budget the next epoch boundary lays out
    /// (BOARD-LAYOUT): a layout change reaches the cached prefix only at
    /// turn one or a fold, never in between.
    people_budget_tok: Option<usize>,
}

impl SelfBriefSession {
    /// Sets the prefix roster's token budget the next turn one or fold
    /// renders under: the `people` share of the agent's board layout, or
    /// `None` for [`super::PEOPLE_PREFIX_BUDGET_TOK`].
    pub fn set_people_budget_tok(&mut self, budget_tok: Option<usize>) {
        self.people_budget_tok = budget_tok;
    }

    pub fn turn_one(
        &mut self,
        vault: &Vault,
        state: &SelfBriefState,
        read_set: &SessionReadSet,
        people: Option<&People>,
    ) -> Result<PlacedSelfBrief> {
        let brief = state.describe_within(vault, read_set, people, self.people_budget_tok)?;
        self.resident_people = brief.resident_people();
        self.cached_prefix = Some(brief.render());
        Ok(PlacedSelfBrief {
            prefix: self.cached_prefix.clone(),
            tail: None,
        })
    }

    pub fn fold(
        &mut self,
        vault: &Vault,
        state: &SelfBriefState,
        read_set: &SessionReadSet,
        people: Option<&People>,
    ) -> Result<PlacedSelfBrief> {
        if self.cached_prefix.is_none() {
            return Err(crate::Error::InvariantViolation(
                "self brief fold before turn one",
            ));
        }
        let brief = state.describe_within(vault, read_set, people, self.people_budget_tok)?;
        self.resident_people = brief.resident_people();
        self.cached_prefix = Some(brief.render());
        Ok(PlacedSelfBrief {
            prefix: self.cached_prefix.clone(),
            tail: None,
        })
    }

    pub fn describe_self(
        &self,
        vault: &Vault,
        state: &SelfBriefState,
        read_set: &SessionReadSet,
        people: Option<&People>,
    ) -> Result<PlacedSelfBrief> {
        if self.cached_prefix.is_none() {
            return Err(crate::Error::InvariantViolation(
                "self brief describe before turn one",
            ));
        }
        Ok(PlacedSelfBrief {
            prefix: None,
            tail: Some(state.describe(vault, read_set, people)?.render()),
        })
    }

    /// [`Self::describe_self`], beside the rows its tail is derived from
    /// ([`SelfBrief::sources`]).
    ///
    /// # Errors
    ///
    /// As [`Self::describe_self`].
    pub fn describe_self_listing(
        &self,
        vault: &Vault,
        state: &SelfBriefState,
        read_set: &SessionReadSet,
        people: Option<&People>,
    ) -> Result<(PlacedSelfBrief, Vec<EntityId>)> {
        if self.cached_prefix.is_none() {
            return Err(crate::Error::InvariantViolation(
                "self brief describe before turn one",
            ));
        }
        let brief = state.describe(vault, read_set, people)?;
        let sources = brief.sources(vault, people)?;
        Ok((
            PlacedSelfBrief {
                prefix: None,
                tail: Some(brief.render()),
            },
            sources,
        ))
    }

    #[must_use]
    pub fn cached_prefix(&self) -> Option<&str> {
        self.cached_prefix.as_deref()
    }

    /// The persons the cached prefix's roster holds.
    #[must_use]
    pub fn resident_people(&self) -> &BTreeSet<EntityId> {
        &self.resident_people
    }
}
