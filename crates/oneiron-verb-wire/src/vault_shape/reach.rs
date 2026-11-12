//! Moved from `crates/oneiron/src/vault_shape/reach.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::connector_key::slate::SlateDisposition;
use crate::vault_shape::plan::ShapeChange;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::consent_bound::ActionClass;
use oneiron_store::consent_bound::ActionEnvelope;
use oneiron_store::consent_bound::ActorBound;
use oneiron_store::consent_bound::BoundClass;
use oneiron_store::consent_bound::BoundEnvelope;
use oneiron_store::consent_bound::BoundSubject;
use oneiron_store::consent_bound::GrantBound;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// Most changes one reach line names before it counts the rest.
pub const REACH_LINE_MAX_CHANGES: usize = 3;

/// The line when a change moves no path.
pub const REACH_LINE_NO_CHANGE: &str = "No change to what these actors can send.";

/// The line when no actor holds a path.
pub const REACH_LINE_NONE: &str = "No actor can send.";

/// Whether a path's sends run on their own.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ShapeReachVerdict {
    /// A standing grant covers the send: it runs without asking.
    Can,
    /// No standing grant covers it: each send asks the owner in the moment.
    Asks,
}

/// One path: an actor, through a sending identity it holds, under one
/// verdict; with a data class and the audience a standing disclosure grant
/// lets hear it, when one does.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub struct ShapeReachFact {
    /// The acting actor, by entity id hex.
    pub actor: String,
    /// The actor's roster name (its agent id), when it is on the roster;
    /// else its stored name, when the line was named and it has one.
    #[serde(default)]
    pub actor_name: Option<String>,
    /// The verb class the path carries: `send`, or a connector's tool.
    pub verb: String,
    /// The channel class, e.g. `email`, or `connector`.
    pub channel: String,
    /// The sending identity's address or handle, or the connector's name:
    /// the credential the path rides.
    pub sender: String,
    /// The sending identity or the connector key, by entity id hex.
    pub identity: String,
    /// A data class a standing disclosure grant lets reach `audience`, e.g.
    /// `health`; none on the path's own fact.
    #[serde(default)]
    pub class: Option<String>,
    /// Who may hear `class`, as the disclosure grant names them.
    #[serde(default)]
    pub audience: Vec<String>,
    /// `audience` as the line reads it, member by member: a stored name, or
    /// a short id. Empty until the line is named.
    #[serde(default)]
    pub audience_names: Vec<String>,
    pub verdict: ShapeReachVerdict,
}

impl ShapeReachFact {
    /// The path without its verdict: two facts on one key are the same path.
    fn key(&self) -> (&str, &str, &str, &str, Option<&str>, &[String]) {
        (
            &self.actor,
            &self.verb,
            &self.channel,
            &self.identity,
            self.class.as_deref(),
            &self.audience,
        )
    }

    fn who(&self) -> String {
        self.actor_name
            .clone()
            .unwrap_or_else(|| format!("actor {}", label(&self.actor)))
    }

    fn audience(&self) -> String {
        if self.audience_names.len() == self.audience.len() {
            return self.audience_names.join(", ");
        }
        self.audience
            .iter()
            .map(|member| label(member))
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn through(&self) -> String {
        format!("through {} {}", self.channel, self.sender)
    }

    /// The path as it stands.
    fn phrase(&self) -> String {
        match (&self.class, self.verdict) {
            (Some(class), _) => format!(
                "{} can {} {class} to {} {}",
                self.who(),
                self.verb,
                self.audience(),
                self.through()
            ),
            (None, ShapeReachVerdict::Can) => {
                format!(
                    "{} can {} {} without asking",
                    self.who(),
                    self.verb,
                    self.through()
                )
            }
            (None, ShapeReachVerdict::Asks) => {
                format!(
                    "{} asks before each {} {}",
                    self.who(),
                    self.verb,
                    self.through()
                )
            }
        }
    }

    /// The path gone.
    fn lost_phrase(&self) -> String {
        match &self.class {
            Some(class) => format!(
                "{} can no longer {} {class} to {} {}",
                self.who(),
                self.verb,
                self.audience(),
                self.through()
            ),
            None => format!(
                "{} can no longer {} {}",
                self.who(),
                self.verb,
                self.through()
            ),
        }
    }
}

/// An entity id hex shortened for a line; any other reference as written.
pub fn label(reference: &str) -> String {
    if EntityId::from_hex(reference).is_ok() {
        reference.chars().take(8).collect()
    } else {
        reference.to_owned()
    }
}

/// Every path at one snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShapeReach {
    /// Sorted, one fact per path.
    pub facts: Vec<ShapeReachFact>,
}

impl ShapeReach {
    /// The facts whose actor, identity and audience members `visible`
    /// admits. The join runs over every row first, so a hidden row never
    /// changes what a visible path is; the hidden paths are left out here,
    /// at the presentation boundary.
    ///
    /// # Errors
    ///
    /// `visible`'s own.
    pub fn visible(mut self, visible: &mut dyn FnMut(&EntityId) -> Result<bool>) -> Result<Self> {
        let mut kept = Vec::with_capacity(self.facts.len());
        for fact in self.facts {
            let mut admitted = true;
            for reference in [&fact.actor, &fact.identity]
                .into_iter()
                .chain(&fact.audience)
            {
                if let Ok(id) = EntityId::from_hex(reference)
                    && !visible(&id)?
                {
                    admitted = false;
                    break;
                }
            }
            if admitted {
                kept.push(fact);
            }
        }
        self.facts = kept;
        Ok(self)
    }

    /// The facts with a name on each audience member and on each actor the
    /// roster leaves unnamed, where `name` finds one; a line reads a short
    /// id otherwise. Runs after [`Self::visible`], so a hidden path's names
    /// are never read.
    ///
    /// # Errors
    ///
    /// `name`'s own.
    pub fn named(mut self, name: &mut dyn FnMut(&str) -> Result<Option<String>>) -> Result<Self> {
        for fact in &mut self.facts {
            if fact.actor_name.is_none() {
                fact.actor_name = name(&fact.actor)?;
            }
            fact.audience_names = fact
                .audience
                .iter()
                .map(|member| -> Result<String> {
                    Ok(name(member)?.unwrap_or_else(|| label(member)))
                })
                .collect::<Result<_>>()?;
        }
        Ok(self)
    }

    /// The reach as it stands, in one line.
    #[must_use]
    pub fn line(&self) -> String {
        if self.facts.is_empty() {
            return REACH_LINE_NONE.to_owned();
        }
        sentence(self.facts.iter().map(ShapeReachFact::phrase).collect())
    }
}

/// Phrases joined into one sentence, capped at [`REACH_LINE_MAX_CHANGES`].
pub fn sentence(mut phrases: Vec<String>) -> String {
    let rest = phrases.len().saturating_sub(REACH_LINE_MAX_CHANGES);
    phrases.truncate(REACH_LINE_MAX_CHANGES);
    let mut line = phrases.join("; ");
    if rest > 0 {
        line.push_str(&format!("; and {rest} more"));
    }
    if let Some(first) = line.get(..1) {
        line = first.to_uppercase() + &line[1..];
    }
    line.push('.');
    line
}

/// A plan's reach line: what its actors can send before it and after it,
/// and the one line the plan card shows.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShapePlanReach {
    pub before: ShapeReach,
    /// The whole set recomputed with the plan's items in place, as though
    /// every one landed.
    pub after: ShapeReach,
    /// The plan's items the projection cannot see through, one line each.
    /// None is ever counted as a path.
    pub unresolved: Vec<String>,
    pub line: String,
}

impl ShapePlanReach {
    /// The line for `before` against `after`: each gained path, then each
    /// lost one; a path whose verdict moves reads as its new verdict.
    pub fn of(before: ShapeReach, after: ShapeReach, unresolved: Vec<String>) -> Self {
        let mut phrases: Vec<String> = after
            .facts
            .iter()
            .filter(|fact| !before.facts.contains(fact))
            .map(|fact| format!("after this, {}", fact.phrase()))
            .collect();
        phrases.extend(
            before
                .facts
                .iter()
                .filter(|fact| after.facts.iter().all(|now| now.key() != fact.key()))
                .map(|fact| format!("after this, {}", fact.lost_phrase())),
        );
        // An item the projection cannot see through may move a path, so a
        // plan with one never reads as "No change" (FIX 10201).
        let mut line = match (phrases.is_empty(), unresolved.is_empty()) {
            (true, true) => REACH_LINE_NO_CHANGE.to_owned(),
            (true, false) => String::new(),
            (false, _) => sentence(phrases),
        };
        if !unresolved.is_empty() {
            let projected = format!("Not projected: {} item(s).", unresolved.len());
            line = if line.is_empty() {
                projected
            } else {
                format!("{line} {projected}")
            };
        }
        Self {
            before,
            after,
            unresolved,
            line,
        }
    }
}
