//! The reach line (ARCH-0070 `shape:reach-line`, OSH p3): what each actor
//! can send, read as a set join over typed rows. Each actor can already see
//! its own scope; the owner sees here what a change reaches, before and
//! after. The projection is pure and runs over the whole set every time,
//! never by deltas, because a series of valid edits can reach a state no
//! single edit would admit. It informs the owner's one tap: it never blocks
//! and never decides whether auto mode runs.
//!
//! A path is an actor, a sending identity it holds, and the verdict the send
//! door would reach: the same requirement the gate composes for an outbound
//! send, matched against the standing grants by the same containment. One
//! fact per path, never a cross product of independent lists. A data class
//! joins a path only through a standing disclosure grant naming who may hear
//! it, and only on a path that runs without asking.
use super::plan::{ShapeChange, ShapePlanItem};
use super::{ShapeRow, ShapeTarget};
use crate::EntityId;
use crate::consent::{
    ActionClass, ActionEnvelope, ActorBound, BoundClass, BoundSubject, GrantBound,
};
use crate::error::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The verb class an outbound send is consented under, as the send door
/// composes it (`gate::effect::external_effect_action_requirement`).
const SEND_VERB: &str = "send";

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
    /// The actor's roster name (its agent id), when it is on the roster.
    #[serde(default)]
    pub actor_name: Option<String>,
    /// The verb class the path carries.
    pub verb: String,
    /// The channel class, e.g. `email`.
    pub channel: String,
    /// The sending identity's address or handle: the credential the path
    /// rides.
    pub sender: String,
    /// The sending identity, by entity id hex.
    pub identity: String,
    /// A data class a standing disclosure grant lets reach `audience`, e.g.
    /// `health`; none on the path's own fact.
    #[serde(default)]
    pub class: Option<String>,
    /// Who may hear `class`, as the disclosure grant names them.
    #[serde(default)]
    pub audience: Vec<String>,
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
                audience(&self.audience),
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
                audience(&self.audience),
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
fn label(reference: &str) -> String {
    if EntityId::from_hex(reference).is_ok() {
        reference.chars().take(8).collect()
    } else {
        reference.to_owned()
    }
}

fn audience(members: &[String]) -> String {
    members
        .iter()
        .map(|member| label(member))
        .collect::<Vec<_>>()
        .join(", ")
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
    pub(super) fn visible(
        mut self,
        visible: &mut dyn FnMut(&EntityId) -> Result<bool>,
    ) -> Result<Self> {
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
fn sentence(mut phrases: Vec<String>) -> String {
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
    pub(super) fn of(before: ShapeReach, after: ShapeReach, unresolved: Vec<String>) -> Self {
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
        let mut line = if phrases.is_empty() {
            REACH_LINE_NO_CHANGE.to_owned()
        } else {
            sentence(phrases)
        };
        if !unresolved.is_empty() {
            line.push_str(&format!(" Not projected: {} item(s).", unresolved.len()));
        }
        Self {
            before,
            after,
            unresolved,
            line,
        }
    }
}

/// One roster actor as the reach reads it.
#[derive(Debug, Clone)]
pub(super) struct ReachActor {
    pub(super) entity: EntityId,
    pub(super) agent_id: String,
    pub(super) enabled: bool,
}

/// One sending identity an actor holds, as the reach reads it.
#[derive(Debug, Clone)]
pub(super) struct ReachSender {
    pub(super) entity: EntityId,
    /// The actor its binding head names.
    pub(super) actor: EntityId,
    pub(super) channel: String,
    pub(super) address: String,
    /// Active, and its send permitted by the manifest's act policy now.
    pub(super) may_send: bool,
}

/// The typed rows the reach joins, read on one snapshot. No secret value is
/// ever among them.
#[derive(Debug, Clone, Default)]
pub(super) struct ReachRows {
    pub(super) actors: Vec<ReachActor>,
    /// Every active standing grant's bound.
    pub(super) grants: Vec<GrantBound>,
    pub(super) senders: Vec<ReachSender>,
}

impl ReachRows {
    /// Feeds these rows to a frontier, so a plan pins the reach it showed.
    pub(super) fn hash_into(&self, hasher: &mut blake3::Hasher) {
        hasher.update(b"reach\0");
        for actor in &self.actors {
            hasher.update(actor.entity.as_bytes());
            hasher.update(&(actor.agent_id.len() as u64).to_be_bytes());
            hasher.update(actor.agent_id.as_bytes());
            hasher.update(&[u8::from(actor.enabled)]);
        }
        hasher.update(b"\0");
        for grant in &self.grants {
            hasher.update(grant.digest().as_bytes());
        }
        hasher.update(b"\0");
        for sender in &self.senders {
            hasher.update(sender.entity.as_bytes());
            hasher.update(sender.actor.as_bytes());
            for text in [&sender.channel, &sender.address] {
                hasher.update(&(text.len() as u64).to_be_bytes());
                hasher.update(text.as_bytes());
            }
            hasher.update(&[u8::from(sender.may_send)]);
        }
    }

    /// These rows with every plan item in place, as though each landed. An
    /// item the rows cannot carry is named in `unresolved`, never guessed.
    pub(super) fn with_plan(&self, items: &[ShapePlanItem], unresolved: &mut Vec<String>) -> Self {
        let mut rows = self.clone();
        for item in items {
            match (&item.target, item.change, item.after.as_ref()) {
                (
                    ShapeTarget::Grant { grant_ref },
                    ShapeChange::Create,
                    Some(ShapeRow::Grant { bound, .. }),
                ) => match bound.as_ref().map(super::ShapeGrantBound::bound) {
                    Some(Ok(bound)) => {
                        if !rows.grants.contains(&bound) {
                            rows.grants.push(bound);
                        }
                    }
                    _ => {
                        unresolved.push(format!("grant {}: no bound to project", label(grant_ref)))
                    }
                },
                (ShapeTarget::Grant { grant_ref }, ShapeChange::Retire, _) => {
                    rows.grants
                        .retain(|bound| bound.digest().to_hex() != *grant_ref);
                }
                (
                    ShapeTarget::Actor { agent_id },
                    ShapeChange::Update,
                    Some(ShapeRow::Actor { enabled, .. }),
                ) => {
                    for actor in rows
                        .actors
                        .iter_mut()
                        .filter(|actor| actor.agent_id == *agent_id)
                    {
                        actor.enabled = *enabled;
                    }
                }
                // Retiring an actor takes it off duty.
                (ShapeTarget::Actor { agent_id }, ShapeChange::Retire, _) => {
                    for actor in rows
                        .actors
                        .iter_mut()
                        .filter(|actor| actor.agent_id == *agent_id)
                    {
                        actor.enabled = false;
                    }
                }
                (ShapeTarget::Channel { channel, address }, ShapeChange::Retire, _) => {
                    rows.senders
                        .retain(|sender| sender.channel != *channel || sender.address != *address);
                }
                // Apply leaves a new identity waiting on its fulfillment; it
                // sends nothing until then.
                (ShapeTarget::Channel { channel, address }, ShapeChange::Create, _) => unresolved
                    .push(format!(
                        "channel {channel} {address}: sends only once its provision is fulfilled"
                    )),
                (ShapeTarget::Manifest { manifest_ref }, _, _) => unresolved.push(format!(
                    "manifest {}: its send policy is not projected",
                    label(manifest_ref)
                )),
                // A new actor holds no sending identity yet; a world, mask,
                // member, pack, skill or sync row opens no send path.
                _ => {}
            }
        }
        rows
    }
}

/// The action requirement an outbound send by `actor_ref` on `channel` must
/// be covered by, composed as the send door composes it for a send that
/// names no brief: actor × `send` × `[verb:send]` pinned to the channel.
fn send_requirement(actor_ref: &str, channel: &str) -> Option<GrantBound> {
    let envelope = ActionEnvelope::new([format!("verb:{SEND_VERB}")])
        .ok()?
        .with_target(channel.trim())
        .ok()?;
    GrantBound::action(
        ActorBound::new(actor_ref).ok()?,
        ActionClass::new(SEND_VERB).ok()?,
        envelope,
    )
    .ok()
}

/// Every path `rows` hold. A disabled actor is not dispatched, so it holds
/// none; a send the requirement cannot be composed for asks.
pub(super) fn reach_projection(rows: &ReachRows) -> ShapeReach {
    let disclosures: Vec<(&str, &[String])> = rows
        .grants
        .iter()
        .filter_map(|bound| match (bound.subject(), bound.class()) {
            (BoundSubject::Audience(audience), BoundClass::Disclosure(class)) => {
                Some((class.as_str(), audience.members()))
            }
            _ => None,
        })
        .collect();
    let mut facts = Vec::new();
    for sender in rows.senders.iter().filter(|sender| sender.may_send) {
        let actor = rows
            .actors
            .iter()
            .find(|actor| actor.entity == sender.actor);
        if actor.is_some_and(|actor| !actor.enabled) {
            continue;
        }
        let actor_ref = sender.actor.to_hex();
        let covered = send_requirement(&actor_ref, &sender.channel)
            .is_some_and(|required| rows.grants.iter().any(|grant| grant.contains(&required)));
        let path = ShapeReachFact {
            actor: actor_ref,
            actor_name: actor.map(|actor| actor.agent_id.clone()),
            verb: SEND_VERB.to_owned(),
            channel: sender.channel.clone(),
            sender: sender.address.clone(),
            identity: sender.entity.to_hex(),
            class: None,
            audience: Vec::new(),
            verdict: if covered {
                ShapeReachVerdict::Can
            } else {
                ShapeReachVerdict::Asks
            },
        };
        if covered {
            for (class, members) in &disclosures {
                facts.push(ShapeReachFact {
                    class: Some((*class).to_owned()),
                    audience: members.to_vec(),
                    ..path.clone()
                });
            }
        }
        facts.push(path);
    }
    facts.sort();
    facts.dedup();
    ShapeReach { facts }
}
