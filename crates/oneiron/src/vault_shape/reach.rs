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
//! send, matched against the standing grants by the same containment. A
//! connector key's outward tool is a path too, under the setting its slate
//! gives the tool. One fact per path, never a cross product of independent
//! lists. A data class joins a path only through a standing disclosure grant
//! naming who may hear it, and only on a path that runs without asking. A
//! standing outbound grant moves its actor's verdicts, and a scoped MCP,
//! contact, or brief grant is a path of its own (see
//! [`super::outbound_reach`]).
use super::outbound_reach::{
    ReachOutbound, contact_brief_paths, outbound_after_plan, outbound_covers, scoped_mcp_paths,
};
use super::plan::{ShapeChange, ShapePlanItem};
use super::{ShapeRow, ShapeTarget};
use crate::connector_key::SlateDisposition;
use crate::consent::{
    ActionClass, ActionEnvelope, ActorBound, BoundClass, BoundEnvelope, BoundSubject, GrantBound,
};
use crate::error::Result;
use crate::reaction::person_name_in;
use crate::{EntityId, Vault};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The verb class an outbound send is consented under, as the send door
/// composes it (`gate::effect::external_effect_action_requirement`).
const SEND_VERB: &str = "send";

/// The channel a connector tool's path names: the credential it rides is the
/// connector key.
const CONNECTOR_CHANNEL: &str = "connector";

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
fn label(reference: &str) -> String {
    if EntityId::from_hex(reference).is_ok() {
        reference.chars().take(8).collect()
    } else {
        reference.to_owned()
    }
}

impl Vault {
    /// The stored name of the entity `reference` names, when it is an
    /// entity id and its body carries one.
    pub(super) fn reach_name_in(
        &self,
        txn: &heed::RoTxn<'_>,
        reference: &str,
    ) -> Result<Option<String>> {
        match EntityId::from_hex(reference) {
            Ok(id) => person_name_in(self, txn, id),
            Err(_) => Ok(None),
        }
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

    /// The facts with a name on each audience member and on each actor the
    /// roster leaves unnamed, where `name` finds one; a line reads a short
    /// id otherwise. Runs after [`Self::visible`], so a hidden path's names
    /// are never read.
    ///
    /// # Errors
    ///
    /// `name`'s own.
    pub(super) fn named(
        mut self,
        name: &mut dyn FnMut(&str) -> Result<Option<String>>,
    ) -> Result<Self> {
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

/// One outward tool of an active connector key, as the reach reads it.
#[derive(Debug, Clone)]
pub(super) struct ReachConnector {
    pub(super) key: EntityId,
    pub(super) connector: String,
    /// The actor the key is bound to; none is any actor on the connector.
    pub(super) actor: Option<EntityId>,
    /// For a key bound to no actor: the actors a key of their own on the
    /// same connector governs instead.
    pub(super) except: Vec<EntityId>,
    pub(super) tool: String,
    /// What a call on the tool meets under the key's slate.
    pub(super) setting: SlateDisposition,
    /// The key's manifest holds the tool for confirmation: every call asks.
    pub(super) held: bool,
}

/// The typed rows the reach joins, read on one snapshot. No secret value is
/// ever among them; a connector key names its custody record, never reads
/// it.
#[derive(Debug, Clone, Default)]
pub(super) struct ReachRows {
    pub(super) actors: Vec<ReachActor>,
    /// Every active standing grant's bound.
    pub(super) grants: Vec<GrantBound>,
    pub(super) senders: Vec<ReachSender>,
    pub(super) connectors: Vec<ReachConnector>,
    /// Every standing outbound grant that counts now (FIX 2801).
    pub(super) outbound: Vec<ReachOutbound>,
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
        hasher.update(b"\0");
        for tool in &self.connectors {
            hasher.update(tool.key.as_bytes());
            hasher.update(&[u8::from(tool.actor.is_some())]);
            if let Some(actor) = tool.actor {
                hasher.update(actor.as_bytes());
            }
            hasher.update(&(tool.except.len() as u64).to_be_bytes());
            for actor in &tool.except {
                hasher.update(actor.as_bytes());
            }
            for text in [&tool.connector, &tool.tool] {
                hasher.update(&(text.len() as u64).to_be_bytes());
                hasher.update(text.as_bytes());
            }
            hasher.update(tool.setting.as_str().as_bytes());
            hasher.update(&[u8::from(tool.held)]);
        }
        hasher.update(b"\0");
        for grant in &self.outbound {
            hasher.update(grant.grant.as_bytes());
            hasher.update(&grant.digest);
        }
    }

    /// These rows with every plan item in place, as though each landed. An
    /// item the rows cannot carry is named in `unresolved`, never guessed.
    /// `sends` is whether each sender may send once the plan's manifest
    /// changes are in place, read under the projected policy.
    pub(super) fn with_plan(
        &self,
        items: &[ShapePlanItem],
        sends: Option<&BTreeMap<EntityId, bool>>,
        unresolved: &mut Vec<String>,
    ) -> Self {
        let mut rows = self.clone();
        outbound_after_plan(&mut rows.outbound, items);
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
                // A new enabled actor is served by every connector key bound
                // to no actor, and the rows cannot name it until its entity
                // exists: its reach is unresolved, never "No change"; its
                // creation is not refused (FIX 10201).
                (
                    ShapeTarget::Actor { agent_id },
                    ShapeChange::Create,
                    Some(ShapeRow::Actor { enabled: true, .. }),
                ) if rows.connectors.iter().any(|tool| tool.actor.is_none()) => {
                    unresolved.push(format!(
                        "actor {agent_id}: what a connector key bound to no actor lets it send is \
                         not projected until it exists"
                    ));
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
                (ShapeTarget::Manifest { manifest_ref }, _, _) => match sends {
                    Some(sends) => {
                        for sender in &mut rows.senders {
                            if let Some(may_send) = sends.get(&sender.entity) {
                                sender.may_send = *may_send;
                            }
                        }
                    }
                    None => unresolved.push(format!(
                        "manifest {}: the plan's manifest changes would not all land, so its send policy is not projected",
                        label(manifest_ref)
                    )),
                },
                // A new actor holds no sending identity yet; a world, mask,
                // member, pack, skill or sync row opens no send path.
                _ => {}
            }
        }
        rows
    }
}

/// The action requirement an effect by `actor_ref` of `verb` on `channel`
/// must be covered by, composed as the gate composes it for an effect that
/// names no brief: actor × verb × `[verb:<verb>]` pinned to the channel. An
/// outbound send is `send` on its channel; a connector call is its tool on
/// its connector.
fn action_requirement(actor_ref: &str, verb: &str, channel: &str) -> Option<GrantBound> {
    let envelope = ActionEnvelope::new([format!("verb:{verb}")])
        .ok()?
        .with_target(channel.trim())
        .ok()?;
    GrantBound::action(
        ActorBound::new(actor_ref).ok()?,
        ActionClass::new(verb).ok()?,
        envelope,
    )
    .ok()
}

/// Whether `grants` holds a brief-pinned send grant for `actor_ref`: an
/// action grant on `send` whose envelope names a brief, covering its own
/// brief's sends.
fn brief_send_covered(grants: &[GrantBound], actor_ref: &str) -> bool {
    grants.iter().any(
        |grant| match (grant.subject(), grant.class(), grant.envelope()) {
            (
                BoundSubject::Actor(actor),
                BoundClass::Action(class),
                BoundEnvelope::Action(envelope),
            ) => {
                actor.actor_ref() == actor_ref
                    && actor.actor_class().is_none()
                    && class.as_str() == SEND_VERB
                    && envelope.target().is_some()
                    && envelope
                        .selectors()
                        .iter()
                        .any(|selector| selector.starts_with("brief:"))
            }
            _ => false,
        },
    )
}

/// `path`, and when it runs without asking, the data classes standing
/// disclosure grants let reach their audiences along it.
fn push_path(
    facts: &mut Vec<ShapeReachFact>,
    disclosures: &[(&str, &[String])],
    path: ShapeReachFact,
) {
    if path.verdict == ShapeReachVerdict::Can {
        for (class, members) in disclosures {
            facts.push(ShapeReachFact {
                class: Some((*class).to_owned()),
                audience: members.to_vec(),
                ..path.clone()
            });
        }
    }
    facts.push(path);
}

/// Every path `rows` hold. A disabled actor is not dispatched, so it holds
/// none; a send the requirement cannot be composed for asks. A brief-pinned
/// send grant covers its own brief's sends. A connector tool the slate
/// never allows is no path; one it always asks for, or one the key's
/// manifest holds, asks; one it always allows runs without asking
/// (a covering grant); and on `auto` the standing grants decide, as they do
/// for a send. A key bound to no actor serves every roster actor that holds
/// no key of its own on the connector.
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
        let covered = action_requirement(&actor_ref, SEND_VERB, &sender.channel)
            .is_some_and(|required| rows.grants.iter().any(|grant| grant.contains(&required)))
            || brief_send_covered(&rows.grants, &actor_ref)
            || outbound_covers(&rows.outbound, &actor_ref, SEND_VERB, &sender.channel);
        let path = ShapeReachFact {
            actor: actor_ref,
            actor_name: actor.map(|actor| actor.agent_id.clone()),
            verb: SEND_VERB.to_owned(),
            channel: sender.channel.clone(),
            sender: sender.address.clone(),
            identity: sender.entity.to_hex(),
            class: None,
            audience: Vec::new(),
            audience_names: Vec::new(),
            verdict: if covered {
                ShapeReachVerdict::Can
            } else {
                ShapeReachVerdict::Asks
            },
        };
        push_path(&mut facts, &disclosures, path);
    }
    for tool in rows
        .connectors
        .iter()
        .filter(|tool| tool.setting != SlateDisposition::NeverAllow)
    {
        let holders: Vec<(EntityId, Option<&ReachActor>)> = match tool.actor {
            Some(bound) => {
                let actor = rows.actors.iter().find(|actor| actor.entity == bound);
                if actor.is_some_and(|actor| !actor.enabled) {
                    continue;
                }
                vec![(bound, actor)]
            }
            None => rows
                .actors
                .iter()
                .filter(|actor| actor.enabled && !tool.except.contains(&actor.entity))
                .map(|actor| (actor.entity, Some(actor)))
                .collect(),
        };
        for (holder, actor) in holders {
            let actor_ref = holder.to_hex();
            let covered = !tool.held
                && match tool.setting {
                    SlateDisposition::AlwaysAllow => true,
                    SlateDisposition::Auto => {
                        action_requirement(&actor_ref, &tool.tool, &tool.connector).is_some_and(
                            |required| rows.grants.iter().any(|grant| grant.contains(&required)),
                        )
                    }
                    SlateDisposition::AlwaysAsk | SlateDisposition::NeverAllow => false,
                };
            let path = ShapeReachFact {
                actor: actor_ref,
                actor_name: actor.map(|actor| actor.agent_id.clone()),
                verb: tool.tool.clone(),
                channel: CONNECTOR_CHANNEL.to_owned(),
                sender: tool.connector.clone(),
                identity: tool.key.to_hex(),
                class: None,
                audience: Vec::new(),
                audience_names: Vec::new(),
                verdict: if covered {
                    ShapeReachVerdict::Can
                } else {
                    ShapeReachVerdict::Asks
                },
            };
            push_path(&mut facts, &disclosures, path);
        }
    }
    for path in scoped_mcp_paths(&rows.outbound, &rows.actors) {
        push_path(&mut facts, &disclosures, path);
    }
    for path in contact_brief_paths(&rows.outbound, &rows.actors) {
        push_path(&mut facts, &disclosures, path);
    }
    facts.sort();
    facts.dedup();
    ShapeReach { facts }
}
