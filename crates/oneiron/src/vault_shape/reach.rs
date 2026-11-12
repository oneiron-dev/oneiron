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
use std::collections::BTreeMap;

/// The verb class an outbound send is consented under, as the send door
/// composes it (`gate::effect::external_effect_action_requirement`).
const SEND_VERB: &str = "send";

/// The channel a connector tool's path names: the credential it rides is the
/// connector key.
const CONNECTOR_CHANNEL: &str = "connector";

#[doc(hidden)]
use oneiron_verb_wire::vault_shape::reach::label;
#[doc(hidden)]
pub use oneiron_verb_wire::vault_shape::reach::{
    REACH_LINE_MAX_CHANGES, REACH_LINE_NO_CHANGE, REACH_LINE_NONE, ShapePlanReach, ShapeReach,
    ShapeReachFact, ShapeReachVerdict,
};

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
