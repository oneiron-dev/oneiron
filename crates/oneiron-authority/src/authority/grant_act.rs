//! The general grant act (Fable pass 28 R2, Engine SR-E3): one signed main-log entry for every
//! giving or end of a Grant row's standing that no other act carries, and its wire codec.
//!
//! The owner's agent Grant keeps its own act (`AgentGrantAct`, FIX 5628), whose bytes this
//! module never touches. This act carries the rest: a shared vault's member roles, an admin's
//! delegate, a house link, an inquiry edge's re-scope, and a rule's end: a lapse that ends an
//! agent Grant no person took back, or a direct delete or erase of any Grant's row (Engine
//! RULING GRANT-ROW-DELETE-NO-END = A, 16 Nov 05:49: every taking back is a counted end). The install that served the decider (a live machine of the vault, in any
//! role) signs it with its install key, in the writer's own transaction.
//!
//! Two things differ from `AgentGrantActRecord`. The decider may be any PERSON whose own
//! standing lets them give (an admin who adds a member): the act names them in the holder
//! meaning of `by: Owner`, as a vault's training setting names its admin, and the reader, not
//! the fold, judges whether they could give those terms. And a giving carries no term in
//! clear: `terms` is a keyed commitment to the row's whole body under a per-grant key stored in
//! the row ([`grant_terms_commitment`]), because scope values are low-entropy and "a
//! host-readable cloud log line yields nothing either" (ARCH-0043:181). A reader holding the
//! row opens it; once the row is erased, the line names nothing anyone can test a guess
//! against.
//!
//! A giving names a fresh Grant or re-gives one in place (a role change rewrites its row at
//! the same id): the newest giving by ancestry is the Grant's terms. An end is forever. An end
//! no person decided (a lapse, or a row's direct delete) carries no owner act: its decider is
//! the rule, and only an end may be one.
//!
//! One family is no Grant row: an agent definition's switches (pass 28 R2d, Engine RULING
//! AGENT-DEF-OWN-LANE-FIX = B, 16 Nov 02:21). Turning a definition back on or moving its
//! models is the owner's alone, so the owner's door states the switches it writes in an act
//! of this family ([`GrantActChange::State`]), in clear, and every install lands a widening
//! row only within the switches the owner last stated. Turning a definition off is any
//! writer's and takes no act, and an agent definition's line never ends.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_GRANT_ACT: &str = "grant_act";
const GRANT_ACT_KEYS: [&str; 7] = [
    OP_KEY_KIND,
    OP_KEY_ACT,
    "machine",
    "subject",
    "family",
    "change",
    "terms",
];
const CHANGE_GIVE: &str = "give";
const CHANGE_END: &str = "end";
const CHANGE_STATE: &str = "state";
const SWITCH_KEYS: [&str; 7] = [
    "enabled",
    "approval",
    "active",
    "models",
    "compaction_model",
    "model_tier",
    "dreaming_model",
];
/// The most model choices one statement lists: a definition names a handful.
pub const MAX_STATED_MODELS: usize = 64;
/// The longest model id or tier a statement names, in bytes.
pub const MAX_STATED_MODEL_LEN: usize = 256;

/// A grant act's `seen`: zero for both kinds. A giving names the row's whole new terms, and an
/// end always lands, never refused as stale.
pub const GRANT_ACT_SEEN: [u8; 32] = [0; 32];

/// The nonce slot's domain tag of a grant terms commitment: the commitment shares the keyed
/// federation scope digest's construction ([`federation_scope_digest`]) under a key no pact
/// ever holds, and binds the row id beside this tag in the hashed bytes.
const GRANT_TERMS_TAG: [u8; 16] = *b"oneiron/grant/v1";

/// Which family of Grant row an act gives or ends: the reader opens `terms` against the row
/// and judges the decider by that family's own rule.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum GrantFamily {
    /// A shared vault's member role, Owner to Viewer (membership, creation, onboarding).
    SharedMember,
    /// An admin's delegate from their own grant.
    Delegate,
    /// A house seated in its org at a role.
    HouseLink,
    /// A Connect inquiry edge: its owner's mint and every rewrite of its terms in place.
    InquiryEdge,
    /// A Connect guest Grant that is no inquiry edge, given by the vault's owner. It confers
    /// only while one Active operative pact with its peer binds it, too.
    Connect,
    /// An Ask guest Grant, given with its ask: its decider is the live owner whose recorded
    /// consent the guest's disclosure stands on.
    AskGuest,
    /// The owner's agent Grant: its giving is `AgentGrantAct`'s mint and his own end that
    /// act's revoke, so a grant act of this family is a rule's end alone (a lapse, or a direct
    /// delete of its row).
    OwnerAgent,
    /// An agent definition's switches (an AGENT_DEF row, not a Grant row): the owner states
    /// them ([`GrantActChange::State`]); no act of this family gives terms or ends.
    AgentDefinition,
}

impl GrantFamily {
    /// The wire tag.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SharedMember => "shared_member",
            Self::Delegate => "delegate",
            Self::HouseLink => "house_link",
            Self::InquiryEdge => "inquiry_edge",
            Self::Connect => "connect",
            Self::AskGuest => "ask_guest",
            Self::OwnerAgent => "owner_agent",
            Self::AgentDefinition => "agent_definition",
        }
    }

    /// The family a wire tag names; `None` for any other text.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "shared_member" => Self::SharedMember,
            "delegate" => Self::Delegate,
            "house_link" => Self::HouseLink,
            "inquiry_edge" => Self::InquiryEdge,
            "connect" => Self::Connect,
            "ask_guest" => Self::AskGuest,
            "owner_agent" => Self::OwnerAgent,
            "agent_definition" => Self::AgentDefinition,
            _ => return None,
        })
    }
}

/// Who decided a grant act.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantDecider {
    /// A person decided, at the surface the act names. Its kind is `grant_give` or
    /// `grant_end`, as the change is, and its target the row.
    Person(OwnerAct),
    /// Nobody decided: a rule ended the Grant (an OAuth sign-in that lapsed before its client
    /// held a token, FIX 22142; a direct delete or erase of its row; an owed end whose person
    /// was erased). Only an end has this decider.
    Rule,
}

/// What a grant act does to its row's standing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantActChange {
    /// Gives the row the terms `terms` commits to ([`grant_terms_commitment`]), replacing every
    /// giving the act's parents carry.
    Give { terms: [u8; 32] },
    /// Ends the row's standing, for good.
    End,
    /// States an agent definition's switches as its owner set them, replacing every statement
    /// the act's parents carry: the most a row at that definition may widen to. Family
    /// [`GrantFamily::AgentDefinition`] alone.
    State { switches: AgentSwitches },
}

impl GrantActChange {
    /// The owner act kind a person's act of this change carries: a statement of switches
    /// gives authority.
    #[must_use]
    pub fn act_kind(&self) -> OwnerActKind {
        match self {
            Self::Give { .. } | Self::State { .. } => OwnerActKind::GrantGive,
            Self::End => OwnerActKind::GrantEnd,
        }
    }
}

/// An agent definition's approval, least authority first.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum AgentApproval {
    Rejected,
    Proposed,
    Approved,
    Auto,
}

impl AgentApproval {
    /// The wire tag.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rejected => "rejected",
            Self::Proposed => "proposed",
            Self::Approved => "approved",
            Self::Auto => "auto",
        }
    }

    /// The approval a wire tag names; `None` for any other text.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "rejected" => Self::Rejected,
            "proposed" => Self::Proposed,
            "approved" => Self::Approved,
            "auto" => Self::Auto,
            _ => return None,
        })
    }
}

/// The switches that decide whether an agent definition runs and which models read its
/// context: what turning it back on or moving its models changes. Every other field of a
/// definition is any writer's.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct AgentSwitches {
    /// The definition is on.
    pub enabled: bool,
    /// Its approval.
    pub approval: AgentApproval,
    /// Its lifecycle is active.
    pub active: bool,
    /// The models it lists, by id, sorted, each once.
    pub models: Vec<String>,
    /// Its compaction model.
    pub compaction_model: Option<String>,
    /// Its model tier.
    pub model_tier: Option<String>,
    /// Its dreaming model.
    pub dreaming_model: Option<String>,
}

impl AgentSwitches {
    /// Every model id and tier is 1 to [`MAX_STATED_MODEL_LEN`] bytes, the list holds at most
    /// [`MAX_STATED_MODELS`], sorted and each once, so one statement has one byte form.
    fn validate(&self) -> Result<()> {
        let named = |name: &String| (1..=MAX_STATED_MODEL_LEN).contains(&name.len());
        let sorted_once = self.models.windows(2).all(|pair| pair[0] < pair[1]);
        let options = [
            &self.compaction_model,
            &self.model_tier,
            &self.dreaming_model,
        ];
        if self.models.len() > MAX_STATED_MODELS
            || !sorted_once
            || !self.models.iter().all(named)
            || !options.into_iter().flatten().all(named)
        {
            return Err(invalid_authority());
        }
        Ok(())
    }
}

/// One giving or end of a Grant row, signed by the install key of `machine`, a live machine of
/// the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantActRecord {
    /// Who decided.
    pub decider: GrantDecider,
    /// The carrier: the machine whose install key signed the record.
    pub machine: EntityId,
    /// The row the act gives or ends.
    pub subject: EntityId,
    /// The row's family.
    pub family: GrantFamily,
    /// The change.
    pub change: GrantActChange,
}

impl GrantActRecord {
    /// The deciding person; `None` for a rule's end.
    #[must_use]
    pub fn decider_person(&self) -> Option<EntityId> {
        match &self.decider {
            GrantDecider::Person(act) => Some(act.owner),
            GrantDecider::Rule => None,
        }
    }

    /// The row this act ends; `None` for a giving.
    #[must_use]
    pub fn ended_grant(&self) -> Option<EntityId> {
        (self.change == GrantActChange::End).then_some(self.subject)
    }

    /// The owner's agent Grant this act ends (a lapse's end); `None` for any other act.
    #[must_use]
    pub fn ended_owner_agent_grant(&self) -> Option<EntityId> {
        self.ended_grant()
            .filter(|_| self.family == GrantFamily::OwnerAgent)
    }

    pub fn validate(&self) -> Result<()> {
        match &self.decider {
            GrantDecider::Person(act) => {
                act.validate_carried(self.change.act_kind(), self.subject)?;
                // A person's own say-so: no agent decides a Grant, and no ask answers it.
                if act.by != ActBy::Owner || act.answer.is_some() || act.seen != GRANT_ACT_SEEN {
                    return Err(invalid_authority());
                }
                // The owner gives and ends his agent Grant by its own act (`AgentGrantAct`'s
                // mint and revoke), whose readers judge his liveness and topology: no second,
                // quieter path to either.
                if self.family == GrantFamily::OwnerAgent {
                    return Err(invalid_authority());
                }
            }
            // A rule only ends, a Grant of any family: every taking back is a counted end,
            // whether a person decided it or not (GRANT-ROW-DELETE-NO-END = A).
            GrantDecider::Rule => {
                if self.change != GrantActChange::End {
                    return Err(invalid_authority());
                }
            }
        }
        if let GrantActChange::Give { terms } = &self.change
            && terms.iter().all(|byte| *byte == 0)
        {
            return Err(invalid_authority());
        }
        // An agent definition's act states switches and nothing else: a statement gives no
        // Grant terms, and no act ends the line, since turning a definition off is any
        // writer's and an ended line would refuse the owner's every later statement.
        match (&self.change, self.family) {
            (GrantActChange::State { switches }, GrantFamily::AgentDefinition) => {
                switches.validate()
            }
            (GrantActChange::State { .. }, _) | (_, GrantFamily::AgentDefinition) => {
                Err(invalid_authority())
            }
            _ => Ok(()),
        }
    }
}

/// The keyed commitment a giving carries to row `subject`'s terms: the keyed federation scope
/// digest's construction under the row's own 32-byte terms key, over the row id and its
/// canonical body bytes, the key itself left out. Without the key, the line yields nothing
/// about the terms; with the row, a reader opens it by computing it again.
#[must_use]
pub fn grant_terms_commitment(
    terms_key: &[u8; 32],
    subject: EntityId,
    canonical_body: &[u8],
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(16 + canonical_body.len());
    bytes.extend_from_slice(subject.as_bytes());
    bytes.extend_from_slice(canonical_body);
    federation_scope_digest(terms_key, &GRANT_TERMS_TAG, &bytes)
}

pub(super) fn grant_act_value(record: &GrantActRecord) -> Value {
    let act = match &record.decider {
        GrantDecider::Person(act) => super::owner_act::owner_act_value(act),
        GrantDecider::Rule => Value::Nil,
    };
    let (change, terms) = match &record.change {
        GrantActChange::Give { terms } => (CHANGE_GIVE, binary_value(*terms)),
        GrantActChange::End => (CHANGE_END, Value::Nil),
        GrantActChange::State { switches } => (CHANGE_STATE, switches_value(switches)),
    };
    Value::Map(vec![
        (Value::from(OP_KEY_KIND), Value::from(OP_KIND_GRANT_ACT)),
        (Value::from(OP_KEY_ACT), act),
        (Value::from("machine"), Value::from(record.machine.to_hex())),
        (Value::from("subject"), Value::from(record.subject.to_hex())),
        (Value::from("family"), Value::from(record.family.as_str())),
        (Value::from("change"), Value::from(change)),
        (Value::from("terms"), terms),
    ])
}

/// A statement's switches under `terms`: seven keys, always, a choice not made as nil.
fn switches_value(switches: &AgentSwitches) -> Value {
    let text = |value: &Option<String>| value.as_deref().map_or(Value::Nil, Value::from);
    Value::Map(vec![
        (Value::from("enabled"), Value::from(switches.enabled)),
        (
            Value::from("approval"),
            Value::from(switches.approval.as_str()),
        ),
        (Value::from("active"), Value::from(switches.active)),
        (
            Value::from("models"),
            Value::Array(
                switches
                    .models
                    .iter()
                    .map(|model| Value::from(model.as_str()))
                    .collect(),
            ),
        ),
        (
            Value::from("compaction_model"),
            text(&switches.compaction_model),
        ),
        (Value::from("model_tier"), text(&switches.model_tier)),
        (
            Value::from("dreaming_model"),
            text(&switches.dreaming_model),
        ),
    ])
}

fn decode_switches(value: &Value) -> Result<AgentSwitches> {
    let entries = map_entries(value)?;
    validate_keys(entries, &SWITCH_KEYS)?;
    let flag = |name: &str| -> Result<bool> {
        required(entries, name)?
            .as_bool()
            .ok_or_else(invalid_authority)
    };
    let text = |value: &Value| -> Result<String> {
        value
            .as_str()
            .map(str::to_owned)
            .ok_or_else(invalid_authority)
    };
    let choice = |name: &str| -> Result<Option<String>> {
        Ok(match required(entries, name)? {
            Value::Nil => None,
            value => Some(text(value)?),
        })
    };
    let Value::Array(models) = required(entries, "models")? else {
        return Err(invalid_authority());
    };
    let switches = AgentSwitches {
        enabled: flag("enabled")?,
        approval: required(entries, "approval")?
            .as_str()
            .and_then(AgentApproval::from_name)
            .ok_or_else(invalid_authority)?,
        active: flag("active")?,
        models: models.iter().map(text).collect::<Result<_>>()?,
        compaction_model: choice("compaction_model")?,
        model_tier: choice("model_tier")?,
        dreaming_model: choice("dreaming_model")?,
    };
    switches.validate()?;
    Ok(switches)
}

/// Seven keys, always: a rule's end carries a nil act, an end a nil `terms`, a statement its
/// switches. The envelope's canonical re-encode then pins every value's form.
pub(super) fn decode_grant_act(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &GRANT_ACT_KEYS)?;
    let decider = match required(entries, OP_KEY_ACT)? {
        Value::Nil => GrantDecider::Rule,
        value => GrantDecider::Person(super::owner_act::decode_owner_act(value)?),
    };
    let family = required(entries, "family")?
        .as_str()
        .and_then(GrantFamily::from_name)
        .ok_or_else(invalid_authority)?;
    let terms = required(entries, "terms")?;
    let change = match required(entries, "change")?.as_str() {
        Some(CHANGE_GIVE) => GrantActChange::Give {
            terms: decode_hash(terms)?,
        },
        Some(CHANGE_END) if terms.is_nil() => GrantActChange::End,
        Some(CHANGE_STATE) => GrantActChange::State {
            switches: decode_switches(terms)?,
        },
        _ => return Err(invalid_authority()),
    };
    Ok(AuthorityOp::GrantAct(GrantActRecord {
        decider,
        machine: decode_canonical_id(required(entries, "machine")?)?,
        subject: decode_canonical_id(required(entries, "subject")?)?,
        family,
        change,
    }))
}
