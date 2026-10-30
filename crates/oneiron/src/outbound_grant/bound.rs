//! A standing outbound grant's scope dial, its one spelling onto a standing
//! consent Grant's bound, and the grant as read back from its Grant row.

use super::verb_class::{classes_of, verb_in_class};
use crate::consent::{
    ActionClass, ActionEnvelope, ActorBound, BoundClass, BoundEnvelope, ConsentGrantRow,
    GrantBound, StandingConsentGrant,
};
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::genui::GrantMintIntentScope;
use crate::outbound_consent::tool_call::ToolGrantDataClass;
use crate::outbound_consent::{DataClass, ScopedMcpGrantRef};

// A standing outbound grant's lifecycle state is the standing consent
// Grant's (`ConsentGrantStatus`): active, or revoked and failing closed at
// once, under the same pinned on-disk strings.
pub use crate::consent::ConsentGrantStatus as StandingOutboundGrantStatus;

/// The send verb class: the class a contact or channel dial covers.
pub(super) const SEND_VERB_CLASS: &str = "send";

/// The verb an artifact publish names, and the class its dial covers.
const ARTIFACT_PUBLISH_VERB: &str = "publish";

/// The channel an artifact publish rides.
const ARTIFACT_CHANNEL: &str = "artifact";

// Selector prefixes of an outbound grant's bound. Each dial spells its
// restriction under its own prefix, and none is the `verb:` selector the
// Gate's external-effect requirement names, so an outbound grant covers an
// effect only through its own dial's match (`StandingOutboundGrant::covers_effect`).
const SELECTOR_GRANT: &str = "grant";
const SELECTOR_POLICY_FRONTIER: &str = "policy_frontier";
const SELECTOR_CONTACT: &str = "contact";
const SELECTOR_VERB_CLASS: &str = "verb_class";
const SELECTOR_CHANNEL: &str = "channel";
const SELECTOR_BRIEF: &str = "brief";
const SELECTOR_ARTIFACT: &str = "artifact";
const SELECTOR_PAGE: &str = "page";
const SELECTOR_SERVER: &str = "server";
const SELECTOR_TOOL: &str = "tool";
const SELECTOR_DATA_CLASS_CEILING: &str = "data_class_ceiling";
const SELECTOR_TOOL_DATA_CLASS: &str = "tool_data_class";
const SELECTOR_ENDPOINT: &str = "endpoint";

/// Scope dial selected by the owner when minting a standing outbound grant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StandingOutboundGrantScope {
    /// Always allow matching sends to one contact/counterparty.
    Contact { contact_ref: String },
    /// Always allow every verb in one outbound verb class.
    VerbClass { verb_class: String },
    /// Always allow matching sends on one channel.
    Channel { channel: String },
    /// Bundle approval for every verb in one verb class, inside one brief.
    BriefVerbClass {
        brief_ref: String,
        verb_class: String,
    },
    /// Publish updates to one artifact, never to another artifact or verb.
    ArtifactPublish { artifact: String },
    /// Payload-aware standing authority for one external tool.
    ScopedMcp {
        server: String,
        tool: String,
        data_class_ceiling: DataClass,
        tool_data_classes: Vec<ToolGrantDataClass>,
        endpoint_allowlist: Vec<String>,
    },
    /// Bounded booking-page authority: `calendar.invite` for bookings that a
    /// confirm persisted on exactly this page. The recipient binding is NOT in
    /// this scope — the consent door resolves it from booking claims — so a
    /// live grant never widens past the page it was minted for.
    BookingPageInvites { page_ref: EntityId },
}

impl StandingOutboundGrantScope {
    /// Builds a dial from the RCPT-3 grant mint intent scope.
    pub fn from_grant_mint_scope(scope: &GrantMintIntentScope) -> Result<Self> {
        let dial = match scope {
            GrantMintIntentScope::Contact { contact_ref } => Self::Contact {
                contact_ref: contact_ref.trim().to_owned(),
            },
            GrantMintIntentScope::VerbClass { verb_class } => Self::VerbClass {
                verb_class: verb_class.trim().to_owned(),
            },
            GrantMintIntentScope::Channel { channel } => Self::Channel {
                channel: channel.trim().to_owned(),
            },
            GrantMintIntentScope::BriefVerbClass {
                brief_ref,
                verb_class,
            } => Self::BriefVerbClass {
                brief_ref: brief_ref.trim().to_owned(),
                verb_class: verb_class.trim().to_owned(),
            },
            GrantMintIntentScope::ArtifactPublish { artifact } => Self::ArtifactPublish {
                artifact: artifact.clone(),
            },
            // A calendar disclosure grant authorizes a READ at a rung. It must
            // never become a standing permission to send; a one-time or bundle
            // approval is no standing grant at all.
            GrantMintIntentScope::JustOnce { .. }
            | GrantMintIntentScope::BundleExactSends { .. }
            | GrantMintIntentScope::Calendar { .. } => return Err(invalid_grant()),
        };
        dial.validate()?;
        Ok(dial)
    }

    /// Stable dial label for grants-lens rows.
    #[must_use]
    pub const fn dial_label(&self) -> &'static str {
        match self {
            Self::Contact { .. } => "always_this_contact",
            Self::VerbClass { .. } => "always_this_verb_class",
            Self::Channel { .. } => "always_this_channel",
            Self::BriefVerbClass { .. } => "brief_verb_class",
            Self::ScopedMcp { .. } => "scoped_mcp",
            Self::ArtifactPublish { .. } => "artifact_publish",
            Self::BookingPageInvites { .. } => "booking_page_invites",
        }
    }

    /// Returns the payload-aware axes when this is a scoped external-tool
    /// grant. Blind grant kinds intentionally return `None`.
    #[must_use]
    pub fn scoped_mcp_grant(&self) -> Option<ScopedMcpGrantRef<'_>> {
        match self {
            Self::ScopedMcp {
                server,
                tool,
                data_class_ceiling,
                tool_data_classes,
                endpoint_allowlist,
            } => Some(ScopedMcpGrantRef {
                server,
                tool,
                data_class_ceiling: *data_class_ceiling,
                tool_data_classes,
                endpoint_allowlist,
            }),
            _ => None,
        }
    }

    /// The bound one grant with this dial holds: `principal_ref` acting,
    /// this dial's class and restrictions, the grant's own id, which its
    /// capability keys and page dispatch name, and the policy frontier it
    /// was minted under, past which it no longer counts.
    ///
    /// # Errors
    ///
    /// [`RecordError::InvalidOutboundGrantBody`] for a dial that fails
    /// validation, and the bound's own errors for a value no bound holds.
    pub fn grant_bound(
        &self,
        principal_ref: &str,
        id: EntityId,
        policy_frontier: &[u8; 32],
    ) -> Result<GrantBound> {
        self.validate()?;
        let (class, mut selectors, target) = self.axes();
        selectors.push(format!("{SELECTOR_GRANT}:{}", id.to_hex()));
        selectors.push(format!(
            "{SELECTOR_POLICY_FRONTIER}:{}",
            crate::entity_id::bytes_to_hex_lower(policy_frontier)
        ));
        let mut envelope = ActionEnvelope::new(selectors)?;
        if let Some(target) = target {
            envelope = envelope.with_target(target)?;
        }
        GrantBound::action(
            ActorBound::new(principal_ref)?,
            ActionClass::new(class)?,
            envelope,
        )
    }

    /// The one spelling of this dial onto a bound's class, selectors and
    /// target. Dial values are trimmed, as an effect's are when it is matched.
    fn axes(&self) -> (String, Vec<String>, Option<String>) {
        match self {
            Self::Contact { contact_ref } => {
                let contact = contact_ref.trim();
                (
                    SEND_VERB_CLASS.to_owned(),
                    vec![format!("{SELECTOR_CONTACT}:{contact}")],
                    Some(contact.to_owned()),
                )
            }
            Self::VerbClass { verb_class } => {
                let class = verb_class.trim();
                (
                    class.to_owned(),
                    vec![format!("{SELECTOR_VERB_CLASS}:{class}")],
                    None,
                )
            }
            Self::Channel { channel } => {
                let channel = channel.trim();
                (
                    SEND_VERB_CLASS.to_owned(),
                    vec![format!("{SELECTOR_CHANNEL}:{channel}")],
                    Some(channel.to_owned()),
                )
            }
            Self::BriefVerbClass {
                brief_ref,
                verb_class,
            } => {
                let brief = brief_ref.trim();
                (
                    verb_class.trim().to_owned(),
                    vec![format!("{SELECTOR_BRIEF}:{brief}")],
                    Some(brief.to_owned()),
                )
            }
            Self::ArtifactPublish { artifact } => (
                ARTIFACT_PUBLISH_VERB.to_owned(),
                vec![format!("{SELECTOR_ARTIFACT}:{artifact}")],
                Some(artifact.clone()),
            ),
            Self::ScopedMcp {
                server,
                tool,
                data_class_ceiling,
                tool_data_classes,
                endpoint_allowlist,
            } => {
                let mut selectors = vec![
                    format!("{SELECTOR_SERVER}:{server}"),
                    format!("{SELECTOR_TOOL}:{tool}"),
                    format!(
                        "{SELECTOR_DATA_CLASS_CEILING}:{}",
                        data_class_ceiling.as_str()
                    ),
                ];
                selectors.extend(
                    tool_data_classes
                        .iter()
                        .map(|class| format!("{SELECTOR_TOOL_DATA_CLASS}:{}", class.as_str())),
                );
                selectors.extend(
                    endpoint_allowlist
                        .iter()
                        .map(|endpoint| format!("{SELECTOR_ENDPOINT}:{endpoint}")),
                );
                (
                    format!("{server}.{tool}"),
                    selectors,
                    Some(format!("{server}/{tool}")),
                )
            }
            // The tightest class this grant can hold: it authorizes exactly
            // one verb, so the verb string IS the action class, as `ScopedMcp`
            // holds `{server}.{tool}`. The target binds the bound to the page.
            Self::BookingPageInvites { page_ref } => {
                let page = page_ref.to_hex();
                (
                    crate::calendar::CALENDAR_INVITE_VERB.to_owned(),
                    vec![format!("{SELECTOR_PAGE}:{page}")],
                    Some(page),
                )
            }
        }
    }

    /// The grant id, policy frontier and dial a bound spells, when it is
    /// exactly the bound [`Self::grant_bound`] builds for them. Any other
    /// bound, a standing consent Grant of another kind included, is no
    /// outbound grant.
    fn from_bound(bound: &GrantBound) -> Option<(EntityId, [u8; 32], Self)> {
        let actor = bound.actor()?;
        let BoundClass::Action(class) = bound.class() else {
            return None;
        };
        let BoundEnvelope::Action(envelope) = bound.envelope() else {
            return None;
        };
        let (mut id, mut frontier) = (None, None);
        let mut fields: Vec<(&str, &str)> = Vec::new();
        for selector in envelope.selectors() {
            let (key, value) = selector.split_once(':')?;
            match key {
                SELECTOR_GRANT if id.replace(EntityId::from_hex(value).ok()?).is_none() => {}
                SELECTOR_POLICY_FRONTIER
                    if frontier
                        .replace(crate::deletion::parse_hex::<32>(value)?)
                        .is_none() => {}
                SELECTOR_GRANT | SELECTOR_POLICY_FRONTIER => return None,
                _ => fields.push((key, value)),
            }
        }
        let (id, frontier) = (id?, frontier?);
        let class = class.as_str();
        let dial = match fields.as_slice() {
            [(SELECTOR_CONTACT, contact)] => Self::Contact {
                contact_ref: (*contact).to_owned(),
            },
            [(SELECTOR_VERB_CLASS, verb_class)] => Self::VerbClass {
                verb_class: (*verb_class).to_owned(),
            },
            [(SELECTOR_CHANNEL, channel)] => Self::Channel {
                channel: (*channel).to_owned(),
            },
            [(SELECTOR_BRIEF, brief)] => Self::BriefVerbClass {
                brief_ref: (*brief).to_owned(),
                verb_class: class.to_owned(),
            },
            [(SELECTOR_ARTIFACT, artifact)] => Self::ArtifactPublish {
                artifact: (*artifact).to_owned(),
            },
            [(SELECTOR_PAGE, page)] => Self::BookingPageInvites {
                page_ref: EntityId::from_hex(page).ok()?,
            },
            _ => scoped_mcp_from_fields(&fields)?,
        };
        // Round trip: only the exact bound this dial spells is this grant,
        // so a target, budget or extra selector a dial never writes reads as
        // no outbound grant at all.
        let rebuilt = dial.grant_bound(actor.actor_ref(), id, &frontier).ok()?;
        (rebuilt == *bound).then_some((id, frontier, dial))
    }

    /// Validates the dial's values before any bound is spelled from them.
    pub(super) fn validate(&self) -> Result<()> {
        match self {
            Self::ArtifactPublish { artifact } => {
                crate::artifact_hosting::validate_artifact_id(artifact)
                    .map_err(|_| invalid_grant())?;
            }
            Self::Contact { contact_ref } => non_empty_str(contact_ref)?,
            Self::VerbClass { verb_class } => non_empty_str(verb_class)?,
            Self::Channel { channel } => non_empty_str(channel)?,
            Self::BriefVerbClass {
                brief_ref,
                verb_class,
            } => {
                non_empty_str(brief_ref)?;
                non_empty_str(verb_class)?;
            }
            Self::ScopedMcp {
                server,
                tool,
                data_class_ceiling,
                tool_data_classes,
                endpoint_allowlist,
            } => {
                // Stored-form == authority-form: the scoped server must ALREADY
                // be the safe canonical segment the capability-key producer and
                // the charter compiler use, or this grant would govern under
                // one spelling and be enforced under another (ONE-1885).
                if crate::connector_key::canonical_scoped_server_segment(server).as_ref()
                    != Some(server)
                {
                    return Err(invalid_grant());
                }
                canonical_non_empty_str(tool)?;
                if !data_class_ceiling.is_grantable() || endpoint_allowlist.is_empty() {
                    return Err(invalid_grant());
                }
                // Canonical class ordering; an explicit independent header
                // class never implies permission for normal arguments.
                if !ToolGrantDataClass::valid_grant_set(tool_data_classes) {
                    return Err(invalid_grant());
                }
                for endpoint in endpoint_allowlist {
                    canonical_non_empty_str(endpoint)?;
                }
            }
            // An `EntityId` is already the validated form of a page reference.
            Self::BookingPageInvites { .. } => {}
        }
        Ok(())
    }
}

/// The scoped-MCP dial a bound's selectors spell, in their sorted order:
/// one server, tool and ceiling, its tool data classes and its endpoints.
fn scoped_mcp_from_fields(fields: &[(&str, &str)]) -> Option<StandingOutboundGrantScope> {
    let (mut server, mut tool, mut ceiling) = (None, None, None);
    let mut tool_data_classes = Vec::new();
    let mut endpoint_allowlist = Vec::new();
    for (key, value) in fields {
        match *key {
            SELECTOR_SERVER if server.replace(*value).is_none() => {}
            SELECTOR_TOOL if tool.replace(*value).is_none() => {}
            SELECTOR_DATA_CLASS_CEILING if ceiling.replace(*value).is_none() => {}
            SELECTOR_TOOL_DATA_CLASS => {
                tool_data_classes.push(ToolGrantDataClass::parse(value)?);
            }
            SELECTOR_ENDPOINT => endpoint_allowlist.push((*value).to_owned()),
            _ => return None,
        }
    }
    Some(StandingOutboundGrantScope::ScopedMcp {
        server: server?.to_owned(),
        tool: tool?.to_owned(),
        data_class_ceiling: DataClass::parse(ceiling?),
        tool_data_classes,
        endpoint_allowlist,
    })
}

/// A standing outbound grant as its standing consent Grant row holds it:
/// the grant's id, the principal it lets act, its dial, the policy frontier
/// it was minted under, and the row's lifecycle. The row is the grant; this
/// is how it reads.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StandingOutboundGrant {
    /// The grant's id: its capability keys and page dispatch name it.
    pub id: EntityId,
    /// Principal the grant lets act.
    pub principal_ref: String,
    /// Owner-selected grant scope dial.
    pub scope: StandingOutboundGrantScope,
    /// Grant lifecycle status.
    pub status: StandingOutboundGrantStatus,
    /// Creation time in Unix seconds.
    pub created_at: u64,
    /// Policy frontier in effect when the grant was minted.
    pub policy_frontier: [u8; 32],
    bound: GrantBound,
}

impl StandingOutboundGrant {
    /// The outbound grant one standing consent Grant row holds, or `None`
    /// for a row of any other kind.
    #[must_use]
    pub fn from_row(row: &ConsentGrantRow) -> Option<Self> {
        let StandingConsentGrant::Action(grant) = &row.grant else {
            return None;
        };
        if row.bypass.is_some() {
            return None;
        }
        let bound = grant.bound();
        let (id, policy_frontier, scope) = StandingOutboundGrantScope::from_bound(bound)?;
        Some(Self {
            id,
            principal_ref: bound.actor()?.actor_ref().to_owned(),
            scope,
            status: row.status,
            created_at: row.created_at,
            policy_frontier,
            bound: bound.clone(),
        })
    }

    /// The reference of the standing consent Grant row this grant is: the
    /// consent registry's revoke, and every Approved, Used and Revoked
    /// receipt, name it.
    #[must_use]
    pub fn grant_ref(&self) -> String {
        self.bound.digest().to_hex()
    }

    /// The bound this grant holds.
    #[must_use]
    pub const fn bound(&self) -> &GrantBound {
        &self.bound
    }

    /// Whether this grant's row is active. Revocation flips the row, so a
    /// revoked grant fails closed at once.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, StandingOutboundGrantStatus::Active)
    }

    /// Whether this grant can authorize anything under the current policy
    /// frontier: its row is active and it was minted under that frontier.
    #[must_use]
    pub fn is_active_under_policy(&self, policy_frontier: &[u8; 32]) -> bool {
        self.is_active() && &self.policy_frontier == policy_frontier
    }

    /// Whether this grant's bound contains the effect its principal would
    /// run by sending `verb` on `channel`, to `counterparty` inside
    /// `brief_ref`. The effect is spelled as each dial would name it, and
    /// [`GrantBound::contains`] decides. MCP calls take the payload-aware
    /// path and a booking page's invite its page binding, so neither is
    /// covered here.
    #[must_use]
    pub fn covers_effect(
        &self,
        verb: &str,
        channel: &str,
        counterparty: Option<&str>,
        brief_ref: Option<&str>,
    ) -> bool {
        effect_candidates(&self.principal_ref, verb, channel, counterparty, brief_ref)
            .iter()
            .any(|candidate| self.bound.contains(candidate))
    }
}

/// The candidate bounds one effect of `principal_ref` presents: one per
/// dial that could name it, each spelled as that dial's bound is.
fn effect_candidates(
    principal_ref: &str,
    verb: &str,
    channel: &str,
    counterparty: Option<&str>,
    brief_ref: Option<&str>,
) -> Vec<GrantBound> {
    // MCP calls require the payload-aware path. No argument-blind dial is
    // allowed to authorize one, even if its channel string matches.
    if is_mcp_channel(channel) {
        return Vec::new();
    }
    let mut axes: Vec<(String, String, Option<String>)> = Vec::new();
    if channel == ARTIFACT_CHANNEL && verb == ARTIFACT_PUBLISH_VERB {
        // A public artifact must never inherit a general send/contact grant:
        // only its own publish dial, for exactly this artifact.
        if let Some(artifact) = counterparty.filter(|artifact| *artifact == artifact.trim()) {
            axes.push((
                ARTIFACT_PUBLISH_VERB.to_owned(),
                format!("{SELECTOR_ARTIFACT}:{artifact}"),
                Some(artifact.to_owned()),
            ));
        }
    } else {
        let sends = verb_in_class(SEND_VERB_CLASS, verb);
        // A send-class verb to this contact, never another verb aimed at
        // them: an invite is a send, a share or a provision is not.
        if let Some(contact) = counterparty.map(str::trim)
            && (sends || verb.trim() == crate::calendar::CALENDAR_INVITE_VERB)
        {
            axes.push((
                SEND_VERB_CLASS.to_owned(),
                format!("{SELECTOR_CONTACT}:{contact}"),
                Some(contact.to_owned()),
            ));
        }
        if sends {
            let channel = channel.trim();
            axes.push((
                SEND_VERB_CLASS.to_owned(),
                format!("{SELECTOR_CHANNEL}:{channel}"),
                Some(channel.to_owned()),
            ));
        }
        // Each class the verb belongs to, its own literal spelling included.
        for class in classes_of(verb) {
            axes.push((
                class.to_owned(),
                format!("{SELECTOR_VERB_CLASS}:{class}"),
                None,
            ));
            if let Some(brief) = brief_ref.map(str::trim) {
                axes.push((
                    class.to_owned(),
                    format!("{SELECTOR_BRIEF}:{brief}"),
                    Some(brief.to_owned()),
                ));
            }
        }
    }
    axes.into_iter()
        .filter_map(|(class, selector, target)| {
            candidate_bound(principal_ref, class, selector, target).ok()
        })
        .collect()
}

/// One candidate bound: `principal_ref` running `class` on one selector,
/// narrowed to `target`.
fn candidate_bound(
    principal_ref: &str,
    class: String,
    selector: String,
    target: Option<String>,
) -> Result<GrantBound> {
    let mut envelope = ActionEnvelope::new([selector])?;
    if let Some(target) = target {
        envelope = envelope.with_target(target)?;
    }
    GrantBound::action(
        ActorBound::new(principal_ref)?,
        ActionClass::new(class)?,
        envelope,
    )
}

/// Whether `channel` names an MCP server.
fn is_mcp_channel(channel: &str) -> bool {
    channel
        .trim()
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("mcp:"))
}

fn non_empty_str(value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(invalid_grant());
    }
    Ok(())
}

fn canonical_non_empty_str(value: &str) -> Result<()> {
    non_empty_str(value)?;
    if value != value.trim() {
        return Err(invalid_grant());
    }
    Ok(())
}

/// The error a dial or grant that fails validation answers with.
pub(super) const fn invalid_grant() -> Error {
    Error::Record(RecordError::InvalidOutboundGrantBody(
        "grant failed validation",
    ))
}
