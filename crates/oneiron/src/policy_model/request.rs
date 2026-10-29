//! What the caller asks about, and how the classifier is configured.

use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::llm::SafeguardModelBinding;
use crate::store::GateSystemNoticeAction;

use super::planes::PolicyPlane;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyClassifySubject {
    OutboundContent,
    Action,
}

impl PolicyClassifySubject {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OutboundContent => "outbound_content",
            Self::Action => "action",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyClassifyRequest {
    pub subject: PolicyClassifySubject,
    pub content: String,
    pub world_ref: Option<String>,
    pub project_ref: Option<String>,
    pub caller_ref: Option<String>,
    /// The person this content is with, as the host's auth layer proved them.
    /// Only a `RouteToHelp` this request settles reads it: it names whose
    /// trusted contacts (OF-527) the verdict may reach. It never shapes the
    /// verdict.
    pub concerned_person: Option<AuthenticatedOwner>,
}

impl PolicyClassifyRequest {
    #[must_use]
    pub fn outbound_content(content: impl Into<String>) -> Self {
        Self {
            subject: PolicyClassifySubject::OutboundContent,
            content: content.into(),
            world_ref: None,
            project_ref: None,
            caller_ref: None,
            concerned_person: None,
        }
    }

    #[must_use]
    pub fn action(content: impl Into<String>) -> Self {
        Self {
            subject: PolicyClassifySubject::Action,
            content: content.into(),
            world_ref: None,
            project_ref: None,
            caller_ref: None,
            concerned_person: None,
        }
    }

    #[must_use]
    pub fn with_world_ref(mut self, world_ref: impl Into<String>) -> Self {
        self.world_ref = Some(world_ref.into());
        self
    }

    #[must_use]
    pub fn with_project_ref(mut self, project_ref: impl Into<String>) -> Self {
        self.project_ref = Some(project_ref.into());
        self
    }

    #[must_use]
    pub fn with_caller_ref(mut self, caller_ref: impl Into<String>) -> Self {
        self.caller_ref = Some(caller_ref.into());
        self
    }

    #[must_use]
    pub fn with_concerned_person(mut self, person: AuthenticatedOwner) -> Self {
        self.concerned_person = Some(person);
        self
    }
}

/// How hard the safeguard model should think before answering.
///
/// Reasoning safeguard models expose this as a knob rather than inferring it,
/// and the right setting depends on how subtle the substrate owner's policy is
/// — which is their call, not the engine's.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyReasoningEffort {
    Low,
    #[default]
    Medium,
    High,
}

impl PolicyReasoningEffort {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// Generation parameters for a safeguard-model call.
///
/// `max_output_tokens` defaults to NO CAP on purpose. A reasoning safeguard
/// model spends output tokens on its reasoning before it answers, so a small
/// ceiling truncates the answer into something unreadable and the plane
/// degrades for a reason that was never about the content. A host that needs a
/// ceiling sets a generous one here.
///
/// These are per-config, and a host that drives more than one safeguard binding
/// gives each binding its own [`PolicyModelConfig`] — the parameters travel
/// with the binding they were tuned for.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyGenerationParams {
    pub reasoning_effort: PolicyReasoningEffort,
    pub temperature: f32,
    pub max_output_tokens: Option<u32>,
}

impl Default for PolicyGenerationParams {
    fn default() -> Self {
        Self {
            reasoning_effort: PolicyReasoningEffort::Medium,
            temperature: 0.0,
            max_output_tokens: None,
        }
    }
}

/// How much of a plane's content the safeguard model sees.
///
/// Each plane carries its OWN dial ([`PolicyModelConfig::owner_classifier_mode`]
/// and [`PolicyModelConfig::hosted_classifier_mode`]) because the two answer
/// different questions. The hosted plane is a relay service's legal duty over
/// traffic it carries; the owner plane is the vault owner's own policy over
/// their own content. A host that wants full coverage of its legal exposure
/// and pattern-gated coverage of the owner's rows — or the reverse — is
/// expressing two independent choices, and one dial made them the same choice
/// twice.
///
/// `non_exhaustive`: a new mode is how this grows, and a downstream exhaustive
/// match would turn that into a breaking change.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RelayClassifierMode {
    /// The default. The model classifies 100% of the plane's content; pattern
    /// hits annotate the pass (and a `Decide` hit still short-circuits it), but
    /// no pattern is required for the model to look.
    #[default]
    ClassifyAll,
    /// Patterns gate the model. A `Decide` hit is the verdict, an `Escalate`
    /// hit buys a model call, and content that matched only `Log` rules — or
    /// nothing at all — is allowed with ZERO model calls and its own receipt
    /// reason.
    PatternGated,
}

impl RelayClassifierMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClassifyAll => "classify_all",
            Self::PatternGated => "pattern_gated",
        }
    }
}

/// What a hosted relay does when its safeguard model was not available.
///
/// The hosted plane's rows are prose only a model can read, so a pass that
/// never got an answer has zero coverage of them. The engine's own position on
/// that is unchanged and is the default: [`Self::Halt`] — an unexamined allow
/// is exactly what the plane exists to refuse.
///
/// But whether a model outage should stop a whole relay is the HOST's
/// exposure, not the engine's. A host whose traffic is low-risk, or who
/// carries the legal argument for continuing while its safeguard tier is down,
/// may prefer availability and a receipt that says plainly what it did not
/// check. That choice belongs to whoever answers for it.
///
/// The knob covers AVAILABILITY only — the model was unreachable, its answer
/// unusable, or no tier was supplied. It does NOT cover
/// [`RelayBoundaryDegrade::PolicyBindingMovedMidPass`] (a verdict that cannot
/// be attested is not an availability problem, and always halts) or
/// [`RelayBoundaryDegrade::OutputContractUndeclared`] (a policy that reached
/// the relay without passing registration). It never softens a hosted
/// `Block` or `RouteToHelp`: those are answers, not outages.
///
/// `non_exhaustive`: a further posture is how this grows.
///
/// [`RelayBoundaryDegrade::PolicyBindingMovedMidPass`]: super::relay::RelayBoundaryDegrade::PolicyBindingMovedMidPass
/// [`RelayBoundaryDegrade::OutputContractUndeclared`]: super::relay::RelayBoundaryDegrade::OutputContractUndeclared
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HostedOutagePolicy {
    /// The default, and the engine's own posture: an availability degrade
    /// stops the relay.
    #[default]
    Halt,
    /// The relay proceeds through an availability degrade. The pass stays
    /// visibly degraded — the degrade marker, the `unresolved` resolution and
    /// the receipt row are all still written — so the allow is never
    /// mistakable for one a model confirmed.
    ProceedReceipted,
}

impl HostedOutagePolicy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Halt => "halt",
            Self::ProceedReceipted => "proceed_receipted",
        }
    }
}

/// Everything about a classify pass that is the HOST's to choose. None of it
/// carries policy content: the patterns and the policy documents live on their
/// own planes, where their authority comes from.
#[derive(Debug, Clone, Default)]
pub struct PolicyModelConfig {
    pub safeguard_binding: SafeguardModelBinding,
    /// Affordance the host attaches to owner-plane notices so the owner can
    /// jump straight to the setting that fired. `None` by default: the engine
    /// knows no product routes, so a host that wants the offer supplies both
    /// its label and its target.
    pub owner_setting_change_offer: Option<GateSystemNoticeAction>,
    /// An overt retry explanation. Required when an owner row uses `reword`;
    /// the engine ships no wording for a model to obey.
    pub owner_reword_notice: Option<String>,
    /// Help text and links supplied by the host. No resources or medical
    /// categories are bundled with the engine.
    pub help_message: Option<String>,
    pub help_resources: Vec<GateSystemNoticeAction>,
    /// A hosted service's local-model/self-host setup link. It is never
    /// attached to owner-plane notices.
    pub hosted_local_model_offer: Option<GateSystemNoticeAction>,
    /// Optional registered decide() paths. Absent means the existing
    /// safeguard backend path, not an engine-selected model or policy.
    pub owner_decisions: Option<std::sync::Arc<super::PolicyDecisions>>,
    pub hosted_decisions: Option<std::sync::Arc<super::PolicyDecisions>>,
    /// Host-supplied explanation shown identically to the user and model on a human hold.
    /// Empty or oversized text falls back to the engine's generic explanation.
    pub owner_hold_notice: Option<String>,
    /// Host-supplied text shown identically to the user and model when a
    /// `RouteToHelp` sends the person's trusted contact their check-in notice.
    /// Empty or oversized text falls back to the engine's generic statement.
    pub trusted_contact_notified_notice: Option<String>,
    /// Host-supplied text shown identically to the user and model when a
    /// `RouteToHelp` asks the person before reaching their trusted contact.
    /// Empty or oversized text falls back to the engine's generic statement.
    pub trusted_contact_ask_notice: Option<String>,
    pub generation: PolicyGenerationParams,
    /// How much of the OWNER plane's content reaches the model. Read by the
    /// owner-plane pass and stamped on the owner-plane receipt; the hosted
    /// pass never consults it.
    pub owner_classifier_mode: RelayClassifierMode,
    /// How much of the HOSTED plane's content reaches the model. Read by the
    /// relay-boundary pass and stamped on the relay receipt; the owner pass
    /// never consults it.
    pub hosted_classifier_mode: RelayClassifierMode,
    /// What the relay does when the hosted pass could not reach a safeguard
    /// model. Defaults to [`HostedOutagePolicy::Halt`].
    pub hosted_outage_policy: HostedOutagePolicy,
    /// The time the safeguard read has, from its call's start to its answer,
    /// its notes included (FIX 1203). `None` is the engine's default,
    /// [`SAFEGUARD_READ_BUDGET`](super::decide::SAFEGUARD_READ_BUDGET).
    pub safeguard_read_budget: Option<std::time::Duration>,
    /// The host ladder's paired question, lent to the safeguard's generated
    /// read (FIX 2436): each read asks it beside its own questions, and the
    /// receipts keep its reading. `None` asks none.
    pub safeguard_paired: Option<crate::llm::decision::DecisionQuestion>,
}

impl PolicyModelConfig {
    /// The safeguard read's time ([`Self::safeguard_read_budget`]), the
    /// engine's default when the host set none.
    pub(super) fn read_budget(&self) -> std::time::Duration {
        self.safeguard_read_budget
            .filter(|budget| !budget.is_zero())
            .unwrap_or(super::decide::SAFEGUARD_READ_BUDGET)
    }

    pub(super) fn decisions(&self, plane: PolicyPlane) -> Option<&super::PolicyDecisions> {
        match plane {
            PolicyPlane::OwnerPolicy => self.owner_decisions.as_deref(),
            PolicyPlane::HostedLegal => self.hosted_decisions.as_deref(),
        }
    }

    pub(super) fn decision_binding(&self, plane: PolicyPlane) -> Option<String> {
        self.decisions(plane).map(super::PolicyDecisions::binding)
    }

    /// The classifier dial that governs `plane`.
    ///
    /// The ONE place plane maps to dial. Every verdict records the dial of the
    /// plane that minted it, and every reuse door compares the dial of the
    /// plane it serves; both go through here, so the two can never disagree
    /// about which field is whose.
    #[must_use]
    pub const fn classifier_mode(&self, plane: PolicyPlane) -> RelayClassifierMode {
        match plane {
            PolicyPlane::OwnerPolicy => self.owner_classifier_mode,
            PolicyPlane::HostedLegal => self.hosted_classifier_mode,
        }
    }
}
