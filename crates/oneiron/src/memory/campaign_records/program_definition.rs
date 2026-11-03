//! Persisted cohort-program values and complete authoring drafts.

use super::CampaignLifecycle;
use crate::entity_id::EntityId;
use crate::write_envelope::cohort_claims::CampaignMemberChannel;

/// A campaign program: the persisted binding between a campaign and the steps
/// its enrollments execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CampaignProgram {
    /// Row schema version.
    pub schema_version: u32,
    /// Program identity.
    pub program_ref: EntityId,
    /// Campaign this program belongs to.
    pub campaign_ref: EntityId,
    /// The saved query this program enrolls from; absent means nothing
    /// enrolls into it from a sweep.
    pub audience: Option<CampaignProgramAudience>,
}

/// A program's audience: the campaign's edge to its target SAVED_QUERY
/// (ARCH-0059), and the program step a newly entered member enrolls at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CampaignProgramAudience {
    /// The saved query whose entries enroll.
    pub query_ref: EntityId,
    /// The step of this program an entry enrolls at.
    pub entry_step_ref: EntityId,
}

/// The outward half of a program step.
///
/// `call_seq` is DURABLE program state, never a clock or a process counter:
/// ONE-1691 derives the intent id from `(attempt_id, call_seq, server, tool,
/// payload_hash)`, so a process-local counter would mint a fresh intent — and a
/// second send — on every restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CampaignProgramOutbound {
    /// Durable call sequence within the program.
    pub call_seq: u64,
    /// Outbound verb.
    pub verb: String,
    /// Frozen program-authored body.
    pub payload: Vec<u8>,
    /// Whether the channel honors the ledger's idempotency key. Persisted
    /// rather than assumed: getting this wrong turns an ambiguous send into a
    /// duplicate one. Derived from the connector's descriptor when one
    /// describes the channel (FIX 2774).
    pub idempotency_supported: bool,
    /// Email subject (FIX 11641): `Some` on channel `email`, `None` on any
    /// other channel, enforced at the checked doors. Small structured data:
    /// it rides the program row directly, never a filed blob.
    pub subject: Option<String>,
}

/// One step of a campaign program.
///
/// The step is the single persisted source for BOTH halves of the consequence:
/// the `campaign.member` channel row (channel, consent basis, sticky sender)
/// and, when present, the outward call. A cohort row with no channel would be
/// an unauthorized send waiting to happen, which is why CA-01 rejects one — so
/// enrollment without a resolvable step fails closed rather than writing a
/// channel-less member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CampaignProgramStep {
    /// Row schema version.
    pub schema_version: u32,
    /// Owning program.
    pub program_ref: EntityId,
    /// Step identity.
    pub step_ref: EntityId,
    /// Normalized channel token.
    pub channel: String,
    /// Sticky sender identity for this channel.
    pub sender_ref: EntityId,
    /// Evidence entity authorizing contact on this channel.
    pub basis_evidence: EntityId,
    /// Outward leg; absent means "enroll, send nothing".
    pub outbound: Option<CampaignProgramOutbound>,
}

impl CampaignProgramStep {
    /// The CA-01 channel row this step authorizes.
    #[must_use]
    pub fn member_channel(&self) -> CampaignMemberChannel {
        CampaignMemberChannel {
            channel: self.channel.clone(),
            basis_evidence: self.basis_evidence,
            sender_ref: self.sender_ref,
        }
    }
}

/// The authored half of a campaign program, stored beside its binding by the
/// checked doors ([`create_campaign_program`] and its siblings).
///
/// No owner is stored: the program's owner is its campaign's, read through the
/// campaign, so there is no second owner to keep in step with the first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CampaignProgramDefinition {
    /// Operator-facing name.
    pub name: String,
    /// Monotonic version, incremented by every accepted write.
    pub definition_version: u64,
    /// Lifecycle state. An archived program enrolls no one.
    pub lifecycle: CampaignLifecycle,
    /// The program's steps, in authored order.
    pub step_refs: Vec<EntityId>,
    /// Creation time.
    pub created_at: u64,
    /// Last accepted write.
    pub updated_at: u64,
}

/// One step as an owner writes it: a [`CampaignProgramStep`] without the
/// fields the engine stamps (its schema version and owning program).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CampaignProgramStepDraft {
    /// Step identity, unique within the program. A program-local key the
    /// caller picks, so an audience can name its entry step in the same
    /// write; it grants nothing.
    pub step_ref: EntityId,
    /// Normalized channel token.
    pub channel: String,
    /// Sticky sender: a channel identity of this step's channel.
    pub sender_ref: EntityId,
    /// Evidence entity the step cites as its contact basis.
    pub basis_evidence: EntityId,
    /// Outward leg; absent means "enroll, send nothing".
    pub outbound: Option<CampaignProgramOutbound>,
}

/// A whole program definition as an owner writes it. Create takes one, and
/// update replaces the stored one with another, whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CampaignProgramDraft {
    /// Operator-facing name.
    pub name: String,
    /// Every step, in order.
    pub steps: Vec<CampaignProgramStepDraft>,
    /// The saved query the program enrolls from, and its entry step. `None`
    /// binds none.
    pub audience: Option<CampaignProgramAudience>,
}

/// An authored campaign program, as the checked doors return it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoredCampaignProgram {
    /// The binding row: identity, campaign and audience.
    pub program: CampaignProgram,
    /// The parent campaign's owner, which is the program's.
    pub owner_actor: EntityId,
    /// The authored definition.
    pub definition: CampaignProgramDefinition,
    /// The steps, in [`CampaignProgramDefinition::step_refs`] order.
    pub steps: Vec<CampaignProgramStep>,
    /// Whether a sweep enrolls from the audience now: the program is bound,
    /// it and its campaign are active, and the query is active and Wake or
    /// Reactive. A Manual or inactive query may be bound; it simply gets no
    /// automatic intake, and this says so.
    pub automatic_intake: bool,
}

/// Schema version shared by every campaign-local row this module persists.
pub const CAMPAIGN_ENROLLMENT_SCHEMA_VERSION: u32 = 1;
