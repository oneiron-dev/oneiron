//! Wire shapes of the four campaign program verbs (`vault.campaign.program.*`).
//!
//! A program's steps and its audience are one definition, so the verbs are
//! aggregate, modelled on the campaign's own four: create, read, a whole
//! replacement under a version CAS, and an archive that keeps every row. There
//! is no per-step put or delete and no hard delete. The checks live with the
//! rows (`crate::campaign::enrollment::create_campaign_program` and its
//! siblings); this file only moves between the wire and those types.
//!
//! These are the SDK rows' own input and output types. The HTTP facade, MCP
//! and code mode reach them through the verb table, and the resource routes
//! (`/campaigns/{campaign_ref}/programs`) through `invoke_campaign_surface`,
//! so every door decodes the same shapes.

use serde::{Deserialize, Serialize};

use super::CampaignLifecycle;
use super::parse::invalid;
use crate::campaign::claims::normalize_campaign_pack_token;
use crate::campaign::enrollment::{
    AuthoredCampaignProgram, CAMPAIGN_ENROLLMENT_SCHEMA_VERSION, CampaignProgramAudience,
    CampaignProgramDraft, CampaignProgramOutbound, CampaignProgramStep, CampaignProgramStepDraft,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;

/// The step slots a program write cites records in. Each must resolve under
/// the writer's own scoped read (OF-063's admission). The facade checks them,
/// so the resource routes meet the check as the SDK doors do. Readable is not
/// consent: consent is checked per recipient at dispatch.
pub(crate) const CAMPAIGN_PROGRAM_STEP_REFS: &[&str] =
    &["/steps/*/basis_evidence", "/steps/*/sender_ref"];

/// One program step on the wire.
///
/// `step_ref` is a program-local id the caller picks (32 hex), unique within
/// the program, so an audience can name its entry step in the same write; it
/// grants nothing. `channel` is normalized (trimmed, lowercased) on the way
/// in. `sender_ref` must be a live channel identity of the step's channel that
/// the writer can read, and `basis_evidence` a record the writer can read.
/// Neither is proven to be consent here: consent is checked per recipient at
/// dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignProgramStepSpec {
    /// Program-local step id.
    #[schemars(with = "String")]
    #[serde(with = "crate::entity_id::serde_hex")]
    pub step_ref: EntityId,
    /// Channel token.
    pub channel: String,
    /// Sticky sender: a channel identity of this step's channel.
    #[schemars(with = "String")]
    #[serde(with = "crate::entity_id::serde_hex")]
    pub sender_ref: EntityId,
    /// Evidence the step cites as its contact basis.
    #[schemars(with = "String")]
    #[serde(with = "crate::entity_id::serde_hex")]
    pub basis_evidence: EntityId,
    /// Outward leg; absent or null enrolls and sends nothing.
    #[serde(default)]
    pub outbound: Option<CampaignProgramOutboundSpec>,
}

/// A step's outward leg on the wire.
///
/// `call_seq` is durable program state: keep it unchanged across updates for
/// the same send, because the send's intent id derives from it. `payload` is
/// the frozen body as lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignProgramOutboundSpec {
    /// Durable call sequence within the program.
    pub call_seq: u64,
    /// Outbound verb.
    pub verb: String,
    /// Frozen program-authored body, lowercase hex.
    pub payload: String,
    /// Whether the channel honors the ledger's idempotency key.
    pub idempotency_supported: bool,
}

/// A program's audience on the wire: the saved query whose entries enroll,
/// and the step of this program they enroll at.
///
/// The query must be the campaign owner's. A Manual or inactive query may be
/// bound: it gets no automatic intake, and the record's `automatic_intake`
/// says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignProgramAudienceSpec {
    /// The saved query whose entries enroll.
    #[schemars(with = "String")]
    #[serde(with = "crate::entity_id::serde_hex")]
    pub query_ref: EntityId,
    /// The step an entry enrolls at; one of this program's `steps`.
    #[schemars(with = "String")]
    #[serde(with = "crate::entity_id::serde_hex")]
    pub entry_step_ref: EntityId,
}

/// `vault.campaign.program.create`'s input.
///
/// There is no owner field: the program's owner is its campaign's, and the
/// campaign must be the caller's own and active.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateCampaignProgramRequest {
    /// Definition schema version; 1.
    #[serde(default = "program_schema_version")]
    pub schema_version: u32,
    /// The campaign the program belongs to, for good.
    #[schemars(with = "String")]
    #[serde(with = "crate::entity_id::serde_hex")]
    pub campaign_ref: EntityId,
    /// Operator-facing name.
    pub name: String,
    /// Every step, in order.
    #[serde(default)]
    pub steps: Vec<CampaignProgramStepSpec>,
    /// The saved query the program enrolls from; absent or null binds none.
    #[serde(default)]
    pub audience: Option<CampaignProgramAudienceSpec>,
}

/// `vault.campaign.program.read`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignProgramReadRequest {
    /// The program's campaign.
    #[schemars(with = "String")]
    #[serde(with = "crate::entity_id::serde_hex")]
    pub campaign_ref: EntityId,
    /// The program.
    #[schemars(with = "String")]
    #[serde(with = "crate::entity_id::serde_hex")]
    pub program_ref: EntityId,
}

/// `vault.campaign.program.update`'s input: a whole replacement under a
/// version CAS.
///
/// `steps` replaces every step: a dropped step is deleted, and work queued at
/// it fails closed. `audience` absent or null unbinds the program. The
/// campaign stays the program's parent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateCampaignProgramRequest {
    /// The program's campaign.
    #[schemars(with = "String")]
    #[serde(with = "crate::entity_id::serde_hex")]
    pub campaign_ref: EntityId,
    /// The program.
    #[schemars(with = "String")]
    #[serde(with = "crate::entity_id::serde_hex")]
    pub program_ref: EntityId,
    /// Version the caller believes is current; the compare half of the CAS.
    pub expected_definition_version: u64,
    /// Replacement name.
    pub name: String,
    /// Replacement steps, in order.
    pub steps: Vec<CampaignProgramStepSpec>,
    /// Replacement audience; absent or null unbinds.
    #[serde(default)]
    pub audience: Option<CampaignProgramAudienceSpec>,
}

/// `vault.campaign.program.archive`'s input. Archive keeps the program, its
/// steps and its audience readable; it enrolls no one afterwards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveCampaignProgramRequest {
    /// The program's campaign.
    #[schemars(with = "String")]
    #[serde(with = "crate::entity_id::serde_hex")]
    pub campaign_ref: EntityId,
    /// The program.
    #[schemars(with = "String")]
    #[serde(with = "crate::entity_id::serde_hex")]
    pub program_ref: EntityId,
    /// Version the caller believes is current.
    pub expected_definition_version: u64,
}

/// A program's lifecycle on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignProgramLifecycle {
    /// Enrolls from its audience.
    Active,
    /// Retired: readable, enrolls no one, never re-opened.
    Archived,
}

/// A stored program's definition on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignProgramDefinitionView {
    /// Definition schema version.
    pub schema_version: u32,
    /// The program's owner: its campaign's.
    #[serde(with = "crate::entity_id::serde_hex")]
    pub owner_actor: EntityId,
    /// The program's campaign.
    #[serde(with = "crate::entity_id::serde_hex")]
    pub campaign_ref: EntityId,
    /// Operator-facing name.
    pub name: String,
    /// Monotonic version, incremented by every accepted write.
    pub definition_version: u64,
    /// Lifecycle state.
    pub lifecycle: CampaignProgramLifecycle,
    /// Every step, in order.
    pub steps: Vec<CampaignProgramStepSpec>,
    /// The bound audience, or null.
    pub audience: Option<CampaignProgramAudienceSpec>,
}

/// A stored campaign program, as the create, update and archive verbs answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignProgramRecord {
    /// Program identity.
    #[serde(with = "crate::entity_id::serde_hex")]
    pub program_ref: EntityId,
    /// Current definition.
    pub definition: CampaignProgramDefinitionView,
    /// Whether a sweep enrolls from the audience now: it is bound, the program
    /// and its campaign are active, and the query is active and Wake or
    /// Reactive. A bound Manual or inactive query reads `false`.
    pub automatic_intake: bool,
    /// Creation time.
    pub created_at: u64,
    /// Last accepted write.
    pub updated_at: u64,
}

/// `vault.campaign.program.read`'s output. A program that is absent, of
/// another campaign, or under a campaign the caller does not own reads
/// `found: false` with a null `record`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignProgramReadResult {
    /// Whether the program was found.
    pub found: bool,
    /// The program, when found.
    pub record: Option<CampaignProgramRecord>,
}

const fn program_schema_version() -> u32 {
    CAMPAIGN_ENROLLMENT_SCHEMA_VERSION
}

impl CreateCampaignProgramRequest {
    /// The engine draft this request writes.
    pub(crate) fn draft(&self) -> Result<CampaignProgramDraft> {
        program_draft(&self.name, &self.steps, self.audience)
    }
}

impl UpdateCampaignProgramRequest {
    /// The engine draft this request writes.
    pub(crate) fn draft(&self) -> Result<CampaignProgramDraft> {
        program_draft(&self.name, &self.steps, self.audience)
    }
}

fn program_draft(
    name: &str,
    steps: &[CampaignProgramStepSpec],
    audience: Option<CampaignProgramAudienceSpec>,
) -> Result<CampaignProgramDraft> {
    Ok(CampaignProgramDraft {
        name: name.to_owned(),
        steps: steps
            .iter()
            .map(CampaignProgramStepSpec::draft)
            .collect::<Result<_>>()?,
        audience: audience.map(|audience| CampaignProgramAudience {
            query_ref: audience.query_ref,
            entry_step_ref: audience.entry_step_ref,
        }),
    })
}

impl CampaignProgramStepSpec {
    fn draft(&self) -> Result<CampaignProgramStepDraft> {
        Ok(CampaignProgramStepDraft {
            step_ref: self.step_ref,
            channel: normalize_campaign_pack_token(&self.channel),
            sender_ref: self.sender_ref,
            basis_evidence: self.basis_evidence,
            outbound: self
                .outbound
                .as_ref()
                .map(CampaignProgramOutboundSpec::outbound)
                .transpose()?,
        })
    }

    fn of(step: &CampaignProgramStep) -> Self {
        Self {
            step_ref: step.step_ref,
            channel: step.channel.clone(),
            sender_ref: step.sender_ref,
            basis_evidence: step.basis_evidence,
            outbound: step
                .outbound
                .as_ref()
                .map(|outbound| CampaignProgramOutboundSpec {
                    call_seq: outbound.call_seq,
                    verb: outbound.verb.clone(),
                    payload: bytes_to_hex_lower(&outbound.payload),
                    idempotency_supported: outbound.idempotency_supported,
                }),
        }
    }
}

impl CampaignProgramOutboundSpec {
    fn outbound(&self) -> Result<CampaignProgramOutbound> {
        Ok(CampaignProgramOutbound {
            call_seq: self.call_seq,
            verb: self.verb.clone(),
            payload: payload_from_hex(&self.payload)?,
            idempotency_supported: self.idempotency_supported,
        })
    }
}

/// Decodes a lowercase-hex payload.
fn payload_from_hex(hex: &str) -> Result<Vec<u8>> {
    let not_hex = || invalid("a step's outbound payload must be lowercase hex");
    if !hex.len().is_multiple_of(2) {
        return Err(not_hex());
    }
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| match (hex_nibble(pair[0]), hex_nibble(pair[1])) {
            (Some(high), Some(low)) => Ok((high << 4) | low),
            _ => Err(not_hex()),
        })
        .collect()
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// The wire record of an authored program.
pub(crate) fn campaign_program_record(program: &AuthoredCampaignProgram) -> CampaignProgramRecord {
    CampaignProgramRecord {
        program_ref: program.program.program_ref,
        definition: CampaignProgramDefinitionView {
            schema_version: program.program.schema_version,
            owner_actor: program.owner_actor,
            campaign_ref: program.program.campaign_ref,
            name: program.definition.name.clone(),
            definition_version: program.definition.definition_version,
            lifecycle: match program.definition.lifecycle {
                CampaignLifecycle::Active => CampaignProgramLifecycle::Active,
                CampaignLifecycle::Archived => CampaignProgramLifecycle::Archived,
            },
            steps: program
                .steps
                .iter()
                .map(CampaignProgramStepSpec::of)
                .collect(),
            audience: program
                .program
                .audience
                .map(|audience| CampaignProgramAudienceSpec {
                    query_ref: audience.query_ref,
                    entry_step_ref: audience.entry_step_ref,
                }),
        },
        automatic_intake: program.automatic_intake,
        created_at: program.definition.created_at,
        updated_at: program.definition.updated_at,
    }
}
