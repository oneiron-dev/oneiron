//! Persisted campaign program and step state authorizing both halves of the consequence.

use serde::{Deserialize, Serialize};

use super::storage::{
    CAMPAIGN_ENROLLMENT_SCHEMA_VERSION, CAMPAIGN_PROGRAM_PREFIX, CAMPAIGN_PROGRAM_STEP_PREFIX,
    bytes_from_hex, from_row, id_from_hex, keyed, pin_schema, put_meta, read_meta, to_row,
};
use crate::Vault;
use crate::campaign::claims::CampaignMemberChannel;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// Campaign program state (the outward leg's persisted authority)
// ---------------------------------------------------------------------------

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
    /// duplicate one.
    pub idempotency_supported: bool,
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

/// Persists a campaign program row.
///
/// # Errors
///
/// Storage errors propagate.
pub fn put_campaign_program(vault: &Vault, program: &CampaignProgram) -> Result<()> {
    put_meta(
        vault,
        &keyed(CAMPAIGN_PROGRAM_PREFIX, &[program.program_ref.as_bytes()]),
        &encode_program(program)?,
    )
}

/// Reads a campaign program row.
///
/// # Errors
///
/// Storage errors propagate; a malformed row is [`Error::CorruptedIndex`].
pub fn campaign_program(vault: &Vault, program_ref: EntityId) -> Result<Option<CampaignProgram>> {
    read_meta(
        vault,
        &keyed(CAMPAIGN_PROGRAM_PREFIX, &[program_ref.as_bytes()]),
    )?
    .map(|raw| decode_program(program_ref, &raw))
    .transpose()
}

/// Persists a campaign program step.
///
/// # Errors
///
/// Storage errors propagate.
pub fn put_campaign_program_step(vault: &Vault, step: &CampaignProgramStep) -> Result<()> {
    put_meta(
        vault,
        &program_step_key(step.program_ref, step.step_ref),
        &encode_program_step(step)?,
    )
}

/// Reads a campaign program step.
///
/// # Errors
///
/// Storage errors propagate; a malformed row is [`Error::CorruptedIndex`].
pub fn campaign_program_step(
    vault: &Vault,
    program_ref: EntityId,
    step_ref: EntityId,
) -> Result<Option<CampaignProgramStep>> {
    read_meta(vault, &program_step_key(program_ref, step_ref))?
        .map(|raw| decode_program_step(program_ref, step_ref, &raw))
        .transpose()
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgramRow {
    schema_version: u32,
    campaign_ref: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgramStepRow {
    schema_version: u32,
    channel: String,
    sender_ref: String,
    basis_evidence: String,
    outbound: Option<ProgramOutboundRow>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgramOutboundRow {
    call_seq: u64,
    verb: String,
    payload: String,
    idempotency_supported: bool,
}

fn encode_program(program: &CampaignProgram) -> Result<Vec<u8>> {
    to_row(&ProgramRow {
        schema_version: CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
        campaign_ref: program.campaign_ref.to_hex(),
    })
}

fn decode_program(program_ref: EntityId, raw: &[u8]) -> Result<CampaignProgram> {
    const CONTEXT: &str = "campaign program";
    let row: ProgramRow = from_row(raw, CONTEXT)?;
    pin_schema(row.schema_version, CONTEXT)?;
    Ok(CampaignProgram {
        schema_version: row.schema_version,
        program_ref,
        campaign_ref: id_from_hex(&row.campaign_ref, CONTEXT)?,
    })
}

fn encode_program_step(step: &CampaignProgramStep) -> Result<Vec<u8>> {
    to_row(&ProgramStepRow {
        schema_version: CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
        channel: step.channel.clone(),
        sender_ref: step.sender_ref.to_hex(),
        basis_evidence: step.basis_evidence.to_hex(),
        outbound: step.outbound.as_ref().map(|outbound| ProgramOutboundRow {
            call_seq: outbound.call_seq,
            verb: outbound.verb.clone(),
            payload: bytes_to_hex_lower(&outbound.payload),
            idempotency_supported: outbound.idempotency_supported,
        }),
    })
}

fn decode_program_step(
    program_ref: EntityId,
    step_ref: EntityId,
    raw: &[u8],
) -> Result<CampaignProgramStep> {
    const CONTEXT: &str = "campaign program step";
    let row: ProgramStepRow = from_row(raw, CONTEXT)?;
    pin_schema(row.schema_version, CONTEXT)?;
    let outbound = row
        .outbound
        .map(|outbound| {
            Ok::<_, Error>(CampaignProgramOutbound {
                call_seq: outbound.call_seq,
                verb: outbound.verb,
                payload: bytes_from_hex(&outbound.payload, CONTEXT)?,
                idempotency_supported: outbound.idempotency_supported,
            })
        })
        .transpose()?;
    Ok(CampaignProgramStep {
        schema_version: row.schema_version,
        program_ref,
        step_ref,
        channel: row.channel,
        sender_ref: id_from_hex(&row.sender_ref, CONTEXT)?,
        basis_evidence: id_from_hex(&row.basis_evidence, CONTEXT)?,
        outbound,
    })
}

fn program_step_key(program_ref: EntityId, step_ref: EntityId) -> Vec<u8> {
    keyed(
        CAMPAIGN_PROGRAM_STEP_PREFIX,
        &[program_ref.as_bytes(), step_ref.as_bytes()],
    )
}
