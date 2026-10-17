//! Persisted campaign program and step state authorizing both halves of the consequence.

use serde::{Deserialize, Serialize};

use super::storage::{
    CAMPAIGN_ENROLLMENT_SCHEMA_VERSION, bytes_from_hex, id_from_hex, invalid, pin_schema,
};
use crate::Vault;
use crate::campaign::claims::CampaignMemberChannel;
use crate::campaign::surface::{CampaignLifecycle, read_campaign};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::side_table::{self, LegacyJson, SideTable};

/// Persisted binding from a campaign program to the campaign it belongs to.
/// Key: the program id.
const PROGRAM: SideTable<EntityId, ProgramRow, LegacyJson> =
    SideTable::new(&side_table::CAMPAIGN_PROGRAM);
/// One step of a campaign program. Key: the program id then the step id.
const PROGRAM_STEP: SideTable<(EntityId, EntityId), ProgramStepRow, LegacyJson> =
    SideTable::new(&side_table::CAMPAIGN_PROGRAM_STEP);

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
/// This is the one door that writes programs, so an audience is validated
/// here: the query and the campaign share an owner, the campaign is active,
/// and the entry step is one of this program's own steps. Any number of
/// programs may enroll from one query; only a second program of the SAME
/// campaign on the same query is refused (`audience_taken_by`). That check
/// shares the write's transaction.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when the audience's query does not exist;
/// [`Error::InvalidConfig`] for an audience the rules above refuse; storage
/// errors propagate.
pub fn put_campaign_program(vault: &Vault, program: &CampaignProgram) -> Result<()> {
    if let Some(audience) = &program.audience {
        validate_audience(vault, program, audience)?;
    }
    vault.with_write_txn_grouped(|wtxn| {
        if let Some(audience) = &program.audience
            && programs_for_query_in_txn(vault, wtxn, audience.query_ref)?
                .iter()
                .any(|other| audience_taken_by(other, program))
        {
            return Err(invalid(
                "another program of this campaign already enrolls from this saved query",
            ));
        }
        PROGRAM.put(
            &vault.store,
            wtxn,
            &program.program_ref,
            &encode_program(program),
        )?;
        Ok(())
    })
}

/// Reads a campaign program row.
///
/// # Errors
///
/// Storage errors propagate; a malformed row is [`Error::CorruptedIndex`].
pub fn campaign_program(vault: &Vault, program_ref: EntityId) -> Result<Option<CampaignProgram>> {
    let rtxn = vault.store.env.read_txn()?;
    PROGRAM
        .get(&vault.store, &rtxn, &program_ref)?
        .map(|row| decode_program(program_ref, row))
        .transpose()
}

/// The programs that name `query_ref` as their audience, in program-id
/// order. [`put_campaign_program`] holds them to one program per campaign.
///
/// # Errors
///
/// Storage errors propagate; a malformed row is [`Error::CorruptedIndex`].
pub fn campaign_programs_for_query(
    vault: &Vault,
    query_ref: EntityId,
) -> Result<Vec<CampaignProgram>> {
    let rtxn = vault.store.env.read_txn()?;
    programs_for_query_in_txn(vault, &rtxn, query_ref)
}

fn programs_for_query_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query_ref: EntityId,
) -> Result<Vec<CampaignProgram>> {
    let mut programs = Vec::new();
    for (program_ref, row) in PROGRAM.scan(&vault.store, txn)? {
        let program = decode_program(program_ref, row)?;
        if program
            .audience
            .is_some_and(|audience| audience.query_ref == query_ref)
        {
            programs.push(program);
        }
    }
    Ok(programs)
}

/// Whether `other`, a program already enrolling from `program`'s audience
/// query, takes that audience from `program`: it is another program of the
/// same campaign. A campaign holds one `campaign.member` claim per person and
/// one epoch sequence per query, so two of its programs on one query would
/// race for the same head, and the second's entry would be dropped as stale.
/// Programs of different campaigns never conflict: each enrolls into its own
/// campaign.
fn audience_taken_by(other: &CampaignProgram, program: &CampaignProgram) -> bool {
    other.program_ref != program.program_ref && other.campaign_ref == program.campaign_ref
}

/// The audience rules that need no write transaction: the query and the
/// campaign share an owner, the campaign is active, and the entry step is
/// this program's own.
fn validate_audience(
    vault: &Vault,
    program: &CampaignProgram,
    audience: &CampaignProgramAudience,
) -> Result<()> {
    let query = crate::saved_query::load_saved_query(vault, audience.query_ref)?
        .ok_or(Error::EntityNotFound)?;
    let campaign = read_campaign(vault, query.definition.owner_actor, program.campaign_ref)?
        .ok_or_else(|| {
            invalid("the campaign is absent or not owned by the audience query's owner")
        })?;
    if campaign.definition.lifecycle != CampaignLifecycle::Active {
        return Err(invalid("an archived campaign takes no audience"));
    }
    if campaign_program_step(vault, program.program_ref, audience.entry_step_ref)?.is_none() {
        return Err(invalid(
            "the audience's entry step is not a step of this program",
        ));
    }
    Ok(())
}

/// Persists a campaign program step.
///
/// # Errors
///
/// Storage errors propagate.
pub fn put_campaign_program_step(vault: &Vault, step: &CampaignProgramStep) -> Result<()> {
    vault.with_write_txn_grouped(|wtxn| {
        PROGRAM_STEP.put(
            &vault.store,
            wtxn,
            &(step.program_ref, step.step_ref),
            &encode_program_step(step),
        )?;
        Ok(())
    })
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
    let rtxn = vault.store.env.read_txn()?;
    PROGRAM_STEP
        .get(&vault.store, &rtxn, &(program_ref, step_ref))?
        .map(|row| decode_program_step(program_ref, step_ref, row))
        .transpose()
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgramRow {
    schema_version: u32,
    campaign_ref: String,
    audience: Option<ProgramAudienceRow>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgramAudienceRow {
    query_ref: String,
    entry_step_ref: String,
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

fn encode_program(program: &CampaignProgram) -> ProgramRow {
    ProgramRow {
        schema_version: CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
        campaign_ref: program.campaign_ref.to_hex(),
        audience: program.audience.map(|audience| ProgramAudienceRow {
            query_ref: audience.query_ref.to_hex(),
            entry_step_ref: audience.entry_step_ref.to_hex(),
        }),
    }
}

fn decode_program(program_ref: EntityId, row: ProgramRow) -> Result<CampaignProgram> {
    const CONTEXT: &str = "campaign program";
    pin_schema(row.schema_version, CONTEXT)?;
    let audience = row
        .audience
        .map(|audience| {
            Ok::<_, Error>(CampaignProgramAudience {
                query_ref: id_from_hex(&audience.query_ref, CONTEXT)?,
                entry_step_ref: id_from_hex(&audience.entry_step_ref, CONTEXT)?,
            })
        })
        .transpose()?;
    Ok(CampaignProgram {
        schema_version: row.schema_version,
        program_ref,
        campaign_ref: id_from_hex(&row.campaign_ref, CONTEXT)?,
        audience,
    })
}

fn encode_program_step(step: &CampaignProgramStep) -> ProgramStepRow {
    ProgramStepRow {
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
    }
}

fn decode_program_step(
    program_ref: EntityId,
    step_ref: EntityId,
    row: ProgramStepRow,
) -> Result<CampaignProgramStep> {
    const CONTEXT: &str = "campaign program step";
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
