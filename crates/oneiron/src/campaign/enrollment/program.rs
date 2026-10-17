//! Persisted campaign program and step state authorizing both halves of the consequence.

use serde::{Deserialize, Serialize};

use super::storage::{
    CAMPAIGN_ENROLLMENT_SCHEMA_VERSION, bytes_from_hex, id_from_hex, invalid, pin_schema,
};
use crate::Vault;
use crate::campaign::claims::{CampaignMemberChannel, normalize_campaign_pack_token};
use crate::campaign::surface::{
    CAMPAIGN_NAME_MAX_BYTES, CampaignLifecycle, CampaignRecord, campaign_type_byte,
    load_campaign_in_txn, owned_campaign_in_txn, read_campaign,
};
use crate::counterparty_contact::normalize_channel_class;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::ports::TombstoneStoreRead;
use crate::saved_query::{
    EvalMode, SavedQueryLifecycle, SavedQueryRecord, load_saved_query_in_txn,
};
use crate::side_table::{self, LegacyJson, SideTable};

/// Persisted binding from a campaign program to the campaign it belongs to.
/// Key: the program id.
const PROGRAM: SideTable<EntityId, ProgramRow, LegacyJson> =
    SideTable::new(&side_table::CAMPAIGN_PROGRAM);
/// One step of a campaign program. Key: the program id then the step id.
const PROGRAM_STEP: SideTable<(EntityId, EntityId), ProgramStepRow, LegacyJson> =
    SideTable::new(&side_table::CAMPAIGN_PROGRAM_STEP);

/// The most campaign programs that may name one saved query as their audience.
///
/// One, because detection history, the membership watermark and the
/// enrollment dedupe key are all keyed by `(query, entity)` with no campaign
/// or program: a second program enrolling from the same query would read the
/// first one's entry as "already entered" and never enroll. A query that
/// should feed two campaigns is two parameterized query instances, each with
/// its own membership (ARCH-0059).
pub const MAX_CAMPAIGN_PROGRAMS_PER_AUDIENCE_QUERY: usize = 1;

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
/// the entry step is one of this program's own steps, and no other program
/// already enrolls from the query
/// ([`MAX_CAMPAIGN_PROGRAMS_PER_AUDIENCE_QUERY`]). The last check shares the
/// write's transaction, so two programs cannot both claim one query.
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
        if let Some(audience) = &program.audience {
            let bound = programs_for_query_in_txn(vault, wtxn, audience.query_ref)?
                .iter()
                .filter(|other| other.program_ref != program.program_ref)
                .count();
            if bound >= MAX_CAMPAIGN_PROGRAMS_PER_AUDIENCE_QUERY {
                return Err(invalid(
                    "another campaign program already enrolls from this saved query",
                ));
            }
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
/// order. [`put_campaign_program`] holds them to
/// [`MAX_CAMPAIGN_PROGRAMS_PER_AUDIENCE_QUERY`].
///
/// # Errors
///
/// Storage errors propagate; a malformed row is [`Error::CorruptedIndex`].
pub fn campaign_programs_for_query(
    vault: &Vault,
    query_ref: EntityId,
) -> Result<Vec<CampaignProgram>> {
    let campaign_kind = campaign_type_byte(vault)?;
    let rtxn = vault.store.env.read_txn()?;
    // Archive stops intake: a program that no longer enrolls (archived, or
    // of an archived campaign) is no audience binding to sweep for.
    let mut live = Vec::new();
    for program in programs_for_query_in_txn(vault, &rtxn, query_ref)? {
        if program_enrolls_in_txn(vault, &rtxn, campaign_kind, &program)? {
            live.push(program);
        }
    }
    Ok(live)
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

// ---------------------------------------------------------------------------
// The checked authoring doors (`vault.campaign.program.*`)
// ---------------------------------------------------------------------------

/// Longest accepted campaign program name, in bytes: the campaign's own bound,
/// for the same reason (every read echoes it, so an unbounded one is an
/// unbounded row).
pub const CAMPAIGN_PROGRAM_NAME_MAX_BYTES: usize = CAMPAIGN_NAME_MAX_BYTES;

/// The most steps one campaign program holds. Every read assembles the whole
/// step list, so an unbounded one is an unbounded read.
pub const CAMPAIGN_PROGRAM_MAX_STEPS: usize = 64;

/// Longest accepted step channel token, in bytes: CA-01's bound on a
/// `campaign.member` channel, which every enrollment at the step copies, so a
/// longer token could never enroll anyone.
pub const CAMPAIGN_PROGRAM_STEP_CHANNEL_MAX_BYTES: usize = 512;

/// Longest accepted outbound verb on a step, in bytes.
pub const CAMPAIGN_PROGRAM_OUTBOUND_VERB_MAX_BYTES: usize = 200;

/// Largest accepted frozen outbound payload on a step, in bytes.
pub const CAMPAIGN_PROGRAM_OUTBOUND_PAYLOAD_MAX_BYTES: usize = 64 * 1024;

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

/// Creates an authored campaign program under a campaign the principal owns.
///
/// The owner is the campaign's, read through `owned_campaign_in_txn`, the
/// check `update_campaign` makes, so a caller who does not own the campaign
/// gets the answer an absent one gets. The campaign must be active. The
/// sender, audience and binding checks (`write_program_in_txn`) share the
/// write's one transaction.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when the campaign is absent or another
/// principal's; [`Error::InvalidConfig`] when the draft fails validation, the
/// campaign is archived, a sender is not a channel identity of its step's
/// channel, or the audience query is absent, another owner's or already taken;
/// storage errors propagate.
pub fn create_campaign_program(
    vault: &Vault,
    authenticated_principal: EntityId,
    campaign_ref: EntityId,
    schema_version: u32,
    draft: &CampaignProgramDraft,
    now: u64,
) -> Result<AuthoredCampaignProgram> {
    if schema_version != CAMPAIGN_ENROLLMENT_SCHEMA_VERSION {
        return Err(invalid("campaign program schema_version is unsupported"));
    }
    validate_program_draft(draft)?;
    let campaign_kind = campaign_type_byte(vault)?;
    let program_ref = vault.store.clock.entity_id()?;
    vault.with_write_txn_grouped(|wtxn| {
        let campaign = owned_campaign_in_txn(
            vault,
            wtxn,
            authenticated_principal,
            campaign_ref,
            campaign_kind,
        )?;
        require_active_campaign(&campaign)?;
        write_program_in_txn(
            vault,
            wtxn,
            ProgramWrite {
                campaign_kind,
                campaign: &campaign,
                program: CampaignProgram {
                    schema_version: CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
                    program_ref,
                    campaign_ref,
                    audience: draft.audience,
                },
                definition: CampaignProgramDefinition {
                    name: draft.name.clone(),
                    definition_version: 1,
                    lifecycle: CampaignLifecycle::Active,
                    step_refs: draft.steps.iter().map(|step| step.step_ref).collect(),
                    created_at: now,
                    updated_at: now,
                },
                steps: &draft.steps,
                replaced_steps: &[],
            },
        )
    })
}

/// Reads an authored campaign program under a campaign the principal owns.
///
/// A campaign the principal does not own, a program of another campaign and a
/// program no checked door wrote all read as absent.
///
/// # Errors
///
/// Storage errors propagate; a malformed row is [`Error::CorruptedIndex`].
pub fn read_campaign_program(
    vault: &Vault,
    authenticated_principal: EntityId,
    campaign_ref: EntityId,
    program_ref: EntityId,
) -> Result<Option<AuthoredCampaignProgram>> {
    let campaign_kind = campaign_type_byte(vault)?;
    let rtxn = vault.store.env.read_txn()?;
    let Some(campaign) = load_campaign_in_txn(vault, &rtxn, campaign_ref, campaign_kind)?
        .filter(|campaign| campaign.definition.owner_actor == authenticated_principal)
    else {
        return Ok(None);
    };
    let Some((program, definition)) =
        authored_program_in_txn(vault, &rtxn, &campaign, program_ref)?
    else {
        return Ok(None);
    };
    let steps = program_steps_in_txn(vault, &rtxn, &program, &definition)?;
    let query = match program.audience {
        Some(audience) => load_saved_query_in_txn(vault, &rtxn, audience.query_ref)?,
        None => None,
    };
    let automatic_intake = intake_open(&campaign, &definition, query.as_ref());
    Ok(Some(AuthoredCampaignProgram {
        program,
        owner_actor: campaign.definition.owner_actor,
        definition,
        steps,
        automatic_intake,
    }))
}

/// Replaces an authored program's definition, steps and audience whole, under
/// a version CAS.
///
/// The compare and the write share one transaction, as `update_campaign`'s do.
/// The campaign stays the program's parent, the lifecycle is kept, and a step
/// the replacement drops is deleted, so work queued at it fails closed
/// (`require_program_step_enrolls`). An archived program, or any program of
/// an archived campaign, is read-only.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when the campaign or program is absent or not the
/// principal's; [`Error::ConcurrentWrite`] when the expected version is not
/// current; [`Error::InvalidConfig`] as [`create_campaign_program`], and for
/// an archived program or campaign.
pub fn update_campaign_program(
    vault: &Vault,
    authenticated_principal: EntityId,
    campaign_ref: EntityId,
    program_ref: EntityId,
    expected_definition_version: u64,
    draft: &CampaignProgramDraft,
    now: u64,
) -> Result<AuthoredCampaignProgram> {
    validate_program_draft(draft)?;
    let campaign_kind = campaign_type_byte(vault)?;
    vault.with_write_txn_grouped(|wtxn| {
        let campaign = owned_campaign_in_txn(
            vault,
            wtxn,
            authenticated_principal,
            campaign_ref,
            campaign_kind,
        )?;
        let (program, current) = authored_program_in_txn(vault, wtxn, &campaign, program_ref)?
            .ok_or(Error::EntityNotFound)?;
        require_expected_program_version(&current, expected_definition_version)?;
        require_active_campaign(&campaign)?;
        if current.lifecycle != CampaignLifecycle::Active {
            return Err(invalid("an archived campaign program is read-only"));
        }
        write_program_in_txn(
            vault,
            wtxn,
            ProgramWrite {
                campaign_kind,
                campaign: &campaign,
                program: CampaignProgram {
                    audience: draft.audience,
                    ..program
                },
                definition: CampaignProgramDefinition {
                    name: draft.name.clone(),
                    definition_version: next_program_version(current.definition_version)?,
                    lifecycle: current.lifecycle,
                    step_refs: draft.steps.iter().map(|step| step.step_ref).collect(),
                    created_at: current.created_at,
                    updated_at: now,
                },
                steps: &draft.steps,
                replaced_steps: &current.step_refs,
            },
        )
    })
}

/// Archives an authored program: a lifecycle transition, never a delete. The
/// program, its steps and its audience stay readable; it enrolls no one from
/// now on, and work already queued for it fails closed
/// (`require_program_step_enrolls`). An archived program no longer holds its
/// audience query (`require_audience_query_free_in_txn`).
///
/// # Errors
///
/// [`Error::EntityNotFound`] when the campaign or program is absent or not the
/// principal's; [`Error::ConcurrentWrite`] when the expected version is stale.
pub fn archive_campaign_program(
    vault: &Vault,
    authenticated_principal: EntityId,
    campaign_ref: EntityId,
    program_ref: EntityId,
    expected_definition_version: u64,
    now: u64,
) -> Result<AuthoredCampaignProgram> {
    let campaign_kind = campaign_type_byte(vault)?;
    vault.with_write_txn_grouped(|wtxn| {
        let campaign = owned_campaign_in_txn(
            vault,
            wtxn,
            authenticated_principal,
            campaign_ref,
            campaign_kind,
        )?;
        let (program, mut definition) =
            authored_program_in_txn(vault, wtxn, &campaign, program_ref)?
                .ok_or(Error::EntityNotFound)?;
        require_expected_program_version(&definition, expected_definition_version)?;
        definition.definition_version = next_program_version(definition.definition_version)?;
        definition.lifecycle = CampaignLifecycle::Archived;
        definition.updated_at = now;
        PROGRAM.put(
            &vault.store,
            wtxn,
            &program.program_ref,
            &encode_authored_program(&program, &definition),
        )?;
        let steps = program_steps_in_txn(vault, wtxn, &program, &definition)?;
        Ok(AuthoredCampaignProgram {
            program,
            owner_actor: campaign.definition.owner_actor,
            definition,
            steps,
            automatic_intake: false,
        })
    })
}

/// The check an enrollment attempt meets before it acts (ARCH-0059: archive
/// stops queued work, not only the sweep): the program and its campaign still
/// enroll, and the attempt's step is still one of the program's own. A step an
/// update dropped fails closed rather than resolving to whatever row holds its
/// ref now.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when the program or its campaign is archived or
/// absent, or the step was dropped; storage errors propagate.
pub(super) fn require_program_step_enrolls(
    vault: &Vault,
    program: &CampaignProgram,
    step_ref: EntityId,
) -> Result<()> {
    let campaign_kind = campaign_type_byte(vault)?;
    let rtxn = vault.store.env.read_txn()?;
    if !program_enrolls_in_txn(vault, &rtxn, campaign_kind, program)? {
        return Err(invalid(
            "the campaign program or its campaign is archived; nothing enrolls into it",
        ));
    }
    let dropped = stored_program_in_txn(vault, &rtxn, program.program_ref)?
        .and_then(|(_, definition)| definition)
        .is_some_and(|definition| !definition.step_refs.contains(&step_ref));
    if dropped {
        return Err(invalid(
            "the step is no longer part of its campaign program",
        ));
    }
    Ok(())
}

/// Whether `program` enrolls now: its campaign exists and is active, and its
/// authored definition, when a checked door wrote one, is not archived.
fn program_enrolls_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    campaign_kind: u8,
    program: &CampaignProgram,
) -> Result<bool> {
    let campaign_active = load_campaign_in_txn(vault, txn, program.campaign_ref, campaign_kind)?
        .is_some_and(|campaign| campaign.definition.lifecycle == CampaignLifecycle::Active);
    if !campaign_active {
        return Ok(false);
    }
    Ok(stored_program_in_txn(vault, txn, program.program_ref)?
        .and_then(|(_, definition)| definition)
        .is_none_or(|definition| definition.lifecycle == CampaignLifecycle::Active))
}

/// Everything one checked definition write lands.
struct ProgramWrite<'a> {
    campaign_kind: u8,
    campaign: &'a CampaignRecord,
    program: CampaignProgram,
    definition: CampaignProgramDefinition,
    steps: &'a [CampaignProgramStepDraft],
    /// The steps the stored definition held, for an update: those the new
    /// one drops are deleted.
    replaced_steps: &'a [EntityId],
}

/// Checks and lands one program definition inside the caller's write
/// transaction: every sender is a channel identity of its step's channel, the
/// audience query is the campaign owner's and free to bind, the dropped steps
/// go, and the steps and program rows are written.
fn write_program_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    write: ProgramWrite<'_>,
) -> Result<AuthoredCampaignProgram> {
    let ProgramWrite {
        campaign_kind,
        campaign,
        program,
        definition,
        steps,
        replaced_steps,
    } = write;
    for step in steps {
        require_step_sender_in_txn(vault, wtxn, step)?;
    }
    let query = match program.audience {
        Some(audience) => {
            let query = load_saved_query_in_txn(vault, wtxn, audience.query_ref)?
                .filter(|query| query.definition.owner_actor == campaign.definition.owner_actor)
                .ok_or_else(|| {
                    invalid("the audience query is absent or not owned by the campaign's owner")
                })?;
            require_audience_query_free_in_txn(
                vault,
                wtxn,
                campaign_kind,
                &program,
                audience.query_ref,
            )?;
            Some(query)
        }
        None => None,
    };
    for dropped in replaced_steps {
        if !definition.step_refs.contains(dropped) {
            PROGRAM_STEP.delete(&vault.store, wtxn, &(program.program_ref, *dropped))?;
        }
    }
    let rows: Vec<CampaignProgramStep> = steps
        .iter()
        .map(|step| CampaignProgramStep {
            schema_version: CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
            program_ref: program.program_ref,
            step_ref: step.step_ref,
            channel: step.channel.clone(),
            sender_ref: step.sender_ref,
            basis_evidence: step.basis_evidence,
            outbound: step.outbound.clone(),
        })
        .collect();
    for row in &rows {
        PROGRAM_STEP.put(
            &vault.store,
            wtxn,
            &(row.program_ref, row.step_ref),
            &encode_program_step(row),
        )?;
    }
    PROGRAM.put(
        &vault.store,
        wtxn,
        &program.program_ref,
        &encode_authored_program(&program, &definition),
    )?;
    let automatic_intake = intake_open(campaign, &definition, query.as_ref());
    Ok(AuthoredCampaignProgram {
        program,
        owner_actor: campaign.definition.owner_actor,
        definition,
        steps: rows,
        automatic_intake,
    })
}

/// The binding rule the checked doors apply inside their write: the rule
/// [`put_campaign_program`] holds a query to
/// ([`MAX_CAMPAIGN_PROGRAMS_PER_AUDIENCE_QUERY`]), counting only programs that
/// still enroll ([`program_enrolls_in_txn`]), so an archived program, or one of
/// an archived campaign, releases its query.
fn require_audience_query_free_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    campaign_kind: u8,
    program: &CampaignProgram,
    query_ref: EntityId,
) -> Result<()> {
    let mut bound: usize = 0;
    for other in programs_for_query_in_txn(vault, txn, query_ref)? {
        if other.program_ref != program.program_ref
            && program_enrolls_in_txn(vault, txn, campaign_kind, &other)?
        {
            bound = bound.saturating_add(1);
        }
    }
    if bound >= MAX_CAMPAIGN_PROGRAMS_PER_AUDIENCE_QUERY {
        return Err(invalid(
            "another campaign program already enrolls from this saved query",
        ));
    }
    Ok(())
}

/// A step's sender must be a live channel identity of the step's channel
/// class, the match sender selection makes. That the caller reaches it is the
/// facade's scoped-read admission, made before this transaction opens.
fn require_step_sender_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    step: &CampaignProgramStepDraft,
) -> Result<()> {
    let not_an_identity = || invalid("a step's sender_ref is not a live channel identity");
    if vault
        .store
        .port_deletion_state(txn, &step.sender_ref)?
        .deleted
    {
        return Err(not_an_identity());
    }
    let identity = match vault.get_channel_identity_in_txn(txn, &step.sender_ref) {
        Ok(Some(identity)) => identity,
        Ok(None) | Err(Error::InvalidEntityType(_)) => return Err(not_an_identity()),
        Err(error) => return Err(error),
    };
    if normalize_channel_class(identity.channel()) != normalize_channel_class(&step.channel) {
        return Err(invalid(
            "a step's sender_ref is a channel identity of another channel",
        ));
    }
    Ok(())
}

/// Whether a sweep enrolls from `query` into this program now. The sweep reads
/// only an active Wake or Reactive query (`sweep_saved_queries`), and the
/// enrollment leg only a program that enrolls ([`program_enrolls_in_txn`]).
fn intake_open(
    campaign: &CampaignRecord,
    definition: &CampaignProgramDefinition,
    query: Option<&SavedQueryRecord>,
) -> bool {
    campaign.definition.lifecycle == CampaignLifecycle::Active
        && definition.lifecycle == CampaignLifecycle::Active
        && query.is_some_and(|query| {
            query.definition.lifecycle == SavedQueryLifecycle::Active
                && query.definition.eval.mode != EvalMode::Manual
        })
}

/// The draft rules that need no transaction: the name, the step count, unique
/// step ids, each step's channel and outbound bounds, and an entry step that is
/// one of the draft's own steps.
fn validate_program_draft(draft: &CampaignProgramDraft) -> Result<()> {
    if draft.name.trim().is_empty() {
        return Err(invalid("campaign program name must not be blank"));
    }
    if draft.name.len() > CAMPAIGN_PROGRAM_NAME_MAX_BYTES {
        return Err(invalid("campaign program name exceeds the maximum length"));
    }
    if draft.name.chars().any(char::is_control) {
        return Err(invalid(
            "campaign program name must not contain control characters",
        ));
    }
    if draft.steps.len() > CAMPAIGN_PROGRAM_MAX_STEPS {
        return Err(invalid("campaign program has more steps than the maximum"));
    }
    for (index, step) in draft.steps.iter().enumerate() {
        if draft.steps[..index]
            .iter()
            .any(|earlier| earlier.step_ref == step.step_ref)
        {
            return Err(invalid("campaign program step_refs must be unique"));
        }
        validate_step_draft(step)?;
    }
    if let Some(audience) = draft.audience
        && !draft
            .steps
            .iter()
            .any(|step| step.step_ref == audience.entry_step_ref)
    {
        return Err(invalid(
            "the audience's entry step is not a step of this program",
        ));
    }
    Ok(())
}

fn validate_step_draft(step: &CampaignProgramStepDraft) -> Result<()> {
    if step.channel.is_empty()
        || step.channel.len() > CAMPAIGN_PROGRAM_STEP_CHANNEL_MAX_BYTES
        || step.channel.chars().any(char::is_control)
    {
        return Err(invalid(
            "a step's channel must be a non-empty token within the maximum length",
        ));
    }
    if step.channel != normalize_campaign_pack_token(&step.channel) {
        return Err(invalid("a step's channel must be normalized"));
    }
    if let Some(outbound) = &step.outbound {
        if outbound.verb.trim().is_empty()
            || outbound.verb.len() > CAMPAIGN_PROGRAM_OUTBOUND_VERB_MAX_BYTES
            || outbound.verb.chars().any(char::is_control)
        {
            return Err(invalid(
                "a step's outbound verb must be a non-empty name within the maximum length",
            ));
        }
        if outbound.payload.len() > CAMPAIGN_PROGRAM_OUTBOUND_PAYLOAD_MAX_BYTES {
            return Err(invalid(
                "a step's outbound payload exceeds the maximum size",
            ));
        }
    }
    Ok(())
}

fn require_active_campaign(campaign: &CampaignRecord) -> Result<()> {
    if campaign.definition.lifecycle == CampaignLifecycle::Active {
        return Ok(());
    }
    Err(invalid("an archived campaign's programs are read-only"))
}

fn require_expected_program_version(
    definition: &CampaignProgramDefinition,
    expected: u64,
) -> Result<()> {
    if definition.definition_version == expected {
        return Ok(());
    }
    Err(Error::ConcurrentWrite(
        "campaign program definition version is not current",
    ))
}

fn next_program_version(current: u64) -> Result<u64> {
    current.checked_add(1).ok_or(Error::ArithmeticOverflow(
        "campaign program definition version",
    ))
}

/// One program row, decoded with its authored definition when it has one.
fn stored_program_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    program_ref: EntityId,
) -> Result<Option<(CampaignProgram, Option<CampaignProgramDefinition>)>> {
    let Some(mut row) = PROGRAM.get(&vault.store, txn, &program_ref)? else {
        return Ok(None);
    };
    let definition = row
        .definition
        .take()
        .map(decode_program_definition)
        .transpose()?;
    Ok(Some((decode_program(program_ref, row)?, definition)))
}

/// An authored program of `campaign`: a program of another campaign, or one no
/// checked door wrote, is absent.
fn authored_program_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    campaign: &CampaignRecord,
    program_ref: EntityId,
) -> Result<Option<(CampaignProgram, CampaignProgramDefinition)>> {
    Ok(
        stored_program_in_txn(vault, txn, program_ref)?.and_then(|(program, definition)| {
            definition
                .filter(|_| program.campaign_ref == campaign.campaign_ref)
                .map(|definition| (program, definition))
        }),
    )
}

/// The definition's steps, in its order. The checked doors write a program's
/// steps with it, so a missing one is a corrupt row, not an absent step.
fn program_steps_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    program: &CampaignProgram,
    definition: &CampaignProgramDefinition,
) -> Result<Vec<CampaignProgramStep>> {
    definition
        .step_refs
        .iter()
        .map(|step_ref| {
            PROGRAM_STEP
                .get(&vault.store, txn, &(program.program_ref, *step_ref))?
                .map(|row| decode_program_step(program.program_ref, *step_ref, row))
                .transpose()?
                .ok_or(Error::CorruptedIndex("campaign program step"))
        })
        .collect()
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgramRow {
    schema_version: u32,
    campaign_ref: String,
    audience: Option<ProgramAudienceRow>,
    /// The authored definition the checked doors write; absent on a row the
    /// raw [`put_campaign_program`] wrote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    definition: Option<ProgramDefinitionRow>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgramDefinitionRow {
    name: String,
    definition_version: u64,
    lifecycle: String,
    steps: Vec<String>,
    created_at: u64,
    updated_at: u64,
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
        definition: None,
    }
}

fn encode_authored_program(
    program: &CampaignProgram,
    definition: &CampaignProgramDefinition,
) -> ProgramRow {
    ProgramRow {
        definition: Some(ProgramDefinitionRow {
            name: definition.name.clone(),
            definition_version: definition.definition_version,
            lifecycle: definition.lifecycle.as_str().to_owned(),
            steps: definition.step_refs.iter().map(EntityId::to_hex).collect(),
            created_at: definition.created_at,
            updated_at: definition.updated_at,
        }),
        ..encode_program(program)
    }
}

fn decode_program_definition(row: ProgramDefinitionRow) -> Result<CampaignProgramDefinition> {
    const CONTEXT: &str = "campaign program definition";
    Ok(CampaignProgramDefinition {
        name: row.name,
        definition_version: row.definition_version,
        lifecycle: CampaignLifecycle::parse(&row.lifecycle)
            .ok_or(Error::CorruptedIndex(CONTEXT))?,
        step_refs: row
            .steps
            .iter()
            .map(|step_ref| id_from_hex(step_ref, CONTEXT))
            .collect::<Result<_>>()?,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
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
