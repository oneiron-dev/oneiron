//! The doors of a project's lead turns, on the caller's own handle. The owner sets them; the
//! owner or a Grant that reaches the project holds, releases and reads them; only the project's
//! lead, under its own live Grant that lists the verb and reaches the project, reads, claims and
//! finishes its turn. Each door judges its caller in the snapshot or write it acts in, and refuses
//! before it writes anything.

use std::collections::BTreeSet;

use oneiron_contracts::fingerprint::ContentHash;

use super::store::{
    FILES, REGISTRATIONS, STARTERS, TURNS, file_in_txn, flush_held_in_txn,
    place_failure_hold_in_txn, place_hold_in_txn, put_registration_in_txn, secs_ms,
};
use super::wire::LeadTurnSeatOutcome;
use super::{
    LEAD_TURNS_CLAIM_VERB, LEAD_TURNS_FILE_VERB, LEAD_TURNS_FINISH_VERB, LEAD_TURNS_HOLD_VERB,
    LEAD_TURNS_LIST_VERB, LEAD_TURNS_OWED_VERB, LEAD_TURNS_RELEASE_VERB, LEAD_TURNS_SET_VERB,
    LeadTurn, LeadTurnClaim, LeadTurnFile, LeadTurnFileRef, LeadTurnFileView, LeadTurnHold,
    LeadTurnHoldBy, LeadTurnOpen, LeadTurnOutcome, LeadTurnRegistration, LeadTurnSettings,
    LeadTurnStarter, LeadTurnTicket, LeadTurnsClaimRequest, LeadTurnsFileRequest,
    LeadTurnsFinishRequest, LeadTurnsHoldRequest, LeadTurnsListRequest, LeadTurnsListView,
    LeadTurnsOwedView, LeadTurnsProjectRequest, LeadTurnsSetRequest,
};
use crate::consent::AuthenticatedOwner;
use crate::error::Error;
use crate::memory::verb_grant_caller::VerbGrantCaller;
use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE,
    MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult,
};

/// The most plain-job starters one registration lists.
const MAX_STARTERS: usize = 64;
/// The most file names one registration keeps.
const MAX_FILE_NAMES: usize = 16;
/// The largest file a registration may allow.
const MAX_FILE_BYTES_CAP: u64 = 4_194_304;
/// The shortest timer gap and lease.
const MIN_SECS: u64 = 60;
/// The longest lease: a week.
const MAX_LEASE_SECS: u64 = 604_800;
/// The most causes a registration may list per turn.
const MAX_CAUSES_CAP: u32 = 1_024;
/// One list page by default, and at most.
const LIST_PAGE: u32 = 50;
const LIST_PAGE_MAX: u32 = 100;

fn refusal(code: &str, verb: &str, why: impl std::fmt::Display, hint: &str) -> MemoryError {
    MemoryError::new(code, format!("{verb}: {why}"), &[hint])
}

fn not_set(verb: &str) -> MemoryError {
    refusal(
        MEMORY_CODE_NOT_FOUND,
        verb,
        "no lead turns are set for this project",
        "The owner sets them with vault.projects.lead_turns.set.",
    )
}

fn bad(verb: &str, why: impl std::fmt::Display) -> MemoryError {
    refusal(
        MEMORY_CODE_BAD_REQUEST,
        verb,
        why,
        "Correct the request and send it again.",
    )
}

fn short_text(verb: &str, field: &str, text: &str, max: usize) -> MemoryResult<()> {
    if text.is_empty() || text.len() > max {
        return Err(bad(verb, format!("{field} holds 1 to {max} bytes")));
    }
    Ok(())
}

/// `verb`'s caller over `project`: the owner under the owner's own proof, or an agent whose own
/// live Grant lists the verb and reaches the project or a project it descends from.
fn caller_over_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    owner: Option<&AuthenticatedOwner>,
    verb: &str,
    project: crate::EntityId,
) -> MemoryResult<VerbGrantCaller> {
    memory.verb_grant_caller_admits_in_txn(txn, owner, verb)?;
    match memory.verb_grant_caller_admits_over_in_txn(txn, owner, verb, project) {
        Err(error) if error.code == MEMORY_CODE_FORBIDDEN => Err(refusal(
            MEMORY_CODE_FORBIDDEN,
            verb,
            "not_this_project: the Grant does not reach this project",
            "Ask the owner to widen the Grant to the project.",
        )),
        other => other,
    }
}

/// `verb`'s caller as the project's lead: an agent that is the registration's lead, or, where
/// `owner_may`, the owner.
fn lead_over_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    owner: Option<&AuthenticatedOwner>,
    verb: &str,
    registration: &LeadTurnRegistration,
    owner_may: bool,
) -> MemoryResult<VerbGrantCaller> {
    let caller = caller_over_in_txn(memory, txn, owner, verb, registration.project)?;
    match caller {
        VerbGrantCaller::Owner if owner_may => Ok(caller),
        VerbGrantCaller::Agent { actor, .. } if registration.lead == Some(actor) => Ok(caller),
        _ => Err(refusal(
            MEMORY_CODE_FORBIDDEN,
            verb,
            "not_the_lead: only the project's lead takes its turns",
            "The lead's own agent calls this verb.",
        )),
    }
}

fn check_set(input: &LeadTurnsSetRequest) -> MemoryResult<()> {
    let verb = LEAD_TURNS_SET_VERB;
    short_text(verb, "lead_model", &input.lead_model, 128)?;
    let starters: BTreeSet<_> = input.plain_job_starters.iter().collect();
    if input.plain_job_starters.len() > MAX_STARTERS
        || starters.len() != input.plain_job_starters.len()
    {
        return Err(bad(
            verb,
            format!("plain_job_starters lists at most {MAX_STARTERS} actors, each once"),
        ));
    }
    check_settings(&input.settings)
}

fn check_settings(settings: &LeadTurnSettings) -> MemoryResult<()> {
    let verb = LEAD_TURNS_SET_VERB;
    if settings.min_timer_gap_secs < MIN_SECS || settings.every_secs < settings.min_timer_gap_secs {
        return Err(bad(
            verb,
            format!("min_timer_gap_secs is at least {MIN_SECS} and every_secs at least that"),
        ));
    }
    if !(MIN_SECS..=MAX_LEASE_SECS).contains(&settings.lease_secs) {
        return Err(bad(
            verb,
            format!("lease_secs is {MIN_SECS} to {MAX_LEASE_SECS}"),
        ));
    }
    if !(1..=MAX_FILE_BYTES_CAP).contains(&settings.max_file_bytes) {
        return Err(bad(
            verb,
            format!("max_file_bytes is 1 to {MAX_FILE_BYTES_CAP}"),
        ));
    }
    if !(1..=MAX_CAUSES_CAP).contains(&settings.max_causes) {
        return Err(bad(verb, format!("max_causes is 1 to {MAX_CAUSES_CAP}")));
    }
    if settings.day_offset_secs.unsigned_abs() >= 86_400 {
        return Err(bad(verb, "day_offset_secs is less than a day either way"));
    }
    let names: BTreeSet<&str> = settings.files.iter().map(String::as_str).collect();
    let named = |name: &str| {
        !name.is_empty()
            && name.len() <= 128
            && !name.starts_with('.')
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    };
    if settings.files.is_empty()
        || settings.files.len() > MAX_FILE_NAMES
        || names.len() != settings.files.len()
        || !settings.files.iter().all(|name| named(name))
    {
        return Err(bad(
            verb,
            format!(
                "files names 1 to {MAX_FILE_NAMES} distinct files of letters, digits, '.', '_' \
                 and '-', none starting with '.'"
            ),
        ));
    }
    Ok(())
}

/// The files a finish hands its turn, as the turn keeps them.
fn kept_files(
    settings: &LeadTurnSettings,
    input: &LeadTurnsFinishRequest,
) -> MemoryResult<Vec<(LeadTurnFileRef, LeadTurnFile)>> {
    let verb = LEAD_TURNS_FINISH_VERB;
    let mut seen = BTreeSet::new();
    let mut kept = Vec::new();
    for file in &input.files {
        if !settings.files.contains(&file.name) {
            return Err(bad(
                verb,
                format!("{} is not a file this project's turns keep", file.name),
            ));
        }
        if !seen.insert(file.name.as_str()) {
            return Err(bad(verb, format!("{} is named twice", file.name)));
        }
        let bytes = file.body.len() as u64;
        if bytes > settings.max_file_bytes {
            return Err(bad(
                verb,
                format!(
                    "{} holds {bytes} bytes, more than max_file_bytes {}",
                    file.name, settings.max_file_bytes
                ),
            ));
        }
        if file.name.ends_with(".json")
            && !serde_json::from_str::<serde_json::Value>(&file.body)
                .is_ok_and(|value| value.is_object())
        {
            return Err(bad(verb, format!("{} holds one JSON object", file.name)));
        }
        let blake3 = ContentHash::of(file.body.as_bytes()).to_hex();
        kept.push((
            LeadTurnFileRef {
                name: file.name.clone(),
                blake3: blake3.clone(),
                bytes,
            },
            LeadTurnFile {
                name: file.name.clone(),
                blake3,
                body: file.body.clone(),
            },
        ));
    }
    if input.outcome == LeadTurnSeatOutcome::Succeeded
        && let Some(missing) = settings
            .files
            .iter()
            .find(|name| !seen.contains(name.as_str()))
    {
        return Err(bad(
            verb,
            format!("a succeeded turn keeps every listed file; {missing} is missing"),
        ));
    }
    Ok(kept)
}

fn ticket(
    registration: &LeadTurnRegistration,
    turn: u64,
    open: &LeadTurnOpen,
    claimed: Option<(u64, u64)>,
) -> LeadTurnTicket {
    LeadTurnTicket {
        project: registration.project,
        turn,
        opened_at_ms: open.opened_at_ms,
        causes: open.causes.clone(),
        cause_count: open.cause_count,
        lead_model: registration.lead_model.clone(),
        files: registration.settings.files.clone(),
        claimed_at_ms: claimed.map(|(at, _)| at),
        lease_until_ms: claimed.map(|(_, until)| until),
    }
}

fn line_ticket(registration: &LeadTurnRegistration, line: &LeadTurn) -> LeadTurnTicket {
    let open = LeadTurnOpen {
        opened_at_ms: line.opened_at_ms,
        causes: line.causes.clone(),
        cause_count: line.cause_count,
    };
    let claimed = line.claimed_at_ms.zip(line.lease_until_ms);
    LeadTurnTicket {
        lead_model: line.model_named.clone(),
        ..ticket(registration, line.seq, &open, claimed)
    }
}

impl Memory<'_> {
    /// `vault.projects.lead_turns.set` at `now_ms`: the owner names `input.project`'s lead, its
    /// model, its plain-job starters and its settings, replacing what was set and keeping where
    /// the turns stand. It arms the timer.
    ///
    /// # Errors
    ///
    /// `forbidden` for any caller but the owner; `not_found` for a project that is not live;
    /// `bad_request` for a setting out of bounds or a starter another project lists.
    pub fn set_project_lead_turns(
        &self,
        owner: Option<&AuthenticatedOwner>,
        input: &LeadTurnsSetRequest,
        now_ms: u64,
    ) -> MemoryResult<LeadTurnRegistration> {
        let verb = LEAD_TURNS_SET_VERB;
        check_set(input)?;
        let vault = self.vault();
        vault.with_write_txn_grouped(|txn| {
            match self.verb_grant_caller_admits_in_txn(txn, owner, verb) {
                Ok(VerbGrantCaller::Owner) => {}
                Ok(VerbGrantCaller::Agent { .. }) => {
                    return Ok(Err(refusal(
                        MEMORY_CODE_FORBIDDEN,
                        verb,
                        "only the owner sets a project's lead turns",
                        "The owner names the lead under the owner's own proof.",
                    )));
                }
                Err(error) => return Ok(Err(error)),
            }
            if vault
                .effective_project_in_txn(txn, input.project)?
                .is_none()
            {
                return Ok(Err(refusal(
                    MEMORY_CODE_NOT_FOUND,
                    verb,
                    "no live project has this id",
                    "Name a live project.",
                )));
            }
            for starter in &input.plain_job_starters {
                if let Some(row) = STARTERS.get_lenient(&vault.store, txn, starter)?
                    && row.project != input.project
                {
                    return Ok(Err(bad(
                        verb,
                        format!(
                            "plain job starter {} is listed for project {}; one actor is a \
                             starter of one project",
                            starter.to_hex(),
                            row.project.to_hex()
                        ),
                    )));
                }
            }
            let prior = REGISTRATIONS.get_lenient(&vault.store, txn, &input.project)?;
            if let Some(prior) = &prior {
                for starter in &prior.plain_job_starters {
                    if !input.plain_job_starters.contains(starter)
                        && STARTERS
                            .get_lenient(&vault.store, txn, starter)?
                            .is_some_and(|row| row.project == input.project)
                    {
                        STARTERS.delete(&vault.store, txn, starter)?;
                    }
                }
            }
            for starter in &input.plain_job_starters {
                STARTERS.put(
                    &vault.store,
                    txn,
                    starter,
                    &LeadTurnStarter {
                        project: input.project,
                    },
                )?;
            }
            let due = now_ms.saturating_add(secs_ms(input.settings.every_secs));
            let mut registration = match prior {
                Some(prior) => LeadTurnRegistration {
                    lead: Some(input.lead),
                    lead_model: input.lead_model.clone(),
                    plain_job_starters: input.plain_job_starters.clone(),
                    settings: input.settings.clone(),
                    next_due_ms: prior.next_due_ms.min(due),
                    armed: true,
                    set_at_ms: now_ms,
                    ..prior
                },
                None => LeadTurnRegistration {
                    project: input.project,
                    lead: Some(input.lead),
                    lead_model: input.lead_model.clone(),
                    plain_job_starters: input.plain_job_starters.clone(),
                    settings: input.settings.clone(),
                    hold: None,
                    next_seq: 1,
                    owed: None,
                    held: None,
                    claimed: None,
                    next_due_ms: due,
                    armed: true,
                    set_at_ms: now_ms,
                    revision: 0,
                },
            };
            put_registration_in_txn(vault, txn, &mut registration)?;
            Ok(Ok(registration))
        })?
    }

    /// `vault.projects.lead_turns.hold` at `now_ms`: a hold that refuses the project's turns until
    /// a release. The owed turn becomes a held line in the same write. An owner's or a Grant's
    /// hold takes the place of the engine's own failure hold; a hold of either standing already
    /// stays as it is.
    ///
    /// # Errors
    ///
    /// `forbidden` for a caller whose Grant does not list the verb or reach the project;
    /// `not_found` when no lead turns are set.
    pub fn hold_project_lead_turns(
        &self,
        owner: Option<&AuthenticatedOwner>,
        input: &LeadTurnsHoldRequest,
        now_ms: u64,
    ) -> MemoryResult<LeadTurnRegistration> {
        let verb = LEAD_TURNS_HOLD_VERB;
        short_text(verb, "reason", &input.reason, 256)?;
        let vault = self.vault();
        vault.with_write_txn_grouped(|txn| {
            let caller = match caller_over_in_txn(self, txn, owner, verb, input.project) {
                Ok(caller) => caller,
                Err(error) => return Ok(Err(error)),
            };
            let Some(mut registration) = REGISTRATIONS.get(&vault.store, txn, &input.project)?
            else {
                return Ok(Err(not_set(verb)));
            };
            let by = match caller {
                VerbGrantCaller::Owner => LeadTurnHoldBy::Owner,
                VerbGrantCaller::Agent { grant, .. } => LeadTurnHoldBy::Grant { grant },
            };
            if registration
                .hold
                .as_ref()
                .is_some_and(|hold| hold.by == LeadTurnHoldBy::Engine)
            {
                registration.hold = None;
            }
            let hold = LeadTurnHold {
                by,
                at_ms: now_ms,
                reason: input.reason.clone(),
                lifts_at_ms: None,
                turn: None,
            };
            if place_hold_in_txn(vault, txn, &mut registration, hold, now_ms)? {
                put_registration_in_txn(vault, txn, &mut registration)?;
            }
            Ok(Ok(registration))
        })?
    }

    /// `vault.projects.lead_turns.release` at `now_ms`: lifts the hold, the engine's own too. The
    /// causes it refused become one held line; the next cause owes a turn.
    ///
    /// # Errors
    ///
    /// As [`Self::hold_project_lead_turns`].
    pub fn release_project_lead_turns(
        &self,
        owner: Option<&AuthenticatedOwner>,
        input: &LeadTurnsProjectRequest,
        now_ms: u64,
    ) -> MemoryResult<LeadTurnRegistration> {
        let verb = LEAD_TURNS_RELEASE_VERB;
        let vault = self.vault();
        vault.with_write_txn_grouped(|txn| {
            if let Err(error) = caller_over_in_txn(self, txn, owner, verb, input.project) {
                return Ok(Err(error));
            }
            let Some(mut registration) = REGISTRATIONS.get(&vault.store, txn, &input.project)?
            else {
                return Ok(Err(not_set(verb)));
            };
            if registration.hold.take().is_some() {
                flush_held_in_txn(vault, txn, &mut registration, now_ms)?;
                put_registration_in_txn(vault, txn, &mut registration)?;
            }
            Ok(Ok(registration))
        })?
    }

    /// `vault.projects.lead_turns.owed` at `now_ms`: the owed turn as its lead takes it, none
    /// while a hold stands. The lead's wake tool reads it (LM-5); the read writes nothing.
    ///
    /// # Errors
    ///
    /// `forbidden` for a caller that is neither the owner nor the lead under its Grant;
    /// `not_found` when no lead turns are set.
    pub fn owed_project_lead_turn(
        &self,
        owner: Option<&AuthenticatedOwner>,
        input: &LeadTurnsProjectRequest,
        now_ms: u64,
    ) -> MemoryResult<LeadTurnsOwedView> {
        let verb = LEAD_TURNS_OWED_VERB;
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        caller_over_in_txn(self, &txn, owner, verb, input.project)?;
        let Some(registration) = REGISTRATIONS.get(&vault.store, &txn, &input.project)? else {
            return Err(not_set(verb));
        };
        lead_over_in_txn(self, &txn, owner, verb, &registration, true)?;
        let held = registration
            .hold
            .as_ref()
            .is_some_and(|hold| hold.stands_at(now_ms));
        let owed = if held {
            None
        } else {
            registration
                .owed
                .as_ref()
                .map(|open| ticket(&registration, registration.next_seq, open, None))
        };
        Ok(LeadTurnsOwedView {
            owed,
            held,
            running: registration.claimed.map(|claimed| claimed.seq),
        })
    }

    /// `vault.projects.lead_turns.claim` at `now_ms`: the lead takes the owed turn, which becomes
    /// its line with a lease of `lease_secs`. A repeat while that turn runs answers the same
    /// ticket.
    ///
    /// # Errors
    ///
    /// `forbidden` for any caller but the lead under its Grant; `invalid_state` while a hold
    /// stands, another turn runs, or no turn (or not `input.turn`) is owed.
    pub fn claim_project_lead_turn(
        &self,
        owner: Option<&AuthenticatedOwner>,
        input: &LeadTurnsClaimRequest,
        now_ms: u64,
    ) -> MemoryResult<LeadTurnTicket> {
        let verb = LEAD_TURNS_CLAIM_VERB;
        let vault = self.vault();
        vault.with_write_txn_grouped(|txn| {
            if let Err(error) = caller_over_in_txn(self, txn, owner, verb, input.project) {
                return Ok(Err(error));
            }
            let Some(mut registration) = REGISTRATIONS.get(&vault.store, txn, &input.project)?
            else {
                return Ok(Err(not_set(verb)));
            };
            if let Err(error) = lead_over_in_txn(self, txn, owner, verb, &registration, false) {
                return Ok(Err(error));
            }
            if let Some(claimed) = registration.claimed {
                if input.turn.is_none_or(|turn| turn == claimed.seq)
                    && let Some(line) =
                        TURNS.get(&vault.store, txn, &(input.project, claimed.seq))?
                {
                    return Ok(Ok(line_ticket(&registration, &line)));
                }
                return Ok(Err(refusal(
                    MEMORY_CODE_INVALID_STATE,
                    verb,
                    format!("running: turn {} is still running", claimed.seq),
                    "Finish the running turn first.",
                )));
            }
            if registration
                .hold
                .as_ref()
                .is_some_and(|hold| hold.stands_at(now_ms))
            {
                return Ok(Err(refusal(
                    MEMORY_CODE_INVALID_STATE,
                    verb,
                    "held: a hold refuses this project's turns",
                    "Wait for the release.",
                )));
            }
            let seq = registration.next_seq;
            let Some(owed) = registration
                .owed
                .take()
                .filter(|_| input.turn.is_none_or(|turn| turn == seq))
            else {
                return Ok(Err(refusal(
                    MEMORY_CODE_INVALID_STATE,
                    verb,
                    "not_owed: that turn is not owed",
                    "Read vault.projects.lead_turns.owed again.",
                )));
            };
            registration.next_seq += 1;
            let lease_until_ms = now_ms.saturating_add(secs_ms(registration.settings.lease_secs));
            let line = LeadTurn {
                seq,
                opened_at_ms: owed.opened_at_ms,
                causes: owed.causes,
                cause_count: owed.cause_count,
                claimed_at_ms: Some(now_ms),
                lease_until_ms: Some(lease_until_ms),
                ended_at_ms: None,
                outcome: None,
                status: None,
                rc: None,
                model_named: registration.lead_model.clone(),
                model_reported: None,
                files: Vec::new(),
                placed_hold: false,
            };
            TURNS.put(&vault.store, txn, &(input.project, seq), &line)?;
            registration.claimed = Some(LeadTurnClaim {
                seq,
                lease_until_ms,
            });
            put_registration_in_txn(vault, txn, &mut registration)?;
            Ok(Ok(line_ticket(&registration, &line)))
        })?
    }

    /// `vault.projects.lead_turns.finish` at `now_ms`: the lead closes its claimed turn with its
    /// outcome, status, exit code, the model it ran and the named files, which the turn keeps. A
    /// failed turn places the registration's `failure_hold`. A repeat of the finish that closed
    /// the turn answers its line.
    ///
    /// # Errors
    ///
    /// `forbidden` for any caller but the lead under its Grant; `not_found` for a turn with no
    /// line; `invalid_state` for a turn not claimed or ended otherwise; `bad_request` for a
    /// file the turn does not keep, a missing file of a succeeded turn, a file past
    /// `max_file_bytes` or a `.json` file that is not one object.
    pub fn finish_project_lead_turn(
        &self,
        owner: Option<&AuthenticatedOwner>,
        input: &LeadTurnsFinishRequest,
        now_ms: u64,
    ) -> MemoryResult<LeadTurn> {
        let verb = LEAD_TURNS_FINISH_VERB;
        short_text(verb, "status", &input.status, 64)?;
        short_text(verb, "model", &input.model, 128)?;
        let vault = self.vault();
        vault.with_write_txn_grouped(|txn| {
            if let Err(error) = caller_over_in_txn(self, txn, owner, verb, input.project) {
                return Ok(Err(error));
            }
            let Some(mut registration) = REGISTRATIONS.get(&vault.store, txn, &input.project)?
            else {
                return Ok(Err(not_set(verb)));
            };
            if let Err(error) = lead_over_in_txn(self, txn, owner, verb, &registration, false) {
                return Ok(Err(error));
            }
            let key = (input.project, input.turn);
            let Some(mut line) = TURNS.get(&vault.store, txn, &key)? else {
                return Ok(Err(refusal(
                    MEMORY_CODE_NOT_FOUND,
                    verb,
                    format!("no turn {} of this project", input.turn),
                    "Name a turn the lead claimed.",
                )));
            };
            let outcome = LeadTurnOutcome::from(input.outcome);
            if line.ended_at_ms.is_some() {
                let same_files = kept_files(&registration.settings, input).is_ok_and(|kept| {
                    kept.into_iter()
                        .map(|(reference, _)| reference)
                        .collect::<Vec<_>>()
                        == line.files
                });
                if line.outcome == Some(outcome)
                    && line.status.as_deref() == Some(input.status.as_str())
                    && line.rc == input.rc
                    && same_files
                {
                    return Ok(Ok(line));
                }
                return Ok(Err(refusal(
                    MEMORY_CODE_INVALID_STATE,
                    verb,
                    format!("already_ended: turn {} has ended", input.turn),
                    "Read the turn with vault.projects.lead_turns.list.",
                )));
            }
            if registration.claimed.map(|claimed| claimed.seq) != Some(input.turn) {
                return Ok(Err(refusal(
                    MEMORY_CODE_INVALID_STATE,
                    verb,
                    format!("not_claimed: turn {} is not the claimed turn", input.turn),
                    "Claim the owed turn first.",
                )));
            }
            let kept = match kept_files(&registration.settings, input) {
                Ok(kept) => kept,
                Err(error) => return Ok(Err(error)),
            };
            let mut references = Vec::with_capacity(kept.len());
            for (reference, file) in kept {
                FILES.put(
                    &vault.store,
                    txn,
                    &(input.project, input.turn, file.name.clone()),
                    &file,
                )?;
                references.push(reference);
            }
            line.ended_at_ms = Some(now_ms);
            line.outcome = Some(outcome);
            line.status = Some(input.status.clone());
            line.rc = input.rc;
            line.model_reported = Some(input.model.clone());
            line.files = references;
            TURNS.put(&vault.store, txn, &key, &line)?;
            registration.claimed = None;
            if let Some(next) = input.next_turn_at_ms {
                let floor = line
                    .opened_at_ms
                    .saturating_add(secs_ms(registration.settings.min_timer_gap_secs));
                registration.next_due_ms = registration.next_due_ms.min(next.max(floor));
            }
            if input.outcome == LeadTurnSeatOutcome::Failed {
                place_failure_hold_in_txn(vault, txn, &mut registration, input.turn, now_ms)?;
            }
            put_registration_in_txn(vault, txn, &mut registration)?;
            Ok(Ok(TURNS.get(&vault.store, txn, &key)?.unwrap_or(line)))
        })?
    }

    /// `vault.projects.lead_turns.list`: the registration and one page of its turn lines, oldest
    /// first, after `input.after`. Kept files show by name, hash and size, never their bodies.
    ///
    /// # Errors
    ///
    /// `forbidden` for a caller whose Grant does not list the verb or reach the project;
    /// `not_found` when no lead turns are set.
    pub fn project_lead_turns(
        &self,
        owner: Option<&AuthenticatedOwner>,
        input: &LeadTurnsListRequest,
    ) -> MemoryResult<LeadTurnsListView> {
        let verb = LEAD_TURNS_LIST_VERB;
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        caller_over_in_txn(self, &txn, owner, verb, input.project)?;
        let Some(registration) = REGISTRATIONS.get(&vault.store, &txn, &input.project)? else {
            return Err(not_set(verb));
        };
        let limit = input.limit.unwrap_or(LIST_PAGE).clamp(1, LIST_PAGE_MAX) as usize;
        let start = input.after.map_or(0, |after| after.saturating_add(1));
        let mut turns = Vec::new();
        let mut more = false;
        for row in TURNS.iter_from(&vault.store, &txn, input.project.as_bytes())? {
            let ((_, seq), line) = row?;
            if seq < start {
                continue;
            }
            if turns.len() == limit {
                more = true;
                break;
            }
            turns.push(line);
        }
        let next_after = if more {
            turns.last().map(|line: &LeadTurn| line.seq)
        } else {
            None
        };
        Ok(LeadTurnsListView {
            registration,
            turns,
            next_after,
        })
    }

    /// `vault.projects.lead_turns.file`: one file a turn kept, with its body.
    ///
    /// # Errors
    ///
    /// `forbidden` as [`Self::project_lead_turns`]; `not_found` for a file the turn did not
    /// keep.
    pub fn project_lead_turn_file(
        &self,
        owner: Option<&AuthenticatedOwner>,
        input: &LeadTurnsFileRequest,
    ) -> MemoryResult<LeadTurnFileView> {
        let verb = LEAD_TURNS_FILE_VERB;
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        caller_over_in_txn(self, &txn, owner, verb, input.project)?;
        let Some(file) = file_in_txn(vault, &txn, input.project, input.turn, &input.name)? else {
            return Err(refusal(
                MEMORY_CODE_NOT_FOUND,
                verb,
                format!("turn {} kept no file {}", input.turn, input.name),
                "Read the turn's files with vault.projects.lead_turns.list.",
            ));
        };
        Ok(LeadTurnFileView {
            turn: input.turn,
            name: file.name,
            blake3: file.blake3,
            bytes: file.body.len() as u64,
            body: file.body,
        })
    }
}
