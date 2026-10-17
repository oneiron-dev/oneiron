//! PEOPLE `about` (owner ruling, ARCH-0067): one line per person per
//! sensitivity band, each written by the Dreamer from only the facts at or
//! below that band.
//!
//! Every wake pass compares each person's facts with the facts its last
//! request was made from, and queues a `dreamer.person_about` attempt on the
//! Micro queue when they moved. The attempt asks the narrative model once per
//! band whose facts differ from the band below it, reads the facts again, and
//! lands every line in one write. The board reads the stored line of the
//! highest band at or below the reader's ceiling; no model runs at render.
//! A CLAIM write about a person hides its lines at once, in the write's own
//! transaction, until the next pass reads the facts again.

use super::resources::document_version;
use super::step_charge::StepChargeTally;
use super::support::{DREAMER_PERSON_ABOUT_ATTEMPT_TYPE, invalid_consolidation};
use super::turn_text::{dreamer_read, snapshot};
use crate::claim::{ClaimSubject, ScopedRead};
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerConsolidationScope, DreamerParkCause,
    DreamerRunnerStore,
};
use crate::dreamer_wake::{
    DREAMER_HARD_CUT_PARK_REASON, DreamerAttemptExecution, DreamerAttemptExecutor,
    WakeAttemptContext,
};
use crate::error::{Error, Result};
use crate::llm::{
    BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart, DurableStepContext,
    DurableStepError, HostInferenceContext, LlmBackend, LlmMessage, LlmMessageRole, LlmRequest,
    ModelId, ModelTierRef, ResponseFormat, ScopeResource, StepOutcome, TierPrecedence,
    call_as_step,
};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use crate::side_table::{self, Named, SideTable};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The four sensitivity bands, public (0) to restricted (3).
const TOP_BAND: u8 = 3;
/// Longest `about` line the board prints, in characters.
const ABOUT_MAX_CHARS: usize = 240;
const FACTS_DIGEST_DOMAIN: &[u8] = b"oneiron:people-about-facts:v1";
/// How long an attempt whose facts moved under the model waits to write again.
const FACTS_DRIFT_RETRY_SECS: u64 = 60;

/// The engine's instruction for one `about` line.
pub const PERSON_ABOUT_INSTRUCTION: &str = "You write the one-line `about` of a person on an \
agent's roster of people. The facts below are everything you may use, one per line as \
`predicate: value`. Write one plain sentence of at most 25 words that says who this person is. \
Never add, guess or imply a fact that is not listed, and never say that facts are missing. \
No markup and no quotes.";

/// One person's `about` lines and the facts they stand on. Key: id16 (PERSON).
const PERSON_ABOUT: SideTable<EntityId, PersonAbout, Named> =
    SideTable::new(&side_table::PEOPLE_ABOUT);

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersonAbout {
    /// Digest of the facts the newest queued attempt writes from.
    asked: [u8; 32],
    /// Digest of the facts `lines` were written from. Lines whose digest is
    /// not `asked` stand on facts that moved, and the board shows none.
    written: [u8; 32],
    /// One line per band that has facts, lowest band first.
    lines: Vec<AboutLine>,
    at: u64,
    /// The lines the Dreamer's newest landing replaced, kept so the owner
    /// can revert it (owner ruling 10-18: each Dreamer change revertible).
    previous: Option<PriorAbout>,
    /// A CLAIM write about the person landed since a wake pass last read its
    /// facts: the board shows no line until one reads them again.
    moved: bool,
}

/// One landing's before-image: the lines and the facts they stood on.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PriorAbout {
    written: [u8; 32],
    lines: Vec<AboutLine>,
    at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AboutLine {
    band: u8,
    text: String,
}

/// One fact about a person, as the Dreamer may read it.
struct Fact {
    claim: EntityId,
    band: u8,
    /// `predicate: value`, as the model reads it.
    line: String,
    /// Content hash of the CLAIM body read.
    version: [u8; 32],
    readable: ScopeResource,
}

/// The facts about `person` the Dreamer reads, band order: active, surfaced
/// CLAIMs whose subject is the PERSON, each in one of the four bands.
fn person_facts(
    vault: &Vault,
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    person: EntityId,
) -> Result<Vec<Fact>> {
    let ids = vault.claims_for_subject_in_txn(txn, &person)?;
    let rows = read.get_entities_parts_in_txn(txn, &ids)?;
    let mut facts = Vec::new();
    for (claim, row) in ids.into_iter().zip(rows) {
        let Some((ENTITY_TYPE_CLAIM, _, body)) = row else {
            continue;
        };
        let Ok(decoded) = crate::claim::decode_claim_body(&body, false) else {
            continue;
        };
        if decoded.subject != ClaimSubject::Entity(person)
            || !crate::claim::claim_surfaceable(&decoded)
        {
            continue;
        }
        let Some(band) = crate::claim::claim_sensitivity_band(&decoded).filter(|b| *b <= TOP_BAND)
        else {
            continue;
        };
        let value = decoded
            .value
            .as_str()
            .map_or_else(|| decoded.value.to_string(), str::to_owned);
        facts.push(Fact {
            claim,
            band,
            line: one_line(&format!("{}: {value}", decoded.predicate), usize::MAX),
            version: super::swarm_evidence_content_hash(&body),
            readable: document_version(claim, &body),
        });
    }
    facts.sort_by_key(|fact| (fact.band, fact.claim));
    Ok(facts)
}

/// Digest of the facts at or below `band`.
fn facts_digest(facts: &[Fact], band: u8) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FACTS_DIGEST_DOMAIN);
    for fact in facts.iter().filter(|fact| fact.band <= band) {
        hasher.update(fact.claim.as_bytes());
        hasher.update(&[fact.band]);
        hasher.update(&fact.version);
    }
    *hasher.finalize().as_bytes()
}

fn one_line(text: &str, max_chars: usize) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    flat.chars().take(max_chars).collect()
}

fn person_about_input(person: EntityId) -> rmpv::Value {
    rmpv::Value::Map(vec![(
        rmpv::Value::from("person"),
        rmpv::Value::Binary(person.as_bytes().to_vec()),
    )])
}

fn person_of_about_input(input: &rmpv::Value) -> Result<EntityId> {
    let rmpv::Value::Map(entries) = input else {
        return Err(invalid_consolidation("person about input is not a map"));
    };
    match entries.as_slice() {
        [(key, rmpv::Value::Binary(bytes))] if key.as_str() == Some("person") => {
            let bytes: [u8; 16] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| invalid_consolidation("person about input is not an id"))?;
            EntityId::from_bytes(bytes)
        }
        _ => Err(invalid_consolidation("person about input names no person")),
    }
}

/// Queues the `about` attempt of every person whose facts moved since its
/// last request. A person with no facts left loses its lines at once, with no
/// model call. Runs at the start of every Dreamer wake pass.
pub(crate) fn enqueue_person_about_on_wake(vault: &Vault, now: u64) -> Result<()> {
    let persons = vault.entities_by_type(ENTITY_TYPE_PERSON)?;
    if persons.is_empty() {
        return Ok(());
    }
    let read = dreamer_read(vault)?;
    let mut due = Vec::new();
    {
        let txn = snapshot(vault)?;
        for person in persons {
            let facts = person_facts(vault, &read, &txn, person)?;
            let digest = facts_digest(&facts, TOP_BAND);
            let row = PERSON_ABOUT.get(&vault.store, &txn, &person)?;
            match &row {
                Some(row) if row.asked == digest && !row.moved => continue,
                None if facts.is_empty() => continue,
                _ => due.push((person, digest, facts.is_empty())),
            }
        }
    }
    if due.is_empty() {
        return Ok(());
    }
    vault.with_write_txn(|txn| {
        for (person, digest, empty) in &due {
            let mut row = PERSON_ABOUT
                .get(&vault.store, txn, person)?
                .unwrap_or_default();
            // A CLAIM write that moved no fact leaves the row as it stood,
            // an owner's revert included. Facts back where the lines were
            // written from show those lines again, with no model call.
            let moved = row.asked != *digest;
            let current = row.written == *digest;
            row.asked = *digest;
            row.moved = false;
            if moved && *empty {
                row.written = *digest;
                row.lines.clear();
                row.at = now;
                row.previous = None;
            } else if moved && !current {
                DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
                    txn,
                    DreamerConsolidationScope::Micro.attempt_kind(),
                    DreamerAttemptPayload {
                        attempt_type: DREAMER_PERSON_ABOUT_ATTEMPT_TYPE.to_owned(),
                        input: person_about_input(*person),
                        parent_attempt: None,
                    },
                    Some(format!(
                        "{DREAMER_PERSON_ABOUT_ATTEMPT_TYPE}:{}:{}",
                        person.to_hex(),
                        crate::entity_id::bytes_to_hex_lower(digest)
                    )),
                    None,
                    now,
                )?;
            }
            PERSON_ABOUT.put(&vault.store, txn, person, &row)?;
        }
        Ok(())
    })?;
    vault.store.notify_attempt_observers();
    Ok(())
}

/// Hides the `about` lines of the PERSON a CLAIM is about, and of the one its
/// stored body was about, until a wake pass reads their facts again. Runs in
/// the CLAIM put's transaction, before the new body replaces the stored one.
pub(crate) fn mark_person_about_moved_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    claim: EntityId,
    body: &crate::claim::ClaimBody,
) -> Result<()> {
    let stored = crate::ports::EntityStoreRead::port_entity_raw_wiped(store, txn, &claim)?
        .filter(|raw| {
            crate::batch::EntityMetadataHeader::parse(raw)
                .is_some_and(|header| header.entity_type == ENTITY_TYPE_CLAIM)
        })
        .and_then(|raw| {
            crate::claim::decode_claim_body(
                raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..)?,
                true,
            )
            .ok()
        })
        .map(|stored| stored.subject);
    for subject in std::iter::once(body.subject).chain(stored) {
        let ClaimSubject::Entity(person) = subject else {
            continue;
        };
        let Some(mut row) = PERSON_ABOUT.get(store, txn, &person)? else {
            continue;
        };
        if !row.moved {
            row.moved = true;
            PERSON_ABOUT.put(store, txn, &person, &row)?;
        }
    }
    Ok(())
}

/// The erase hook's PEOPLE half (FIX 3155): an erased fact takes the
/// `about` lines of the PERSON it was about, and their kept before-image,
/// with it, so no stored line still says what the fact said; the next wake
/// pass writes new lines from the facts left. An erased PERSON takes its
/// whole row. Runs in the erasing transaction, before the tear.
pub(crate) fn erase_person_about_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    if PERSON_ABOUT.get(store, txn, id)?.is_some() {
        PERSON_ABOUT.delete(store, txn, id)?;
        return Ok(());
    }
    let subject = crate::ports::EntityStoreRead::port_entity_raw_wiped(store, txn, id)?
        .filter(|raw| {
            crate::batch::EntityMetadataHeader::parse(raw)
                .is_some_and(|header| header.entity_type == ENTITY_TYPE_CLAIM)
        })
        .and_then(|raw| {
            crate::claim::decode_claim_body(
                raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..)?,
                true,
            )
            .ok()
        })
        .map(|body| body.subject);
    let Some(ClaimSubject::Entity(person)) = subject else {
        return Ok(());
    };
    let Some(mut row) = PERSON_ABOUT.get(store, txn, &person)? else {
        return Ok(());
    };
    row.moved = true;
    row.lines.clear();
    row.previous = None;
    PERSON_ABOUT.put(store, txn, &person, &row)
}

/// The owner's revert of the Dreamer's newest `about` landing for `person`:
/// the lines it replaced stand again on the facts they were written from,
/// so the board shows them only while those facts hold, and the Dreamer
/// writes again once the facts move. `false` when no landing is kept to
/// revert.
pub(super) fn revert_person_about_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    person: EntityId,
) -> Result<bool> {
    let Some(mut row) = PERSON_ABOUT.get(&vault.store, txn, &person)? else {
        return Ok(false);
    };
    let Some(prior) = row.previous.take() else {
        return Ok(false);
    };
    row.written = prior.written;
    row.lines = prior.lines;
    row.at = prior.at;
    PERSON_ABOUT.put(&vault.store, txn, &person, &row)?;
    Ok(true)
}

/// Each person whose newest `about` landing the owner may revert, with when
/// it landed.
pub(super) fn revertible_person_abouts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(EntityId, u64)>> {
    Ok(PERSON_ABOUT
        .scan(&vault.store, txn)?
        .into_iter()
        .filter(|(_, row)| row.previous.is_some())
        .map(|(person, row)| (person, row.at))
        .collect())
}

impl Vault {
    /// `person`'s `about` line for a reader whose sensitivity ceiling is
    /// `ceiling`: the line of the highest band at or below it. `None` reads
    /// no band. A person whose facts moved since its lines were written shows
    /// none until the Dreamer writes them again.
    pub fn person_about(&self, person: EntityId, ceiling: Option<u8>) -> Result<Option<String>> {
        let Some(ceiling) = ceiling else {
            return Ok(None);
        };
        let txn = self.store.env.read_txn()?;
        let Some(row) = PERSON_ABOUT.get(&self.store, &txn, &person)? else {
            return Ok(None);
        };
        if row.moved || row.asked != row.written {
            return Ok(None);
        }
        Ok(row
            .lines
            .iter()
            .rev()
            .find(|line| line.band <= ceiling)
            .map(|line| line.text.clone()))
    }
}

/// Wraps an executor with the `about` arm. Every other attempt is delegated
/// untouched.
pub struct PersonAboutExecutor<'a, E> {
    inner: E,
    backend: &'a dyn LlmBackend,
    guard: &'a BudgetGuard,
    actor: WriteActor,
    model: ModelId,
    inference: HostInferenceContext<'a>,
    instruction: &'a str,
}

impl<'a, E> PersonAboutExecutor<'a, E> {
    #[must_use]
    pub fn new(
        inner: E,
        backend: &'a dyn LlmBackend,
        guard: &'a BudgetGuard,
        actor: WriteActor,
        model: ModelId,
        inference: HostInferenceContext<'a>,
        instruction: Option<&'a str>,
    ) -> Self {
        Self {
            inner,
            backend,
            guard,
            actor,
            model,
            inference,
            instruction: instruction.unwrap_or(PERSON_ABOUT_INSTRUCTION),
        }
    }
}

impl<E: DreamerAttemptExecutor> DreamerAttemptExecutor for PersonAboutExecutor<'_, E> {
    async fn execute(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        if attempt.status.payload.attempt_type != DREAMER_PERSON_ABOUT_ATTEMPT_TYPE {
            return self.inner.execute(attempt, ctx).await;
        }
        self.compose(attempt, ctx).await
    }
}

impl<E> PersonAboutExecutor<'_, E> {
    async fn compose(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        let attempt_id = attempt.status.attempt.id;
        if self.actor != ctx.vault.dreamer_actor_for_attempt(attempt_id)? {
            return Err(invalid_consolidation(
                "executor actor is not the queued Dreamer authority",
            ));
        }
        let person = person_of_about_input(&attempt.status.payload.input)?;
        let read = dreamer_read(ctx.vault)?;
        let (facts, written) = {
            let txn = snapshot(ctx.vault)?;
            let facts = person_facts(ctx.vault, &read, &txn, person)?;
            let row = PERSON_ABOUT.get(&ctx.vault.store, &txn, &person)?;
            (facts, row.map(|row| row.written))
        };
        let digest = facts_digest(&facts, TOP_BAND);
        // An earlier attempt already wrote from these facts.
        if written == Some(digest) || facts.is_empty() {
            return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
        }
        let locality = self
            .inference
            .selected_locality()
            .ok_or_else(|| Error::InvalidConfig("about host binding needs locality".into()))?;
        let mut charges = StepChargeTally::default();
        let mut lines: Vec<AboutLine> = Vec::new();
        let mut below: Option<[u8; 32]> = None;
        for band in 0..=TOP_BAND {
            let admitted: Vec<&Fact> = facts.iter().filter(|fact| fact.band <= band).collect();
            if admitted.is_empty() {
                continue;
            }
            let band_digest = facts_digest(&facts, band);
            // No fact sits at this band: its line is the line below.
            if below == Some(band_digest)
                && let Some(last) = lines.last()
            {
                let text = last.text.clone();
                lines.push(AboutLine { band, text });
                continue;
            }
            let request = LlmRequest {
                model: self.model.clone(),
                envelope: CallEnvelope {
                    seat_effort: None,
                    // The call reads exactly the facts admitted at this band.
                    scope: crate::llm::Scope {
                        readable: admitted
                            .iter()
                            .map(|fact| fact.readable.clone())
                            .collect::<BTreeSet<_>>(),
                        ..crate::llm::Scope::default()
                    },
                    purpose: CallPurpose::Extraction,
                    class: CallClass::BestEffort,
                    tier: TierPrecedence::for_purpose(
                        &CallPurpose::Extraction,
                        ModelTierRef("consolidation".into()),
                    ),
                    response_format: ResponseFormat::Text,
                    locality,
                }
                .with_purpose_defaults(),
                messages: vec![
                    LlmMessage {
                        role: LlmMessageRole::System,
                        content: vec![ContentPart::Text {
                            text: self.instruction.to_owned(),
                        }],
                    },
                    LlmMessage {
                        role: LlmMessageRole::User,
                        content: vec![ContentPart::Text {
                            text: admitted
                                .iter()
                                .map(|fact| fact.line.as_str())
                                .collect::<Vec<_>>()
                                .join("\n"),
                        }],
                    },
                ],
                tools: Vec::new(),
                params: BTreeMap::new(),
                provider_options: BTreeMap::new(),
            };
            let mut request = ctx
                .vault
                .authorize_model_role(super::DREAMER_NARRATIVE_ROLE, request, &self.inference)?
                .into_request();
            super::roles::bind_reasoning(ctx.vault, self.backend, &mut request)?;
            let step_hash = request
                .canonical_hash()
                .map_err(|_| invalid_consolidation("about request did not hash"))?;
            let step_ctx = DurableStepContext {
                vault: ctx.vault,
                attempt_id,
                run_id: attempt.status.attempt.run_id.clone(),
                envelope_actor: self.actor,
                subject: person,
                deadline: Some(ctx.deadline),
                now_ms: ctx.now_ms,
            };
            let response = match call_as_step(&step_ctx, self.backend, self.guard, request).await {
                Ok(StepOutcome::Finished { response, .. }) => {
                    charges.record_terminal(ctx.vault, attempt_id, step_hash, &response.usage)?;
                    response
                }
                Ok(StepOutcome::Trapped { .. }) => {
                    return Ok(DreamerAttemptExecution::Park {
                        reason: "durable step trapped for resume".to_owned(),
                        cause: DreamerParkCause::Signal,
                    });
                }
                Err(DurableStepError::SpentFinalizeRefused { usage }) => {
                    charges.record_usage(&usage);
                    return Ok(charges.checkpoint());
                }
                Err(DurableStepError::DeadlineHardCut) => {
                    return Ok(DreamerAttemptExecution::Park {
                        reason: DREAMER_HARD_CUT_PARK_REASON.to_owned(),
                        cause: DreamerParkCause::Checkpoint,
                    });
                }
                Err(DurableStepError::FinalizeRefused) => {
                    return Ok(DreamerAttemptExecution::Park {
                        reason: "wake pass finalize window".to_owned(),
                        cause: DreamerParkCause::Checkpoint,
                    });
                }
                Err(DurableStepError::Engine(error)) => return Err(error),
                Err(other) => {
                    return Ok(DreamerAttemptExecution::Park {
                        reason: other.to_string(),
                        cause: DreamerParkCause::of_step(&other),
                    });
                }
            };
            let reply: String = response
                .message
                .content
                .iter()
                .filter_map(|part| match part {
                    ContentPart::Text { text } => Some(text.as_str()),
                    _ => None,
                })
                .collect();
            let text = one_line(
                reply
                    .lines()
                    .find(|line| !line.trim().is_empty())
                    .unwrap_or(""),
                ABOUT_MAX_CHARS,
            );
            if text.is_empty() {
                return Ok(charges.park("the model wrote an empty about line"));
            }
            lines.push(AboutLine { band, text });
            below = Some(band_digest);
            if ctx.deadline.expired() {
                return Ok(charges.checkpoint());
            }
        }
        // The lines must stand on the facts as they are: a fact that moved
        // while the model wrote sends the attempt round again, soon.
        let now_facts = {
            let txn = snapshot(ctx.vault)?;
            person_facts(ctx.vault, &read, &txn, person)?
        };
        if facts_digest(&now_facts, TOP_BAND) != digest {
            return Ok(DreamerAttemptExecution::Deferred {
                completed_units: charges.units,
                retry_at: ctx
                    .now_ms
                    .div_ceil(1_000)
                    .saturating_add(FACTS_DRIFT_RETRY_SECS),
            });
        }
        let at = ctx.now_ms.div_ceil(1_000);
        ctx.vault.with_write_txn(|txn| {
            let mut row = PERSON_ABOUT
                .get(&ctx.vault.store, txn, &person)?
                .unwrap_or_default();
            row.previous = Some(PriorAbout {
                written: row.written,
                lines: std::mem::replace(&mut row.lines, lines),
                at: row.at,
            });
            row.written = digest;
            row.at = at;
            PERSON_ABOUT.put(&ctx.vault.store, txn, &person, &row)
        })?;
        Ok(DreamerAttemptExecution::Completed {
            completed_units: charges.units,
        })
    }
}
