//! Psych Mirror (ARCH-0025, FIX 18867): one person's three-tier profile
//! (compact, text, narrative) for one facet and world, written by the
//! Dreamer in one call from the claims about that person there.
//!
//! Every wake pass compares each profile's inputs with the snapshot it last
//! stored: the person's active, surfaced claims in that facet and world,
//! below the restricted band, ranked by the Psych Mirror source selection
//! (connectivity, affect salience, recency, entropy). A key whose inputs
//! moved, or that has no profile yet, queues a `dreamer.psych_mirror`
//! attempt on the Micro queue, at most once a day for a stored profile
//! (canon: regeneration at most daily per facet); a withdrawn profile is
//! regenerated at once. The attempt asks the narrative role once for all
//! three tiers, reads the claims again, and lands the profile with every
//! source claim registered as a dependency in the same write, so erasing
//! one withdraws the profile. Each source names the claim, the exact stored
//! revision read and the content hash of its words (FIX 11766), so a
//! companion reader's admission judges those words under its own key. A
//! withdrawn profile's regeneration clears its stale mark through the
//! regeneration fence.

use super::request_sources::{CallBackend, SourcedBackend};
use super::residency::spent_or_deferred;
use super::resources::document_version;
use super::step_charge::StepChargeTally;
use super::support::{DREAMER_PSYCH_MIRROR_ATTEMPT_TYPE, invalid_consolidation};
use super::turn_text::{dreamer_read, snapshot};
use crate::claim::{ClaimSource, ClaimSubject, ScopedRead};
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerConsolidationScope, DreamerParkCause,
    DreamerRunnerStore,
};
use crate::dreamer_wake::{DreamerAttemptExecution, DreamerAttemptExecutor, WakeAttemptContext};
use crate::error::{Error, Result};
use crate::inference_context::HostInferenceContext;
use crate::llm::call_as_step_checked;
use crate::model_step_context::{DurableStepContext, StepOutcome};
use crate::model_step_error::DurableStepError;
use crate::ports::{DependencyIndex, SourceSpan};
use crate::psych_profile::{
    PsychMirrorSourceCandidate, PsychProfile, PsychProfileConfidence, PsychProfileKey,
    PsychProfileSnapshotStatus, PsychProfileSource, PsychProfileSourceWords,
    psych_profile_entity_id,
};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};
use oneiron_model::llm::{
    BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart, LlmBackend, LlmMessage,
    LlmMessageRole, LlmRequest, LlmResponse, ModelId, ModelTierRef, ResponseFormat, ScopeResource,
    TierPrecedence,
};
use std::collections::{BTreeMap, BTreeSet};

/// The lowest sensitivity band the Dreamer never reads into consolidation
/// context (the neighbourhood's own floor): a profile's prose cannot be cut
/// by band, so it reads only the bands below it.
const RESTRICTED_BAND: u8 = 3;
/// How many ranked claims one profile reads: canon's claim density
/// saturates at 50, past which more claims add no confidence.
const SOURCE_LIMIT: usize = 50;
/// Canon: a stored profile regenerates at most daily per facet.
const REGENERATE_SECS: u64 = 86_400;
/// How long an attempt whose claims moved under the model waits to write again.
const INPUTS_DRIFT_RETRY_SECS: u64 = 60;
const INPUTS_DIGEST_DOMAIN: &[u8] = b"oneiron:psych-mirror-inputs:v1";

/// The engine's instruction for one profile's three tiers (ARCH-0025).
pub const PSYCH_MIRROR_INSTRUCTION: &str = "You write a person's psychological profile from \
the facts below, which are everything you may use, one per line as `predicate: value`. A fact \
marked (observed) was read from what the person did; where it disagrees with a fact marked \
(stated), go by the stated one. Never add, guess or imply a fact that is not listed. Answer \
with one JSON object of three strings. `text` (about 150 to 200 tokens): one plain paragraph on \
how this person thinks, decides and behaves, then their scores: OCEAN openness, \
conscientiousness, extraversion, agreeableness and neuroticism, each 0 to 100; their \
Enneagram type and its core fear; and up to five Schwartz values, highest first. `compact` \
(about 30 to 50 tokens): one sentence that compresses `text`, with the same scores in short \
form. `narrative` (about 500 to 1000 tokens): a readable character sheet on the same facts and \
the same scores, with the contradictions the facts show. When the facts are too few to judge \
a score, leave that score out rather than guess, and say only what is known. No markup outside \
the JSON.";

/// One claim a profile reads, as the Dreamer may read it.
#[derive(Clone)]
struct Source {
    claim: EntityId,
    learned_at: u64,
    /// The WORLD the claim lies in.
    world: Option<EntityId>,
    /// Content hash of the CLAIM body read.
    version: [u8; 32],
    /// blake3 of the body read, which names the stored revision it is.
    body_hash: [u8; 32],
    /// How many citations tie the claim in: its evidence references.
    citations: usize,
    readable: ScopeResource,
    source: Option<ClaimSource>,
    /// The claim's question, so a held observed fact sits beside the stated
    /// one of its question.
    question: Option<[u8; 32]>,
    /// `predicate: value`, as the model reads it.
    line: String,
    /// The selection signals; connectivity is set against the key's other
    /// claims when they are ranked.
    candidate: PsychMirrorSourceCandidate,
}

/// Each profile key a person's readable claims fall under, with those claims:
/// active, surfaced claims about the PERSON below the restricted band, by the
/// facet they were born in (none for the vault default) and their world, in
/// facet and world order.
fn person_inputs(
    vault: &Vault,
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    person: EntityId,
    default_facet: EntityId,
) -> Result<Vec<(PsychProfileKey, Vec<Source>)>> {
    let ids = vault.claims_for_subject_in_txn(txn, &person)?;
    let rows = read.get_entities_parts_in_txn(txn, &ids)?;
    let mut keys: BTreeMap<(Option<EntityId>, Option<EntityId>), Vec<Source>> = BTreeMap::new();
    for (claim, row) in ids.into_iter().zip(rows) {
        let Some((ENTITY_TYPE_CLAIM, learned_at, body)) = row else {
            continue;
        };
        let Ok(decoded) = crate::claim::decode_claim_body(&body, false) else {
            continue;
        };
        if decoded.subject != ClaimSubject::Entity(person) {
            continue;
        }
        // Every key a claim about the person names is visited, with no
        // eligible claim too: its profile then stands on nothing.
        let facet = (decoded.scope_facet != default_facet).then_some(decoded.scope_facet);
        let sources = keys.entry((facet, decoded.world)).or_default();
        if !crate::claim::claim_surfaceable(&decoded)
            || crate::claim::claim_sensitivity_band(&decoded).is_none_or(|b| b >= RESTRICTED_BAND)
        {
            continue;
        }
        let Ok(candidate) = crate::context_pack::psych_mirror_source_candidate_from_claim(
            claim, claim, 0.0, learned_at, &decoded,
        ) else {
            continue;
        };
        let citations = decoded.evidence_refs().map_or(0, |refs| refs.len());
        let value = decoded
            .value
            .as_str()
            .map_or_else(|| decoded.value.to_string(), str::to_owned);
        sources.push(Source {
            claim,
            learned_at,
            world: decoded.world,
            version: super::swarm_evidence_content_hash(&body),
            body_hash: *blake3::hash(&body).as_bytes(),
            citations,
            readable: document_version(claim, &body),
            source: decoded.source,
            question: crate::context_pack::source_ranking::question_key(&decoded),
            line: one_line(&format!("{}: {value}", decoded.predicate)),
            candidate,
        });
    }
    Ok(keys
        .into_iter()
        .map(|((facet, world), sources)| {
            (
                PsychProfileKey {
                    person,
                    facet,
                    world,
                },
                sources,
            )
        })
        .collect())
}

/// The claims a profile reads, by the Psych Mirror source selection, in
/// claim order: at most [`SOURCE_LIMIT`] of the key's readable claims. A
/// claim's connectivity is its citations against the key's most cited
/// claim (canon's fan-in, read off the claim itself).
fn selected(sources: Vec<Source>, now_secs: u64) -> Result<Vec<Source>> {
    let most = sources
        .iter()
        .map(|source| source.citations)
        .max()
        .unwrap_or(0);
    let candidates: Vec<_> = sources
        .iter()
        .map(|source| PsychMirrorSourceCandidate {
            connectivity: if most == 0 {
                0.0
            } else {
                source.citations as f32 / most as f32
            },
            ..source.candidate
        })
        .collect();
    let chosen: BTreeSet<EntityId> =
        crate::psych_profile::rank_psych_mirror_sources(&candidates, now_secs, SOURCE_LIMIT)?
            .into_iter()
            .map(|selected| selected.source_id)
            .collect();
    let mut kept: Vec<Source> = sources
        .into_iter()
        .filter(|source| chosen.contains(&source.claim))
        .collect();
    kept.sort_by_key(|source| source.claim);
    Ok(kept)
}

/// The selected claims of `key` read now, in the caller's snapshot.
fn key_sources(
    vault: &Vault,
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    key: &PsychProfileKey,
    now_secs: u64,
) -> Result<Vec<Source>> {
    let default_facet = vault.default_facet_in_txn(txn)?;
    let sources = person_inputs(vault, read, txn, key.person, default_facet)?
        .into_iter()
        .find_map(|(found, sources)| (found == *key).then_some(sources))
        .unwrap_or_default();
    selected(sources, now_secs)
}

/// The source record of each claim in `sources`, in `txn` (FIX 11766): the
/// claim, the exact stored revision whose body was read and the content
/// hash of those words. `None` when a claim's body read names no revision
/// it retains: the landing writes nothing and the next pass rebuilds.
fn profile_sources_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    sources: &[Source],
) -> Result<Option<Vec<PsychProfileSource>>> {
    let mut records = Vec::with_capacity(sources.len());
    for source in sources {
        let Some(revision) = crate::vault::entity_revision::revision_for_body_hash_in_txn(
            vault,
            txn,
            &source.claim,
            &source.body_hash,
        )?
        else {
            return Ok(None);
        };
        records.push(PsychProfileSource {
            revision_ref: source.claim,
            document_ref: source.claim,
            world_ref: source.world,
            document_revision: revision,
            words: PsychProfileSourceWords::Record {
                content: source.version,
            },
        });
    }
    Ok(Some(records))
}

/// Digest of the selected claims and the versions read.
fn inputs_digest(sources: &[Source]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(INPUTS_DIGEST_DOMAIN);
    for source in sources {
        hasher.update(source.claim.as_bytes());
        hasher.update(&source.version);
    }
    *hasher.finalize().as_bytes()
}

/// Whether the stored profile at `id` was written from exactly `sources`:
/// the same claims, each at the version the profile pinned (its content
/// hash: a claim rewritten under its id is another version), every one
/// learned no later than the profile, and the profile neither marked stale
/// nor withdrawn. Also when it was written.
fn stored_state(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    sources: &[Source],
) -> Result<StoredProfile> {
    if crate::ports::stale_in_txn(&vault.store, txn, id)? {
        return Ok(StoredProfile::Withdrawn);
    }
    let Some(raw) = vault.get_raw_in(txn, id)? else {
        return Ok(StoredProfile::Missing);
    };
    let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
        return Ok(StoredProfile::Missing);
    };
    let Some(profile) = vault.get_psych_profile_in_txn(txn, id)? else {
        return Ok(StoredProfile::Missing);
    };
    let ids: Vec<EntityId> = sources.iter().map(|source| source.claim).collect();
    let pinned = |source: &Source| {
        profile.sources.iter().any(|kept| {
            kept.revision_ref == source.claim
                && kept.words
                    == PsychProfileSourceWords::Record {
                        content: source.version,
                    }
        })
    };
    let current = profile.status == PsychProfileSnapshotStatus::Fresh
        && profile.source_revision_ids == ids
        && sources
            .iter()
            .all(|source| pinned(source) && source.learned_at <= header.learned_at);
    Ok(if current {
        StoredProfile::Current
    } else {
        StoredProfile::Behind {
            written_at: header.learned_at,
        }
    })
}

enum StoredProfile {
    Missing,
    Withdrawn,
    Current,
    /// A profile written from other claims, `written_at`.
    Behind {
        written_at: u64,
    },
}

/// The facts as the model reads them, one per line. Where they hold an
/// observed and a stated fact on one question, both say which they are.
fn prompt_lines(sources: &[Source]) -> String {
    let held = |kind: ClaimSource| -> BTreeSet<[u8; 32]> {
        sources
            .iter()
            .filter(|source| source.source == Some(kind))
            .filter_map(|source| source.question)
            .collect()
    };
    let (stated, observed) = (held(ClaimSource::UserStated), held(ClaimSource::Observed));
    sources
        .iter()
        .map(|source| {
            let pair = source
                .question
                .is_some_and(|question| stated.contains(&question) && observed.contains(&question));
            match source.source {
                Some(ClaimSource::UserStated) if pair => format!("{} (stated)", source.line),
                Some(ClaimSource::Observed) if pair => format!("{} (observed)", source.line),
                _ => source.line.clone(),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Canon's confidence: claim density saturating at 50 claims, blended 60/40
/// with the claims' mean source quality (stated 1.0, observed 0.8, imported
/// 0.7, inferred and the rest 0.5), to two decimals. The same for each tier.
fn profile_confidence(sources: &[Source]) -> f32 {
    if sources.is_empty() {
        return 0.0;
    }
    let count = sources.len() as f64;
    let density = (count / SOURCE_LIMIT as f64).min(1.0);
    let quality = sources
        .iter()
        .map(|source| match source.source {
            Some(ClaimSource::UserStated) => 1.0,
            Some(ClaimSource::Observed) => 0.8,
            Some(ClaimSource::Imported) => 0.7,
            _ => 0.5,
        })
        .sum::<f64>()
        / count;
    (((density * 0.6 + quality * 0.4) * 100.0).round() / 100.0) as f32
}

fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The three tiers a reply gives, as the step's check and the landing read
/// them alike.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileTiers {
    compact: String,
    text: String,
    narrative: String,
}

fn tiers_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["compact", "text", "narrative"],
        "properties": {
            "compact": {"type": "string"},
            "text": {"type": "string"},
            "narrative": {"type": "string"},
        }
    })
}

/// The profile a reply gives over `sources`, validated as the record is:
/// every tier non-empty and within its stored cap.
fn reply_profile(
    response: &LlmResponse,
    person: EntityId,
    sources: &[Source],
) -> std::result::Result<PsychProfile, String> {
    let reply = super::step_charge::reply_text(response);
    let tiers: ProfileTiers = serde_json::from_str(reply.trim())
        .map_err(|error| format!("the profile reply is not its JSON object: {error}"))?;
    let confidence = profile_confidence(sources);
    let confidence = PsychProfileConfidence::new(confidence, confidence, confidence)
        .map_err(|error| error.to_string())?;
    PsychProfile::new(
        person,
        tiers.compact.trim(),
        tiers.text.trim(),
        tiers.narrative.trim(),
        sources.iter().map(|source| source.claim).collect(),
        confidence,
    )
    .map_err(|error| error.to_string())
}

fn key_input(key: &PsychProfileKey) -> rmpv::Value {
    let id = |id: &EntityId| rmpv::Value::Binary(id.as_bytes().to_vec());
    let mut entries = vec![(rmpv::Value::from("person"), id(&key.person))];
    if let Some(facet) = &key.facet {
        entries.push((rmpv::Value::from("facet"), id(facet)));
    }
    if let Some(world) = &key.world {
        entries.push((rmpv::Value::from("world"), id(world)));
    }
    rmpv::Value::Map(entries)
}

/// The profile key a `dreamer.psych_mirror` attempt's input names.
pub(crate) fn psych_mirror_key_of_input(input: &rmpv::Value) -> Result<PsychProfileKey> {
    let rmpv::Value::Map(entries) = input else {
        return Err(invalid_consolidation("psych mirror input is not a map"));
    };
    let mut person = None;
    let (mut facet, mut world) = (None, None);
    for (name, value) in entries {
        let rmpv::Value::Binary(bytes) = value else {
            return Err(invalid_consolidation("psych mirror input holds a non-id"));
        };
        let bytes: [u8; 16] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| invalid_consolidation("psych mirror input holds a non-id"))?;
        let id = EntityId::from_bytes(bytes)?;
        let slot = match name.as_str() {
            Some("person") => &mut person,
            Some("facet") => &mut facet,
            Some("world") => &mut world,
            _ => {
                return Err(invalid_consolidation(
                    "psych mirror input names an unknown key",
                ));
            }
        };
        if slot.replace(id).is_some() {
            return Err(invalid_consolidation("psych mirror input repeats a key"));
        }
    }
    let person =
        person.ok_or_else(|| invalid_consolidation("psych mirror input names no person"))?;
    Ok(PsychProfileKey {
        person,
        facet,
        world,
    })
}

/// Queues the profile attempt of every key whose inputs moved since its
/// stored profile, or that has none: at most daily for a stored profile, at
/// once for a missing or withdrawn one. A stored profile whose key has no
/// eligible claim left (each retracted, hidden or restricted) is withdrawn
/// at once: it stands on nothing. Runs at the start of every Dreamer wake
/// pass.
pub(crate) fn enqueue_psych_mirror_on_wake(vault: &Vault, now: u64) -> Result<()> {
    let persons = vault.entities_by_type(ENTITY_TYPE_PERSON)?;
    if persons.is_empty() {
        return Ok(());
    }
    let read = dreamer_read(vault)?;
    let (mut due, mut withdrawn) = (Vec::new(), Vec::new());
    {
        let txn = snapshot(vault)?;
        let default_facet = vault.default_facet_in_txn(&txn)?;
        for person in persons {
            for (key, sources) in person_inputs(vault, &read, &txn, person, default_facet)? {
                let sources = selected(sources, now)?;
                let id = psych_profile_entity_id(&key);
                if sources.is_empty() {
                    if matches!(
                        stored_state(vault, &txn, &id, &sources)?,
                        StoredProfile::Current | StoredProfile::Behind { .. }
                    ) {
                        withdrawn.push(id);
                    }
                    continue;
                }
                let regenerate = match stored_state(vault, &txn, &id, &sources)? {
                    StoredProfile::Current => false,
                    StoredProfile::Missing | StoredProfile::Withdrawn => true,
                    StoredProfile::Behind { written_at } => {
                        now.saturating_sub(written_at) >= REGENERATE_SECS
                    }
                };
                if regenerate {
                    due.push((key, inputs_digest(&sources)));
                }
            }
        }
    }
    if due.is_empty() && withdrawn.is_empty() {
        return Ok(());
    }
    vault.with_write_txn(|txn| {
        for id in &withdrawn {
            crate::ports::RetrievalIndex::port_retrieval_mark_stale(vault, txn, id)?;
        }
        for (key, digest) in &due {
            DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
                txn,
                DreamerConsolidationScope::Micro.attempt_kind(),
                DreamerAttemptPayload {
                    attempt_type: DREAMER_PSYCH_MIRROR_ATTEMPT_TYPE.to_owned(),
                    input: key_input(key),
                    parent_attempt: None,
                },
                Some(format!(
                    "{DREAMER_PSYCH_MIRROR_ATTEMPT_TYPE}:{}:{}",
                    psych_profile_entity_id(key).to_hex(),
                    crate::entity_id::bytes_to_hex_lower(digest)
                )),
                None,
                now,
            )?;
        }
        Ok(())
    })?;
    vault.store.notify_attempt_observers();
    Ok(())
}

/// Lands `profile` at `id` over `sources` in the caller's writer, learned at
/// `now`, with each source claim registered as a dependency at the version
/// read. A withdrawn profile's stale mark clears through the regeneration
/// fence; any other profile's old registrations are replaced.
fn land_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    profile: &PsychProfile,
    sources: &[Source],
    now: u64,
) -> Result<()> {
    vault.put_psych_profile_in_txn(txn, id, profile, now)?;
    let spans: Vec<SourceSpan> = sources
        .iter()
        .map(|source| SourceSpan {
            document: source.claim,
            frontier: source.learned_at,
        })
        .collect();
    if !vault.port_dependency_complete_regeneration(txn, id, now, &spans)? {
        crate::ports::remove_dependency_rows_for_dependent_in_txn(&vault.store, txn, id)?;
        for span in spans {
            crate::ports::record_dependency_in_txn(&vault.store, txn, span, id)?;
        }
    }
    Ok(())
}

/// Wraps an executor with the Psych Mirror arm. Every other attempt is
/// delegated untouched.
pub struct PsychMirrorExecutor<'a, E> {
    inner: E,
    backend: &'a dyn LlmBackend,
    /// `backend` bound per call to the rows its input was read from, when
    /// the host lends that (FIX 6998).
    sourced: Option<&'a dyn SourcedBackend>,
    guard: &'a BudgetGuard,
    actor: WriteActor,
    model: ModelId,
    inference: HostInferenceContext<'a>,
    instruction: &'a str,
}

impl<'a, E> PsychMirrorExecutor<'a, E> {
    #[must_use]
    pub fn new(
        inner: E,
        backend: &'a dyn LlmBackend,
        sourced: Option<&'a dyn SourcedBackend>,
        guard: &'a BudgetGuard,
        actor: WriteActor,
        model: ModelId,
        inference: HostInferenceContext<'a>,
        instruction: Option<&'a str>,
    ) -> Self {
        Self {
            inner,
            backend,
            sourced,
            guard,
            actor,
            model,
            inference,
            instruction: instruction.unwrap_or(PSYCH_MIRROR_INSTRUCTION),
        }
    }
}

impl<E: DreamerAttemptExecutor> DreamerAttemptExecutor for PsychMirrorExecutor<'_, E> {
    fn runs_coach_host_jobs(&self) -> bool {
        self.inner.runs_coach_host_jobs()
    }

    fn runs_coach_heals(&self) -> bool {
        self.inner.runs_coach_heals()
    }

    async fn execute_partition_window<'w>(
        &mut self,
        window: &mut [(&'w DreamerAdmittedAttempt, WakeAttemptContext<'w>)],
    ) -> Vec<Result<DreamerAttemptExecution>> {
        self.inner.execute_partition_window(window).await
    }

    async fn execute(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        if attempt.status.payload.attempt_type != DREAMER_PSYCH_MIRROR_ATTEMPT_TYPE {
            return self.inner.execute(attempt, ctx).await;
        }
        self.compose(attempt, ctx).await
    }
}

impl<E> PsychMirrorExecutor<'_, E> {
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
        let key = psych_mirror_key_of_input(&attempt.status.payload.input)?;
        let id = psych_profile_entity_id(&key);
        let now_secs = ctx.now_ms / 1_000;
        let read = dreamer_read(ctx.vault)?;
        let (sources, stored) = {
            let txn = snapshot(ctx.vault)?;
            let sources = key_sources(ctx.vault, &read, &txn, &key, now_secs)?;
            let stored = stored_state(ctx.vault, &txn, &id, &sources)?;
            (sources, stored)
        };
        // Nothing to write from, or an earlier attempt already wrote from
        // these claims.
        if sources.is_empty() || matches!(stored, StoredProfile::Current) {
            return Ok(DreamerAttemptExecution::Completed {
                completed_units: 0,
                step_hashes: Vec::new(),
            });
        }
        let digest = inputs_digest(&sources);
        let locality = self.inference.selected_locality().ok_or_else(|| {
            Error::InvalidConfig("psych mirror host binding needs locality".into())
        })?;
        let keyless = self.inference.selected_keyless();
        let mut charges = StepChargeTally::default();
        let claims: Vec<EntityId> = sources.iter().map(|source| source.claim).collect();
        let request = LlmRequest {
            model: self.model.clone(),
            envelope: CallEnvelope {
                seat_effort: None,
                // The call reads exactly the claims the profile is written from.
                scope: oneiron_model::llm::Scope {
                    readable: sources
                        .iter()
                        .map(|source| source.readable.clone())
                        .collect::<BTreeSet<_>>(),
                    ..oneiron_model::llm::Scope::default()
                },
                purpose: CallPurpose::Extraction,
                class: CallClass::BestEffort,
                tier: TierPrecedence::for_purpose(
                    &CallPurpose::Extraction,
                    ModelTierRef("consolidation".into()),
                ),
                response_format: ResponseFormat::Json {
                    schema: tiers_schema(),
                },
                locality,
                host_keyless: keyless,
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
                        text: prompt_lines(&sources),
                    }],
                },
            ],
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
            host_segments: None,
        };
        let authorized = match ctx.vault.authorize_model_role(
            super::DREAMER_NARRATIVE_ROLE,
            request,
            &self.inference,
        ) {
            Ok(authorized) => authorized,
            Err(error) => return spent_or_deferred(error, ctx, &charges),
        };
        let mut request = authorized.into_request();
        if let Err(error) = super::roles::bind_reasoning(ctx.vault, self.backend, &mut request) {
            return spent_or_deferred(error, ctx, &charges);
        }
        let Ok(step_hash) = request.canonical_hash() else {
            return spent_or_deferred(
                invalid_consolidation("psych mirror request did not hash"),
                ctx,
                &charges,
            );
        };
        let step_ctx = DurableStepContext {
            vault: ctx.vault,
            attempt_id,
            run_id: attempt.status.attempt.run_id.clone(),
            envelope_actor: self.actor,
            subject: key.person,
            deadline: Some(ctx.deadline),
            now_ms: ctx.now_ms,
        };
        let backend = CallBackend::new(self.backend, self.sourced, Some(claims));
        // A reply that gives no profile is refused inside the step, paid and
        // never memoized, so its Retry asks again (FIX 7431).
        let check_sources = sources.clone();
        let check = move |response: &LlmResponse| {
            reply_profile(response, key.person, &check_sources).map(|_| ())
        };
        let response =
            match call_as_step_checked(&step_ctx, backend.get(), self.guard, request, &check).await
            {
                Ok(StepOutcome::Finished {
                    response, memoized, ..
                }) => {
                    if let Err(error) =
                        charges.record_terminal(ctx.vault, attempt_id, step_hash, &response.usage)
                    {
                        if !memoized {
                            charges.record_usage(&response.usage);
                        }
                        return spent_or_deferred(error, ctx, &charges);
                    }
                    response
                }
                Ok(StepOutcome::Trapped { .. }) => {
                    return Ok(charges
                        .park_for("durable step trapped for resume", DreamerParkCause::Signal));
                }
                Err(DurableStepError::SpentFinalizeRefused { usage }) => {
                    charges.record_usage(&usage);
                    return Ok(charges.checkpoint());
                }
                Err(DurableStepError::DeadlineHardCut) => return Ok(charges.checkpoint()),
                Err(DurableStepError::FinalizeRefused) => {
                    return Ok(
                        charges.park_for("wake pass finalize window", DreamerParkCause::Checkpoint)
                    );
                }
                Err(DurableStepError::SpentSchemaValidation { usage, errors, .. }) => {
                    charges.record_usage(&usage);
                    return Ok(charges.park_for(&errors.join("; "), DreamerParkCause::Retry));
                }
                Err(DurableStepError::Engine(error)) => {
                    return spent_or_deferred(error, ctx, &charges);
                }
                Err(other) => {
                    return Ok(
                        charges.park_for(&other.to_string(), DreamerParkCause::of_step(&other))
                    );
                }
            };
        let profile = match reply_profile(&response, key.person, &sources) {
            Ok(profile) => profile,
            // Only a memo stored before the check can give no profile: it
            // goes, and the Retry asks again (FIX 7431, OF-193a).
            Err(_) => {
                return match charges.park_refused_reply(
                    ctx.vault,
                    attempt_id,
                    step_hash,
                    "the model wrote no psych profile",
                ) {
                    Ok(parked) => Ok(parked),
                    Err(error) => spent_or_deferred(error, ctx, &charges),
                };
            }
        };
        // The profile must stand on the claims as they are: a claim that
        // moved while the model wrote sends the attempt round again, soon.
        let now_sources = {
            let txn = match snapshot(ctx.vault) {
                Ok(txn) => txn,
                Err(error) => return spent_or_deferred(error, ctx, &charges),
            };
            match key_sources(ctx.vault, &read, &txn, &key, now_secs) {
                Ok(now_sources) => now_sources,
                Err(error) => return spent_or_deferred(error, ctx, &charges),
            }
        };
        if inputs_digest(&now_sources) != digest {
            return Ok(DreamerAttemptExecution::Deferred {
                completed_units: charges.units,
                retry_at: ctx
                    .now_ms
                    .div_ceil(1_000)
                    .saturating_add(INPUTS_DRIFT_RETRY_SECS),
                step_hashes: charges.step_hashes.clone(),
            });
        }
        let landed = match ctx.vault.with_write_txn(|txn| {
            // An erase that lands between the read above and this write must
            // not have its words put back: the PERSON and the exact claims
            // are read again through this write's own snapshot, and a stale
            // landing writes nothing; the next pass rebuilds.
            if !crate::consent::person_is_live_in_txn(ctx.vault, txn, &key.person)? {
                return Ok(false);
            }
            let in_txn = key_sources(ctx.vault, &read, txn, &key, now_secs)?;
            if inputs_digest(&in_txn) != digest {
                return Ok(false);
            }
            let Some(records) = profile_sources_in(ctx.vault, txn, &in_txn)? else {
                return Ok(false);
            };
            let profile = profile.clone().with_sources(records)?;
            let now = ctx.vault.store.clock.now_recorded_at();
            land_in_txn(ctx.vault, txn, &id, &profile, &in_txn, now)?;
            Ok(true)
        }) {
            Ok(landed) => landed,
            Err(error) => return spent_or_deferred(error, ctx, &charges),
        };
        if !landed {
            tracing::warn!(
                target: "oneiron::dreamer",
                code = "psych_mirror_stale_landing",
                person = %key.person.to_hex(),
                "a stale psych profile landing wrote nothing; the next pass rebuilds"
            );
        }
        Ok(DreamerAttemptExecution::Completed {
            completed_units: charges.units,
            step_hashes: charges.step_hashes.clone(),
        })
    }
}
