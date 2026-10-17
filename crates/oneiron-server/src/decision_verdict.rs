//! `ai.verdict` (ARCH-0076): a caller's own typed question through the
//! host's decision ladder. The SDK host door and any other server caller
//! (a fact hook's host) run it through [`run_verdict`], so one question
//! family, one evidence rule and one clock serve them all.
//!
//! A routine driver step (OF-523, the CUA-S1 pattern) is the same call with
//! `routine` set: its options are the step's candidates, the ladder also
//! offers NONE, reobserve and "too complicated, ask up", and the answer comes
//! back as the outcome the program acts on. A screenshot rides as an image
//! evidence ref, read at the Local-vision rung on the caller's own run; a Box
//! or Point question finds its target there, once the host's presence
//! question says it is there. A Score is one number in the caller's own
//! range. The subgoal's steps share one clock through `until_ms`.
//!
//! A screenshot the calling code run's browser holds is named by its
//! `blake3:` ref. The run reads it from its own browser and hands it in as
//! [`HELD_IMAGE`]: no scoped read pulls it, and a ref no browser of the run
//! holds is refused. The decision keeps it as a blob artifact written on the
//! run, so its receipt's evidence pin names pixels a later reader can pull
//! back after the browser dropped them.
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use oneiron::claim::ScopedRead;
use oneiron::llm::decision::catalogue::{AI_VERDICT, AI_VERDICT_ROUTINE};
use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionImage, DecisionProvider, DecisionRung, EvidenceVersion,
    LocatedDecision, MAX_DECISION_STATE_BYTES, ModelDecisionProvider, RoutineOutcome, RoutineTrail,
    routine_choice,
};
use oneiron::llm::image::ImageBytes;
use oneiron::memory::caps::MAX_RECALL_DEADLINE_MS;
use oneiron::memory::{
    BlobArtifactInput, BlobVersionView, ImageViewRequest, MEMORY_CODE_INTERNAL, Memory,
    MemoryError, MemoryResult,
};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::task_verb::sdk::{AI_VERDICT_DEADLINE_MS, AiVerdict, AiVerdictRequest};
use oneiron::{BudgetExhaustionPolicy, EdgeActorClass, EntityId, WriteActor};

use crate::ai_host::LocalVisionModel;
use crate::server::SyncServer;

/// The state field, and the question's name, for a call's image.
const IMAGE: &str = "image";

/// The ref prefix of a screenshot a code run's browser holds.
pub(crate) const HELD_PREFIX: &str = "blake3:";

tokio::task_local! {
    /// The screenshot an `ai.verdict` in this task names by its `blake3:`
    /// ref, as the calling code run's browser holds it (OF-523).
    pub(crate) static HELD_IMAGE: Option<HeldImage>;
}

/// A held browser screenshot as a decision reads it: an evidence ref on the
/// code run that holds it, versioned by its bytes.
#[derive(Debug, Clone)]
pub(crate) struct HeldImage {
    handle: String,
    image: DecisionImage,
}

impl HeldImage {
    /// The PNG `png` that code run `run`'s browser holds under `handle`.
    pub(crate) fn new(run: EntityId, handle: &str, png: Vec<u8>) -> Self {
        Self {
            handle: handle.to_owned(),
            image: DecisionImage {
                name: IMAGE.to_owned(),
                evidence: EvidenceVersion {
                    id: run,
                    body_hash: *blake3::hash(&png).as_bytes(),
                },
                image: ImageBytes {
                    bytes: png,
                    media_type: "image/png".to_owned(),
                },
                frame: None,
            },
        }
    }

    /// The held image `handle` names, when this task holds it.
    pub(crate) fn in_task(handle: Option<&str>) -> Option<DecisionImage> {
        let handle = handle?;
        HELD_IMAGE
            .try_with(|held| {
                held.as_ref()
                    .filter(|held| held.handle == handle)
                    .map(|held| held.image.clone())
            })
            .ok()
            .flatten()
    }
}

/// Asks `request` through the host's ladder for `principal`, under one clock
/// started here (or the subgoal's, when the request names `until_ms`). Each
/// evidence ref is read under `reader`, the caller's own scoped read: a ref
/// it cannot read is refused as a missing one is, and the providers read the
/// views it can in the call's state, beside the caller's own `state`. An
/// image is pulled through `lane`, the same caller's scoped read; a caller
/// with none reads no image. A `held` image is the run's own screenshot,
/// read from its browser. The dial climbs from the first rung that takes the
/// question's contract over its images (the Local-vision seat for an image)
/// to the request's ceiling (`big` when absent); a verdict never queues an
/// owner ask.
///
/// Every model rung blocks on the server's runtime: call this on a blocking
/// thread.
pub(crate) fn run_verdict(
    server: &SyncServer,
    principal: EntityId,
    class: EdgeActorClass,
    reader: &Memory<'_>,
    lane: Option<&ScopedRead<'_>>,
    held: Option<DecisionImage>,
    request: &AiVerdictRequest,
) -> MemoryResult<AiVerdict> {
    let started = Instant::now();
    oneiron::memory::caps::check_deadline_ms(request.deadline_ms)?;
    oneiron::memory::caps::check_batch_len("evidence", request.evidence.len())?;
    let ceiling = request.ceiling.unwrap_or(DecisionRung::Big);
    if ceiling == DecisionRung::Human {
        return Err(MemoryError::bad_request_with(
            "ai.verdict never queues an owner ask",
            &["Name a ceiling below human, or ask the owner through ask."],
        ));
    }
    let contract = contract(request)?;
    let family = if request.routine {
        AI_VERDICT_ROUTINE
    } else {
        AI_VERDICT
    };
    let key = serde_json::to_vec(&contract).map_err(|_| internal())?;
    let question = family
        .question(&[key.as_slice()], request.question.clone(), contract)
        .map_err(|_| {
            MemoryError::bad_request_with(
                "the question does not make a typed question",
                &[
                    "Word it in 1 to 16384 bytes, with at most 64 distinct options of 1 to 256 bytes each, or a score's finite min below its max.",
                ],
            )
        })?;
    let views = if request.evidence.is_empty() {
        Vec::new()
    } else {
        reader.hydrate(&request.evidence)?.value
    };
    let mut evidence = views
        .iter()
        .map(|view| EntityId::from_hex(&view.id_hex))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| internal())?;
    let state = serde_json::json!({
        "state": request.state.clone().unwrap_or(serde_json::Value::Null),
        "evidence": views
            .iter()
            .map(|view| serde_json::json!({
                "ref": view.id_hex,
                "kind": view.kind,
                "body": view.body,
            }))
            .collect::<Vec<_>>(),
    });
    if serde_json::to_vec(&state).map_or(true, |bytes| bytes.len() > MAX_DECISION_STATE_BYTES) {
        return Err(MemoryError::bad_request_with(
            format!(
                "the state and the evidence views pass the ladder's {MAX_DECISION_STATE_BYTES}-byte state"
            ),
            &["Name fewer or smaller evidence refs, or a smaller state."],
        ));
    }
    let images = match (&request.image, held) {
        (Some(handle), Some(held)) => vec![kept(reader, handle, readable(held)?)],
        (Some(handle), None) if handle.starts_with(HELD_PREFIX) => {
            return Err(MemoryError::bad_request_with(
                format!("no browser of this run holds image {handle}"),
                &["Take the screenshot again in this run, and name the ref it gave."],
            ));
        }
        (Some(handle), None) => vec![pull(lane, handle)?],
        (None, _) => Vec::new(),
    };
    evidence.extend(images.iter().map(|image| image.evidence.id));
    let (budget, until_ms) = clock(request);
    let deadline = RetrievalDeadline::hard(started, budget);
    let host = server.decision_host();
    let mut dial = host.dial(ceiling);
    // An image is read at the Local-vision rung, seated on this call's own
    // run; a rung above it that reads no image is skipped.
    let local = if images.is_empty() {
        None
    } else {
        if ceiling < DecisionRung::Local {
            return Err(MemoryError::bad_request_with(
                "an image is read from the Local-vision rung up",
                &["Name a ceiling of local or above."],
            ));
        }
        dial.first = DecisionRung::Local;
        Some(vision_rung(
            server,
            principal,
            class,
            &images,
            "ai.verdict",
        )?)
    };
    let mut ladder = host.ladder().ladder();
    if let Some(rung) = &local {
        ladder.local = Some(rung as &dyn DecisionProvider);
    }
    // A rung that cannot take the contract over the images is passed over:
    // a Score starts above a seat that reads none, and never drops its image.
    dial.first = ladder
        .first_taking(&question, dial, &images)
        .ok_or_else(|| {
            MemoryError::bad_request_with(
                "no rung up to the ceiling answers this contract over this evidence",
                &[
                    "Raise the ceiling, or ask a score without an image: no image seat reads a score.",
                ],
            )
        })?;
    let failed = |error: oneiron::Error| {
        MemoryError::bad_request_with(
            format!("ai.verdict: {error}"),
            &["Change the question, its options or its state as the ladder asks."],
        )
    };
    let reversibility = request.reversibility.into();
    // A Box or Point question asks the host's presence question first.
    if question.contract.locates() {
        let located = ladder
            .run_located(
                &question,
                principal,
                &evidence,
                &images,
                &state,
                dial,
                &host.bands(),
                reversibility,
                &deadline,
            )
            .map_err(failed)?;
        let outcome = if request.routine {
            Some(RoutineOutcome::of_located(&located).map_err(failed)?)
        } else {
            None
        };
        let screenshot = outcome.as_ref().is_some_and(|outcome| {
            RoutineTrail {
                misses: request.misses,
            }
            .record(outcome)
        });
        return Ok(AiVerdict {
            outcome,
            screenshot,
            until_ms: Some(until_ms),
            ..located_verdict(located)
        });
    }
    if request.routine {
        let routine = ladder
            .run_routine(
                &question,
                principal,
                &evidence,
                &images,
                &state,
                dial,
                &host.bands(),
                reversibility,
                &deadline,
            )
            .map_err(failed)?;
        let mut trail = RoutineTrail {
            misses: request.misses,
        };
        let screenshot = trail.record(&routine.outcome);
        return Ok(AiVerdict {
            outcome: Some(routine.outcome),
            screenshot,
            until_ms: Some(until_ms),
            ..routine.decision.into()
        });
    }
    let decision = ladder
        .run_images(
            &question,
            principal,
            &evidence,
            &images,
            &state,
            dial,
            &host.bands(),
            reversibility,
            &deadline,
        )
        .map_err(failed)?;
    Ok(AiVerdict {
        until_ms: Some(until_ms),
        ..decision.into()
    })
}

/// The request's answer contract, as the call asks it: a Box or a Point
/// finds its target in `image`, and a routine step is a Choice among its
/// candidates (the ladder adds NONE, reobserve and ask up) or a Box or a
/// Point.
fn contract(request: &AiVerdictRequest) -> MemoryResult<AnswerContract> {
    let contract = request.contract.clone();
    if contract.locates() && request.image.is_none() {
        return Err(MemoryError::bad_request_with(
            "a box or point question finds its target in an image",
            &["Name the image's view handle."],
        ));
    }
    if !request.routine {
        return Ok(contract);
    }
    match contract {
        AnswerContract::Choice { options } => routine_choice(&options).map_err(|_| {
            MemoryError::bad_request_with(
                "a routine step offers 1 to 61 candidates",
                &[
                    "Name each candidate once; NONE, reobserve and \"too complicated, ask up\" are offered for you.",
                ],
            )
        }),
        AnswerContract::Box | AnswerContract::Point => Ok(contract),
        AnswerContract::Noul | AnswerContract::Score { .. } => {
            Err(MemoryError::bad_request_with(
                "a routine step is a choice among its candidates, or a box or point",
                &["Ask a yes/no or a score without `routine`."],
            ))
        }
    }
}

/// A Box or Point call's verdict: the answer on its contract, the
/// coordinates' confidence only when they were read (a found absence's
/// P(yes) is the presence step's, never a coordinate's), no rung for an
/// abstain, the standing step's receipt, and the presence step beside it.
fn located_verdict(located: LocatedDecision) -> AiVerdict {
    let answer = located.answer.clone();
    let read = located.location.is_some();
    let presence = located.presence.clone();
    let (standing, _) = located.split();
    let verdict = AiVerdict::from(standing);
    AiVerdict {
        p: verdict.p.filter(|_| read),
        rung: verdict.rung.filter(|_| answer != DecisionAnswer::Abstain),
        answer,
        presence,
        ..verdict
    }
}

/// A held screenshot kept as a blob artifact the caller writes, its bytes a
/// version made by the run that took it: the pin then names that artifact
/// at the bytes' hash, which is the version's own. A caller that may not
/// write keeps the pin on the run, and the pixels go with its browser.
fn kept(reader: &Memory<'_>, handle: &str, image: DecisionImage) -> DecisionImage {
    let stored = keep_screenshot(
        reader,
        &image.evidence.id.to_hex(),
        format!("decision screenshot {handle}"),
        image.image.media_type.clone(),
        &image.image.bytes,
    );
    let artifact = match stored.map(|version| EntityId::from_hex(&version.artifact_ref)) {
        Ok(Ok(artifact)) => artifact,
        Ok(Err(_)) => return image,
        Err(error) => {
            tracing::warn!(%error, %handle, "the decision screenshot stays a ref on its run");
            return image;
        }
    };
    DecisionImage {
        evidence: EvidenceVersion {
            id: artifact,
            ..image.evidence
        },
        ..image
    }
}

/// A screenshot's pixels as a new blob artifact `writer` writes, named
/// `name`, with `bytes` as its one version, made by run `run`. The version
/// names the exact bytes (its hash) where the artifact's head may move.
pub(crate) fn keep_screenshot(
    writer: &Memory<'_>,
    run: &str,
    name: String,
    media_type: String,
    bytes: &[u8],
) -> MemoryResult<BlobVersionView> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let artifact = writer.put_blob_artifact(&BlobArtifactInput {
        id: None,
        name,
        media_type,
        occurred_at: now,
        learned_at: None,
    })?;
    writer.append_blob_version(&artifact.id_hex, bytes, Some(run), now, None)
}

/// The call's budget, and the Unix milliseconds it ends at: the time left
/// to the subgoal's `until_ms` (none when it has passed), or the request's
/// own `deadline_ms`, and one call never past [`MAX_RECALL_DEADLINE_MS`].
fn clock(request: &AiVerdictRequest) -> (Duration, u64) {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        });
    let asked = request.deadline_ms.unwrap_or(AI_VERDICT_DEADLINE_MS);
    let budget_ms = match request.until_ms {
        Some(until) => until
            .saturating_sub(now_ms)
            .min(request.deadline_ms.unwrap_or(MAX_RECALL_DEADLINE_MS)),
        None => asked,
    }
    .min(MAX_RECALL_DEADLINE_MS);
    (
        Duration::from_millis(budget_ms),
        now_ms.saturating_add(budget_ms),
    )
}

/// The image behind `handle`, pulled through the caller's own scoped read
/// before any model reads it, as an evidence ref with its body version.
fn pull(lane: Option<&ScopedRead<'_>>, handle: &str) -> MemoryResult<DecisionImage> {
    let lane = lane.ok_or_else(|| {
        MemoryError::bad_request_with(
            "this caller reads no image through ai.verdict",
            &["Ask through the SDK host door, which reads under your scoped read."],
        )
    })?;
    let request = ImageViewRequest {
        handle: handle.to_owned(),
        region: None,
        edge: None,
    };
    let mut pulled = oneiron::memory::pull_image(lane, &request, true)?.value;
    let image = pulled.image.take().ok_or_else(internal)?;
    let asset = EntityId::from_hex(&pulled.asset_ref).map_err(|_| internal())?;
    readable(DecisionImage {
        name: IMAGE.to_owned(),
        evidence: EvidenceVersion {
            id: asset,
            body_hash: *blake3::hash(&image.bytes).as_bytes(),
        },
        image,
        frame: None,
    })
}

/// `image`, when it is one a decision reads.
fn readable(image: DecisionImage) -> MemoryResult<DecisionImage> {
    DecisionImage::validate_all(std::slice::from_ref(&image)).map_err(|_| {
        MemoryError::bad_request_with(
            "the image is not one a decision reads",
            &["Name a PNG or JPEG image of at most 10 MiB."],
        )
    })?;
    Ok(image)
}

/// The Local-vision seat at the Local rung, spending on a run of its own for
/// `principal`, as ask_image's Box ask does. `label` names the run's caller.
pub(crate) fn vision_rung(
    server: &SyncServer,
    principal: EntityId,
    class: EdgeActorClass,
    images: &[DecisionImage],
    label: &str,
) -> MemoryResult<ModelDecisionProvider> {
    let vault = Arc::clone(server.vault());
    let unbound = || {
        MemoryError::bad_request_with(
            "no [models.roles.local_vision] seat reads the image",
            &["Bind a local_vision role, or ask without an image."],
        )
    };
    let asset = images
        .first()
        .map(|image| image.evidence.id.to_hex())
        .unwrap_or_default();
    let run_id = format!("{label}:{asset}:{}", vault.now_recorded_at());
    let settings = server.ai.chat_settings();
    let meter = vault
        .policy_budget_guard(
            run_id.clone(),
            settings.turn_budget_units,
            oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS.min(settings.turn_budget_units),
            BudgetExhaustionPolicy::Suspend,
            WriteActor::new(principal, class),
        )
        .map_err(|error| {
            MemoryError::bad_request_with(
                format!("the Local-vision call was not admitted: {error}"),
                &["Raise the turn budget, or ask without an image."],
            )
        })?;
    let run = server.ai.undeclared_run(run_id, meter);
    let seat = LocalVisionModel::new(&server.ai, vault, run, tokio::runtime::Handle::current())
        .ok_or_else(unbound)?;
    seat.rung().map_err(|_| unbound())
}

fn internal() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INTERNAL,
        "ai.verdict did not finish on this server",
        &["Report this decision-ladder failure."],
    )
}
