//! The import audience sweep (OF-492). Every tick it reads the pending history-import
//! reviews, groups their extracted claims by the extractor's question topic, and asks
//! each new topic once whether it is sensitive, on the model rungs only. A sensitive or
//! unsure topic goes to the vault owner as ONE ask (only me, one of the owner's
//! projects, or everyone the source shared it with); a later tick settles the owner's
//! answer as a standing rule for the topic's LATER imports. The import that raised the
//! ask stays private. CLI imports are covered too: their extraction runs here in serve,
//! and the ask waits in the owner's inbox, so the CLI never waits on it.
//!
//! Without `[models.decisions.import_audience]` the sweep asks nothing and every
//! import stays private. A pass never awaits an answer and never holds a write
//! transaction across a ladder call; a topic that fails a tick is tried again next tick.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use oneiron::claim::ClaimBody;
use oneiron::edge::EdgeActorClass;
use oneiron::ingest::{ImportAudienceState, import_audience_topic};
use oneiron::llm::decision::catalogue::{IMPORT_AUDIENCE_ASK, IMPORT_AUDIENCE_SENSITIVE};
use oneiron::llm::decision::{AnswerContract, AskTo, DecisionAnswer, DecisionRung, Reversibility};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::write_envelope::WriteActor;
use oneiron::{EntityId, Vault};
use serde_json::json;

use crate::config::models::ImportAudienceSettings;
use crate::decision_host::DecisionHost;
use crate::server::SyncServer;

const SWEEP_EVERY: Duration = Duration::from_secs(60);

/// The review ids history imports file their claims under
/// (`oneiron::ingest::history::history_import_review_id`).
const IMPORT_REVIEW_PREFIX: &str = "import:";

/// The claims of a topic a question shows the model and the owner, first by id (CALLS
/// "OF-492 import audience topics"). Every claim still joins its topic.
const QUESTION_SAMPLE_CLAIMS: usize = 16;

/// The clock the owner ask's queueing runs under.
const ASK_BUDGET: Duration = Duration::from_secs(30);

/// Starts the sweep on the server's runtime.
pub(crate) fn spawn(
    server: &Arc<SyncServer>,
    admit: crate::server::HousekeepingAdmission,
) -> tokio::task::JoinHandle<()> {
    let weak = Arc::downgrade(server);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(SWEEP_EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let Some(server) = weak.upgrade() else {
                break;
            };
            let Some(pass) = admit() else {
                continue;
            };
            match tokio::task::spawn_blocking(move || {
                let _pass = pass;
                sweep(&server)
            })
            .await
            {
                Ok(Err(error)) => {
                    tracing::warn!(%error, "import audience sweep failed; it runs again next tick");
                }
                Err(error) => tracing::warn!(%error, "import audience sweep stopped"),
                Ok(Ok(())) => {}
            }
        }
    })
}

/// One topic's claims in this pass's pending reviews.
#[derive(Default)]
struct Found {
    label: String,
    claims: BTreeMap<EntityId, ClaimBody>,
    reviews: BTreeSet<String>,
}

/// One pass: settle answered asks, then record and ask the pending reviews' topics.
fn sweep(server: &SyncServer) -> anyhow::Result<()> {
    let host = server.decision_host();
    let Some(settings) = host.import_audience() else {
        return Ok(());
    };
    let vault = server.vault();
    for topic in vault.asked_import_audience_topics()? {
        match vault.settle_import_audience(&topic) {
            Ok(Some(rule)) => {
                tracing::info!(topic = %topic.to_hex(), rule = %rule.to_hex(), "import audience topic settled")
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, topic = %topic.to_hex(), "import audience answer did not settle")
            }
        }
    }
    let reviews: Vec<String> = vault
        .pending_gate_consent_groups(usize::MAX)?
        .into_iter()
        .filter_map(|group| group.dreamer_run_id)
        .filter(|id| id.starts_with(IMPORT_REVIEW_PREFIX))
        .collect();
    if reviews.is_empty() {
        return Ok(());
    }
    let owner = crate::owner::local_owner(vault)?.revalidate(vault)?;
    for (topic, found) in pending_topics(vault, owner, reviews)? {
        let claims: Vec<EntityId> = found.claims.keys().copied().collect();
        let reviews: Vec<String> = found.reviews.iter().cloned().collect();
        if vault
            .record_import_audience_cluster(&topic, &found.label, &claims, &reviews, None)?
            .is_some()
        {
            continue;
        }
        match open(vault, host, settings, owner, topic, &found) {
            Ok(opening) => {
                vault.record_import_audience_cluster(
                    &topic,
                    &found.label,
                    &claims,
                    &reviews,
                    Some(opening),
                )?;
            }
            Err(error) => {
                tracing::warn!(%error, topic = %topic.to_hex(), "import audience topic stays unasked for the next tick");
            }
        }
    }
    Ok(())
}

/// The pending history-import `reviews`' claims, by topic. A claim with no topic joins
/// none.
fn pending_topics(
    vault: &Vault,
    owner: EntityId,
    reviews: Vec<String>,
) -> anyhow::Result<BTreeMap<EntityId, Found>> {
    let mut topics: BTreeMap<EntityId, Found> = BTreeMap::new();
    // The review door reads Proposed claims as the owner's own review does.
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    for review in reviews {
        let (bundle, bodies) = match vault.review_gate_consent_bundle_with_bodies(&actor, &review) {
            Ok(read) => read,
            // Settled between the scan and the read.
            Err(oneiron::Error::EntityNotFound) => continue,
            Err(error) => return Err(error).context("import review read"),
        };
        for (member, body) in bundle.members.iter().zip(bodies) {
            let Some((topic, label)) = import_audience_topic(body.scope.as_ref())? else {
                continue;
            };
            let found = topics.entry(topic).or_default();
            found.label = label;
            found.reviews.insert(review.clone());
            found.claims.insert(member.claim_id, body);
        }
    }
    Ok(topics)
}

/// A new topic's opening: clear when the model rungs read it as not sensitive in band,
/// else the owner's ask, queued and read back by its frozen question.
fn open(
    vault: &Vault,
    host: &DecisionHost,
    settings: &ImportAudienceSettings,
    owner: EntityId,
    topic: EntityId,
    found: &Found,
) -> anyhow::Result<ImportAudienceState> {
    let sample: Vec<(&EntityId, &ClaimBody)> =
        found.claims.iter().take(QUESTION_SAMPLE_CLAIMS).collect();
    let evidence: Vec<EntityId> = sample.iter().map(|(id, _)| **id).collect();
    let state = json!({
        "topic": found.label,
        "claims": sample
            .iter()
            .map(|(_, body)| json!({
                "predicate": body.predicate,
                "value": body.value.to_string(),
            }))
            .collect::<Vec<_>>(),
    });
    let sensitive = IMPORT_AUDIENCE_SENSITIVE.question(
        &[topic.as_bytes().as_slice()],
        worded(&settings.sensitive_wording, &found.label),
        AnswerContract::Noul,
    )?;
    let read = host.ladder().ladder().run(
        &sensitive,
        owner,
        &evidence,
        &state,
        host.dial(DecisionRung::Big),
        &host.bands(),
        Reversibility::ReversibleRead,
        &RetrievalDeadline::hard(Instant::now(), settings.budget),
    )?;
    if read.in_band && matches!(read.answer, DecisionAnswer::Noul(false)) {
        return Ok(ImportAudienceState::Clear);
    }
    let options = vault.import_audience_options()?;
    let question = IMPORT_AUDIENCE_ASK.question(
        &[topic.as_bytes().as_slice()],
        worded(&settings.audience_wording, &found.label),
        AnswerContract::Choice {
            options: options.iter().map(|option| option.label.clone()).collect(),
        },
    )?;
    let to = AskTo::owner();
    let mut dial = host.dial(DecisionRung::Human);
    dial.first = DecisionRung::Human;
    let mut ladder = host.ladder().ladder();
    ladder.ask_to = Some(&to);
    ladder.correlation = Some(topic);
    ladder.run(
        &question,
        owner,
        &evidence,
        &state,
        dial,
        &host.bands(),
        Reversibility::ReversibleRead,
        &RetrievalDeadline::hard(Instant::now(), ASK_BUDGET),
    )?;
    let ask = vault
        .decision_ask_for(&question, owner, &evidence, &to, Some(topic))?
        .context("the owner ask was not queued")?;
    if ask.question != question {
        // An ask queued before the owner's projects changed: put the current one.
        host.asks().withdraw(ask.seq)?;
        anyhow::bail!("an earlier ask's options were stale; withdrawn");
    }
    Ok(ImportAudienceState::Asked {
        seq: ask.seq,
        question,
        evidence,
        options,
    })
}

/// A question's text: the host's wording, then the topic.
fn worded(wording: &str, topic: &str) -> String {
    format!("{wording}\n\nTopic: {topic}")
}
