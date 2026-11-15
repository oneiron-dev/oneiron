//! Backfill waits for the GPU box's hours instead of embedding on the
//! endpoint (NIGHT-BACKFILL-HOLD = C, 15 Nov 20:48; CROSS-ARCH-0024
//! #my-network 07: "Embeddings can run on the GPU box at night"; census
//! L10-15). While every pod the batches route to keeps hours and each is
//! outside them, a backfill row (an import, a re-embed after a model swap, a
//! rebuild) stays pending, unleased and unsent; a fresh write embeds at once.
//! A pod without hours takes batches at any hour, so it never holds.
//!
//! Which embeds wait is the owner's Setting key "Wait for the night box"
//! (`embed.pod_hours_wait`): backfill only (the default), everything, or
//! nothing. The owner sets it through the Setting primitive's door; a holder's
//! row may only make more embeds wait, never fewer.
//!
//! Public crate surface only: a model swap queues every record again at
//! backfill priority, a public `GpuPool` built from its `[gpu]` TOML is the
//! hours the reconciler reads, and a recording embedder stands for the
//! endpoint. No pod is polled: hours alone decide the hold.
//! `cargo test --locked -p oneiron-server --test embed_backfill_pod_hours`.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::embed::{
    EMBED_PRIORITY_BACKFILL, EMBED_PRIORITY_DEVICE, EMBED_PRIORITY_SERVER,
    EMBED_PRIORITY_SURFACED_HOT, Embedder, EmbedderLocality, PendingEmbeddingInput,
    PendingEmbeddingReconcileReport, PendingEmbeddingReconciler, PodHoursClock, PodHoursWait,
    payload_text,
};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::setting::{
    ScopeKind, SetBy, SetSetting, SetSettingOutcome, SettingCaller, spec_named,
};
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_server::runtime::{GpuPool, GpuPoolConfig};
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const OLD_MODEL: &str = "test/old@v1";
const NEW_MODEL: &str = "test/new@v2";
const DIMENSIONS: usize = 4;
const MINUTES_PER_DAY: u64 = 24 * 60;
/// The turn written before the model swap: the swap queues it as backfill.
const BACKFILLED: &str = "The harbour ferry timetable changes in December.";
/// The turn written after the swap: a fresh write.
const FRESH: &str = "Lunch moved to the harbour cafe at noon.";
/// The owner's "Wait for the night box": which queued embeds wait for the
/// pods' hours.
const WAIT_KEY: &str = "embed.pod_hours_wait";

/// The endpoint: keeps every text it is sent.
struct RecordingEmbedder {
    sent: Mutex<Vec<String>>,
}

impl RecordingEmbedder {
    fn sent(&self) -> Vec<String> {
        self.sent
            .lock()
            .map(|sent| sent.clone())
            .unwrap_or_default()
    }

    fn was_sent(&self, text: &str) -> bool {
        self.sent().iter().any(|sent| sent.contains(text))
    }
}

impl Embedder for RecordingEmbedder {
    fn model_id(&self) -> &str {
        NEW_MODEL
    }

    fn dimensions(&self) -> usize {
        DIMENSIONS
    }

    fn locality(&self) -> EmbedderLocality {
        EmbedderLocality::ThirdParty
    }

    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> oneiron::Result<Vec<Vec<f32>>> {
        let mut sent = self
            .sent
            .lock()
            .map_err(|_| oneiron::Error::InvariantViolation("recording embedder lock"))?;
        for input in inputs {
            sent.push(payload_text(&input.payload)?.into_owned());
        }
        Ok(inputs.iter().map(|_| vec![1.0, 0.0, 0.0, 0.0]).collect())
    }
}

fn witness(vault: &Vault, owner_id: EntityId, text: &str) -> TestResult {
    vault
        .memory(owner_id, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: Some(EntityId::now().to_hex()),
            thread_audience: None,
            occurred_at: vault.now_recorded_at(),
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "text".to_owned(),
                content: text.to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            assertions: Default::default(),
        })?;
    Ok(())
}

/// A vault holding one turn written under the old model and then swapped to
/// the new one: every record, the turn included, is queued again at backfill
/// priority. Returns the vault and its owner.
fn swapped_vault(
    dir: &std::path::Path,
) -> Result<(Arc<Vault>, EntityId), Box<dyn std::error::Error>> {
    let mut config = VaultConfig::device();
    config.dimensions = DIMENSIONS;
    config.embedding_model = Some(OLD_MODEL.to_owned());
    let mut vault = Vault::open(dir, config)?;
    let owner_id = vault.ensure_embedded_owner_actor()?;
    witness(&vault, owner_id, BACKFILLED)?;
    vault.begin_embedding_migration(NEW_MODEL)?;
    Ok((Arc::new(vault), owner_id))
}

/// `"HH:MM"` for the UTC minute `minutes` after now (mod one day).
fn utc_clock_in(minutes: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default();
    let minute = (now / 60 + minutes) % MINUTES_PER_DAY;
    format!("{:02}:{:02}", minute / 60, minute % 60)
}

/// One `[[pods]]` table; `hours` is `(start, end)` in UTC. No pod is polled,
/// so the URL is never dialled.
fn pod(id: &str, hours: Option<(String, String)>) -> String {
    let hours = hours.map_or_else(String::new, |(start, end)| {
        format!("hours = {{ start = \"{start}\", end = \"{end}\", utc_offset = \"+00:00\" }}\n")
    });
    format!("[[pods]]\nid = \"{id}\"\nurl = \"http://127.0.0.1:9/v1\"\ncapacity = 1\n{hours}")
}

/// The serve host's pool over `pods`, from its `[gpu]` section.
fn pool(pods: &[String]) -> Result<GpuPool, Box<dyn std::error::Error>> {
    let text = format!("region = \"home\"\npoll_seconds = 3600\n{}", pods.concat());
    let config: GpuPoolConfig = toml::from_str(&text)?;
    Ok(GpuPool::new(config)?)
}

/// A pod whose hours start in two hours: outside them now.
fn closed_pod(id: &str) -> String {
    pod(id, Some((utc_clock_in(120), utc_clock_in(180))))
}

/// A pod whose hours run from an hour ago to an hour from now.
fn open_pod(id: &str) -> String {
    pod(
        id,
        Some((utc_clock_in(MINUTES_PER_DAY - 60), utc_clock_in(60))),
    )
}

/// Runs passes until one leases nothing; returns every pass's report.
fn drain(
    reconciler: &PendingEmbeddingReconciler,
) -> Result<Vec<PendingEmbeddingReconcileReport>, Box<dyn std::error::Error>> {
    let mut reports = Vec::new();
    for _ in 0..64 {
        let report = reconciler.reconcile_once()?;
        let leased = report.leased;
        reports.push(report);
        if leased == 0 {
            break;
        }
    }
    Ok(reports)
}

fn reconciler(
    vault: &Arc<Vault>,
    embedder: &Arc<RecordingEmbedder>,
    pool: GpuPool,
) -> PendingEmbeddingReconciler {
    PendingEmbeddingReconciler::new(Arc::clone(vault), Arc::clone(embedder) as Arc<dyn Embedder>)
        .with_pod_hours(Arc::new(pool) as Arc<dyn PodHoursClock>)
}

/// The owner sets the wait to `value` through the Setting primitive's door;
/// `None` clears the owner's row, so the catalogue default reads again.
fn set_wait(
    vault: &Vault,
    owner_id: EntityId,
    value: Option<Value>,
) -> oneiron::Result<SetSettingOutcome> {
    let owner =
        vault.authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())?;
    let mut request = SetSetting::vault_value(WAIT_KEY, Value::Null);
    request.value = value;
    vault.set_setting(SettingCaller::Owner(&owner), request)
}

/// [`set_wait`], applied at once: the owner sets the key without asking.
fn owner_sets_wait(vault: &Vault, owner_id: EntityId, value: Option<Value>) -> TestResult {
    let outcome = set_wait(vault, owner_id, value)?;
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "the owner's change to the wait did not apply: {outcome:?}"
    );
    Ok(())
}

fn recording_embedder() -> Arc<RecordingEmbedder> {
    Arc::new(RecordingEmbedder {
        sent: Mutex::new(Vec::new()),
    })
}

#[tokio::test]
async fn backfill_waits_for_pod_hours_instead_of_embedding_on_the_endpoint() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (vault, owner_id) = swapped_vault(dir.path())?;
    let embedder = Arc::new(RecordingEmbedder {
        sent: Mutex::new(Vec::new()),
    });

    // Every pod outside its hours: the backfill stays pending and unsent.
    let night = reconciler(&vault, &embedder, pool(&[closed_pod("night-box")])?);
    let reports = drain(&night)?;
    assert!(
        !embedder.was_sent(BACKFILLED),
        "a backfill row went to the endpoint outside the pod's hours: sent {:?}",
        embedder.sent()
    );
    assert!(
        reports
            .first()
            .is_some_and(|report| report.leased == 0 && report.held_for_pod_hours > 0),
        "the first pass outside the hours leases nothing and counts the held backfill: {reports:?}"
    );

    // A fresh write embeds at once, outside the hours too.
    witness(&vault, owner_id, FRESH)?;
    let reports = drain(&night)?;
    assert!(
        embedder.was_sent(FRESH),
        "a fresh write waited for the pod's hours: sent {:?}, passes {reports:?}",
        embedder.sent()
    );
    assert!(
        !embedder.was_sent(BACKFILLED),
        "the backfill row left with the fresh write: sent {:?}",
        embedder.sent()
    );

    // Inside the hours the backfill embeds.
    let day = reconciler(&vault, &embedder, pool(&[open_pod("night-box")])?);
    let reports = drain(&day)?;
    assert!(
        embedder.was_sent(BACKFILLED),
        "the backfill row did not embed inside the pod's hours: sent {:?}, passes {reports:?}",
        embedder.sent()
    );
    assert!(
        reports.iter().all(|report| report.held_for_pod_hours == 0),
        "a pass inside the hours held a row: {reports:?}"
    );
    Ok(())
}

#[tokio::test]
async fn a_pod_without_hours_never_holds_the_backfill() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (vault, _owner_id) = swapped_vault(dir.path())?;
    let embedder = Arc::new(RecordingEmbedder {
        sent: Mutex::new(Vec::new()),
    });

    // One pod outside its hours, one that keeps none: the batches still have
    // a pod at this hour, so nothing waits.
    let pods = [closed_pod("night-box"), pod("any-hour", None)];
    let reports = drain(&reconciler(&vault, &embedder, pool(&pods)?))?;
    assert!(
        embedder.was_sent(BACKFILLED),
        "a pool with a pod open at any hour held the backfill: sent {:?}, passes {reports:?}",
        embedder.sent()
    );
    assert!(
        reports.iter().all(|report| report.held_for_pod_hours == 0),
        "a pass held a row: {reports:?}"
    );
    Ok(())
}

#[test]
fn the_night_box_wait_names_which_embeds_wait_for_pod_hours() {
    let hotter = [
        EMBED_PRIORITY_SURFACED_HOT,
        EMBED_PRIORITY_SERVER,
        EMBED_PRIORITY_DEVICE,
    ];
    assert_eq!(PodHoursWait::default(), PodHoursWait::BackfillOnly);
    assert!(PodHoursWait::BackfillOnly.holds(EMBED_PRIORITY_BACKFILL));
    assert!(
        hotter
            .iter()
            .all(|priority| !PodHoursWait::BackfillOnly.holds(*priority))
    );
    assert!(
        hotter
            .iter()
            .chain([EMBED_PRIORITY_BACKFILL].iter())
            .all(|priority| PodHoursWait::Everything.holds(*priority))
    );
    assert!(
        hotter
            .iter()
            .chain([EMBED_PRIORITY_BACKFILL].iter())
            .all(|priority| !PodHoursWait::Nothing.holds(*priority))
    );
}

#[tokio::test]
async fn the_owners_wait_for_everything_holds_a_fresh_write_until_the_pods_hours() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (vault, owner_id) = swapped_vault(dir.path())?;
    let embedder = recording_embedder();
    owner_sets_wait(&vault, owner_id, Some(json!("everything")))?;

    // Every pod outside its hours: the fresh write waits with the backfill.
    witness(&vault, owner_id, FRESH)?;
    let night = reconciler(&vault, &embedder, pool(&[closed_pod("night-box")])?);
    let reports = drain(&night)?;
    assert!(
        !embedder.was_sent(FRESH) && !embedder.was_sent(BACKFILLED),
        "a row went to the endpoint outside the pod's hours while the owner's wait holds \
         everything: sent {:?}",
        embedder.sent()
    );
    assert!(
        reports
            .first()
            .is_some_and(|report| report.leased == 0 && report.held_for_pod_hours > 0),
        "the first pass outside the hours leases nothing and counts the held rows: {reports:?}"
    );

    // Inside the hours both embed.
    let day = reconciler(&vault, &embedder, pool(&[open_pod("night-box")])?);
    let reports = drain(&day)?;
    assert!(
        embedder.was_sent(FRESH) && embedder.was_sent(BACKFILLED),
        "a held row did not embed inside the pod's hours: sent {:?}, passes {reports:?}",
        embedder.sent()
    );
    Ok(())
}

#[tokio::test]
async fn the_owners_wait_for_nothing_sends_the_backfill_to_the_endpoint_outside_the_pods_hours()
-> TestResult {
    let dir = tempfile::tempdir()?;
    let (vault, owner_id) = swapped_vault(dir.path())?;
    let embedder = recording_embedder();
    owner_sets_wait(&vault, owner_id, Some(json!("nothing")))?;

    let reports = drain(&reconciler(
        &vault,
        &embedder,
        pool(&[closed_pod("night-box")])?,
    ))?;
    assert!(
        embedder.was_sent(BACKFILLED),
        "the backfill waited for the pod's hours while the owner's wait holds nothing: sent \
         {:?}, passes {reports:?}",
        embedder.sent()
    );
    assert!(
        reports.iter().all(|report| report.held_for_pod_hours == 0),
        "a pass held a row: {reports:?}"
    );
    Ok(())
}

#[tokio::test]
async fn a_cleared_wait_holds_backfill_only_again_and_an_unknown_wait_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (vault, owner_id) = swapped_vault(dir.path())?;
    let embedder = recording_embedder();
    let refused = set_wait(&vault, owner_id, Some(json!("sometimes")));
    assert!(
        refused.is_err(),
        "a wait the key does not name was stored: {refused:?}"
    );
    owner_sets_wait(&vault, owner_id, Some(json!("everything")))?;
    owner_sets_wait(&vault, owner_id, None)?;

    // The default again: the fresh write embeds at once, the backfill waits.
    witness(&vault, owner_id, FRESH)?;
    let reports = drain(&reconciler(
        &vault,
        &embedder,
        pool(&[closed_pod("night-box")])?,
    ))?;
    assert!(
        embedder.was_sent(FRESH) && !embedder.was_sent(BACKFILLED),
        "a cleared wait does not hold backfill only: sent {:?}, passes {reports:?}",
        embedder.sent()
    );
    Ok(())
}

#[test]
fn the_night_box_wait_is_the_owners_key_and_more_waiting_is_tighter() -> TestResult {
    let spec = spec_named(WAIT_KEY)?;
    assert_eq!(spec.set_by, SetBy::Owner);
    assert!(
        matches!(spec.scopes, [ScopeKind::Vault]),
        "the wait has rows at the vault alone"
    );
    let kind = spec.kind;
    assert_eq!(
        kind.to_json(&kind.default_value()?),
        Some(json!("backfill_only"))
    );
    let strictest = kind
        .strictest_value()?
        .ok_or("the wait names no strictest value")?;
    assert_eq!(kind.to_json(&strictest), Some(json!("everything")));

    // A holder's row stays inside the owner's: it may hold more embeds for
    // the pods' hours, never send more to the endpoint.
    let nothing = kind.from_json(json!("nothing"))?;
    let backfill_only = kind.from_json(json!("backfill_only"))?;
    let everything = kind.from_json(json!("everything"))?;
    assert!(kind.has_direction());
    assert_eq!(kind.is_tighter(&everything, &backfill_only), Some(true));
    assert_eq!(kind.is_tighter(&backfill_only, &nothing), Some(true));
    assert_eq!(kind.is_tighter(&backfill_only, &everything), Some(false));
    assert_eq!(kind.is_tighter(&nothing, &backfill_only), Some(false));
    Ok(())
}
