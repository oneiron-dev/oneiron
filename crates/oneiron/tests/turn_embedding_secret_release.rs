//! The embedding worker sends a TURN's text to its embedder, and an embedder
//! off this device is an egress. The text holds only the words a door that
//! releases a turn's text gives (ARCH-0069 #readers-followups-open, "The
//! embedding worker's TURN egress"; census L6-30): a message stored while
//! the owner's write-door scan was off, whose words the write door now
//! refuses, gives none, as the chat and served-turn doors give it none. The
//! turn's other words still embed.
//!
//! Public crate surface only: the owner's scan switch, a witnessed turn, and
//! `embed::PendingEmbeddingReconciler` with a recording third-party embedder.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test turn_embedding_secret_release`.
#![cfg(feature = "sync")]

use std::sync::{Arc, Mutex};

use oneiron::embed::{
    Embedder, EmbedderLocality, PendingEmbeddingInput, PendingEmbeddingReconciler, payload_text,
};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::policy_model::SecretScanMode;
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const MODEL: &str = "test/model@v1";
const DIMENSIONS: usize = 4;
/// A 12-word recovery phrase with a valid checksum: the write door refuses it.
const PHRASE: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
/// The turn's other message: ordinary words.
const CLEAN: &str = "Lunch moved to the harbour cafe at noon.";

/// A model off this device that keeps every text it is sent.
struct RecordingEmbedder {
    sent: Mutex<Vec<String>>,
}

impl Embedder for RecordingEmbedder {
    fn model_id(&self) -> &str {
        MODEL
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

fn message(text: &str, order: u32) -> WitnessMessage {
    WitnessMessage {
        id: None,
        author: WitnessAuthor::User,
        message_type: "text".to_owned(),
        content: text.to_owned(),
        parts: None,
        metadata: None,
        is_visible: true,
        order,
        quote: None,
    }
}

#[test]
fn a_message_the_write_door_refuses_never_reaches_the_embedder_in_its_turns_text() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.dimensions = DIMENSIONS;
    config.embedding_model = Some(MODEL.to_owned());
    let vault = Arc::new(Vault::open(dir.path(), config)?);
    let owner_id = vault.ensure_embedded_owner_actor()?;
    let owner =
        vault.authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())?;
    let at = vault.now_recorded_at();
    // The owner's scan off: the phrase is stored as written.
    vault.set_secret_scan_mode(&owner, SecretScanMode::Off, at)?;

    let turn = EntityId::now();
    vault
        .memory(owner_id, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            occurred_at: at,
            messages: vec![message(CLEAN, 0), message(PHRASE, 1)],
            assertions: Default::default(),
        })?;

    let embedder = Arc::new(RecordingEmbedder {
        sent: Mutex::new(Vec::new()),
    });
    let reconciler = PendingEmbeddingReconciler::new(
        Arc::clone(&vault),
        Arc::clone(&embedder) as Arc<dyn Embedder>,
    );
    // A pass leases one batch (32 rows), and the vault's own seeded rows
    // (skills, models) come before the turn: run passes until none leases.
    let mut reports = Vec::new();
    for _ in 0..64 {
        let report = reconciler.reconcile_once()?;
        let leased = report.leased;
        reports.push(report);
        if leased == 0 {
            break;
        }
    }
    let sent = embedder
        .sent
        .lock()
        .map_err(|_| "recording embedder lock")?
        .clone();

    assert!(
        sent.iter().all(|text| !text.contains("sausage")),
        "the refused message's words reached the embedder off this device: {sent:?}"
    );
    assert!(
        sent.iter().any(|text| text.contains(CLEAN)),
        "the turn's other words still embed: sent {sent:?}, passes {reports:?}"
    );
    Ok(())
}
