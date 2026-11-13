//! The PERSON-vector producer feeds the entity linker's vector rung, end to
//! end (FIX LINKER-PERSON-VECTOR-PRODUCER; ruling PERSON-VECTOR-CHOICES = A).
//!
//! Two persons are both named Owen, so the identity key leaves a mention of
//! "Owen" both of them as candidates. The Dreamer lands each Owen's `about`
//! lines; one embed worker pass fills each Owen's vector from his public
//! (band 0) line and the turn's vector from its text; then the tagger saves
//! the mention with the Owen whose public line lies nearest the turn first.
//! The rung only reorders: both Owens stay candidates, the nightly re-check
//! asks which one it is in that order, and neither is merged. A line above
//! the public band never steers the rung.
//!
//! No step writes a person's vector on #7408's head, so the rung keeps the
//! key's order there, the first-made Owen first, and both tests fail.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test person_vector_linker`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::dreamer_runner::maintenance::identity::IdentityAskReason;
use oneiron::embed::{
    Embedder, EmbedderLocality, PendingEmbeddingInput, PendingEmbeddingPayload,
    PendingEmbeddingReconciler,
};
use oneiron::memory::extraction::{
    EncoderAttempt, EncoderInput, EncoderOutput, ExtractionEncoder, ExtractionWork, NerSpan,
};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::tagging::{MentionLink, TaggingMarkerConfig, TaggingMode, TaggingReconciler};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault_with;
use oneiron::test_doors::derive::{About, Derived, Named, about_facts, commit};
use oneiron::test_doors::identity_recheck::run_identity_recheck;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::steward::dreamer;
use oneiron::{EdgeActorClass, EntityId, ModelId, Vault, VaultConfig};

const READER: &str = "reader";
const CHECKPOINT: &str = "0123456789abcdef";
const ROOM: &str = "52525252525252525252525252525252";
const TURN: &str = "76767676767676767676767676767676";
const MODEL: &str = "fixture/vectors@v1";
/// Four dimensions, so each cosine is exact in the stored f16 rows.
const DIMENSIONS: usize = 4;

/// The owner's turn, and the vector the test embedder gives its text.
const TURN_TEXT: &str = "Owen sent the budget forecast.";
const TURN_VECTOR: [f32; DIMENSIONS] = [1.0, 0.0, 0.0, 0.0];
/// The climbing Owen's public line: cosine 0 to the turn.
const CLIMBER_LINE: &str = "Owen climbs mountains on weekends.";
const CLIMBER_VECTOR: [f32; DIMENSIONS] = [0.0, 1.0, 0.0, 0.0];
/// The budget Owen's public line: cosine 0.6 to the turn, over the 0.3
/// evidence floor and ahead of the climber's by more than the 0.05 margin.
const BUDGET_LINE: &str = "Owen runs the budget forecast.";
const BUDGET_VECTOR: [f32; DIMENSIONS] = [3.0, 4.0, 0.0, 0.0];
/// A line above the public band: cosine 0 to the turn.
const PRIVATE_LINE: &str = "Owen keeps a private diary.";
const PRIVATE_VECTOR: [f32; DIMENSIONS] = [0.0, 0.0, 1.0, 0.0];
/// A line above the public band in the turn's own words: cosine 1 to it.
const PRIVATE_FORECAST_LINE: &str = "Owen sends the budget forecast in private.";
/// Any other text: a claim body.
const OTHER_VECTOR: [f32; DIMENSIONS] = [0.0, 0.0, 0.0, 1.0];

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs()
}

/// An on-device embedder that gives each line its fixed vector and the
/// owner's turn [`TURN_VECTOR`].
struct LineVectors;

fn line_vector(text: &str) -> [f32; DIMENSIONS] {
    match text {
        CLIMBER_LINE => CLIMBER_VECTOR,
        BUDGET_LINE => BUDGET_VECTOR,
        PRIVATE_LINE => PRIVATE_VECTOR,
        PRIVATE_FORECAST_LINE => TURN_VECTOR,
        _ => OTHER_VECTOR,
    }
}

impl Embedder for LineVectors {
    fn model_id(&self) -> &str {
        MODEL
    }

    fn dimensions(&self) -> usize {
        DIMENSIONS
    }

    fn locality(&self) -> EmbedderLocality {
        EmbedderLocality::OnDevice
    }

    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> oneiron::Result<Vec<Vec<f32>>> {
        Ok(inputs
            .iter()
            .map(|input| match &input.payload {
                PendingEmbeddingPayload::TurnText(_) => TURN_VECTOR.to_vec(),
                PendingEmbeddingPayload::SummaryText(text) => line_vector(text).to_vec(),
                PendingEmbeddingPayload::ClaimBody(_) => OTHER_VECTOR.to_vec(),
            })
            .collect())
    }
}

/// A tagger that tags the first "Owen" of every MESSAGE it is given as a
/// `PERSON`.
struct Owens(ModelId);

impl ExtractionEncoder for Owens {
    fn model_id(&self) -> &ModelId {
        &self.0
    }

    fn locality(&self) -> EmbedderLocality {
        EmbedderLocality::OnDevice
    }

    fn infer(&self, input: &EncoderInput, _work: ExtractionWork) -> EncoderAttempt {
        let spans = input
            .messages
            .iter()
            .enumerate()
            .filter_map(|(message, each)| {
                each.text.find("Owen").map(|start| NerSpan {
                    message,
                    start,
                    end: start + 4,
                    label: "PERSON".to_owned(),
                    confidence: 0.9,
                })
            })
            .collect();
        EncoderAttempt {
            execution: None,
            panicked: false,
            result: Ok(EncoderOutput {
                spans,
                links: Vec::new(),
                vad: None,
                context_links: Vec::new(),
                speaker_links: Vec::new(),
                mood_parts: Vec::new(),
                stack_sha16: None,
            }),
        }
    }
}

/// A Dreamer vault with an embedding model over [`DIMENSIONS`] and a tagger
/// that saves its tags, mapping the `PERSON` label.
fn open_vault(dir: &tempfile::TempDir) -> Arc<Vault> {
    let mut config = VaultConfig::device();
    config.dimensions = DIMENSIONS;
    config.embedding_model = Some(MODEL.to_owned());
    config.tagging = Some(
        TaggingMarkerConfig::new(CHECKPOINT)
            .expect("checkpoint")
            .with_labels(BTreeMap::from([("PERSON".to_owned(), ENTITY_TYPE_PERSON)]))
            .with_mode(TaggingMode::Save),
    );
    Arc::new(open_dreamer_vault_with(dir.path(), READER, config).expect("vault"))
}

/// A PERSON named Owen, with one stated, approved, public fact about him.
fn owen(vault: &Vault) -> EntityId {
    let at = vault.now_recorded_at();
    let person = EntityId::now();
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: at, end: at },
            at,
            &rmp_serde::to_vec_named(&serde_json::json!({ "name": "Owen" })).expect("body"),
        )
        .expect("a person");
    let mut body = ClaimBody::new(
        "profile.hobby",
        ClaimSubject::Entity(person),
        rmpv::Value::from("weekends"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .expect("a claim body");
    body.source = Some(ClaimSource::UserStated);
    body.scope = Some(rmpv::Value::Map(vec![(
        rmpv::Value::from("sensitivity"),
        rmpv::Value::from("public"),
    )]));
    vault
        .put_claim(
            &EntityId::now(),
            &body,
            TimeRange { start: at, end: at },
            at,
        )
        .expect("a fact about the person");
    person
}

/// Lands `person`'s `about` lines as the Dreamer under `run`: `public` in
/// the public band and `higher` in each band above it.
fn land(
    vault: &Vault,
    dreamer: EntityId,
    person: EntityId,
    run: &str,
    public: &'static str,
    higher: &'static str,
) {
    let (digest, bands) =
        about_facts(vault, dreamer, EdgeActorClass::System, person).expect("facts");
    assert_eq!(
        bands,
        [0, 1, 2, 3],
        "FIXTURE: a public fact gives a line in every band"
    );
    let committed = commit(
        vault,
        dreamer,
        EdgeActorClass::System,
        run,
        &[Derived::About(About {
            local: "about",
            person: Named::Stored(person),
            written_from: digest,
            lines: bands
                .iter()
                .map(|band| (*band, if *band == 0 { public } else { higher }))
                .collect(),
        })],
    )
    .expect("commit");
    let [item] = committed.items.as_slice() else {
        panic!("FIXTURE: one item: {:?}", committed.items);
    };
    assert!(item.landed, "FIXTURE: the lines land: {:?}", item.reasons);
}

/// The owner says [`TURN_TEXT`] as one turn with no held tags. Returns the
/// turn.
fn witness(vault: &Vault, owner: EntityId) -> EntityId {
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: ROOM.into(),
            turn_ref: Some(TURN.to_owned()),
            thread_audience: None,
            occurred_at: now_seconds(),
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: TURN_TEXT.into(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            assertions: WitnessAssertions::default(),
        })
        .expect("the owner's turn");
    EntityId::from_hex(TURN).expect("turn id")
}

struct TwoOwens {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    turn: EntityId,
    /// Made first, so the key orders him first.
    climber: EntityId,
    budget: EntityId,
    /// The saved link of the turn's one mention.
    link: MentionLink,
}

/// Two Owens, each with a public fact; the Dreamer lands the climber's
/// lines (his public line [`CLIMBER_LINE`], `climber_higher` above it) and
/// the budget Owen's ([`BUDGET_LINE`], [`PRIVATE_LINE`] above it). The owner
/// says [`TURN_TEXT`]; one embed worker pass runs, then one tagging pass.
fn two_owens(climber_higher: &'static str) -> TwoOwens {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_vault(&dir);
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let (owner, _proof) = embedded_owner(&vault).expect("the owner");
    let climber = owen(&vault);
    let budget = owen(&vault);
    assert!(
        climber < budget,
        "FIXTURE: the key orders the climber first"
    );
    land(
        &vault,
        dreamer,
        climber,
        "run-climber",
        CLIMBER_LINE,
        climber_higher,
    );
    land(
        &vault,
        dreamer,
        budget,
        "run-budget",
        BUDGET_LINE,
        PRIVATE_LINE,
    );
    let turn = witness(&vault, owner);

    let embedder: Arc<dyn Embedder> = Arc::new(LineVectors);
    PendingEmbeddingReconciler::new(Arc::clone(&vault), embedder)
        .reconcile_once()
        .expect("one embed pass");
    TaggingReconciler::new(
        Arc::clone(&vault),
        Arc::new(Owens("fixture/owens@v1".parse().expect("model id"))),
    )
    .expect("reconciler")
    .drain_once()
    .expect("one tagging pass");

    let tags = vault
        .turn_tags(&turn)
        .expect("tags read")
        .expect("FIXTURE: the turn's tags are saved");
    let [mention] = tags.mentions.as_slice() else {
        panic!("FIXTURE: one mention, found {:?}", tags.mentions);
    };
    let link = mention.link.clone();
    TwoOwens {
        _dir: dir,
        vault,
        turn,
        climber,
        budget,
        link,
    }
}

/// The stored vectors of the turn and both Owens, for a failure message.
fn vectors(owens: &TwoOwens) -> String {
    let read = |id: &EntityId| owens.vault.get_vector(id).expect("vector read");
    format!(
        "turn {:?}, climber {:?}, budget {:?}",
        read(&owens.turn),
        read(&owens.climber),
        read(&owens.budget)
    )
}

/// The mention's saved link and the nightly ask both put the budget Owen
/// first, and both Owens stay candidates.
fn assert_budget_owen_first(owens: &TwoOwens) {
    assert_eq!(
        owens.link,
        MentionLink::Candidates {
            kind: ENTITY_TYPE_PERSON,
            entities: vec![owens.budget, owens.climber],
        },
        "the Owen whose public line lies nearest the turn goes first, and both stay \
         candidates; stored vectors: {}",
        vectors(owens)
    );
    let asks = run_identity_recheck(&owens.vault, now_seconds()).expect("recheck");
    assert_eq!(asks.len(), 1, "one ask for the one mention: {asks:?}");
    assert_eq!(asks[0].reason, IdentityAskReason::Unsettled);
    assert_eq!(asks[0].candidates, vec![owens.budget, owens.climber]);
}

/// The worker fills the turn's vector from its text and each Owen's from
/// his public line, and the rung puts the budget Owen first: his line is
/// the nearer one. The re-check asks about both, budget Owen first, and
/// each stays his own entity. RED on 261646dcccd: neither Owen has a
/// vector there, so the climber stays first.
#[test]
fn the_owen_whose_public_line_lies_nearest_the_turn_goes_first() {
    let owens = two_owens(PRIVATE_LINE);

    assert_budget_owen_first(&owens);
    let vault = &owens.vault;
    assert_eq!(
        vault.get_vector(&owens.turn).expect("vector read"),
        Some(TURN_VECTOR.to_vec()),
        "the turn holds its text's vector"
    );
    assert_eq!(
        vault.get_vector(&owens.climber).expect("vector read"),
        Some(CLIMBER_VECTOR.to_vec()),
        "the climber holds his public line's vector"
    );
    assert_eq!(
        vault.get_vector(&owens.budget).expect("vector read"),
        Some(BUDGET_VECTOR.to_vec()),
        "the budget Owen holds his public line's vector"
    );
    for owen in [owens.climber, owens.budget] {
        assert_eq!(vault.resolve_entity(&owen).expect("resolve"), vec![owen]);
    }
}

/// The climber's lines above the public band are in the turn's own words,
/// but only his public line reaches his vector, and it lies far from the
/// turn: the budget Owen still goes first. RED on 261646dcccd: neither Owen
/// has a vector there, so the climber stays first.
#[test]
fn a_line_above_the_public_band_never_steers_the_rung() {
    let owens = two_owens(PRIVATE_FORECAST_LINE);

    assert_budget_owen_first(&owens);
    assert_eq!(
        owens.vault.get_vector(&owens.climber).expect("vector read"),
        Some(CLIMBER_VECTOR.to_vec()),
        "the climber's vector is his public line's"
    );
}
