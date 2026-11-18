//! Restriction wave 16: four owner Setting keys over hard-coded restrictions.
//!
//! In plain sentences: a commitment longer than 8 KiB writes once the owner raises
//! `commitment.content.max_text_bytes`, is refused at the default, and still reads after the
//! owner lowers the cap again. With the key unset, the generic claim commit, an import batch and a
//! docs deep review each refuse a 9,000-byte promise, as main does. A reminder quotes the promise up to
//! `commitment.reminder.max_quoted_chars`, 400 chars at the default. Reminder wording over 4 KiB
//! files once the owner raises `commitment.reminder.max_wording_bytes`, and is refused at the
//! default. A cursor idle 8 days keeps its place under a 30-day `feeds.retention.idle_secs`, and
//! gaps at the default.
//!
//! Run with `cargo test -p oneiron --all-features --test restriction_wave_16`.

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::claim::ScopedReadActorKey;
use oneiron::commitment::{
    CommitmentBirthKind, CommitmentBirthProvenance, CommitmentContent, CommitmentObligor,
    CommitmentObligorKind, CommitmentRecord, CommitmentStatus, CommitmentStrength,
    PREDICATE_COMMITMENT_RECORD, encode_commitment_value,
};
use oneiron::commitment_wake::COMMITMENT_REMINDER_CONTENT_PREFIX;
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::{EdgeActorClass, EdgeKind};
use oneiron::feeds::{
    FEED_RETENTION_SECS, FeedGap, FeedOp, FeedPage, FeedRead, FeedReadRequest, FeedResyncFrom,
    FeedSelector, FeedSource, FeedStart, FeedSubscribeRequest,
};
use oneiron::ingest::{
    DOCS_EXPORT_SOURCE_ID, DocsDeepClaim, DocsDeepExtractor, DocsDeepTrigger, DocsExport,
    DocsImportCeiling, DocsPage, DocsSegment, ImportedClaimBatch, ImportedClaimBatchEntry,
};
use oneiron::memory::ClaimInput;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope};
use oneiron::store::GateDecisionId;
use oneiron::workspace_roster::{ProjectRecord, ProjectRole};
use oneiron::{
    ClaimApprovalStatus, ClaimSource, EntityId, TimeRange, Vault, VaultConfig, WriteActor,
    WriteEnvelope, WriteProvenance,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use rmpv::Value;
use serde_json::json;

const T0: u64 = 1_790_000_000;
const TEXT_KEY: &str = "commitment.content.max_text_bytes";
const QUOTE_KEY: &str = "commitment.reminder.max_quoted_chars";
const WORDING_KEY: &str = "commitment.reminder.max_wording_bytes";
const RETENTION_KEY: &str = "feeds.retention.idle_secs";
const THIRTY_DAYS: u64 = 30 * 24 * 60 * 60;
const EIGHT_DAYS: u64 = 8 * 24 * 60 * 60;
/// Past the default 8 KiB cap and within the 64 KiB ceiling every decode admits.
const PAST_DEFAULT_TEXT_BYTES: usize = 9000;
/// The refusal of commitment text past the cap in force, at every door and in the codec.
const TEXT_REFUSAL: &str = "commitment content text must be non-empty and bounded";
/// The short text a value is encoded with before its long text is put in.
const ENCODED_TEXT_MARKER: &str = "restriction wave 16 encoded text";
/// The source sentence the docs deep extractor quotes.
const DOCS_QUOTE: &str = "Gravity describes attraction";
const OBLIGOR: u8 = 0x71;
const BENEFICIARY: u8 = 0x72;

struct Fixture {
    vault: Vault,
    clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner bound, opened owned.
    fn rooted() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = ManualClock::new(T0);
        let keystore = Arc::new(MemoryKeystore::new());
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open_owned(dir.path(), config).expect("owned vault");
        vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
        vault.prepare_install_signing().expect("install signing");
        let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("serving install profile");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            clock,
            _dir: dir,
            issuer,
            owner,
            owner_proof,
        }
    }

    /// Sets `key` to `value` as the owner. The change applies.
    fn set(&self, key: &str, value: serde_json::Value) {
        let outcome = self
            .vault
            .set_setting(
                SettingCaller::Owner(&self.owner_proof),
                SetSetting {
                    key: key.to_owned(),
                    item: None,
                    scope: SettingScope::Vault,
                    mode: SettingMode::Value,
                    value: Some(value),
                    expected_revision: None,
                    why: None,
                    check_in_ref: None,
                    weight_runs: None,
                },
            )
            .expect("the owner sets the key");
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "the owner's change to {key} applies, not {outcome:?}"
        );
    }

    /// The owner's read lane, as a client holds it: a slip the host root mints for the owner,
    /// live for `ttl_secs`.
    fn owner_key_for(&self, slip_id: [u8; 32], ttl_secs: u64) -> ScopedReadActorKey {
        let root = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("host root slip");
        let issued_at = self.vault.capability_slip_now().expect("authority clock");
        let mut claims = root.claims.clone();
        claims.slip_id = slip_id;
        claims.holder_ref = self.owner.to_hex();
        claims.actor_class = Some("human".into());
        claims.issued_at = issued_at;
        claims.expires_at = issued_at + ttl_secs;
        claims.ttl_secs = ttl_secs;
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("the owner's slip");
        let challenge = b"restriction-wave-16";
        let proof = self
            .issuer
            .binding_proof(&slip, challenge)
            .expect("binding proof");
        let verified = self
            .vault
            .verify_capability_slip(&self.issuer.public_key(), &slip, challenge, &proof)
            .expect("verified slip");
        ScopedReadActorKey::from_verified_slip(&verified).expect("owner key")
    }

    /// Two people the commitments are between, and the owner's envelope.
    fn seed_commitment_world(&self) -> WriteEnvelope {
        for seed in [OBLIGOR, BENEFICIARY] {
            self.vault
                .put_entity(
                    &party(seed),
                    ENTITY_TYPE_PERSON,
                    instant(1),
                    1,
                    b"fixture person",
                )
                .expect("seed person");
        }
        WriteEnvelope::new(
            WriteActor::new(party(OBLIGOR), EdgeActorClass::Human),
            ClaimSource::UserStated,
            WriteProvenance::new(Value::from("restriction wave 16 fixture")).expect("provenance"),
            ClaimApprovalStatus::Auto,
        )
    }

    /// Tries to write one open commitment with `text`: the first refusal, if any, as text.
    fn try_put_commitment(
        &self,
        id: &EntityId,
        text: String,
        envelope: &WriteEnvelope,
    ) -> Result<(), String> {
        let content = CommitmentContent::new(text, None).map_err(|error| format!("{error:?}"))?;
        let record = CommitmentRecord::new(
            CommitmentObligor::new(CommitmentObligorKind::Owner, party(OBLIGOR)),
            party(BENEFICIARY),
            content,
            Value::Map(vec![
                (Value::from("kind"), Value::from("once")),
                (Value::from("due"), Value::from(10_000_u64)),
            ]),
            CommitmentStrength::Commitment,
            CommitmentStatus::Open,
            CommitmentBirthProvenance::new(
                CommitmentBirthKind::RunTreeNode,
                "run:restriction-wave-16",
            )
            .map_err(|error| format!("{error:?}"))?,
        )
        .map_err(|error| format!("{error:?}"))?;
        self.vault
            .put_commitment_claim(
                id,
                &record,
                envelope,
                TimeRange {
                    start: 1,
                    end: 2_000_000_000,
                },
                1,
            )
            .map_err(|error| format!("{error:?}"))
    }
}

fn party(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("fixture entity id")
}

fn instant(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// A `commitment.record` value whose obligor is `obligor` and whose promise text is
/// `text_bytes` bytes, as JSON, for a generic door. The record is encoded with a short text and
/// the long text is put in after, so the value builds under any encoder cap.
fn commitment_value_json(obligor: EntityId, text_bytes: usize) -> serde_json::Value {
    let record = CommitmentRecord::new(
        CommitmentObligor::new(CommitmentObligorKind::Owner, obligor),
        party(BENEFICIARY),
        CommitmentContent::new(ENCODED_TEXT_MARKER.to_owned(), None).expect("short text"),
        Value::Map(vec![
            (Value::from("kind"), Value::from("once")),
            (Value::from("due"), Value::from(10_000_u64)),
        ]),
        CommitmentStrength::Commitment,
        CommitmentStatus::Open,
        CommitmentBirthProvenance::new(CommitmentBirthKind::RunTreeNode, "run:restriction-wave-16")
            .expect("birth provenance"),
    )
    .expect("commitment record");
    let mut value = json_of(&encode_commitment_value(&record).expect("encoded commitment"));
    assert!(
        replace_text(&mut value, &"x".repeat(text_bytes)),
        "the encoded value carries its text"
    );
    value
}

/// The JSON form of an encoded commitment value: text-keyed maps, text, integers and nil.
fn json_of(value: &Value) -> serde_json::Value {
    match value {
        Value::Nil => serde_json::Value::Null,
        Value::Boolean(flag) => json!(flag),
        Value::Integer(number) => number
            .as_u64()
            .map_or_else(|| json!(number.as_i64()), |unsigned| json!(unsigned)),
        Value::String(text) => json!(text.as_str().expect("utf-8 text")),
        Value::Array(items) => serde_json::Value::Array(items.iter().map(json_of).collect()),
        Value::Map(entries) => serde_json::Value::Object(
            entries
                .iter()
                .map(|(key, item)| (key.as_str().expect("text key").to_owned(), json_of(item)))
                .collect(),
        ),
        other => panic!("an encoded commitment holds no {other:?}"),
    }
}

/// Puts `text` where the encoded marker text stands. True when it stood somewhere.
fn replace_text(value: &mut serde_json::Value, text: &str) -> bool {
    match value {
        serde_json::Value::String(current) if current == ENCODED_TEXT_MARKER => {
            *current = text.to_owned();
            true
        }
        serde_json::Value::Array(items) => items
            .iter_mut()
            .fold(false, |found, item| replace_text(item, text) || found),
        serde_json::Value::Object(entries) => entries
            .values_mut()
            .fold(false, |found, item| replace_text(item, text) || found),
        _ => false,
    }
}

/// Asserts `refused` is the text-cap refusal, from whichever check holds it.
fn assert_text_refusal<T: std::fmt::Debug>(door: &str, refused: Result<T, String>) {
    match refused {
        Ok(admitted) => panic!(
            "{door}: a {PAST_DEFAULT_TEXT_BYTES}-byte promise is refused at the default cap, \
             not admitted as {admitted:?}"
        ),
        Err(error) => assert!(
            error.contains(TEXT_REFUSAL),
            "{door}: the refusal is the text cap's, not {error}"
        ),
    }
}

/// A docs extractor that finds one promise on the sentence it quotes.
struct PromiseExtractor {
    value: serde_json::Value,
}

impl DocsDeepExtractor for PromiseExtractor {
    fn binding(&self) -> &str {
        "fixture.restriction-wave-16.promise"
    }

    fn extract(&self, segment: &DocsSegment) -> oneiron::Result<Vec<DocsDeepClaim>> {
        if !segment.text.contains(DOCS_QUOTE) {
            return Ok(Vec::new());
        }
        Ok(vec![DocsDeepClaim {
            predicate: PREDICATE_COMMITMENT_RECORD.to_owned(),
            value: self.value.clone(),
            quote: DOCS_QUOTE.to_owned(),
        }])
    }
}

/// A reminder content ref for `instance`, due at instant 1,000.
fn reminder_ref(instance: &EntityId) -> String {
    format!(
        "{COMMITMENT_REMINDER_CONTENT_PREFIX}{}:due:1000",
        instance.to_hex()
    )
}

fn edges_from(start: FeedStart) -> FeedSubscribeRequest {
    FeedSubscribeRequest {
        selector: FeedSelector {
            sources: vec![FeedSource::Edges],
            kinds: Vec::new(),
            entity_types: Vec::new(),
            predicates: Vec::new(),
        },
        start,
    }
}

fn put_person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .expect("person");
    id
}

fn read_page(vault: &Vault, key: &ScopedReadActorKey, subscription: EntityId) -> FeedPage {
    match read_answer(vault, key, subscription) {
        FeedRead::Page(page) => page,
        FeedRead::Gap(gap) => panic!("a page, not {gap:?}"),
    }
}

fn read_answer(vault: &Vault, key: &ScopedReadActorKey, subscription: EntityId) -> FeedRead {
    vault
        .feed_read(
            &vault.scoped_read(key.clone()),
            &FeedReadRequest {
                subscription,
                limit: None,
            },
        )
        .expect("feed read")
}

fn edge_ops(page: &FeedPage, from: EntityId, to: EntityId, kind: &str) -> Vec<FeedOp> {
    page.entries
        .iter()
        .filter(|entry| {
            entry
                .edge
                .as_ref()
                .is_some_and(|edge| edge.source == from && edge.target == to && edge.kind == kind)
        })
        .map(|entry| entry.op)
        .collect()
}

#[test]
fn a_commitment_longer_than_8_kib_is_written_once_the_owner_raises_the_cap() {
    let fx = Fixture::rooted();
    let envelope = fx.seed_commitment_world();
    fx.set(TEXT_KEY, json!(16384));
    let id = party(0x91);
    fx.try_put_commitment(&id, "x".repeat(9000), &envelope)
        .expect("a 9000-byte text writes under a 16384 cap");
    let stored = fx
        .vault
        .get_commitment_claim(&id)
        .expect("commitment read")
        .expect("the commitment is stored");
    assert_eq!(
        stored.content.text.len(),
        9000,
        "the 9000-byte text reads back whole"
    );
}

#[test]
fn the_default_cap_refuses_a_commitment_over_8_kib() {
    let fx = Fixture::rooted();
    let envelope = fx.seed_commitment_world();
    let refused = fx.try_put_commitment(&party(0x91), "x".repeat(8193), &envelope);
    assert!(
        refused.is_err(),
        "8193 bytes are refused at the default, not {refused:?}"
    );
    fx.try_put_commitment(&party(0x92), "x".repeat(8192), &envelope)
        .expect("8192 bytes write at the default");
}

#[test]
fn a_long_commitment_still_reads_after_the_owner_lowers_the_cap() {
    let fx = Fixture::rooted();
    let envelope = fx.seed_commitment_world();
    fx.set(TEXT_KEY, json!(16384));
    let id = party(0x91);
    fx.try_put_commitment(&id, "x".repeat(9000), &envelope)
        .expect("a 9000-byte text writes under a 16384 cap");
    fx.set(TEXT_KEY, json!(8192));
    let stored = fx
        .vault
        .get_commitment_claim(&id)
        .expect("commitment read")
        .expect("the commitment is stored");
    assert_eq!(
        stored.content.text.len(),
        9000,
        "the 9000-byte text still reads whole after the cap is lowered"
    );
}

#[test]
fn with_the_text_cap_unset_the_generic_claim_commit_refuses_a_9000_byte_promise() {
    let fx = Fixture::rooted();
    fx.seed_commitment_world();
    let id = EntityId::now();
    let refused = fx
        .vault
        .memory(fx.owner, EdgeActorClass::Human)
        .claim_upsert(&ClaimInput {
            id: Some(id.to_hex()),
            predicate: PREDICATE_COMMITMENT_RECORD.to_owned(),
            subject_ref: fx.owner.to_hex(),
            value: commitment_value_json(fx.owner, PAST_DEFAULT_TEXT_BYTES),
            confidence: 0.9,
            source: "user_stated".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: None,
            valid_from: None,
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
            confidence_details: None,
        })
        .map_err(|error| format!("{error:?}"));
    assert_text_refusal("the generic claim commit", refused);
    assert!(
        fx.vault.get_claim(&id).expect("claim read").is_none(),
        "the refused promise is not stored"
    );
}

#[test]
fn with_the_text_cap_unset_an_import_batch_refuses_a_9000_byte_promise() {
    let fx = Fixture::rooted();
    fx.seed_commitment_world();
    let id = EntityId::now();
    let batch = ImportedClaimBatch {
        request_id: EntityId::now(),
        source_id: DOCS_EXPORT_SOURCE_ID.to_owned(),
        entries: vec![ImportedClaimBatchEntry {
            claim_id: id,
            subject: fx.owner,
            source_record_id: "restriction-wave-16-import".to_owned(),
            predicate: PREDICATE_COMMITMENT_RECORD.to_owned(),
            value: commitment_value_json(fx.owner, PAST_DEFAULT_TEXT_BYTES),
            occurred: instant(T0),
            learned_at: T0,
        }],
    };
    let refused = fx
        .vault
        .admit_imported_claim_batch(&fx.owner_proof, &batch)
        .map_err(|error| format!("{error:?}"));
    assert_text_refusal("an import batch", refused);
    assert!(
        fx.vault.get_claim(&id).expect("claim read").is_none(),
        "the refused promise is not stored"
    );
}

#[test]
fn with_the_text_cap_unset_a_docs_deep_review_refuses_a_9000_byte_promise() {
    let fx = Fixture::rooted();
    fx.seed_commitment_world();
    let docs = DocsExport {
        corpus_id: "restriction-wave-16-manual".to_owned(),
        project_id: party(0xD6),
        registry: json!({"rows": []}),
        pages: vec![DocsPage {
            page_id: "promise-page".to_owned(),
            path: "promise.md".to_owned(),
            text: format!("# Gravity\n\n{DOCS_QUOTE}."),
        }],
    };
    let root = fx.vault.root_project().expect("root project");
    let mut corpus =
        ProjectRecord::new(docs.project_id, Some(root), root, fx.owner).expect("corpus record");
    corpus.role = ProjectRole::Corpus;
    fx.vault
        .put_project(docs.project_id, &corpus, 1)
        .expect("corpus project");
    let ceiling = DocsImportCeiling {
        max_pages: 2,
        max_bytes: 10_000,
        allow_derivations: true,
    };
    let request = EntityId::now();
    let digest = fx
        .vault
        .docs_import_effect(&fx.owner_proof, request, &docs, ceiling)
        .expect("docs import effect")
        .digest();
    fx.vault
        .approve_once(&fx.owner_proof, digest)
        .expect("the owner approves the import");
    let receipt = fx
        .vault
        .ingest_docs_export(&fx.owner_proof, request, &docs, ceiling, None, None, T0)
        .expect("docs import");
    let asset = EntityId::from_hex(&receipt.asset_refs[0]).expect("asset ref");
    // The asset is the subject of every derived claim, so it is the promise's obligor: only the
    // text can refuse it.
    let extractor = PromiseExtractor {
        value: commitment_value_json(asset, PAST_DEFAULT_TEXT_BYTES),
    };
    let refused = fx
        .vault
        .deep_ingest_docs_asset(
            &fx.owner_proof,
            asset,
            DocsDeepTrigger::Explicit,
            &extractor,
            T0 + 1,
        )
        .map_err(|error| format!("{error:?}"));
    assert_text_refusal("a docs deep review", refused);
    assert!(
        fx.vault
            .claims_for_subject(&asset)
            .expect("asset claims")
            .is_empty(),
        "the refused promise is not stored"
    );
}

#[test]
fn a_reminder_quotes_the_promise_up_to_the_owner_cap() {
    let fx = Fixture::rooted();
    let envelope = fx.seed_commitment_world();
    fx.set(QUOTE_KEY, json!(1000));
    let id = party(0x91);
    let promise = "a".repeat(900);
    fx.try_put_commitment(&id, promise.clone(), &envelope)
        .expect("a 900-char promise writes");
    let text = fx
        .vault
        .commitment_reminder_text(&reminder_ref(&id))
        .expect("reminder read")
        .expect("a reminder is owed");
    assert!(
        text.contains(promise.as_str()),
        "the reminder quotes all 900 chars, not {text:?}"
    );
}

#[test]
fn the_default_reminder_quotes_400_chars() {
    let fx = Fixture::rooted();
    let envelope = fx.seed_commitment_world();
    let id = party(0x91);
    fx.try_put_commitment(&id, "a".repeat(900), &envelope)
        .expect("a 900-char promise writes");
    let text = fx
        .vault
        .commitment_reminder_text(&reminder_ref(&id))
        .expect("reminder read")
        .expect("a reminder is owed");
    assert!(
        text.contains("a".repeat(400).as_str()),
        "the reminder quotes 400 chars, not {text:?}"
    );
    assert!(
        !text.contains("a".repeat(401).as_str()),
        "the reminder quotes no more than 400 chars, not {text:?}"
    );
}

#[test]
fn reminder_wording_over_4_kib_is_filed_once_the_owner_raises_the_cap() {
    let fx = Fixture::rooted();
    fx.set(WORDING_KEY, json!(8192));
    let wording = "x".repeat(5000);
    fx.vault
        .file_commitment_reminder_wording(&reminder_ref(&party(0x91)), &wording, T0)
        .expect("5000 bytes file under an 8192 cap");
}

#[test]
fn the_default_refuses_reminder_wording_over_4_kib() {
    let fx = Fixture::rooted();
    let refused = fx.vault.file_commitment_reminder_wording(
        &reminder_ref(&party(0x91)),
        &"x".repeat(4097),
        T0,
    );
    assert!(
        refused.is_err(),
        "4097 bytes are refused at the default, not {refused:?}"
    );
    fx.vault
        .file_commitment_reminder_wording(&reminder_ref(&party(0x92)), &"x".repeat(4096), T0)
        .expect("4096 bytes file at the default");
}

#[test]
fn a_cursor_idle_8_days_keeps_its_place_under_a_30_day_retention() {
    let fx = Fixture::rooted();
    fx.set(RETENTION_KEY, json!(THIRTY_DAYS));
    let key = fx.owner_key_for([0x47; 32], 4 * FEED_RETENTION_SECS);
    let lane = fx.vault.scoped_read(key.clone());
    let subscription = fx
        .vault
        .feed_subscribe(&lane, &edges_from(FeedStart::Head))
        .expect("subscribe")
        .subscription;
    let (from, to) = (put_person(&fx.vault), put_person(&fx.vault));
    fx.vault
        .put_edge(&from, EdgeKind::Supports, &to, 0.5)
        .expect("edge");
    let page = read_page(&fx.vault, &key, subscription);
    assert_eq!(
        edge_ops(&page, from, to, "supports"),
        vec![FeedOp::EdgeAdded],
        "the edge reaches the follower: {page:?}"
    );
    fx.clock.set(T0 + EIGHT_DAYS);
    match read_answer(&fx.vault, &key, subscription) {
        FeedRead::Page(page) => assert_eq!(
            edge_ops(&page, from, to, "supports"),
            vec![FeedOp::EdgeAdded],
            "the idle cursor keeps its place: {page:?}"
        ),
        FeedRead::Gap(gap) => panic!("a page, not a gap, under a 30-day retention: {gap:?}"),
    }
}

#[test]
fn the_default_retention_gaps_a_cursor_idle_past_7_days() {
    let fx = Fixture::rooted();
    let key = fx.owner_key_for([0x47; 32], 4 * FEED_RETENTION_SECS);
    let lane = fx.vault.scoped_read(key.clone());
    let subscription = fx
        .vault
        .feed_subscribe(&lane, &edges_from(FeedStart::Head))
        .expect("subscribe")
        .subscription;
    let (from, to) = (put_person(&fx.vault), put_person(&fx.vault));
    fx.vault
        .put_edge(&from, EdgeKind::Supports, &to, 0.5)
        .expect("edge");
    let page = read_page(&fx.vault, &key, subscription);
    assert_eq!(
        edge_ops(&page, from, to, "supports"),
        vec![FeedOp::EdgeAdded],
        "the edge reaches the follower: {page:?}"
    );
    fx.clock.set(T0 + EIGHT_DAYS);
    assert_eq!(
        read_answer(&fx.vault, &key, subscription),
        FeedRead::Gap(FeedGap {
            resync_from: FeedResyncFrom::Snapshot,
        }),
        "a cursor idle 8 days gaps at the default"
    );
}
