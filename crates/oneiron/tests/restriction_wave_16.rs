//! Restriction wave 16: four owner Setting keys over hard-coded restrictions.
//!
//! In plain sentences: a commitment longer than 8 KiB writes once the owner raises
//! `commitment.content.max_text_bytes`, is refused at the default, and still reads after the
//! owner lowers the cap again. A reminder quotes the promise up to
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
};
use oneiron::commitment_wake::COMMITMENT_REMINDER_CONTENT_PREFIX;
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::{EdgeActorClass, EdgeKind};
use oneiron::feeds::{
    FEED_RETENTION_SECS, FeedGap, FeedOp, FeedPage, FeedRead, FeedReadRequest, FeedResyncFrom,
    FeedSelector, FeedSource, FeedStart, FeedSubscribeRequest,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope};
use oneiron::store::GateDecisionId;
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
