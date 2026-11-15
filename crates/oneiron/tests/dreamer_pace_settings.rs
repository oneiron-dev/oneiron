//! The Dreamer's paces as the owner's Setting keys (restriction wave 14, C104 + C105; owner 16
//! Nov 00:44: "optional freedom with good defaults everywhere").
//!
//! Each pace is an owner Setting key whose default is today's value, so nothing moves until the
//! owner sets a row through `vault.settings.set`: the nightly identity pass reads `scan_turns`
//! tag sets (2048) and keeps `max_open_asks` asks open at once (64), a failed identity decision
//! waits `retry_secs` seconds (3600), and one Meso round takes `meso_round_turn_cap` admissible
//! TURNs (500). Lower is tighter for the three counts; a longer wait is tighter for the retry.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test dreamer_pace_settings`.

#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use oneiron::authority::HostSlipIssuer;
use oneiron::claim::ScopedReadActorKey;
use oneiron::dreamer_runner::DreamerConsolidationScope;
use oneiron::dreamer_runner::maintenance::identity::{
    IdentityAskReason, IdentityDecisions, IdentityRuling,
};
use oneiron::edge::EdgeActorClass;
use oneiron::llm::decision::{
    DecisionBand, DecisionBandPolicy, DecisionCall, DecisionDial, DecisionLadder, DecisionProvider,
    DecisionRung, HumanDecisionQueue, HumanDecisionRequest, ProviderDecision, ProviderPin,
};
use oneiron::memory::extraction::{EncoderOutput, NerSpan};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::setting::{
    ScopeKind, SetBy, SetSetting, SetSettingOutcome, SettingCaller, spec_named,
};
use oneiron::store::GateDecisionId;
use oneiron::tagging::{HeldTagsOutcome, MentionLink, TaggingMarkerConfig, TaggingMode};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::identity_recheck::run_identity_recheck;
use oneiron::{EntityId, Error, Vault, VaultConfig, read_watermark, scan_dirty_turns};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Tag sets one nightly identity pass reads (2048 today).
const SCAN_TURNS_KEY: &str = "dreamer.identity.scan_turns";
/// Identity asks open at once, besides those kept separate (64 today).
const MAX_OPEN_ASKS_KEY: &str = "dreamer.identity.max_open_asks";
/// Seconds a failed identity decision waits before the host tries it again (3600 today).
const RETRY_SECS_KEY: &str = "dreamer.identity.retry_secs";
/// Admissible TURNs one Meso round takes (500 today).
const MESO_CAP_KEY: &str = "dreamer.consolidation.meso_round_turn_cap";

const CHECKPOINT: &str = "0123456789abcdef";
const ROOM: &str = "52525252525252525252525252525252";

/// Sound-alike pairs: two persons each, and the mention that sounds like both but keys to
/// neither. Every part's Soundex matches the pair's (Owen/Owan O500, John/Jon J500,
/// Robert/Robart R163; Smith/Smyth S530), so each mention keeps exactly its pair.
const PAIRS: [(&str, &str, &str); 3] = [
    ("Owen Smith", "Owen Smyth", "Owan Smyth"),
    ("John Smith", "John Smyth", "Jon Smyth"),
    ("Robert Smith", "Robert Smyth", "Robart Smyth"),
];

fn now_seconds() -> TestResult<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

/// A device config whose tagger saves its tags, mapping the `PERSON` label.
fn tagging_config() -> TestResult<VaultConfig> {
    let mut config = VaultConfig::device();
    config.tagging = Some(
        TaggingMarkerConfig::new(CHECKPOINT)?
            .with_labels(BTreeMap::from([("PERSON".to_owned(), ENTITY_TYPE_PERSON)]))
            .with_mode(TaggingMode::Save),
    );
    Ok(config)
}

/// A vault whose tagger saves its tags, and its embedded owner.
fn open_identity_vault(dir: &tempfile::TempDir) -> TestResult<(Vault, EntityId)> {
    let vault = Vault::open(dir.path(), tagging_config()?)?;
    let owner = vault.ensure_embedded_owner_actor()?;
    Ok((vault, owner))
}

/// A PERSON named `name`; its birth writes its identity hints and its phonetic postings.
fn person(vault: &Vault, name: &str) -> TestResult<EntityId> {
    let id = EntityId::now();
    vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        &rmp_serde::to_vec_named(&json!({ "name": name }))?,
    )?;
    Ok(id)
}

/// Witnesses `text` as the turn `turn` of `author`, whose held tags name `name` in it as a
/// `PERSON`, saved in the witness write; returns the saved link of that one mention.
fn save_as(
    vault: &Vault,
    turn: EntityId,
    author: EntityId,
    text: &str,
    name: &str,
) -> TestResult<MentionLink> {
    let start = text.find(name).ok_or_else(|| {
        Error::InvalidConfig(format!("the name {name:?} is in its text {text:?}"))
    })?;
    let witness = WitnessTurn {
        conversation_ref: ROOM.to_owned(),
        turn_ref: Some(turn.to_hex()),
        thread_audience: None,
        occurred_at: now_seconds()?,
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
        assertions: WitnessAssertions::default(),
    };
    let tags = EncoderOutput {
        spans: vec![NerSpan {
            message: 0,
            start,
            end: start + name.len(),
            label: "PERSON".to_owned(),
            confidence: 1.0,
        }],
        links: Vec::new(),
        vad: None,
        context_links: Vec::new(),
        speaker_links: Vec::new(),
        stack_sha16: None,
        mood_parts: Vec::new(),
    };
    let (_, outcome) = vault
        .memory(author, EdgeActorClass::Human)
        .witness_with_held_tags(&witness, &tags)?;
    assert!(
        matches!(outcome, HeldTagsOutcome::Completed(_)),
        "the held tags are saved in the witness write: {outcome:?}"
    );
    let saved = vault.turn_tags(&turn)?.ok_or_else(|| {
        Error::InvalidConfig(format!("the turn {} has saved tags", turn.to_hex()))
    })?;
    assert_eq!(
        saved.mentions.len(),
        1,
        "one mention is saved on the turn: {}",
        saved.mentions.len()
    );
    Ok(saved.mentions[0].link.clone())
}

/// Two persons who sound alike, and one turn naming the mention that sounds like both; returns
/// the pair and the mention's saved link.
fn seed_pair(
    vault: &Vault,
    speaker: EntityId,
    first: &str,
    second: &str,
    mention: &str,
) -> TestResult<(EntityId, EntityId, MentionLink)> {
    let a = person(vault, first)?;
    let b = person(vault, second)?;
    let link = save_as(
        vault,
        EntityId::now(),
        speaker,
        &format!("{mention} called."),
        mention,
    )?;
    Ok((a, b, link))
}

/// The mention sounds like exactly its pair: its saved link holds the two as candidates.
fn assert_candidates(
    link: &MentionLink,
    mention: &str,
    a: EntityId,
    b: EntityId,
) -> TestResult<()> {
    let MentionLink::Candidates { kind, entities } = link else {
        return Err(Error::InvalidConfig(format!(
            "the mention {mention:?} keeps its pair as candidates, not a mint: {link:?}"
        ))
        .into());
    };
    assert_eq!(
        *kind, ENTITY_TYPE_PERSON,
        "the candidates are persons: {kind}"
    );
    assert_eq!(
        entities.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([a, b]),
        "the mention {mention:?} sounds like exactly its pair: {entities:?}"
    );
    Ok(())
}

/// Three turns, each with one ask-worthy mention of a distinct sound-alike pair.
fn seed_three_asks(vault: &Vault) -> TestResult<()> {
    let speaker = person(vault, "fixture speaker")?;
    for (first, second, mention) in PAIRS {
        let (a, b, link) = seed_pair(vault, speaker, first, second, mention)?;
        assert_candidates(&link, mention, a, b)?;
    }
    Ok(())
}

/// One pace key's catalogue row: the owner's key at the vault scope, defaulting to today's pace,
/// strictest at the least work that still moves, with its tighter direction.
fn assert_pace_key(
    key: &str,
    default: u64,
    strictest: u64,
    lower_is_tighter: bool,
) -> TestResult<()> {
    let spec = spec_named(key)?;
    assert_eq!(
        spec.set_by,
        SetBy::Owner,
        "{key} is set by its owner: {:?}",
        spec.set_by
    );
    assert!(
        matches!(spec.scopes, [ScopeKind::Vault]),
        "{key} has rows at the vault alone: {:?}",
        spec.scopes
    );
    let kind = spec.kind;
    assert_eq!(
        kind.to_json(&kind.default_value()?),
        Some(json!(default)),
        "{key} defaults to today's pace"
    );
    let strictest_value = kind
        .strictest_value()?
        .ok_or_else(|| Error::InvalidConfig(format!("{key} names no strictest value")))?;
    assert_eq!(
        kind.to_json(&strictest_value),
        Some(json!(strictest)),
        "{key} reads its strictest value when a row does not decode"
    );
    assert!(kind.has_direction(), "{key} names its tighter direction");
    let direction = if lower_is_tighter { "lower" } else { "higher" };
    let tight = kind.from_json(json!(strictest))?;
    let loose = kind.from_json(json!(default))?;
    assert_eq!(
        kind.is_tighter(&tight, &loose),
        Some(true),
        "{key} is tighter {direction}: {strictest} against {default}"
    );
    assert_eq!(
        kind.is_tighter(&loose, &tight),
        Some(false),
        "{key} is tighter {direction}: {default} against {strictest}"
    );
    Ok(())
}

/// The owner sets `key` to `value` through the Setting primitive's door; `None` clears the
/// owner's row, so the catalogue default reads again.
fn owner_set(
    vault: &Vault,
    owner: EntityId,
    key: &str,
    value: Option<Value>,
) -> oneiron::Result<SetSettingOutcome> {
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let mut request = SetSetting::vault_value(key, Value::Null);
    request.value = value;
    vault.set_setting(SettingCaller::Owner(&proof), request)
}

/// [`owner_set`], applied at once: the owner sets the key without asking.
fn owner_sets(vault: &Vault, owner: EntityId, key: &str, value: Option<Value>) -> TestResult {
    let outcome = owner_set(vault, owner, key, value)?;
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "the owner's change to {key} did not apply: {outcome:?}"
    );
    Ok(())
}

/// The owner's read lane, as a client holds it: a slip the host root mints for the owner, with
/// the root's whole scope, verified and read through `from_verified_slip`.
fn owner_key(vault: &Vault, owner: EntityId) -> TestResult<ScopedReadActorKey> {
    let issuer = HostSlipIssuer::from_secret(b"dreamer-pace-settings-test-secret")?;
    let root = vault.ensure_host_root_slip(&issuer)?;
    let issued_at = vault.capability_slip_now()?;
    let mut claims = root.claims.clone();
    claims.slip_id = [0x51; 32];
    claims.holder_ref = owner.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.issued_at = issued_at;
    claims.expires_at = issued_at + 3_600;
    claims.ttl_secs = 3_600;
    let slip = vault.mint_capability_slip(&issuer, claims)?;
    let challenge = b"dreamer-pace-settings";
    let proof = issuer.binding_proof(&slip, challenge)?;
    let verified = vault.verify_capability_slip(&issuer.public_key(), &slip, challenge, &proof)?;
    let key = ScopedReadActorKey::from_verified_slip(&verified)
        .ok_or_else(|| Error::InvalidConfig("the verified slip builds no read key".to_owned()))?;
    Ok(key)
}

/// A decision rung that fails every call, so the ladder fails with work time left.
struct FailingRung;

impl DecisionProvider for FailingRung {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::SystemOne,
            model: "dreamer-pace-settings-failing-rung".to_owned(),
            version: "1".to_owned(),
        }
    }

    fn decide(&self, _call: &DecisionCall<'_>) -> oneiron::Result<ProviderDecision> {
        Err(Error::InvalidConfig("the provider failed".to_owned()))
    }
}

/// No person is ever asked: the failing ladder fails the call instead.
struct NoPerson;

impl HumanDecisionQueue for NoPerson {
    fn queue(&self, _request: HumanDecisionRequest) -> oneiron::Result<()> {
        panic!("the failing ladder fails the call, never asks a person");
    }
}

/// One ask, decided once on a ladder whose only rung fails; returns the ask's `retry_at` after
/// the decision. With `wait`, the owner sets the retry wait first.
fn fail_one_decision(
    vault: &Vault,
    owner: EntityId,
    now: u64,
    wait: Option<u64>,
) -> TestResult<u64> {
    let speaker = person(vault, "fixture speaker")?;
    let (a, b, link) = seed_pair(vault, speaker, "Owen Smith", "Owen Smyth", "Owan Smyth")?;
    assert_candidates(&link, "Owan Smyth", a, b)?;
    let asks = run_identity_recheck(vault, now)?;
    assert_eq!(asks.len(), 1, "one mention opens one ask: {asks:?}");
    assert_eq!(
        asks[0].reason,
        IdentityAskReason::Unsettled,
        "the ask waits for the nightly decision: {:?}",
        asks[0].reason
    );
    if let Some(secs) = wait {
        owner_sets(vault, owner, RETRY_SECS_KEY, Some(json!(secs)))?;
    }
    let read = vault.scoped_read(owner_key(vault, owner)?);
    let due = vault.identity_asks_due(&read, now, 4)?;
    assert_eq!(
        due.len(),
        1,
        "the open ask is due on the owner's lane: {due:?}"
    );
    let rung = FailingRung;
    let queue = NoPerson;
    let deadline = RetrievalDeadline::hard(Instant::now(), Duration::from_secs(20));
    let decisions = IdentityDecisions {
        ladder: DecisionLadder {
            rule: None,
            local: None,
            system_one: Some(&rung),
            escalation: None,
            big: None,
            human: &queue,
            human_pin: ProviderPin {
                rung: DecisionRung::Human,
                model: "never-asked".to_owned(),
                version: "1".to_owned(),
            },
            ask_to: None,
            paired: None,
            person: None,
            presence: None,
            correlation: None,
        },
        principal: owner,
        dial: DecisionDial {
            first: DecisionRung::SystemOne,
            ceiling: DecisionRung::SystemOne,
            band: DecisionBand::default(),
        },
        bands: DecisionBandPolicy::default(),
        wording: "Which candidate is the person this mention names?".to_owned(),
        deadline: &deadline,
    };
    let ruling = vault.decide_identity_ask(&read, &decisions, &due[0], now)?;
    assert_eq!(
        ruling,
        IdentityRuling::Retry,
        "the failed decision waits for another round: {ruling:?}"
    );
    let asks = run_identity_recheck(vault, now)?;
    assert_eq!(
        asks.len(),
        1,
        "the ask still stands after its failed decision: {asks:?}"
    );
    Ok(asks[0].retry_at)
}

/// One admissible TURN at `learned_at`, as the Meso round reads it: type TURN with a user speaker.
fn seed_turn(vault: &Vault, learned_at: u64) -> TestResult<EntityId> {
    let id = EntityId::now();
    let body = rmp_serde::to_vec_named(&json!({"spkr": "user", "txt": "meso fixture turn"}))?;
    vault.put_entity(
        &id,
        ENTITY_TYPE_TURN,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
        &body,
    )?;
    Ok(id)
}

/// A vault with an owner and 501 admissible TURNs in one second, past the bootstrap watermark.
fn seed_meso_backlog(dir: &tempfile::TempDir) -> TestResult<(Vault, EntityId)> {
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    for _ in 0..501 {
        seed_turn(&vault, 1)?;
    }
    Ok((vault, owner))
}

#[test]
fn the_identity_paces_are_owner_keys_with_todays_defaults() -> TestResult {
    // Each key with its default, its strictest value, and whether lower is tighter.
    let keys = [
        (SCAN_TURNS_KEY, 2_048u64, 1u64, true),
        (MAX_OPEN_ASKS_KEY, 64u64, 1u64, true),
        (RETRY_SECS_KEY, 3_600u64, 86_400u64, false),
    ];
    for (key, default, strictest, lower_is_tighter) in keys {
        assert_pace_key(key, default, strictest, lower_is_tighter)?;
    }
    Ok(())
}

#[test]
fn a_zero_identity_pace_is_refused() -> TestResult {
    for key in [SCAN_TURNS_KEY, MAX_OPEN_ASKS_KEY, RETRY_SECS_KEY] {
        let dir = tempfile::tempdir()?;
        let (vault, owner) = open_identity_vault(&dir)?;
        let refused = owner_set(&vault, owner, key, Some(json!(0)));
        assert!(
            matches!(&refused, Err(Error::InvalidConfig(_))),
            "a zero {key} is refused as invalid config: {refused:?}"
        );
        // The refused write stored nothing: setting 1 lands as the vault's first change.
        match owner_set(&vault, owner, key, Some(json!(1)))? {
            SetSettingOutcome::Applied {
                sequence,
                revision,
                value,
            } => {
                assert_eq!(
                    sequence,
                    Some(1),
                    "the refused zero wrote no change for {key}: {sequence:?}"
                );
                assert_eq!(
                    revision, 1,
                    "the refused zero stored no row for {key}: {revision}"
                );
                assert_eq!(value, json!(1), "{key} reads back 1: {value:?}");
            }
            SetSettingOutcome::Pending { check_in } => {
                return Err(Error::InvalidConfig(format!(
                    "{key} set to 1 waits on a check-in: {check_in}"
                ))
                .into());
            }
        }
    }
    Ok(())
}

#[test]
fn one_tag_set_per_pass_opens_one_ask_per_pass() -> TestResult {
    let now = now_seconds()?;
    // Guard: one pass at today's pace opens all three asks.
    {
        let dir = tempfile::tempdir()?;
        let (vault, _owner) = open_identity_vault(&dir)?;
        seed_three_asks(&vault)?;
        let asks = run_identity_recheck(&vault, now)?;
        assert_eq!(
            asks.len(),
            3,
            "one pass at today's pace opens every ask: {asks:?}"
        );
    }
    // The owner's page of one opens one ask per pass.
    {
        let dir = tempfile::tempdir()?;
        let (vault, owner) = open_identity_vault(&dir)?;
        seed_three_asks(&vault)?;
        owner_sets(&vault, owner, SCAN_TURNS_KEY, Some(json!(1)))?;
        let asks = run_identity_recheck(&vault, now)?;
        assert_eq!(
            asks.len(),
            1,
            "pass 1 at scan_turns = 1 opens one ask: {asks:?}"
        );
        let asks = run_identity_recheck(&vault, now)?;
        assert_eq!(
            asks.len(),
            2,
            "pass 2 at scan_turns = 1 opens one more: {asks:?}"
        );
        let asks = run_identity_recheck(&vault, now)?;
        assert_eq!(
            asks.len(),
            3,
            "pass 3 at scan_turns = 1 opens the last: {asks:?}"
        );
    }
    Ok(())
}

#[test]
fn a_full_tray_stops_the_pass_at_the_waiting_turn() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (vault, owner) = open_identity_vault(&dir)?;
    seed_three_asks(&vault)?;
    let now = now_seconds()?;
    owner_sets(&vault, owner, MAX_OPEN_ASKS_KEY, Some(json!(2)))?;
    let asks = run_identity_recheck(&vault, now)?;
    assert_eq!(
        asks.len(),
        2,
        "one pass at max_open_asks = 2 opens two asks: {asks:?}"
    );
    owner_sets(&vault, owner, MAX_OPEN_ASKS_KEY, None)?;
    let asks = run_identity_recheck(&vault, now)?;
    assert_eq!(
        asks.len(),
        3,
        "the next pass after the clear opens the waiting ask: {asks:?}"
    );
    Ok(())
}

#[test]
fn a_failed_identity_decision_waits_the_owners_retry() -> TestResult {
    let now = now_seconds()?;
    // The owner's wait of a minute.
    {
        let dir = tempfile::tempdir()?;
        let (vault, owner) = open_identity_vault(&dir)?;
        let retry_at = fail_one_decision(&vault, owner, now, Some(60))?;
        assert_eq!(
            retry_at,
            now + 60,
            "the failed ask waits the owner's 60 seconds: {retry_at}"
        );
    }
    // Guard: with no row the failed ask waits today's hour.
    {
        let dir = tempfile::tempdir()?;
        let (vault, owner) = open_identity_vault(&dir)?;
        let retry_at = fail_one_decision(&vault, owner, now, None)?;
        assert_eq!(
            retry_at,
            now + 3_600,
            "the failed ask waits today's 3600 seconds: {retry_at}"
        );
    }
    Ok(())
}

#[test]
fn the_meso_round_turn_cap_is_an_owner_key_with_todays_default() -> TestResult {
    assert_pace_key(MESO_CAP_KEY, 500, 1, true)
}

#[test]
fn a_meso_scan_takes_the_owners_turn_cap() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (vault, owner) = seed_meso_backlog(&dir)?;
    let meso = read_watermark(&vault, DreamerConsolidationScope::Meso)?;
    let full: Vec<EntityId> =
        scan_dirty_turns(&vault, DreamerConsolidationScope::Meso, &meso, usize::MAX)?
            .into_iter()
            .map(|turn| turn.turn_id)
            .collect();
    assert_eq!(
        full.len(),
        500,
        "a Meso round takes today's 500 without a row"
    );
    let micro_watermark = read_watermark(&vault, DreamerConsolidationScope::Micro)?;
    let micro = scan_dirty_turns(
        &vault,
        DreamerConsolidationScope::Micro,
        &micro_watermark,
        usize::MAX,
    )?;
    assert_eq!(
        micro.len(),
        501,
        "Micro keeps the requested limit: {}",
        micro.len()
    );
    owner_sets(&vault, owner, MESO_CAP_KEY, Some(json!(100)))?;
    let capped: Vec<EntityId> =
        scan_dirty_turns(&vault, DreamerConsolidationScope::Meso, &meso, usize::MAX)?
            .into_iter()
            .map(|turn| turn.turn_id)
            .collect();
    assert_eq!(capped.len(), 100, "a Meso round takes the owner's 100");
    assert_eq!(
        capped.as_slice(),
        &full[..100],
        "the owner's cap takes the first 100 of the default order"
    );
    let micro = scan_dirty_turns(
        &vault,
        DreamerConsolidationScope::Micro,
        &micro_watermark,
        usize::MAX,
    )?;
    assert_eq!(
        micro.len(),
        501,
        "Micro still keeps the requested limit under the owner's cap: {}",
        micro.len()
    );
    owner_sets(&vault, owner, MESO_CAP_KEY, None)?;
    let again = scan_dirty_turns(&vault, DreamerConsolidationScope::Meso, &meso, usize::MAX)?;
    assert_eq!(
        again.len(),
        500,
        "a cleared cap takes 500 again: {}",
        again.len()
    );
    Ok(())
}

#[test]
fn a_zero_meso_cap_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (vault, owner) = seed_meso_backlog(&dir)?;
    let refused = owner_set(&vault, owner, MESO_CAP_KEY, Some(json!(0)));
    assert!(
        matches!(&refused, Err(Error::InvalidConfig(_))),
        "a zero Meso cap is refused as invalid config: {refused:?}"
    );
    let meso = read_watermark(&vault, DreamerConsolidationScope::Meso)?;
    let scan = scan_dirty_turns(&vault, DreamerConsolidationScope::Meso, &meso, usize::MAX)?;
    assert_eq!(
        scan.len(),
        500,
        "the refused zero leaves today's 500: {}",
        scan.len()
    );
    // The key the refusal protects is live: setting 1 caps the round at one turn.
    owner_sets(&vault, owner, MESO_CAP_KEY, Some(json!(1)))?;
    let one = scan_dirty_turns(&vault, DreamerConsolidationScope::Meso, &meso, usize::MAX)?;
    assert_eq!(
        one.len(),
        1,
        "the live key caps the round at 1: {}",
        one.len()
    );
    Ok(())
}
