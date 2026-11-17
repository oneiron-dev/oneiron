//! The owner's raised page maxima, served (restriction wave 19).
//!
//! Commit `50013775890` moves three list maxima onto the Setting primitive as
//! owner keys, each defaulting to today's maximum: `feeds.read.max_per_source`
//! (256 entries per source), `conversation_dag.reply_strips.max_page` (256
//! strips) and `verbs.files.max_page_limit` (1000 files). This file pins the
//! first two: with no row each list serves today's maximum (guard), and after
//! the owner raises the key the same ask serves the raised maximum. A zero
//! page maximum is refused for all three keys, and the lists keep serving
//! today's maximum after the refusal.
//!
//! The Files key is not pinned here: filling a Files ledger needs a Files
//! source, whose only public makers run through this install's Files world,
//! and no public-paths-only fixture in the tree walks that machine
//! enrolment. See the rw19-test leg notes.
//!
//! Public paths only:
//! `cargo test --locked -p oneiron --all-features --test restriction_page_keys`.

use std::collections::BTreeSet;

use oneiron::authority::HostSlipIssuer;
use oneiron::claim::ScopedReadActorKey;
use oneiron::consent::AuthenticatedOwner;
use oneiron::conversation_dag::{AddressMode, AppendRecord, QuoteSpan, ReplyStripsRequest};
use oneiron::feeds::{
    FEED_READ_DEFAULT_LIMIT, FEED_READ_MAX_LIMIT, FeedPage, FeedRead, FeedReadRequest,
    FeedSelector, FeedSource, FeedStart, FeedSubscribeRequest,
};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// `crates/oneiron/src/conversation_dag/quote_strips.rs` `PAGE_LIMIT`
/// (private): a reply-strip page holds 256 strips when the request names no
/// limit, and at most 256 while the owner has not moved
/// `conversation_dag.reply_strips.max_page`.
const QUOTE_STRIP_PAGE_LIMIT: usize = 256;

fn open_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    Ok((dir, vault))
}

fn owner_proof(
    vault: &Vault,
    owner: EntityId,
) -> Result<AuthenticatedOwner, Box<dyn std::error::Error>> {
    Ok(vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?)
}

fn put_person(vault: &Vault, learned_at: u64) -> Result<EntityId, Box<dyn std::error::Error>> {
    let id = EntityId::now();
    vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        learned_at,
        b"a person",
    )?;
    Ok(id)
}

/// The owner's read lane, as a client holds it: a slip the host root mints
/// for the owner, with the root's whole scope, verified and read through
/// `from_verified_slip`. Copied from `crates/oneiron/tests/list_limit_rules.rs`,
/// except the `None` arm, which names its error instead of `?` on an `Option`.
fn owner_key(vault: &Vault) -> Result<ScopedReadActorKey, Box<dyn std::error::Error>> {
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"restriction-page-keys-host-secret")?;
    let root = vault.ensure_host_root_slip(&issuer)?;
    let issued_at = vault.capability_slip_now()?;
    let mut claims = root.claims.clone();
    claims.slip_id = [0x52; 32];
    claims.holder_ref = owner.to_hex();
    claims.actor_class = Some("human".into());
    claims.issued_at = issued_at;
    claims.expires_at = issued_at + 3_600;
    claims.ttl_secs = 3_600;
    let slip = vault.mint_capability_slip(&issuer, claims)?;
    let challenge = b"restriction-page-keys";
    let proof = issuer.binding_proof(&slip, challenge)?;
    let verified = vault.verify_capability_slip(&issuer.public_key(), &slip, challenge, &proof)?;
    Ok(ScopedReadActorKey::from_verified_slip(&verified).ok_or("the owner's slip reads no key")?)
}

fn changes_from(start: FeedStart) -> FeedSubscribeRequest {
    FeedSubscribeRequest {
        selector: FeedSelector {
            sources: vec![FeedSource::Changes],
            kinds: Vec::new(),
            entity_types: Vec::new(),
            predicates: Vec::new(),
        },
        start,
    }
}

fn read_feed_page(
    vault: &Vault,
    key: &ScopedReadActorKey,
    subscription: EntityId,
    limit: Option<usize>,
) -> Result<FeedPage, Box<dyn std::error::Error>> {
    match vault.feed_read(
        &vault.scoped_read(key.clone()),
        &FeedReadRequest {
            subscription,
            limit,
        },
    )? {
        FeedRead::Page(page) => Ok(page),
        FeedRead::Gap(gap) => panic!("a page, not a gap: {gap:?}"),
    }
}

/// The owner's witness turn `turn` in `room`, one MESSAGE: a trunk turn, or with
/// `anchor` the root of a thread on it, private to `audience` when named.
/// Returns the MESSAGE id.
fn speak_turn(
    vault: &Vault,
    owner: EntityId,
    room: EntityId,
    turn: EntityId,
    anchor: Option<EntityId>,
    audience: Option<BTreeSet<EntityId>>,
) -> Result<EntityId, Box<dyn std::error::Error>> {
    let metadata = match anchor {
        Some(anchor) => serde_json::json!({"room_thread_of": anchor.to_hex()}),
        None => serde_json::json!({}),
    };
    let message = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .rooms_speak(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: audience,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "owen".into(),
                parts: None,
                metadata: Some(metadata),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: Default::default(),
        })?;
    Ok(message)
}

struct StripFixture {
    vault: Vault,
    owner: EntityId,
    room: EntityId,
    thread: EntityId,
    root_message: EntityId,
    _directory: tempfile::TempDir,
}

/// A project room with a thread rooted on a witness turn, as
/// `crates/oneiron/tests/thread_task_one_surface.rs` opens one, without its
/// agents, grants, policy seats or tasks: the strips read is the owner's own.
fn open_strip_fixture() -> Result<StripFixture, Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    // `open_owned` holds the writer lease the owner's doors ask for.
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let root_project = vault.root_project()?;
    let project_id = EntityId::now();
    let project = ProjectRecord::new(project_id, Some(root_project), root_project, owner)?;
    vault.put_project(project_id, &project, vault.now_recorded_at())?;
    let room = EntityId::from_hex(&project.home_room)?;
    let anchor = EntityId::now();
    speak_turn(&vault, owner, room, anchor, None, None)?;
    let thread = EntityId::now();
    let root_message = speak_turn(
        &vault,
        owner,
        room,
        thread,
        Some(anchor),
        Some(BTreeSet::from([owner])),
    )?;
    Ok(StripFixture {
        vault,
        owner,
        room,
        thread,
        root_message,
        _directory: directory,
    })
}

/// The owner's reply in the thread, through the REST thread reply's door;
/// with `quote`, it quotes that span. Returns the reply TURN.
fn quoted_reply(
    fixture: &StripFixture,
    quote: Option<QuoteSpan>,
) -> Result<EntityId, Box<dyn std::error::Error>> {
    let now = fixture.vault.now_recorded_at();
    let input = AppendRecord {
        conversation: fixture.room,
        parent: None,
        reply_to: None,
        quote,
        address: AddressMode::Broadcast,
        recipients: vec![],
        advance: false,
        kind: ENTITY_TYPE_TURN,
        containing_turn: None,
        occurred: TimeRange {
            start: now,
            end: now,
        },
        learned_at: now,
        body: rmp_serde::to_vec_named(&serde_json::json!({"txt": "owen"}))?,
        text: vec![],
        session: None,
        actor: WriteActor::new(fixture.owner, EdgeActorClass::Human),
        thread_audience: None,
    };
    let writer = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    Ok(fixture
        .vault
        .reply_in_thread(&writer, fixture.thread, &input)?
        .id)
}

/// The strips one page holds over the fixture's thread at `limit`, and the
/// cursor to the rest.
fn strip_count(
    fixture: &StripFixture,
    limit: Option<usize>,
) -> Result<(usize, Option<String>), Box<dyn std::error::Error>> {
    let page = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .rooms_reply_strips(&ReplyStripsRequest {
            room_ref: fixture.room.to_hex(),
            thread_ref: fixture.thread.to_hex(),
            after: None,
            limit,
        })?;
    let strips: usize = page.groups.iter().map(|group| group.strips.len()).sum();
    Ok((strips, page.next_after))
}

/// `Vault::feed_read` (`crates/oneiron/src/feeds/mod.rs:570`) serves the
/// owner's raised `feeds.read.max_per_source`: with no row `Some(300)` serves
/// 256 entries and says more remain; after the owner raises the key to 300
/// the same ask on the same subscription serves 300, and an absent ask still
/// serves 64.
#[test]
fn feed_read_serves_the_owners_raised_maximum_per_source() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let key = owner_key(&vault)?;
    let subscription = vault
        .feed_subscribe(
            &vault.scoped_read(key.clone()),
            &changes_from(FeedStart::Beginning),
        )?
        .subscription;
    for learned_at in 1..=300 {
        put_person(&vault, learned_at)?;
    }
    let page = read_feed_page(&vault, &key, subscription, Some(300))?;
    assert_eq!(
        page.entries.len(),
        FEED_READ_MAX_LIMIT,
        "guard: with no row, an ask past the maximum serves it"
    );
    assert!(page.more, "guard: 300 entries fill a 256 page");
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = owner_proof(&vault, owner)?;
    let outcome = vault.set_setting(
        SettingCaller::Owner(&proof),
        SetSetting::vault_value("feeds.read.max_per_source", serde_json::json!(300)),
    )?;
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "the owner's raise applies"
    );
    let page = read_feed_page(&vault, &key, subscription, Some(300))?;
    assert_eq!(
        page.entries.len(),
        300,
        "raised: the same ask serves the owner's maximum"
    );
    let page = read_feed_page(&vault, &key, subscription, None)?;
    assert_eq!(
        page.entries.len(),
        FEED_READ_DEFAULT_LIMIT,
        "raised: an absent ask still serves 64"
    );
    Ok(())
}

/// `Memory::rooms_reply_strips`
/// (`crates/oneiron/src/conversation_dag/quote_strips.rs:409`) serves the
/// owner's raised `conversation_dag.reply_strips.max_page`: with no row
/// `Some(257)` over 257 reply strips serves 256 with a cursor to the rest;
/// after the owner raises the key to 257 the same ask serves all 257.
#[test]
fn reply_strips_serve_the_owners_raised_maximum() -> TestResult {
    let fixture = open_strip_fixture()?;
    for _ in 0..257 {
        quoted_reply(
            &fixture,
            Some(QuoteSpan {
                message: fixture.root_message,
                start: 0,
                end: 4,
            }),
        )?;
    }
    let (served, next) = strip_count(&fixture, Some(257))?;
    assert_eq!(
        served, QUOTE_STRIP_PAGE_LIMIT,
        "guard: with no row, an ask past the maximum serves it"
    );
    assert!(next.is_some(), "guard: one strip is left past a full page");
    let proof = owner_proof(&fixture.vault, fixture.owner)?;
    let outcome = fixture.vault.set_setting(
        SettingCaller::Owner(&proof),
        SetSetting::vault_value(
            "conversation_dag.reply_strips.max_page",
            serde_json::json!(257),
        ),
    )?;
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "the owner's raise applies"
    );
    let (served, next) = strip_count(&fixture, Some(257))?;
    assert_eq!(
        served, 257,
        "raised: the same ask serves the owner's maximum"
    );
    assert_eq!(next, None, "raised: no strip is left past it");
    Ok(())
}

/// The owner's set of 0 on `key` answers `InvalidConfig` with the page
/// maximum's refusal.
fn assert_zero_refused(
    vault: &Vault,
    proof: &AuthenticatedOwner,
    key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match vault.set_setting(
        SettingCaller::Owner(proof),
        SetSetting::vault_value(key, serde_json::json!(0)),
    ) {
        Err(oneiron::Error::InvalidConfig(text)) => {
            assert_eq!(
                text, "a page maximum is at least one row",
                "{key} refuses zero"
            );
            Ok(())
        }
        Err(other) => {
            Err(format!("{key}: zero is refused as invalid config, not {other:?}").into())
        }
        Ok(_) => Err(format!("{key}: a zero page maximum is refused").into()),
    }
}

/// A zero page maximum is refused (`PageMax::check`,
/// `crates/oneiron/src/setting/page_max.rs:30`, surfaced by
/// `Vault::set_setting`, `crates/oneiron/src/setting/set.rs:166`): the
/// owner's set of 0 on each of the three keys answers `InvalidConfig`, and a
/// later read of the feed and the strips on the same vault still serves
/// today's maximum. (The Files list has no public-paths-only fixture; see the
/// module doc.)
#[test]
fn a_zero_page_maximum_is_refused() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = owner_proof(&vault, owner)?;
    for key in [
        "feeds.read.max_per_source",
        "verbs.files.max_page_limit",
        "conversation_dag.reply_strips.max_page",
    ] {
        assert_zero_refused(&vault, &proof, key)?;
    }
    for learned_at in 1..=300 {
        put_person(&vault, learned_at)?;
    }
    let read_key = owner_key(&vault)?;
    let subscription = vault
        .feed_subscribe(
            &vault.scoped_read(read_key.clone()),
            &changes_from(FeedStart::Beginning),
        )?
        .subscription;
    let page = read_feed_page(&vault, &read_key, subscription, Some(300))?;
    assert_eq!(
        page.entries.len(),
        FEED_READ_MAX_LIMIT,
        "refused: the feed still serves today's maximum"
    );
    assert!(page.more, "refused: 300 entries fill a 256 page");
    let fixture = open_strip_fixture()?;
    let strip_proof = owner_proof(&fixture.vault, fixture.owner)?;
    assert_zero_refused(
        &fixture.vault,
        &strip_proof,
        "conversation_dag.reply_strips.max_page",
    )?;
    for _ in 0..257 {
        quoted_reply(
            &fixture,
            Some(QuoteSpan {
                message: fixture.root_message,
                start: 0,
                end: 4,
            }),
        )?;
    }
    let (served, next) = strip_count(&fixture, Some(257))?;
    assert_eq!(
        served, QUOTE_STRIP_PAGE_LIMIT,
        "refused: the strips still serve today's maximum"
    );
    assert!(
        next.is_some(),
        "refused: one strip is left past a full page"
    );
    Ok(())
}
