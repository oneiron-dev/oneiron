//! Change feed subscriptions (untangle slices 6.8a and 6.8b, primitive B), on the public crate surface only:
//! `Vault`, `ScopedReadActorKey` and `oneiron::feeds`. Run with
//! `cargo test -p oneiron --all-features --test feeds`.

use oneiron::authority::HostSlipIssuer;
use oneiron::claim::ScopedReadActorKey;
use oneiron::code_memory::BlocksWriteContext;
use oneiron::edge::EdgeKind;
use oneiron::feeds::{
    FEED_RETENTION_SECS, FeedAckRequest, FeedEntryKind, FeedGap, FeedOp, FeedPage, FeedPosition,
    FeedRead, FeedReadRequest, FeedResyncFrom, FeedSelector, FeedSource, FeedStart,
    FeedSubscribeRequest,
};
use oneiron::registry::{ENTITY_TYPE_CODE_SYMBOL, ENTITY_TYPE_PERSON};
use oneiron::{ClaimSource, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_store::ports::manual_clock::ManualClock;

fn open() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    (dir, vault)
}

/// The owner's read lane, as a client holds it: a slip the host root mints for the owner, with
/// the root's whole scope, verified and read through `from_verified_slip`.
fn owner_key(vault: &Vault) -> ScopedReadActorKey {
    owner_slip(vault, [0x46; 32]).1
}

/// [`owner_key`] with the issuer that minted its slip `slip_id`, so a test can revoke it.
fn owner_slip(vault: &Vault, slip_id: [u8; 32]) -> (HostSlipIssuer, ScopedReadActorKey) {
    owner_slip_for(vault, slip_id, 3_600)
}

fn owner_slip_for(
    vault: &Vault,
    slip_id: [u8; 32],
    ttl_secs: u64,
) -> (HostSlipIssuer, ScopedReadActorKey) {
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let issuer = HostSlipIssuer::from_secret(b"feeds-test-host-secret").expect("host issuer");
    let root = vault
        .ensure_host_root_slip(&issuer)
        .expect("host root slip");
    let issued_at = vault.capability_slip_now().expect("authority clock");
    let mut claims = root.claims.clone();
    claims.slip_id = slip_id;
    claims.holder_ref = owner.to_hex();
    claims.actor_class = Some("human".into());
    claims.issued_at = issued_at;
    claims.expires_at = issued_at + ttl_secs;
    claims.ttl_secs = ttl_secs;
    let slip = vault
        .mint_capability_slip(&issuer, claims)
        .expect("the owner's slip");
    let challenge = b"feeds-test";
    let proof = issuer
        .binding_proof(&slip, challenge)
        .expect("binding proof");
    let verified = vault
        .verify_capability_slip(&issuer.public_key(), &slip, challenge, &proof)
        .expect("verified slip");
    let key = ScopedReadActorKey::from_verified_slip(&verified).expect("owner key");
    (issuer, key)
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

fn read(vault: &Vault, key: &ScopedReadActorKey, subscription: EntityId) -> FeedPage {
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

/// The grant is judged at delivery, never frozen at subscribe: the owner's lane is shown the
/// PERSON written after subscribing. The same actor reading through a lane that reads nothing,
/// as a grant narrowed after the write, is shown no entry and told nothing of it: no count, and
/// the one token a page gives per source.
#[test]
fn an_entry_is_shown_only_where_the_readers_lane_shows_it_now() {
    let (_dir, vault) = open();
    let shown = owner_key(&vault);
    let subscription = vault
        .feed_subscribe(
            &vault.scoped_read(shown.clone()),
            &changes_from(FeedStart::Head),
        )
        .expect("subscribe")
        .subscription;
    let person = put_person(&vault);

    let page = read(&vault, &shown, subscription);
    assert!(
        page.entries
            .iter()
            .any(|entry| entry.entity == person && entry.kind == FeedEntryKind::Edit),
        "{page:?}"
    );
    assert_eq!(page.through.len(), 1, "one token per source");

    let narrowed =
        ScopedReadActorKey::read_nothing(shown.actor_ref(), "human").expect("narrowed key");
    let page = read(&vault, &narrowed, subscription);
    assert!(page.entries.is_empty(), "{page:?}");
    assert!(!page.more, "{page:?}");
    assert_eq!(page.through.len(), 1, "one token per source, shown or not");
}

/// An ack moves the cursor to a page's `through`, so the next page starts after it. An older
/// token, behind the cursor, moves nothing. A plain position, or another subscription's token,
/// is refused: a reader acks only the sealed tokens its own subscription gave it.
#[test]
fn an_ack_moves_the_cursor_forward_only_and_takes_only_its_own_tokens() {
    let (_dir, vault) = open();
    let key = owner_key(&vault);
    let lane = vault.scoped_read(key.clone());
    let subscription = vault
        .feed_subscribe(&lane, &changes_from(FeedStart::Head))
        .expect("subscribe")
        .subscription;
    let ack = |through: Vec<FeedPosition>| {
        vault.feed_ack(
            &lane,
            &FeedAckRequest {
                subscription,
                through,
            },
        )
    };
    let first = put_person(&vault);
    let older = read(&vault, &key, subscription).through;
    let second = put_person(&vault);
    let page = read(&vault, &key, subscription);
    for person in [first, second] {
        assert!(
            page.entries.iter().any(|entry| entry.entity == person),
            "{page:?}"
        );
    }
    let acked = ack(page.through.clone()).expect("ack");
    assert_eq!(acked.cursors.len(), 1, "{acked:?}");

    let next = read(&vault, &key, subscription);
    assert!(next.entries.is_empty(), "{next:?}");
    assert_eq!(
        next.through.len(),
        1,
        "one token per source, scanned or not"
    );

    ack(older).expect("an ack behind the cursor moves nothing");
    let still = read(&vault, &key, subscription);
    assert!(still.entries.is_empty(), "{still:?}");

    let plain = FeedPosition(format!("changes:{}", "f".repeat(32)));
    assert!(ack(vec![plain]).is_err(), "a plain position is refused");
    let other = vault
        .feed_subscribe(&lane, &changes_from(FeedStart::Head))
        .expect("another subscription")
        .subscription;
    let foreign = read(&vault, &key, other).through;
    assert!(
        ack(foreign).is_err(),
        "another subscription's token is refused"
    );
}

/// A subscription is its actor's own: another actor's read and unsubscribe find nothing.
#[test]
fn another_actors_subscription_is_not_found() {
    let (_dir, vault) = open();
    let lane = vault.scoped_read(owner_key(&vault));
    let subscription = vault
        .feed_subscribe(&lane, &changes_from(FeedStart::Head))
        .expect("subscribe")
        .subscription;
    let stranger = vault.scoped_read(
        ScopedReadActorKey::with_actor_class(EntityId::now().to_hex(), "agent")
            .expect("stranger key"),
    );
    assert!(
        vault
            .feed_read(
                &stranger,
                &FeedReadRequest {
                    subscription,
                    limit: None,
                },
            )
            .is_err()
    );
    assert!(
        !vault
            .feed_unsubscribe(&stranger, subscription)
            .expect("unsubscribe")
    );
    assert_eq!(vault.feed_subscriptions(&lane).expect("list").len(), 1);
    assert!(
        vault
            .feed_unsubscribe(&lane, subscription)
            .expect("unsubscribe")
    );
    assert!(vault.feed_subscriptions(&lane).expect("list").is_empty());
}

/// A key revoked since it subscribed reaches no subscription: listing, reading, acking and
/// ending one each check the credential in their own transaction (review #6897).
#[test]
fn a_revoked_credential_reaches_no_subscription() {
    let (_dir, vault) = open();
    let slip_id = [0x52; 32];
    let (issuer, key) = owner_slip(&vault, slip_id);
    let subscription = vault
        .feed_subscribe(
            &vault.scoped_read(key.clone()),
            &changes_from(FeedStart::Head),
        )
        .expect("subscribe")
        .subscription;
    vault
        .revoke_capability_slip(&issuer, slip_id)
        .expect("revoke the slip");

    let lane = vault.scoped_read(key);
    assert!(vault.feed_subscriptions(&lane).is_err(), "list");
    assert!(
        vault
            .feed_read(
                &lane,
                &FeedReadRequest {
                    subscription,
                    limit: None,
                },
            )
            .is_err(),
        "read"
    );
    assert!(
        vault
            .feed_ack(
                &lane,
                &FeedAckRequest {
                    subscription,
                    through: Vec::new(),
                },
            )
            .is_err(),
        "ack"
    );
    assert!(
        vault.feed_unsubscribe(&lane, subscription).is_err(),
        "unsubscribe"
    );
}

/// A physical delete still reaches the owner as a withdrawal: the change log's delete names no
/// type and removes the row, so the feed keeps the type while it follows the log (review #6897
/// round 2).
#[test]
fn a_physical_delete_reaches_the_owner_as_a_withdrawal() {
    let (_dir, vault) = open();
    let key = owner_key(&vault);
    let lane = vault.scoped_read(key.clone());
    let subscription = vault
        .feed_subscribe(&lane, &changes_from(FeedStart::Head))
        .expect("subscribe")
        .subscription;
    let person = put_person(&vault);
    let through = read(&vault, &key, subscription).through;
    vault
        .feed_ack(
            &lane,
            &FeedAckRequest {
                subscription,
                through,
            },
        )
        .expect("ack the edit");

    vault
        .batch()
        .delete(&person)
        .commit()
        .expect("delete the person");
    let page = read(&vault, &key, subscription);
    assert!(
        page.entries
            .iter()
            .any(|entry| entry.entity == person && entry.kind == FeedEntryKind::Withdrawal),
        "{page:?}"
    );
}

/// A selector follows at least one source, each once.
#[test]
fn a_selector_names_each_source_once() {
    let (_dir, vault) = open();
    let lane = vault.scoped_read(owner_key(&vault));
    let mut request = changes_from(FeedStart::Head);
    request.selector.sources = Vec::new();
    assert!(vault.feed_subscribe(&lane, &request).is_err());
    request.selector.sources = vec![FeedSource::Changes, FeedSource::Changes];
    assert!(vault.feed_subscribe(&lane, &request).is_err());
}

fn follow_from(
    vault: &Vault,
    key: &ScopedReadActorKey,
    source: FeedSource,
    start: FeedStart,
) -> EntityId {
    vault
        .feed_subscribe(
            &vault.scoped_read(key.clone()),
            &FeedSubscribeRequest {
                selector: FeedSelector {
                    sources: vec![source],
                    kinds: Vec::new(),
                    entity_types: Vec::new(),
                    predicates: Vec::new(),
                },
                start,
            },
        )
        .expect("subscribe")
        .subscription
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

/// Untangle slice 6.8b: while nothing follows edges, an edge write leaves no edge feed row, so a
/// subscription made afterwards from the feed's beginning finds none; once one follows, an edge
/// reaches it as it is added and as it is removed.
#[test]
fn an_edge_is_fed_only_while_edges_are_followed() {
    let (_dir, vault) = open();
    let key = owner_key(&vault);
    let (from, to) = (put_person(&vault), put_person(&vault));
    vault
        .put_edge(&from, EdgeKind::Mentions, &to, 0.5)
        .expect("edge before any follower");

    let subscription = follow_from(&vault, &key, FeedSource::Edges, FeedStart::Beginning);
    let page = read(&vault, &key, subscription);
    assert!(
        edge_ops(&page, from, to, "mentions").is_empty(),
        "no follower, no edge feed row: {page:?}"
    );

    vault
        .put_edge(&from, EdgeKind::Supports, &to, 0.5)
        .expect("edge");
    assert!(
        vault
            .delete_edge(&from, EdgeKind::Supports, &to)
            .expect("delete")
    );
    let page = read(&vault, &key, subscription);
    assert_eq!(
        edge_ops(&page, from, to, "supports"),
        vec![FeedOp::EdgeAdded, FeedOp::EdgeRemoved],
        "{page:?}"
    );
}

/// Review #6942: the Blocks door writes its edge rows past the batch's edge seam, and an edges
/// follower still sees a Blocks edge added and removed through it.
#[test]
fn a_blocks_edge_reaches_an_edges_follower_through_its_own_door() {
    let (_dir, vault) = open();
    let key = owner_key(&vault);
    let subscription = follow_from(&vault, &key, FeedSource::Edges, FeedStart::Head);
    let (blocker, blocked) = (put_symbol(&vault), put_symbol(&vault));
    let actor = WriteActor::new(put_person(&vault), EdgeActorClass::Human);
    let context = || BlocksWriteContext {
        actor: &actor,
        source: ClaimSource::UserStated,
    };

    vault
        .insert_blocks_edge(blocker, blocked, context())
        .expect("blocker blocks blocked");
    assert!(
        vault
            .remove_blocks_edge(blocker, blocked, context())
            .expect("unblock")
    );
    let page = read(&vault, &key, subscription);
    assert_eq!(
        edge_ops(&page, blocker, blocked, "blocks"),
        vec![FeedOp::EdgeAdded, FeedOp::EdgeRemoved],
        "{page:?}"
    );
}

/// Lead call K: a cursor in a pruned source left idle past retention gets the typed gap answer,
/// never a page that skips what a prune took. Its ack is refused until the reader resyncs, and
/// after the resync the subscription pages on from its sources' heads.
#[test]
fn a_returning_cursor_past_retention_gets_a_gap_and_resyncs() {
    const T0: u64 = 1_780_000_000;
    let clock = ManualClock::new(T0);
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(
        dir.path(),
        VaultConfig {
            store_clock: clock.bundle(),
            ..VaultConfig::device()
        },
    )
    .expect("open vault");
    let key = owner_slip_for(&vault, [0x47; 32], 4 * FEED_RETENTION_SECS).1;
    let lane = vault.scoped_read(key.clone());
    let subscription = follow_from(&vault, &key, FeedSource::Edges, FeedStart::Head);
    let (from, to) = (put_person(&vault), put_person(&vault));
    vault
        .put_edge(&from, EdgeKind::Supports, &to, 0.5)
        .expect("edge");
    let page = read(&vault, &key, subscription);
    assert_eq!(
        edge_ops(&page, from, to, "supports"),
        vec![FeedOp::EdgeAdded],
        "{page:?}"
    );

    clock.set(T0 + FEED_RETENTION_SECS + 1);
    assert_eq!(
        read_answer(&vault, &key, subscription),
        FeedRead::Gap(FeedGap {
            resync_from: FeedResyncFrom::Snapshot,
        })
    );
    assert!(
        vault
            .feed_ack(
                &lane,
                &FeedAckRequest {
                    subscription,
                    through: page.through,
                },
            )
            .is_err(),
        "no ack moves a cursor past a gap"
    );

    vault.feed_resync(&lane, subscription).expect("resync");
    let resumed = read(&vault, &key, subscription);
    assert!(
        edge_ops(&resumed, from, to, "supports").is_empty(),
        "the resync stands at the head: {resumed:?}"
    );
    assert!(
        vault
            .delete_edge(&from, EdgeKind::Supports, &to)
            .expect("delete")
    );
    let page = read(&vault, &key, subscription);
    assert_eq!(
        edge_ops(&page, from, to, "supports"),
        vec![FeedOp::EdgeRemoved],
        "{page:?}"
    );
}

/// Lead call K: filtering happens at delivery and leaves no trace. A lane that reads nothing gets
/// the same page whether or not entities it may not see changed since its cursor: no entries,
/// no count, one token per source and `more` false. The tokens are opaque and fresh on every
/// read, so a new token is no sign of a change either.
#[test]
fn a_reader_without_the_label_sees_no_sign_that_hidden_entities_changed() {
    let (_dir, vault) = open();
    let owner = owner_key(&vault);
    let subscription = vault
        .feed_subscribe(
            &vault.scoped_read(owner.clone()),
            &changes_from(FeedStart::Head),
        )
        .expect("subscribe")
        .subscription;
    let narrowed =
        ScopedReadActorKey::read_nothing(owner.actor_ref(), "human").expect("narrowed key");

    let quiet = read(&vault, &narrowed, subscription);
    let quiet_again = read(&vault, &narrowed, subscription);
    let hidden = [put_person(&vault), put_person(&vault), put_person(&vault)];
    let busy = read(&vault, &narrowed, subscription);

    for page in [&quiet, &quiet_again, &busy] {
        assert!(page.entries.is_empty(), "{page:?}");
        assert!(!page.more, "{page:?}");
        assert_eq!(page.through.len(), 1, "{page:?}");
        let token = &page.through[0].0;
        assert!(
            token.starts_with("fp1.") && !token.contains("changes"),
            "{token}"
        );
        assert_eq!(token.len(), quiet.through[0].0.len(), "one token length");
        let json = serde_json::to_value(page).expect("page json");
        let mut keys: Vec<&str> = json
            .as_object()
            .expect("a page is an object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["entries", "more", "through"], "no count, no marker");
    }
    assert_ne!(
        quiet.through, quiet_again.through,
        "every read seals afresh, so a new token says nothing"
    );

    let shown = read(&vault, &owner, subscription);
    for person in hidden {
        assert!(
            shown.entries.iter().any(|entry| entry.entity == person),
            "the owner's lane is shown them: {shown:?}"
        );
    }
}

fn put_symbol(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_CODE_SYMBOL,
            TimeRange { start: 1, end: 1 },
            1,
            b"symbol",
        )
        .expect("code symbol");
    id
}
