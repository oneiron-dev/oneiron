//! Change feed subscriptions (untangle slices 6.8a and 6.8b, primitive B), on the public crate surface only:
//! `Vault`, `ScopedReadActorKey` and `oneiron::feeds`. Run with
//! `cargo test -p oneiron --all-features --test feeds`.

use oneiron::authority::HostSlipIssuer;
use oneiron::claim::ScopedReadActorKey;
use oneiron::edge::EdgeKind;
use oneiron::feeds::{
    FeedAckRequest, FeedEntryKind, FeedOp, FeedPage, FeedPosition, FeedReadRequest, FeedSelector,
    FeedSource, FeedStart, FeedSubscribeRequest,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

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
    claims.expires_at = issued_at + 3_600;
    claims.ttl_secs = 3_600;
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
/// as a grant narrowed after the write, is shown no entry, counts it withheld without naming it,
/// and still pages past it.
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
    assert_eq!(page.through.len(), 1, "one source scanned");

    let narrowed =
        ScopedReadActorKey::read_nothing(shown.actor_ref(), "human").expect("narrowed key");
    let page = read(&vault, &narrowed, subscription);
    assert!(page.entries.is_empty(), "{page:?}");
    assert!(page.withheld >= 1, "{page:?}");
    assert_eq!(
        page.through.len(),
        1,
        "the page still moves past what it withheld"
    );
}

/// An ack moves the cursor to a page's `through`, so the next page starts after it; an ack
/// behind the cursor moves nothing; one past the source's head is refused.
#[test]
fn an_ack_moves_the_cursor_forward_only_and_never_past_the_head() {
    let (_dir, vault) = open();
    let key = owner_key(&vault);
    let lane = vault.scoped_read(key.clone());
    let subscription = vault
        .feed_subscribe(&lane, &changes_from(FeedStart::Head))
        .expect("subscribe")
        .subscription;
    put_person(&vault);
    let through = read(&vault, &key, subscription).through;
    assert_eq!(through.len(), 1, "the write is past the cursor");
    let acked = vault
        .feed_ack(
            &lane,
            &FeedAckRequest {
                subscription,
                through: through.clone(),
            },
        )
        .expect("ack");
    assert_eq!(acked.cursors, through);

    let next = read(&vault, &key, subscription);
    assert!(next.entries.is_empty(), "{next:?}");
    assert!(next.through.is_empty(), "nothing after the cursor");

    let behind = FeedPosition(format!("changes:{}", "0".repeat(32)));
    let held = vault
        .feed_ack(
            &lane,
            &FeedAckRequest {
                subscription,
                through: vec![behind],
            },
        )
        .expect("an ack behind the cursor moves nothing");
    assert_eq!(held.cursors, through);

    let past = FeedPosition(format!("changes:{}", "f".repeat(32)));
    assert!(
        vault
            .feed_ack(
                &lane,
                &FeedAckRequest {
                    subscription,
                    through: vec![past],
                },
            )
            .is_err(),
        "an ack past the head is refused"
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
