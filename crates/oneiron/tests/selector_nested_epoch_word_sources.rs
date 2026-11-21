//! A federation selector window follows an epoch summary's words to every
//! depth (L5-02 PR 4, FIX-LIST [SELECTOR-NESTED-WORD-SOURCES-TEST]), public
//! API and test doors only.
//!
//! An epoch summary's words are those of every row it was written from, its
//! `DerivedFrom` targets, and a nested epoch summary among them carries the
//! words of its own sources in turn. The vault holds a `private`-stamped
//! CLAIM, an epoch summary S1 written from it, and an epoch summary S2
//! written from S1 alone. A member P holds a live Member federation grant
//! whose Scope admits every record, and P is neither an Owner nor one of the
//! vault's own agents, so P reads no stamped claim (selector home clearance).
//! The member gate judged only S2's direct source, S1, which is unstamped,
//! so S2 rode P's window with the private claim's words. It now walks every
//! source to every depth and withholds S2 (fix: `member_reads_word_sources`
//! in `sync/selector/authorize/filter.rs`). The LEAK assertion is red at
//! 7c32447038d0 and green at 09478ca1e464.
//!
//! Two over-refusal guards pin the other side: the same two-level chain over
//! an unstamped claim rides P's window, and a co-Owner's window carries every
//! row.
//!
//! The epoch summaries are stored SUMMARY rows in the pinned epoch codec,
//! with their `DerivedFrom` edges, written through the public put: no
//! compaction run, no model. Each `FIXTURE:` assertion checks the setup,
//! never the leak. The `LEAK:` assertion comes last.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test selector_nested_epoch_word_sources`.
// `put_selector_test_federation_grant` exists only under `test-hooks`.
#![cfg(all(oneiron_test_support, feature = "test-hooks"))]

use std::collections::BTreeSet;

use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SUMMARY};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::window::reverse_rematerialize;
use oneiron::sync::{
    SyncSelector, SyncSelectorWorld, WindowKey, authorize_sync_selector, filtered_window_doc,
    put_selector_test_federation_grant,
};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::open_member_vault;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EPOCH_SUMMARY_BODY_KEYS, EPOCH_SUMMARY_BODY_VERSION, EPOCH_SUMMARY_LEVEL, EdgeKind, EntityId,
    Vault, VaultConfig, decode_epoch_summary_body,
};
use oneiron_authority::federation::scope_codec::read_preset;
use rmpv::Value;

/// The shared vault the federation grant names.
const SHARED_VAULT_ID: u64 = 7;

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

/// One stated CLAIM about `subject` holding `text` and learned at `now`,
/// stamped `sensitivity` when a band is named, as
/// `selector_home_clearance.rs` seeds one.
fn seed_claim(
    vault: &Vault,
    subject: EntityId,
    text: &str,
    sensitivity: Option<&str>,
    now: u64,
) -> EntityId {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        Value::from(text),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    body.source = Some(ClaimSource::UserStated);
    if let Some(band) = sensitivity {
        body.scope = Some(Value::Map(vec![(
            Value::from("sensitivity"),
            Value::from(band),
        )]));
    }
    vault.put_claim(&id, &body, at(now), now).expect("a record");
    id
}

/// One epoch summary of `session`'s log, epoch `epoch`, holding `text` and
/// learned at `now`, written from `sources`: a SUMMARY row in the pinned
/// epoch codec (its keys in `EPOCH_SUMMARY_BODY_KEYS` order) with one
/// `DerivedFrom` edge to each source, as a compaction run lands one.
fn put_epoch(
    vault: &Vault,
    session: EntityId,
    epoch: u64,
    text: &str,
    sources: &[EntityId],
    now: u64,
) -> EntityId {
    let id = EntityId::now();
    let values = [
        Value::from(EPOCH_SUMMARY_BODY_VERSION),
        Value::from(session.to_hex()),
        Value::Nil,
        Value::from(epoch),
        Value::from(1_u64),
        Value::from(1_u64),
        Value::from(EPOCH_SUMMARY_LEVEL),
        Value::from(text),
        Value::from(EntityId::now().to_hex()),
    ];
    let body = Value::Map(
        EPOCH_SUMMARY_BODY_KEYS
            .iter()
            .map(|key| Value::from(*key))
            .zip(values)
            .collect(),
    );
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body).expect("an epoch summary body");
    let decoded = decode_epoch_summary_body(&bytes)
        .expect("FIXTURE: the body decodes under the strict epoch codec");
    assert_eq!(decoded.epoch, epoch, "FIXTURE: the body is epoch {epoch}");
    vault
        .put_entity(&id, ENTITY_TYPE_SUMMARY, at(now), now, &bytes)
        .expect("an epoch summary");
    for source in sources {
        vault
            .put_edge(&id, EdgeKind::DerivedFrom, source, 1.0)
            .expect("the epoch's DerivedFrom edge");
    }
    id
}

/// The rows one export planted, and the ids its window carried.
struct Export {
    /// The `private`-stamped claim, S1 written from it, and S2 from S1.
    private_claim: EntityId,
    private_inner: EntityId,
    private_outer: EntityId,
    /// The same chain over an unstamped claim.
    open_claim: EntityId,
    open_inner: EntityId,
    open_outer: EntityId,
    carried: BTreeSet<EntityId>,
}

/// Plants both chains, gives the member a live federation grant of `role`
/// whose Scope admits every record, and exports the packed window through
/// its selector.
fn export_through(role: FederationGrantRole, preset: FederationGrantPreset) -> Export {
    let dir = tempfile::tempdir().expect("tempdir");
    let member = EntityId::now();
    let vault = open_member_vault(dir.path(), VaultConfig::device(), &[member.to_hex()])
        .expect("fixture vault");
    // Every row is learned now, so all of them pack into one window.
    let now = vault.now_recorded_at();
    let person_body =
        rmp_serde::to_vec_named(&serde_json::json!({ "name": "member" })).expect("body");
    vault
        .put_entity(&member, ENTITY_TYPE_PERSON, at(now), now, &person_body)
        .expect("a member PERSON");
    // The claims' subject: `put_claim` refuses a subject that does not exist.
    let subject = EntityId::now();
    vault
        .put_entity(&subject, ENTITY_TYPE_PERSON, at(now), now, &person_body)
        .expect("the claims' subject");

    let scope = FederationGrantScope::vault(SHARED_VAULT_ID);
    let grant_id = EntityId::now();
    let mut grant = FederationGrant::new(scope, member, role, preset);
    grant.authority_scope = read_preset();
    put_selector_test_federation_grant(&vault, &grant_id, &grant, now)
        .expect("the member's federation grant");
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    authorize_sync_selector(&vault, scope, &selector)
        .expect("FIXTURE: the member's selector is authorized");

    let private_claim = seed_claim(&vault, subject, "a private note", Some("private"), now);
    let private_session = EntityId::now();
    let private_inner = put_epoch(
        &vault,
        private_session,
        1,
        "the first epoch retells a private note",
        &[private_claim],
        now,
    );
    let private_outer = put_epoch(
        &vault,
        private_session,
        2,
        "the second epoch retells the first",
        &[private_inner],
        now,
    );
    let open_claim = seed_claim(&vault, subject, "an unstamped note", None, now);
    let open_session = EntityId::now();
    let open_inner = put_epoch(
        &vault,
        open_session,
        1,
        "the first epoch retells an unstamped note",
        &[open_claim],
        now,
    );
    let open_outer = put_epoch(
        &vault,
        open_session,
        2,
        "the second epoch retells the first",
        &[open_inner],
        now,
    );
    let planted = [
        private_claim,
        private_inner,
        private_outer,
        open_claim,
        open_inner,
        open_outer,
    ];
    // A row with no birth stamp rides no selector window at all, which
    // would make the LEAK assertion vacuous.
    for id in planted {
        assert!(
            vault
                .record_scope(&id)
                .expect("record scope read")
                .is_some(),
            "FIXTURE: {} holds its birth stamp",
            id.to_hex()
        );
    }

    let key = WindowKey::from_timestamp(now);
    let source = create_window_doc("selector", &key);
    reverse_rematerialize(&vault, &source, &key).expect("the window pack");
    for id in planted {
        assert!(
            source.get_map("entities").get(&id.to_hex()).is_some(),
            "FIXTURE: the packed window holds {}",
            id.to_hex()
        );
    }
    let selected = filtered_window_doc(&vault, &source, &key, scope, &selector)
        .expect("the member's selector window");
    let mut carried = BTreeSet::new();
    selected.get_map("entities").for_each(|key, _| {
        carried.insert(EntityId::from_hex(key).expect("an entity key"));
    });
    Export {
        private_claim,
        private_inner,
        private_outer,
        open_claim,
        open_inner,
        open_outer,
        carried,
    }
}

#[test]
fn a_members_window_withholds_an_epoch_over_an_epoch_over_a_private_claim() {
    let Export {
        private_claim,
        private_inner,
        private_outer,
        open_claim,
        open_inner,
        open_outer,
        carried,
    } = export_through(FederationGrantRole::Member, FederationGrantPreset::Member);
    // The unstamped chain rides at both depths: an epoch summary rides the
    // window at all, and the walk refuses no clean source (OVER-REFUSAL).
    let withheld: Vec<&str> = [
        (open_claim, "unstamped claim"),
        (open_inner, "epoch over it"),
        (open_outer, "epoch over that epoch"),
    ]
    .into_iter()
    .filter(|(id, _)| !carried.contains(id))
    .map(|(_, row)| row)
    .collect();
    assert!(
        withheld.is_empty(),
        "OVER-REFUSAL: the Member's selector window withholds the unstamped chain's {withheld:?}"
    );
    // The private claim and the epoch written from it directly stay home
    // (the home clearance and the one-level word-source gate, both on the
    // base already).
    assert!(
        !carried.contains(&private_claim),
        "FIXTURE: the Member's selector window withholds the private-stamped claim"
    );
    assert!(
        !carried.contains(&private_inner),
        "FIXTURE: the Member's selector window withholds the epoch written from the private claim"
    );
    assert!(
        !carried.contains(&private_outer),
        "LEAK: the Member's selector window carries an epoch summary written from an epoch \
         summary of a private-stamped claim to a Member homed elsewhere"
    );
}

#[test]
fn a_co_owners_window_carries_both_nested_chains() {
    let Export {
        private_claim,
        private_inner,
        private_outer,
        open_claim,
        open_inner,
        open_outer,
        carried,
    } = export_through(FederationGrantRole::Owner, FederationGrantPreset::Owner);
    let withheld: Vec<&str> = [
        (private_claim, "private claim"),
        (private_inner, "epoch over the private claim"),
        (private_outer, "epoch over that epoch"),
        (open_claim, "unstamped claim"),
        (open_inner, "epoch over the unstamped claim"),
        (open_outer, "epoch over that epoch"),
    ]
    .into_iter()
    .filter(|(id, _)| !carried.contains(id))
    .map(|(_, row)| row)
    .collect();
    assert!(
        withheld.is_empty(),
        "OVER-REFUSAL: the selector window withholds the {withheld:?} from a co-Owner"
    );
}
