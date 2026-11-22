//! A federation selector window carries no stamped claim to a member homed
//! elsewhere (L5-02 PR 4, RULING SECREAD-HOME-SELECTOR-EXPORT = A), public
//! API and test doors only.
//!
//! The vault holds four claims about one PERSON: one unstamped, one stamped
//! `sensitivity: public`, one `private`, one `sensitive`. A member P holds a
//! live Member federation grant whose Scope admits every record, and a
//! `core:read` policy grant. P is neither an Owner (vault owner, or a member
//! on an Owner-role grant) nor one of the vault's own agents, so the export
//! withholds the `private` and `sensitive` claims from P's selector window
//! while the unstamped and `public` claims still ride it. Before the fix the
//! stamped claims rode it too.
//!
//! Two over-refusal guards pin the other side: a co-Owner's window, and the
//! window of a member that is one of the vault's own agents, carry all four.
//!
//! Each `FIXTURE:` assertion checks the setup, never the leak. The `LEAK:`
//! assertions come last.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test selector_home_clearance`.
// `put_selector_test_federation_grant` exists only under `test-hooks`.
#![cfg(all(oneiron_test_support, feature = "test-hooks"))]

use std::collections::BTreeSet;

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::window::reverse_rematerialize;
use oneiron::sync::{
    SyncSelector, SyncSelectorWorld, WindowKey, authorize_sync_selector, filtered_window_doc,
    put_selector_test_federation_grant,
};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::open_member_vault;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    Vault, VaultConfig,
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
/// stamped `sensitivity` when a band is named: `seed_claim` from
/// `home_clearance_scoped_read.rs:77` without its text indexing, which window
/// packing does not read.
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

/// An inert custom agent definition, as `agent_definition_person_in_txn.rs`
/// writes one: `Vault::put_agent_definition` stores it as a live AGENT_DEF
/// row, which reads as one of the vault's own agents.
fn agent_definition(agent_id: &str) -> AgentDefinition {
    AgentDefinition::new(
        agent_id,
        "selector home clearance fixture",
        "1",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::Base,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Value::Map(vec![("definedVia".into(), "define_agent".into())]),
        None,
        true,
        None,
    )
}

/// The four claims one selector export planted, and the ids its window carried.
struct Export {
    unstamped: EntityId,
    public: EntityId,
    private_claim: EntityId,
    sensitive_claim: EntityId,
    carried: BTreeSet<EntityId>,
}

/// Plants the four claims, gives the member a live federation grant of `role`
/// whose Scope admits every record, and exports the packed window through its
/// selector. With `own_agent`, the member is one of the vault's own agents (a
/// live AGENT_DEF row) instead of a PERSON outside them.
fn export_through(
    role: FederationGrantRole,
    preset: FederationGrantPreset,
    own_agent: bool,
) -> Export {
    let dir = tempfile::tempdir().expect("tempdir");
    let member = EntityId::now();
    let vault = open_member_vault(dir.path(), VaultConfig::device(), &[member.to_hex()])
        .expect("fixture vault");
    // Every row is learned now, so all of them pack into one window.
    let now = vault.now_recorded_at();
    let person_body =
        rmp_serde::to_vec_named(&serde_json::json!({ "name": "member" })).expect("body");
    if own_agent {
        vault
            .put_agent_definition(
                &member,
                &agent_definition("home.clearance.agent"),
                at(now),
                now,
            )
            .expect("the member's own-agent definition");
        assert!(
            vault.is_vault_agent(&member).expect("own-agent read"),
            "FIXTURE: the member is one of the vault's own agents"
        );
    } else {
        vault
            .put_entity(&member, ENTITY_TYPE_PERSON, at(now), now, &person_body)
            .expect("a member PERSON");
    }
    // The claims' subject: `put_claim` refuses a subject that does not exist.
    let subject = EntityId::now();
    vault
        .put_entity(&subject, ENTITY_TYPE_PERSON, at(now), now, &person_body)
        .expect("the claims' subject");

    let scope = FederationGrantScope::vault(SHARED_VAULT_ID);
    let grant_id = EntityId::now();
    let mut grant = FederationGrant::new(scope, member, role, preset);
    // Every test exports under the same Scope, so the role (and, for the
    // agent, the member) is the only difference between them.
    grant.authority_scope = read_preset();
    put_selector_test_federation_grant(&vault, &grant_id, &grant, now)
        .expect("the member's federation grant");
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    authorize_sync_selector(&vault, scope, &selector)
        .expect("FIXTURE: the member's selector is authorized");

    let unstamped = seed_claim(&vault, subject, "an unstamped note", None, now);
    let public = seed_claim(&vault, subject, "a public note", Some("public"), now);
    let private_claim = seed_claim(&vault, subject, "a private note", Some("private"), now);
    let sensitive_claim = seed_claim(&vault, subject, "a sensitive note", Some("sensitive"), now);

    let key = WindowKey::from_timestamp(now);
    let source = create_window_doc("selector", &key);
    reverse_rematerialize(&vault, &source, &key).expect("the window pack");
    for id in [unstamped, public, private_claim, sensitive_claim] {
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
    assert!(
        carried.contains(&unstamped),
        "FIXTURE: the selector window carries the unstamped claim"
    );
    Export {
        unstamped,
        public,
        private_claim,
        sensitive_claim,
        carried,
    }
}

#[test]
fn a_members_selector_window_carries_no_stamped_claim() {
    let export = export_through(
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
        false,
    );
    let Export {
        public,
        private_claim,
        sensitive_claim,
        carried,
        ..
    } = export;
    assert!(
        carried.contains(&public),
        "the selector window carries the public-stamped claim (control)"
    );
    let leaked: Vec<&str> = [(private_claim, "private"), (sensitive_claim, "sensitive")]
        .into_iter()
        .filter(|(id, _)| carried.contains(id))
        .map(|(_, band)| band)
        .collect();
    assert!(
        leaked.is_empty(),
        "LEAK: the selector window carries the {leaked:?}-stamped claims to a Member homed elsewhere"
    );
}

#[test]
fn a_co_owners_selector_window_carries_every_claim() {
    let export = export_through(
        FederationGrantRole::Owner,
        FederationGrantPreset::Owner,
        false,
    );
    let Export {
        unstamped,
        public,
        private_claim,
        sensitive_claim,
        carried,
    } = export;
    let withheld: Vec<&str> = [
        (unstamped, "unstamped"),
        (public, "public"),
        (private_claim, "private"),
        (sensitive_claim, "sensitive"),
    ]
    .into_iter()
    .filter(|(id, _)| !carried.contains(id))
    .map(|(_, band)| band)
    .collect();
    assert!(
        withheld.is_empty(),
        "OVER-REFUSAL: the selector window withholds the {withheld:?} claims from a co-Owner"
    );
}

#[test]
fn an_own_agents_selector_window_carries_every_claim() {
    let export = export_through(
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
        true,
    );
    let Export {
        unstamped,
        public,
        private_claim,
        sensitive_claim,
        carried,
    } = export;
    let withheld: Vec<&str> = [
        (unstamped, "unstamped"),
        (public, "public"),
        (private_claim, "private"),
        (sensitive_claim, "sensitive"),
    ]
    .into_iter()
    .filter(|(id, _)| !carried.contains(id))
    .map(|(_, band)| band)
    .collect();
    assert!(
        withheld.is_empty(),
        "OVER-REFUSAL: the selector window withholds the {withheld:?} claims from an own agent"
    );
}
