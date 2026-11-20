//! A reverted derivation batch stands the claim its `supersede` item had
//! replaced again, also when that claim does not reopen in place: a claim the
//! Dreamer signed, and an agent's unsigned `generated` claim at `auto` (lead
//! ruling 21 Nov, INTENT-17 rows 1+2 = A; FIX DERIVE-REVERT-SIGNED-CLAIM,
//! DERIVE-REVERT-GENERATED-CLAIM). Such a claim stands again as a fresh copy
//! under a new id, written as its original author, and the revert's receipt
//! names the copy. A copy the Gate refuses leaves the claim closed and the
//! `supersede` item listed as left.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test derive_revert_replaced_claim`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::claim::{ClaimBody, ClaimSource};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{
    Claim, Committed, Derived, Named, Supersede, commit, commit_claims, define_auto_agent,
    grant_derive_rows,
};
use oneiron::test_doors::steward::dreamer;
use oneiron::test_support::{bind_host_owner, test_host_issuer};
use oneiron::{EdgeActorClass, EntityId, Vault, WriteActor};
use serde_json::json;

const READER: &str = "reader";
const INVERSE_REFUSED: &str = "derive.revert.inverse_refused";
/// The evidence key of a claim's stamped author.
const ACTOR_KEY: &str = "actor_entity_ref";
/// The evidence key of a MACHINE author's signature.
const MACHINE_SIGNATURE_KEY: &str = "machine_signature";

fn put(vault: &Vault, entity_type: u8, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_entity(&id, entity_type, TimeRange { start: at, end: at }, at, body)
        .expect("a row");
    id
}

/// A Dreamer vault with one person and one user TURN to cite.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    dreamer: EntityId,
    person: EntityId,
    turn: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let person = put(&vault, ENTITY_TYPE_PERSON, b"someone");
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "user")]))
        .expect("a TURN body");
    let turn = put(&vault, ENTITY_TYPE_TURN, &body);
    Fixture {
        _dir: dir,
        vault,
        dreamer,
        person,
        turn,
    }
}

impl Fixture {
    fn claim(&self, local: &'static str, predicate: &'static str) -> Claim {
        Claim {
            local,
            predicate,
            subject: Named::Stored(self.person),
            value: json!(local),
            evidence: vec![Named::Stored(self.turn)],
        }
    }

    /// Commits one claim as `actor` of `class`; the claim's id. It stands at
    /// `auto` with the source `generated`.
    fn landed(
        &self,
        actor: EntityId,
        class: EdgeActorClass,
        run: &str,
        local: &'static str,
        predicate: &'static str,
    ) -> EntityId {
        let committed = commit_claims(
            &self.vault,
            actor,
            class,
            run,
            &[self.claim(local, predicate)],
        )
        .expect("the batch commits");
        let [item] = committed.items.as_slice() else {
            panic!("one item: {:?}", committed.items);
        };
        assert!(item.landed, "the claim lands: {:?}", item.reasons);
        assert_eq!(item.approval.as_deref(), Some("auto"), "{item:?}");
        let id = item.rows[0];
        assert_eq!(self.body(id).source, Some(ClaimSource::Generated));
        id
    }

    /// An ordinary agent that lands what it derives at `auto` under its own
    /// `generated` permit.
    fn auto_agent(&self) -> EntityId {
        let agent = define_auto_agent(&self.vault).expect("an Auto agent");
        grant_derive_rows(&self.vault, &[agent]).expect("the agent's policy rows");
        agent
    }

    /// The Dreamer's batch of a `green_tea` claim that supersedes `old`.
    fn dreamer_replaces(&self, old: EntityId) -> (Committed, EntityId) {
        let committed = commit(
            &self.vault,
            self.dreamer,
            EdgeActorClass::System,
            "run-replace",
            &[
                Derived::Claim(self.claim("green_tea", "preference.tea")),
                Derived::Supersede(Supersede {
                    local: "replace_tea",
                    new: Named::Local("green_tea"),
                    old: Named::Stored(old),
                }),
            ],
        )
        .expect("the replacing batch commits");
        assert!(
            committed.items.iter().all(|item| item.landed),
            "{:?}",
            committed.items
        );
        let green_tea = committed.items[0].rows[0];
        assert_eq!(self.lifecycle(old), "superseded");
        assert_eq!(self.lifecycle(green_tea), "active");
        (committed, green_tea)
    }

    fn body(&self, claim: EntityId) -> ClaimBody {
        self.vault
            .get_claim(&claim)
            .expect("read")
            .expect("the claim")
    }

    fn lifecycle(&self, claim: EntityId) -> &'static str {
        self.body(claim).lifecycle.as_str()
    }

    /// The standing claims about the person that a revert wrote as a fresh
    /// copy of `member`.
    fn standing_copies(&self, member: EntityId) -> Vec<EntityId> {
        self.vault
            .claims_for_subject(&self.person)
            .expect("the person's claims")
            .into_iter()
            .filter(|id| {
                let body = self.body(*id);
                body.lifecycle.as_str() == "active" && restores(&body) == Some(member)
            })
            .collect()
    }
}

fn evidence_entry<'a>(body: &'a ClaimBody, key: &str) -> Option<&'a rmpv::Value> {
    let Some(rmpv::Value::Map(fields)) = body.evidence.as_ref() else {
        return None;
    };
    fields
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| value)
}

fn id_of(value: &rmpv::Value) -> Option<EntityId> {
    let rmpv::Value::Binary(bytes) = value else {
        return None;
    };
    EntityId::from_bytes(<[u8; 16]>::try_from(bytes.as_slice()).ok()?).ok()
}

/// The actor the claim's write envelope stamped.
fn author(body: &ClaimBody) -> Option<EntityId> {
    evidence_entry(body, ACTOR_KEY).and_then(id_of)
}

fn signed(body: &ClaimBody) -> bool {
    evidence_entry(body, MACHINE_SIGNATURE_KEY).is_some()
}

/// The member a revert's fresh copy says it restores.
fn restores(body: &ClaimBody) -> Option<EntityId> {
    let rmpv::Value::Map(rows) = evidence_entry(
        body,
        oneiron::write_envelope::WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY,
    )?
    else {
        return None;
    };
    rows.iter()
        .find(|(key, _)| key.as_str() == Some("restores"))
        .and_then(|(_, value)| id_of(value))
}

/// The copy stands as `member` stood: same predicate, value, source, facet,
/// project and author, at `auto`.
fn assert_copy_of(fixture: &Fixture, copy: EntityId, member: EntityId) {
    let (copy, member) = (fixture.body(copy), fixture.body(member));
    assert_eq!(copy.lifecycle.as_str(), "active");
    assert_eq!(copy.approval.as_str(), "auto");
    assert_eq!(copy.predicate, member.predicate);
    assert_eq!(copy.value, member.value);
    assert_eq!(copy.source, member.source);
    assert_eq!(copy.scope_facet, member.scope_facet);
    assert_eq!(copy.scope_project, member.scope_project);
    assert_eq!(author(&copy), author(&member));
    assert_eq!(signed(&copy), signed(&member));
    assert_eq!(member.lifecycle.as_str(), "superseded");
}

#[test]
fn a_reverted_supersession_of_a_claim_the_dreamer_signed_stands_it_again_as_a_fresh_copy() {
    let fixture = fixture();
    let tea = fixture.landed(
        fixture.dreamer,
        EdgeActorClass::System,
        "run-tea",
        "tea",
        "preference.tea",
    );
    assert!(signed(&fixture.body(tea)), "the Dreamer signs its claim");
    let (replacing, green_tea) = fixture.dreamer_replaces(tea);

    let receipt = fixture
        .vault
        .derive_revert(
            WriteActor::new(fixture.dreamer, EdgeActorClass::System),
            None,
            replacing.batch,
        )
        .expect("the Dreamer reverts its own batch");
    assert_eq!(
        receipt.reverted,
        vec!["replace_tea".to_owned(), "green_tea".to_owned()]
    );
    assert!(receipt.left.is_empty(), "{:?}", receipt.left);
    let [(item, replaced, copy)] = receipt.copied.as_slice() else {
        panic!("one fresh copy: {:?}", receipt.copied);
    };
    assert_eq!((item.as_str(), *replaced), ("replace_tea", tea));
    assert_copy_of(&fixture, *copy, tea);
    assert_eq!(author(&fixture.body(*copy)), Some(fixture.dreamer));
    assert_ne!(fixture.lifecycle(green_tea), "active");
    // The claim item's own revert finds the copy and writes no second one.
    assert_eq!(fixture.standing_copies(tea), vec![*copy]);
}

#[test]
fn a_reverted_supersession_of_an_agents_generated_claim_stands_it_again_as_a_fresh_copy() {
    let fixture = fixture();
    let agent = fixture.auto_agent();
    let tea = fixture.landed(
        agent,
        EdgeActorClass::Agent,
        "run-tea",
        "tea",
        "preference.tea",
    );
    let stored = fixture.body(tea);
    assert!(!signed(&stored), "an agent's claim carries no signature");
    assert_eq!(author(&stored), Some(agent));
    let (replacing, green_tea) = fixture.dreamer_replaces(tea);

    let receipt = fixture
        .vault
        .derive_revert(
            WriteActor::new(fixture.dreamer, EdgeActorClass::System),
            None,
            replacing.batch,
        )
        .expect("the Dreamer reverts its own batch");
    assert_eq!(
        receipt.reverted,
        vec!["replace_tea".to_owned(), "green_tea".to_owned()]
    );
    assert!(receipt.left.is_empty(), "{:?}", receipt.left);
    let [(item, replaced, copy)] = receipt.copied.as_slice() else {
        panic!("one fresh copy: {:?}", receipt.copied);
    };
    assert_eq!((item.as_str(), *replaced), ("replace_tea", tea));
    assert_copy_of(&fixture, *copy, tea);
    assert_eq!(author(&fixture.body(*copy)), Some(agent));
    assert_ne!(fixture.lifecycle(green_tea), "active");
    assert_eq!(fixture.standing_copies(tea), vec![*copy]);
}

#[test]
fn a_supersession_by_a_stored_claim_is_taken_back_once() {
    let fixture = fixture();
    let dreamer = WriteActor::new(fixture.dreamer, EdgeActorClass::System);
    let tea = fixture.landed(
        fixture.dreamer,
        EdgeActorClass::System,
        "run-tea",
        "tea",
        "preference.tea",
    );
    let coffee = fixture.landed(
        fixture.dreamer,
        EdgeActorClass::System,
        "run-coffee",
        "coffee",
        "preference.coffee",
    );
    // The replacement is a stored claim: the batch holds no claim item, so
    // only the supersede item's inverse can stand `tea` again.
    let replacing = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-replace-by-stored",
        &[Derived::Supersede(Supersede {
            local: "replace_tea",
            new: Named::Stored(coffee),
            old: Named::Stored(tea),
        })],
    )
    .expect("the supersession commits");
    assert!(replacing.items[0].landed, "{:?}", replacing.items);
    assert_eq!(fixture.lifecycle(tea), "superseded");

    let first = fixture
        .vault
        .derive_revert(dreamer, None, replacing.batch)
        .expect("the first revert");
    assert_eq!(first.reverted, vec!["replace_tea".to_owned()]);
    assert!(first.left.is_empty(), "{:?}", first.left);
    let [(_, replaced, copy)] = first.copied.as_slice() else {
        panic!("one fresh copy: {:?}", first.copied);
    };
    assert_eq!(*replaced, tea);
    assert_copy_of(&fixture, *copy, tea);
    assert_eq!(fixture.lifecycle(coffee), "active");

    // The copy changed no row of the item, so a second revert reaches the
    // item again: it finds the standing copy and leaves the item listed.
    let second = fixture
        .vault
        .derive_revert(dreamer, None, replacing.batch)
        .expect("the second revert");
    assert!(second.reverted.is_empty(), "{:?}", second.reverted);
    assert_eq!(
        second.left,
        vec![("replace_tea".to_owned(), INVERSE_REFUSED.to_owned())]
    );
    assert!(second.copied.is_empty(), "{:?}", second.copied);
    assert_eq!(fixture.standing_copies(tea), vec![*copy]);
}

#[test]
fn a_copy_the_gate_refuses_leaves_the_claim_closed_and_the_item_listed() {
    let fixture = fixture();
    let agent = fixture.auto_agent();
    let tea = fixture.landed(
        agent,
        EdgeActorClass::Agent,
        "run-tea",
        "tea",
        "preference.tea",
    );
    let (replacing, green_tea) = fixture.dreamer_replaces(tea);
    // The owner's policy no longer holds the agent's ceiling and permit.
    grant_derive_rows(&fixture.vault, &[]).expect("the shipped policy alone");

    let receipt = fixture
        .vault
        .derive_revert(
            WriteActor::new(fixture.dreamer, EdgeActorClass::System),
            None,
            replacing.batch,
        )
        .expect("the Dreamer reverts its own batch");
    assert_eq!(receipt.reverted, vec!["green_tea".to_owned()]);
    assert_eq!(
        receipt.left,
        vec![("replace_tea".to_owned(), INVERSE_REFUSED.to_owned())]
    );
    assert!(receipt.copied.is_empty(), "{:?}", receipt.copied);
    assert_eq!(fixture.lifecycle(tea), "superseded");
    assert_ne!(fixture.lifecycle(green_tea), "active");
    assert!(fixture.standing_copies(tea).is_empty());
}

#[test]
fn the_owners_revert_of_a_dreamer_claim_stands_an_agents_generated_claim_again() {
    let fixture = fixture();
    let agent = fixture.auto_agent();
    let tea = fixture.landed(
        agent,
        EdgeActorClass::Agent,
        "run-tea",
        "tea",
        "preference.tea",
    );
    let (_, green_tea) = fixture.dreamer_replaces(tea);
    let owner_id = fixture
        .vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    bind_host_owner(&fixture.vault, &test_host_issuer(), owner_id)
        .expect("the owner's root binding");
    let owner = fixture
        .vault
        .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
        .expect("the owner's proof");

    let receipt = fixture
        .vault
        .memory(owner_id, EdgeActorClass::Human)
        .revert_dreamer_change(&owner, green_tea, fixture.vault.now_recorded_ms())
        .expect("the owner reverts the Dreamer's claim");
    assert_eq!(receipt.reverted.retracted.first(), Some(&green_tea));
    assert!(
        receipt.reverted.left_closed.is_empty(),
        "{:?}",
        receipt.reverted.left_closed
    );
    let [(replaced, copy)] = receipt.reverted.copied.as_slice() else {
        panic!("one fresh copy: {:?}", receipt.reverted.copied);
    };
    assert_eq!(*replaced, tea);
    assert_copy_of(&fixture, *copy, tea);
    assert_eq!(author(&fixture.body(*copy)), Some(agent));
    assert_eq!(fixture.standing_copies(tea), vec![*copy]);
}
