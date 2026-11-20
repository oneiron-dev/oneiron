// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The Engine's RULING RESTRICTION-CLOSE-BY-DERIVE-ARCHIVE-TOPOLOGY = B
//! (15 Nov 21:30): the two derive items left that close a claim restricting
//! someone's access, by no person, are refused at the item with their own
//! reason token, and the restricting claim stands (canon #widen-world-floor:
//! lifting a restriction is a widening, which asks a person).
//! - An Archive item under a strength attempt (the Dreamer's, or an agent's
//!   with the Steward `archive` verb) never archives a restricting claim.
//! - An applied Facet item under an agent's `topology_seal` Grant never
//!   forks a restricting claim: the fork would supersede it.
//!
//! The guards show the cut is narrow: the same items over a note still land.
//! The restricting claim is a `delivery_window.context` row about one PERSON;
//! the manifest declares the window normal, so it carries no critical
//! confirm and whether it restricts reads its predicate alone. The vault is
//! rooted under the test host (the owner's native Grant needs a rooted
//! vault, and `test_doors::derive::grant_topology_seal` enrols its install
//! under that host).
//!
//! The tokens are spelled out so this file also builds on the red tree,
//! which lacks them.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --no-fail-fast --test derive_archive_topology_restriction`.
#![cfg(oneiron_test_support)]

use oneiron::agent_def::AgentCeiling;
use oneiron::attempt_queue::AttemptId;
use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::derive::{
    DerivationBatch, DerivationItem, DerivationStamp, DerivedTopology, ItemOutcome,
};
use oneiron::identity_topology::{
    FacetOp, FacetSpec, IdentityOpEvidence, IdentityTopologyOp, ReassignmentEntry, ReassignmentMap,
    ReassignmentTarget,
};
use oneiron::memory::{ClaimInput, resolve_entity_ref};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::derive::{
    Archive, Claim, Derived, Named, commit_claims, commit_in_attempt, grant_derive_rows,
    grant_topology_seal, row_live,
};
use oneiron::test_doors::steward::{archive_every_quiet_claim, record_strength_observations};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, SourceLineage, TimeRange, Vault, VaultConfig, WriteActor,
};
use rmpv::Value;
use serde_json::json;

const LEARNED_AT: u64 = 1_780_000_000;

/// The test host's root secret (`oneiron::test_support::test_host_issuer`).
/// `grant_topology_seal` enrols the install under that host, so the vault is
/// rooted under it too.
const TEST_HOST_SECRET: &[u8] = b"oneiron unit test host root";

/// A delivery window: it holds interrupts while its condition holds.
const DELIVERY_WINDOW_CONTEXT: &str = "delivery_window.context";

/// A row that restricts no one. The shipped manifest rates `profile.` normal.
const NOTE: &str = "profile.note";

/// The refusal of an archive over a restricting claim
/// (`oneiron::derive::ARCHIVE_RESTRICTION`).
const ARCHIVE_RESTRICTION: &str = "gate.deny.derive.archive_restriction";

/// The refusal of an applied facet whose fork would close a restricting
/// claim (`oneiron::derive::TOPOLOGY_RESTRICTION`).
const TOPOLOGY_RESTRICTION: &str = "gate.deny.derive.topology_restriction";

struct Fixture {
    vault: Vault,
    /// An agent with an Auto ceiling and the derive landing and read rows.
    agent: EntityId,
    /// The PERSON the claims are about.
    subject: EntityId,
    facet: EntityId,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
        vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("load this install's signing keys");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        let issuer = HostSlipIssuer::from_secret(TEST_HOST_SECRET).expect("the test host issuer");
        vault
            .ensure_host_root_slip(&issuer)
            .expect("the host root binds the owner");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's profile");
        // The Dreamer signs its derived claims as a MACHINE; an unsigned
        // MACHINE write is refused.
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("the engine's machine signers");
        let agent = vault
            .ensure_agent_principal("archive-topology-agent")
            .expect("agent");
        // Before the window rule: this door rewrites the manifest from the
        // shipped default, and the rule is added to the live manifest.
        grant_derive_rows(&vault, &[agent]).expect("the agent's landing and read rows");
        let facet = vault.default_facet().expect("default facet");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        vault
            .grant_agent_principal(&owner_proof, &agent.to_hex(), AgentCeiling::Auto)
            .expect("the owner grants the agent read and an Auto ceiling");
        declare_delivery_window_normal(&vault, &owner_proof);
        Self {
            subject: person(&vault),
            vault,
            agent,
            facet,
            _directory: directory,
        }
    }

    /// The Dreamer, the actor of the archive batches below.
    fn dreamer(&self) -> WriteActor {
        self.vault.dreamer_authority().expect("the Dreamer")
    }

    /// The Dreamer's derived `predicate` about the subject holding `value`,
    /// citing a fresh TURN, landed at Auto. Returns the claim's row.
    fn derived_claim(&self, predicate: &'static str, value: serde_json::Value) -> EntityId {
        let dreamer = self.dreamer();
        let committed = commit_claims(
            &self.vault,
            dreamer.entity_ref(),
            dreamer.actor_class(),
            "run-derived-claim",
            &[Claim {
                local: "derived",
                predicate,
                subject: Named::Stored(self.subject),
                value,
                evidence: vec![Named::Stored(turn(&self.vault))],
            }],
        )
        .expect("the batch commits");
        let [item] = committed.items.as_slice() else {
            panic!("one item: {:?}", committed.items);
        };
        assert!(item.landed, "the derived claim lands: {item:?}");
        assert_eq!(item.approval.as_deref(), Some("auto"), "at Auto: {item:?}");
        item.rows[0]
    }

    /// The agent's observed upsert of `predicate` about the subject holding
    /// `value`: an Observed head at Auto. Returns the claim's row.
    fn observed_head(&self, predicate: &str, value: serde_json::Value) -> EntityId {
        let input = ClaimInput {
            id: None,
            predicate: predicate.to_owned(),
            subject_ref: self.subject.to_hex(),
            value,
            confidence: 1.0,
            confidence_details: None,
            source: "observed".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: Some(json!({ "facet": self.facet.to_hex() })),
            valid_from: Some(100),
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
        };
        let receipt = self
            .vault
            .memory(self.agent, EdgeActorClass::Agent)
            .claim_upsert(&input)
            .unwrap_or_else(|error| panic!("the {predicate} write: {error:?}"));
        assert_eq!(receipt.approval, "auto", "the {predicate} head lands");
        resolve_entity_ref(&self.vault, &receipt.claim_short_id).expect("the claim's id")
    }

    /// The Dreamer's Archive item over `claim` in a strength attempt: whether
    /// it landed, and its reasons.
    fn dreamer_archives(&self, claim: EntityId) -> (bool, Vec<String>) {
        let dreamer = self.dreamer();
        let committed = commit_in_attempt(
            &self.vault,
            dreamer.entity_ref(),
            dreamer.actor_class(),
            "run-archive",
            Some(AttemptId::now()),
            &[Derived::Archive(Archive {
                local: "archive",
                claim: Named::Stored(claim),
                score: 0.1,
            })],
        )
        .expect("the batch commits");
        let [item] = committed.items.as_slice() else {
            panic!("one item: {:?}", committed.items);
        };
        (item.landed, item.reasons.clone())
    }

    /// The agent's applied Facet item assigning `head` to one new facet of
    /// the subject, under its own `topology_seal` Grant: whether it landed,
    /// and its reasons. The Grant door swaps the device keystore, so it runs
    /// after every owner act.
    fn agent_facets(&self, head: EntityId) -> (bool, Vec<String>) {
        let grant = grant_topology_seal(&self.vault, self.agent).expect("the agent's grant");
        let op = IdentityTopologyOp::Facet(FacetOp {
            entity: self.subject,
            facets: vec![FacetSpec {
                label: "facet-a".to_owned(),
            }],
            reassignment: ReassignmentMap {
                entries: vec![ReassignmentEntry {
                    item: ClaimSubject::Entity(head),
                    target: ReassignmentTarget::Facet { index: 0 },
                }],
            },
            evidence: IdentityOpEvidence {
                refs: Vec::new(),
                rationale: "a fixture facet".to_owned(),
            },
        });
        let stamp = DerivationStamp {
            actor: WriteActor::new(self.agent, EdgeActorClass::Agent),
            run: Some("run-topology-facet".to_owned()),
            attempt: None,
            lineage: SourceLineage::of(ClaimSource::Generated),
        };
        let batch = DerivationBatch {
            items: vec![DerivationItem::Topology(DerivedTopology {
                local: "facet".to_owned(),
                op,
                grant,
                apply: true,
            })],
            sources: Vec::new(),
        };
        let receipt = self
            .vault
            .derive_commit(&stamp, &batch)
            .expect("the batch commits");
        let [item] = receipt.items.as_slice() else {
            panic!("one item: {:?}", receipt.items);
        };
        match &item.outcome {
            ItemOutcome::Landed { .. } => (true, Vec::new()),
            ItemOutcome::Refused { reasons, .. } => (false, reasons.clone()),
        }
    }

    /// The claim stored at `id`.
    fn stored(&self, id: EntityId) -> ClaimBody {
        self.vault
            .get_claim(&id)
            .expect("claim read")
            .expect("the row stands")
    }

    /// Observes `claim` with one user-stated `independent` source about the
    /// subject, then makes every claim quiet and weak under the strength
    /// policy, and lets the vault's second-grained clock pass the policy's
    /// 1 ms window (as `tests/derive_archive_pins.rs` and
    /// `tests/derive_archive.rs` do).
    fn quiet(&self, claim: EntityId, independent: &str) {
        let latest = self.vault.now_recorded_at().saturating_add(1);
        let mut body = ClaimBody::new(
            independent,
            ClaimSubject::Entity(self.subject),
            Value::from("yuki"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
        .expect("an independent body");
        body.source = Some(ClaimSource::UserStated);
        let source = EntityId::now();
        self.vault
            .put_claim(
                &source,
                &body,
                TimeRange {
                    start: latest,
                    end: latest,
                },
                latest,
            )
            .expect("the independent source lands");
        record_strength_observations(&self.vault, claim, &[source], latest.saturating_mul(1_000))
            .expect("the observation lands");
        archive_every_quiet_claim(&self.vault).expect("strength policy");
        std::thread::sleep(std::time::Duration::from_millis(2_100));
    }
}

/// Installs the shipped manifest plus one rule: `delivery_window.context` is
/// normal, as `tests/conflict_settle_restriction.rs` declares it.
fn declare_delivery_window_normal(vault: &Vault, owner_proof: &AuthenticatedOwner) {
    let id = oneiron_store::policy_record::default_policy_manifest_id()
        .expect("default policy manifest id");
    let body = vault
        .get(&id)
        .expect("read default policy manifest")
        .expect("default policy manifest exists");
    let Value::Map(mut fields) =
        rmpv::decode::read_value(&mut body.as_slice()).expect("decode default policy manifest")
    else {
        panic!("default policy manifest is a map");
    };
    let (_, Value::Array(rules)) = fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("rules"))
        .expect("default policy rules")
    else {
        panic!("default policy rules are an array");
    };
    rules.push(Value::Map(vec![
        (Value::from("prefix"), Value::from(DELIVERY_WINDOW_CONTEXT)),
        (Value::from("exact"), Value::Boolean(true)),
        (
            Value::from("axes"),
            Value::Map(vec![
                (Value::from("criticality"), Value::from("normal")),
                (Value::from("sensitivity"), Value::from("normal")),
            ]),
        ),
    ]));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(fields))
        .expect("encode delivery window policy");
    vault
        .install_owner_policy_manifest(owner_proof, id, bytes, vault.now_recorded_at())
        .expect("declare the delivery window normal");
}

/// A TURN, the evidence a derived claim cites, as `tests/derive_revert.rs`
/// puts one.
fn turn(vault: &Vault) -> EntityId {
    let at = vault.now_recorded_at();
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "user")]))
        .expect("a TURN body");
    let turn = EntityId::now();
    vault
        .put_entity(
            &turn,
            ENTITY_TYPE_TURN,
            TimeRange { start: at, end: at },
            at,
            &body,
        )
        .expect("a TURN");
    turn
}

/// A live PERSON.
fn person(vault: &Vault) -> EntityId {
    let person = EntityId::now();
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            LEARNED_AT,
            b"human",
        )
        .expect("a live person");
    person
}

/// A delivery window value, as JSON, that holds interrupts `when`.
fn window_json(when: &str) -> serde_json::Value {
    json!({ "schema_version": 1, "applies_to": "interrupt", "when": when })
}

#[test]
fn a_derive_archive_never_archives_a_delivery_window() {
    let fixture = Fixture::new();
    let window = fixture.derived_claim(DELIVERY_WINDOW_CONTEXT, window_json("asleep"));
    fixture.quiet(window, "profile.hobby");
    let (landed, reasons) = fixture.dreamer_archives(window);
    assert!(!landed, "the archive item is refused: {reasons:?}");
    assert_eq!(reasons, vec![ARCHIVE_RESTRICTION.to_owned()]);
    assert!(
        row_live(&fixture.vault, window).expect("read"),
        "the restricting window stays live"
    );
    assert_eq!(
        fixture.stored(window).lifecycle,
        ClaimLifecycleStatus::Active
    );
}

#[test]
fn a_derive_archive_still_archives_a_note() {
    let fixture = Fixture::new();
    let note = fixture.derived_claim(NOTE, json!("the first note"));
    fixture.quiet(note, "profile.hobby");
    let (landed, reasons) = fixture.dreamer_archives(note);
    assert!(landed, "the archive item lands: {reasons:?}");
    assert!(
        !row_live(&fixture.vault, note).expect("read"),
        "the note is archived"
    );
}

#[test]
fn a_derive_facet_never_forks_a_delivery_window() {
    let fixture = Fixture::new();
    let window = fixture.observed_head(DELIVERY_WINDOW_CONTEXT, window_json("asleep"));
    let (landed, reasons) = fixture.agent_facets(window);
    assert!(!landed, "the facet item is refused: {reasons:?}");
    assert_eq!(reasons, vec![TOPOLOGY_RESTRICTION.to_owned()]);
    assert_eq!(
        fixture.stored(window).lifecycle,
        ClaimLifecycleStatus::Active,
        "the restricting window still holds"
    );
}

#[test]
fn a_derive_facet_still_forks_a_note() {
    let fixture = Fixture::new();
    let note = fixture.observed_head(NOTE, json!("the first note"));
    let (landed, reasons) = fixture.agent_facets(note);
    assert!(landed, "the facet item lands: {reasons:?}");
    assert_eq!(
        fixture.stored(note).lifecycle,
        ClaimLifecycleStatus::Superseded,
        "the fork closes the note"
    );
}
