//! Restriction wave 9b, census C33: the owner's Setting key
//! `lens.slot.agent_select` lets a named agent select a proposed lens
//! revision for its pack slot, or clear the slot
//! (`vault.lenses.activate_as`, `vault.lenses.deactivate_as`). Each door
//! admits the agent only under its own live Grant listing the verb and the
//! key read true for it; an agent never selects a revision its own lineage
//! proposed, whatever the key says. With the key off the slot stays the
//! owner's, and the owner's own doors answer as before.
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test lens_slot_agent_select`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, AgentTier, MachineRole};
use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeId};
use oneiron::lens::{
    CollectionAtom, GeneratedLens, LensActivateRequest, LensAtom, LensAtomId, LensNode,
    LensProposeRequest, LensSlot, LensText,
};
use oneiron::memory::{Memory, MemoryError};
use oneiron::store::{GateDecisionId, GateDecisionRecord};
use oneiron::task_verb::sdk::invoke;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const KEY: &str = "lens.slot.agent_select";
const ACTIVATE_AS: &str = "vault.lenses.activate_as";
const DEACTIVATE_AS: &str = "vault.lenses.deactivate_as";
const SET: &str = "vault.settings.set";
/// The first-party weave lens pack and its lens, as the vault seeds them at
/// open (`WEAVE_LENS_PACK_NAME`, `WEAVE_REPORT_LENS`).
const WEAVE_PACK: &str = "oneiron.weave";
const WEAVE_LENS: &str = "weave-report";

/// The vault clock's fixed time for every test here: no wall time, no sleeps.
const T0: u64 = 1_780_000_000;

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
}

/// A rooted vault with its install enrolled and its embedded owner.
fn rooted_vault() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = ManualClock::new(T0);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("open vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
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
    Fixture {
        vault,
        _dir: dir,
        owner,
    }
}

fn owner_proof(fixture: &Fixture) -> AuthenticatedOwner {
    fixture
        .vault
        .authenticate_owner(
            fixture.owner,
            &fixture.owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof")
}

fn owner_memory(fixture: &Fixture) -> Memory<'_> {
    fixture.vault.memory(fixture.owner, EdgeActorClass::Human)
}

fn agent_memory(fixture: &Fixture, agent: EntityId) -> Memory<'_> {
    fixture.vault.memory(agent, EdgeActorClass::Agent)
}

/// `name`'s agent definition with an owner Grant of base reach, listing the
/// full-access tier's verbs and `extra`.
fn granted_agent(fixture: &Fixture, name: &str, extra: &[&str]) -> EntityId {
    let agent = define_agent(&fixture.vault, name).expect("agent");
    grant_extra(fixture, agent, extra);
    agent
}

/// The owner Grant of base reach [`granted_agent`] mints, for an agent
/// defined another way (a fork).
fn grant_extra(fixture: &Fixture, agent: EntityId, extra: &[&str]) {
    let mut authority_scope = Scope::top();
    authority_scope.worlds = [ScopeId(base_world_id())].into_iter().collect();
    authority_scope.verbs = AgentTier::FullAccess
        .grant_verbs()
        .iter()
        .chain(extra.iter())
        .map(|verb| (*verb).to_owned())
        .collect();
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &owner_proof(fixture),
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("the owner grants the agent base reach");
    assert!(minted.grant.confers, "the grant confers");
}

/// The owner turns the agent-select key on: for `agent` alone, or with
/// `None` for every agent. At the base the key does not exist yet, so the
/// set is refused as unknown; the red tests then fail at the new verb, and
/// the guards still hold.
fn owner_turns_on(fixture: &Fixture, agent: Option<EntityId>) {
    let scope = agent.map_or_else(
        || json!({ "kind": "vault" }),
        |agent| json!({ "kind": "agent", "id": agent.to_hex() }),
    );
    match invoke(
        &owner_memory(fixture),
        SET,
        json!({ "key": KEY, "scope": scope, "value": true }),
    ) {
        Ok(applied) => assert_eq!(applied["status"], json!("applied"), "{applied}"),
        Err(refused) => assert!(
            refused.message.contains("no setting key is named"),
            "at the base the key does not exist yet: {refused:?}"
        ),
    }
}

/// A minimal valid compiled tree: one sheet card, stamped current.
fn compiled_tree() -> GeneratedLens {
    let root = LensNode::with_fallback_text(
        LensAtomId::new("root").expect("valid atom id"),
        LensAtom::Sheet(CollectionAtom {
            title: LensText::new("Card").expect("valid text"),
            rows: Vec::new(),
        }),
        LensText::new("Card").expect("valid text"),
    );
    GeneratedLens::new(root).expect("a current tree validates")
}

/// The weave slot the vault seeds at open: its installed content hash and
/// the skill id of its lens's slot.
fn weave_slot(fixture: &Fixture) -> (String, String) {
    let entry = fixture
        .vault
        .pack_lens(WEAVE_PACK, WEAVE_LENS)
        .expect("the open seeds the weave lens pack Active");
    (entry.content_hash, entry.skill_id)
}

/// `proposer`'s proposal of the compiled tree for the weave slot: its lens
/// ref and its revision hash.
fn propose(fixture: &Fixture, proposer: EntityId) -> (String, String) {
    let (content_hash, skill_id) = weave_slot(fixture);
    let receipt = agent_memory(fixture, proposer)
        .lenses_propose(LensProposeRequest {
            slot: LensSlot {
                pack_name: WEAVE_PACK.to_owned(),
                skill_id,
            },
            pack_content_hash: content_hash,
            compiled: compiled_tree(),
            intent_prompt: "word the week's changes for the reader".to_owned(),
            trigger: None,
            scope: None,
        })
        .unwrap_or_else(|error| panic!("the proposer proposes: {error:?}"));
    (receipt.lens_ref, receipt.compiled_hash)
}

/// The slot's selected lens ref, if the slot holds one now.
fn selected(fixture: &Fixture) -> Option<String> {
    let (_, skill_id) = weave_slot(fixture);
    let skill = EntityId::from_hex(&skill_id).expect("the slot's skill id");
    fixture
        .vault
        .active_pack_lens(WEAVE_PACK, &skill)
        .expect("the slot reads")
        .map(|(lens_ref, _)| lens_ref.to_hex())
}

/// The gate ledger row a slot decision appended, by its receipt's decision ref.
fn ledger_row(fixture: &Fixture, decision_ref: &str) -> GateDecisionRecord {
    fixture
        .vault
        .gate_decisions(64)
        .expect("the ledger reads")
        .into_iter()
        .find(|row| row.decision_id.to_hex() == decision_ref)
        .unwrap_or_else(|| panic!("the decision appended its ledger row: {decision_ref}"))
}

/// A definition born forked from `parent`: the parent's row, re-stored under
/// a new id with `forked_from` set.
fn forked_agent(fixture: &Fixture, name: &str, parent: EntityId) -> EntityId {
    let mut fork = fixture
        .vault
        .get_agent_definition(&parent)
        .expect("the parent's definition reads")
        .expect("the parent is defined");
    fork.agent_id = name.to_owned();
    fork.forked_from = Some(parent);
    let child = EntityId::now();
    fixture
        .vault
        .put_agent_definition(&child, &fork, TimeRange { start: 1, end: 1 }, 1)
        .expect("the fork stores");
    child
}

/// The agent's selection of `lens_ref` at `compiled_hash` for its slot.
fn select_as(fixture: &Fixture, agent: EntityId, lens_ref: &str, compiled_hash: &str) -> Value {
    invoke(
        &agent_memory(fixture, agent),
        ACTIVATE_AS,
        json!({ "lens_ref": lens_ref, "compiled_hash": compiled_hash }),
    )
    .unwrap_or_else(|error| panic!("the admitted agent selects: {error:?}"))
}

/// The agent's clearing of its slot while it still holds `lens_ref`.
fn clear_as(fixture: &Fixture, agent: EntityId, lens_ref: &str) -> Value {
    let (_, skill_id) = weave_slot(fixture);
    invoke(
        &agent_memory(fixture, agent),
        DEACTIVATE_AS,
        json!({
            "slot": { "pack_name": WEAVE_PACK, "skill_id": skill_id },
            "expected_active_ref": lens_ref,
        }),
    )
    .unwrap_or_else(|error| panic!("the admitted agent clears: {error:?}"))
}

/// The agent's selection is refused, for a reason that says why.
fn assert_select_refused(
    fixture: &Fixture,
    agent: EntityId,
    lens_ref: &str,
    compiled_hash: &str,
) -> MemoryError {
    let refused: MemoryError = invoke(
        &agent_memory(fixture, agent),
        ACTIVATE_AS,
        json!({ "lens_ref": lens_ref, "compiled_hash": compiled_hash }),
    )
    .expect_err("an agent the door does not admit selects nothing");
    assert!(
        !refused.message.is_empty(),
        "the refusal says why: {refused:?}"
    );
    refused
}

/// A refusal for the lineage rule: at the base the verb itself is unknown.
fn assert_lineage_refused(refused: &MemoryError) {
    assert!(
        refused.message.contains("lineage") || refused.message.contains("unknown SDK agent verb"),
        "its own lineage's proposal is refused as its own: {refused:?}"
    );
}

#[test]
fn an_agent_the_owner_turns_the_key_on_for_selects_and_clears_a_lens() {
    let fixture = rooted_vault();
    let proposer = granted_agent(&fixture, "lens-proposer", &[]);
    let (lens_ref, compiled_hash) = propose(&fixture, proposer);
    let decider = granted_agent(&fixture, "lens-decider", &[ACTIVATE_AS, DEACTIVATE_AS]);
    owner_turns_on(&fixture, Some(decider));

    let receipt = select_as(&fixture, decider, &lens_ref, &compiled_hash);
    assert_eq!(receipt["decision"], json!("activated"), "{receipt}");
    assert_eq!(receipt["decided_by"], json!(decider.to_hex()), "{receipt}");
    let authenticated = receipt["authenticated_under"]
        .as_str()
        .unwrap_or_else(|| panic!("an agent's decision names its grant: {receipt}"));
    let Some(grant) = authenticated.strip_prefix("grant:") else {
        panic!("an agent's decision names its grant: {receipt}");
    };
    assert_eq!(
        selected(&fixture),
        Some(lens_ref.clone()),
        "the slot holds the lens"
    );
    let decision_ref = receipt["decision_ref"]
        .as_str()
        .unwrap_or_else(|| panic!("the receipt names its decision: {receipt}"));
    let row = ledger_row(&fixture, decision_ref);
    assert_eq!(row.actor_class, "agent", "{row:?}");
    assert_eq!(row.grant_ref, Some(grant.to_owned()), "{row:?}");

    let cleared = clear_as(&fixture, decider, &lens_ref);
    assert_eq!(cleared["decision"], json!("deactivated"), "{cleared}");
    assert_eq!(cleared["decided_by"], json!(decider.to_hex()), "{cleared}");
    assert_eq!(selected(&fixture), None, "the slot is empty again");
}

#[test]
fn a_vault_row_turns_the_key_on_for_every_agent() {
    let fixture = rooted_vault();
    let proposer = granted_agent(&fixture, "lens-proposer", &[]);
    let (lens_ref, compiled_hash) = propose(&fixture, proposer);
    let decider = granted_agent(&fixture, "lens-decider", &[ACTIVATE_AS]);
    owner_turns_on(&fixture, None);

    let receipt = select_as(&fixture, decider, &lens_ref, &compiled_hash);
    assert_eq!(receipt["decision"], json!("activated"), "{receipt}");
    assert_eq!(receipt["decided_by"], json!(decider.to_hex()), "{receipt}");
    assert_eq!(
        selected(&fixture),
        Some(lens_ref),
        "the slot holds the lens"
    );
}

#[test]
fn the_key_off_leaves_the_slot_to_the_owner() {
    let fixture = rooted_vault();
    let proposer = granted_agent(&fixture, "lens-proposer", &[]);
    let (lens_ref, compiled_hash) = propose(&fixture, proposer);
    let decider = granted_agent(&fixture, "lens-decider", &[ACTIVATE_AS]);

    assert_select_refused(&fixture, decider, &lens_ref, &compiled_hash);
    assert_eq!(
        selected(&fixture),
        None,
        "the refused agent changed nothing"
    );

    let proof = owner_proof(&fixture);
    let receipt = fixture
        .vault
        .activate_lens(
            &proof,
            LensActivateRequest {
                lens_ref: lens_ref.clone(),
                compiled_hash,
                expected_active_ref: None,
            },
        )
        .unwrap_or_else(|error| panic!("the owner selects: {error:?}"));
    assert_eq!(receipt.decided_by, fixture.owner.to_hex());
    assert_eq!(receipt.authenticated_under, proof.decision_id().to_hex());
    assert_eq!(
        selected(&fixture),
        Some(lens_ref),
        "the slot holds the lens"
    );
    let row = ledger_row(&fixture, &receipt.decision_ref);
    assert_eq!(row.actor_class, "human", "{row:?}");
    assert_eq!(row.grant_ref, None, "{row:?}");
}

#[test]
fn an_agent_never_selects_a_revision_its_own_lineage_proposed() {
    let fixture = rooted_vault();
    let proposer = granted_agent(&fixture, "lineage-proposer", &[ACTIVATE_AS]);
    let (lens_ref, compiled_hash) = propose(&fixture, proposer);
    let fork = forked_agent(&fixture, "lineage-fork", proposer);
    grant_extra(&fixture, fork, &[ACTIVATE_AS]);
    let outsider = granted_agent(&fixture, "lineage-outsider", &[ACTIVATE_AS]);
    owner_turns_on(&fixture, None);

    let own = assert_select_refused(&fixture, proposer, &lens_ref, &compiled_hash);
    assert_lineage_refused(&own);
    let kin = assert_select_refused(&fixture, fork, &lens_ref, &compiled_hash);
    assert_lineage_refused(&kin);
    assert_eq!(
        selected(&fixture),
        None,
        "the refused agents changed nothing"
    );

    let receipt = select_as(&fixture, outsider, &lens_ref, &compiled_hash);
    assert_eq!(receipt["decision"], json!("activated"), "{receipt}");
    assert_eq!(selected(&fixture), Some(lens_ref), "the outsider selects");
}

#[test]
fn an_agent_whose_grant_lists_no_select_verb_is_refused() {
    let fixture = rooted_vault();
    let proposer = granted_agent(&fixture, "lens-proposer", &[]);
    let (lens_ref, compiled_hash) = propose(&fixture, proposer);
    let decider = granted_agent(&fixture, "lens-decider", &[]);
    owner_turns_on(&fixture, Some(decider));

    assert_select_refused(&fixture, decider, &lens_ref, &compiled_hash);
    assert_eq!(
        selected(&fixture),
        None,
        "the refused agent changed nothing"
    );
}

#[test]
fn a_fork_through_a_deleted_definition_never_selects_its_roots_proposal() {
    let fixture = rooted_vault();
    let root = granted_agent(&fixture, "lineage-root", &[]);
    let (lens_ref, compiled_hash) = propose(&fixture, root);
    let middle = forked_agent(&fixture, "lineage-middle", root);
    let grandchild = forked_agent(&fixture, "lineage-grandchild", middle);
    grant_extra(&fixture, grandchild, &[ACTIVATE_AS]);
    fixture
        .vault
        .batch()
        .delete(&middle)
        .commit()
        .expect("the owner deletes the middle definition");
    assert_eq!(
        fixture
            .vault
            .get_agent_definition(&middle)
            .expect("the deleted definition reads"),
        None,
        "the middle definition is gone"
    );
    let outsider = granted_agent(&fixture, "lineage-outsider", &[ACTIVATE_AS]);
    owner_turns_on(&fixture, None);

    // The middle id's pin still names the root, so the grandchild is the
    // root's lineage although the row between them is gone.
    let kin = assert_select_refused(&fixture, grandchild, &lens_ref, &compiled_hash);
    assert_lineage_refused(&kin);
    assert_eq!(selected(&fixture), None, "the refused fork changed nothing");

    let receipt = select_as(&fixture, outsider, &lens_ref, &compiled_hash);
    assert_eq!(receipt["decision"], json!("activated"), "{receipt}");
    assert_eq!(selected(&fixture), Some(lens_ref), "the outsider selects");
}
