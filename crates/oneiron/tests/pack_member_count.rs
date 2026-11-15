//! A reader's context pack counts no row it cannot read (FIX-LIST
//! ROOM-PACK-MEMBER-COUNT; the lead's ruling on ARCH-0052
//! #e5-read-union-open, Fri 13 Nov). The edge walk hydrates a pack's
//! neighbors before the reader's filter runs, so a neighbor the reader may
//! not read was counted in `neighbors_hydrated` though the filter withheld
//! it. A credential reader's native pack (`NativeRawRead::context_pack`, the
//! napi `contextPack` door with a read proof) served that count as it stood.
//!
//! The owner writes an anchor claim and two claims it supports: one in the
//! base world, one in a second world. Each claim is about its own PERSON, so
//! none supersedes another and none is an L2 base row (a claim about the
//! owner is served in `l2_base`, never in results or neighbors), and each is
//! born Public, so no disclosure clamp withholds it. The agent's Grant reads
//! the base world alone. The owner's pack holds both neighbors; the agent's
//! holds the base one, and every count it carries counts the rows it serves.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test pack_member_count`
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole, PairingPrincipal, VerifiedSlip};
use oneiron::claim::{NativeRawRead, ScopedReadActorKey, base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput};
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{
    ContextPackBuilder, EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, VaultConfig,
};
use serde_json::{Value, json};

const OCCURRED_AT: u64 = 1_769_947_200;
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:pack-member-count";
/// The anchor's words, which no neighbor's value shares.
const ANCHOR_QUERY: &str = "harbor lantern";
const ANCHOR_VALUE: &str = "harbor lantern ledger";
const READABLE_VALUE: &str = "amber kettle";
const WITHHELD_VALUE: &str = "violet quarry";
/// Sensitivity band 0, Public: the world axis alone tells the two neighbors
/// apart for the agent.
const PUBLIC_BAND: u8 = 0;

struct PackCountFixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    anchor: EntityId,
    readable: EntityId,
    withheld: EntityId,
    agent_slip: VerifiedSlip,
    agent_key: ScopedReadActorKey,
}

/// A rooted vault whose owner wrote an anchor claim in the base world, with
/// a `Supports` edge to a base-world claim and one to a second-world claim,
/// each about its own PERSON, and an agent whose one Grant reads the base
/// world.
fn pack_count_fixture() -> PackCountFixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let (owner, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    let second_world = vault
        .create_world(
            &owner_proof,
            "World the agent's Grant leaves out",
            OCCURRED_AT,
        )
        .expect("owner creates the second world");
    let anchor = write_owner_claim(
        &vault,
        owner,
        &owner_proof,
        (base_world_id(), "owen"),
        ANCHOR_VALUE,
    );
    let readable = write_owner_claim(
        &vault,
        owner,
        &owner_proof,
        (base_world_id(), "yuki"),
        READABLE_VALUE,
    );
    let withheld = write_owner_claim(
        &vault,
        owner,
        &owner_proof,
        (second_world, "noor"),
        WITHHELD_VALUE,
    );
    for target in [readable, withheld] {
        vault
            .put_edge(&anchor, EdgeKind::Supports, &target, 0.9)
            .expect("the anchor supports each neighbor");
    }

    let agent = create_enabled_agent(&vault, &owner_proof, "pack_member_count_agent");
    let mut authority_scope = Scope::top();
    authority_scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let minted = mint_agent_grant_as(
        &vault,
        &owner_proof,
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
    .expect("owner mints the agent a base-world read Grant");
    assert!(minted.grant.confers, "FIXTURE: the agent's Grant confers");
    let agent_slip = paired_agent_slip(&vault, &issuer, &owner_proof, agent, 0x5c);
    let agent_key = vault
        .credential_read_key(&agent_slip)
        .expect("agent credential read key")
        .expect("agent credential grants read");
    PackCountFixture {
        vault,
        _dir: dir,
        owner,
        anchor,
        readable,
        withheld,
        agent_slip,
        agent_key,
    }
}

/// The owner's Public claim, in `world`, about a fresh PERSON named
/// `subject_name`.
fn write_owner_claim(
    vault: &Vault,
    owner: EntityId,
    owner_proof: &AuthenticatedOwner,
    (world, subject_name): (EntityId, &str),
    value: &str,
) -> EntityId {
    let subject = EntityId::now();
    let at = TimeRange {
        start: OCCURRED_AT,
        end: OCCURRED_AT,
    };
    let person = rmp_serde::to_vec_named(&json!({ "name": subject_name })).expect("PERSON body");
    vault
        .put_entity(&subject, ENTITY_TYPE_PERSON, at, OCCURRED_AT, &person)
        .expect("the claim's PERSON subject");
    let id = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(owner_proof)
        .claim_upsert_scoped(&ScopedClaimInput {
            id: Some(id.to_hex()),
            predicate: "profile.preference".to_owned(),
            subject_ref: subject.to_hex(),
            value: json!(value),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            scope: ClaimScope {
                world_id: world.to_hex(),
                scope_facet_id: vault.default_facet().expect("owner default facet").to_hex(),
                scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                scope_project_id: default_project_id().to_hex(),
            },
            sensitivity: Some(PUBLIC_BAND),
            evidence_turn_refs: Vec::new(),
            valid_from: None,
            valid_to: None,
            occurred_at: Some(OCCURRED_AT),
            learned_at: Some(OCCURRED_AT),
            salience: None,
        })
        .expect("owner writes a claim in the named world");
    id
}

/// An enabled, active agent definition the owner creates as `agent_id`.
fn create_enabled_agent(
    vault: &Vault,
    owner_proof: &AuthenticatedOwner,
    agent_id: &str,
) -> EntityId {
    let agent = EntityId::now();
    create_agent_definition_as(
        vault,
        owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": agent_id,
                "desc": "Context pack count reader",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates an enabled, active agent definition");
    agent
}

/// The agent's paired credential, as `token_pair` mints it: only the verbs
/// axis narrows the pairing; the Grant imposes the world ceiling.
fn paired_agent_slip(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    owner: &AuthenticatedOwner,
    agent: EntityId,
    binding_seed: u8,
) -> VerifiedSlip {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "core:read".to_owned(),
        "core:write".to_owned(),
    ]));
    let holder = agent.to_hex();
    let link = vault
        .issue_owner_pairing_link(
            issuer,
            owner,
            scope,
            3_600,
            PairingPrincipal {
                holder_ref: Some(holder.clone()),
                actor_class: Some("agent".to_owned()),
                ..PairingPrincipal::default()
            },
        )
        .expect("owner issues the agent's pairing link");
    let signing_key = SigningKey::from_bytes(&[binding_seed; 32]);
    let binding_key = signing_key.verifying_key().to_bytes();
    let transcript = oneiron::authority::pairing_binding_transcript_pinned(
        &link.code,
        &binding_key,
        &holder,
        link.pin.as_ref(),
    )
    .expect("agent pairing transcript");
    let slip = vault
        .redeem_pairing_link(
            issuer,
            &link.code,
            &holder,
            binding_key,
            &signing_key.sign(&transcript).to_bytes(),
        )
        .expect("agent redeems its pairing link");
    let signature = signing_key
        .sign(
            &slip
                .binding_transcript(REQUEST_CHALLENGE)
                .expect("agent request transcript"),
        )
        .to_bytes();
    vault
        .verify_capability_slip(&issuer.public_key(), &slip, REQUEST_CHALLENGE, &signature)
        .expect("paired agent proves possession of its credential")
}

/// The anchor's pack, claims only (no FACET or PERSON the claims point at),
/// one hop out, every world at full share, neighbors in their own section,
/// stats included.
fn anchor_pack(builder: ContextPackBuilder<'_>) -> ContextPackBuilder<'_> {
    builder
        .search_text(ANCHOR_QUERY, 10)
        .filter_types(&[ENTITY_TYPE_CLAIM])
        .edge_hop(1)
        .non_base_world_claim_fraction(1.0)
        .merge_neighbors(false)
        .include_stats(true)
}

/// A native pack's JSON as `read` serves it.
fn native_pack_json(read: &NativeRawRead<'_>) -> oneiron::Result<Value> {
    let bytes = read.context_pack(anchor_pack)?;
    Ok(serde_json::from_slice(&bytes).expect("a JSON pack"))
}

/// A native pack's sections: under `delta` when the pack carries an L2 base
/// prefix (`serialize/l2_prefix.rs`), else at the top.
fn pack_body(pack: &Value) -> &Value {
    pack.get("delta").unwrap_or(pack)
}

/// How many rows a native pack's `section` serves, over every group in it.
fn section_rows(pack: &Value, section: &str) -> u64 {
    let rows: usize = pack_body(pack)
        .get(section)
        .and_then(Value::as_object)
        .map_or(0, |groups| {
            groups
                .values()
                .filter_map(Value::as_array)
                .map(Vec::len)
                .sum()
        });
    u64::try_from(rows).expect("a row count fits u64")
}

/// Whether a row of a native pack's `section` carries `value`.
fn section_holds(pack: &Value, section: &str, value: &str) -> bool {
    pack_body(pack)
        .get(section)
        .is_some_and(|rows| rows.to_string().contains(value))
}

fn stat(pack: &Value, name: &str) -> u64 {
    pack_body(pack)
        .pointer(&format!("/stats/{name}"))
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("the pack's stats carry {name}: {pack}"))
}

/// The agent's native credential pack serves the base neighbor and counts it
/// alone: the second-world neighbor the walk hydrated adds nothing to
/// `neighbors_hydrated`. The owner's pack, over the same rows, serves and
/// counts both, so the agent's count is the filter's, not the walk's.
#[test]
fn a_credential_pack_counts_no_neighbor_it_cannot_read() {
    let fixture = pack_count_fixture();
    let owner_pack = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_credential_raw_read(native_pack_json)
        .expect("the owner's native pack");
    assert!(
        section_holds(&owner_pack, "results", ANCHOR_VALUE)
            && section_holds(&owner_pack, "neighbors", READABLE_VALUE)
            && section_holds(&owner_pack, "neighbors", WITHHELD_VALUE),
        "FIXTURE: the owner's pack holds the anchor and both neighbors: {owner_pack}",
    );

    let agent_pack = fixture
        .vault
        .with_credential_raw_read(&fixture.agent_slip, native_pack_json)
        .expect("the agent's native pack");
    assert!(
        section_holds(&agent_pack, "results", ANCHOR_VALUE)
            && section_holds(&agent_pack, "neighbors", READABLE_VALUE)
            && !section_holds(&agent_pack, "neighbors", WITHHELD_VALUE),
        "FIXTURE: the agent's pack holds the anchor and the base neighbor, \
         never the second-world one: {agent_pack}",
    );
    assert_eq!(
        (
            stat(&agent_pack, "hydrated"),
            stat(&agent_pack, "neighbors_hydrated")
        ),
        (
            section_rows(&agent_pack, "results"),
            section_rows(&agent_pack, "neighbors")
        ),
        "FAILBEFORE ROOM-PACK-MEMBER-COUNT: the agent's pack counts the rows it serves, \
         never the second-world neighbor it cannot read: {agent_pack}",
    );
}

/// The scoped filter every scoped pack door runs (`ScopedRead::
/// filter_context_pack`) leaves the pack's hydrated counts at the rows it
/// keeps, whichever door renders the pack after it.
#[test]
fn a_scoped_pack_filter_counts_only_the_rows_it_keeps() {
    let fixture = pack_count_fixture();
    let read = fixture.vault.scoped_read(fixture.agent_key.clone());
    let plan = read.context_pack_plan().expect("the agent's pack plan");
    let mut pack = anchor_pack(plan.admit(fixture.vault.context_pack()))
        .run()
        .expect("the agent's pack");
    let holds = |rows: &[oneiron::ContextEntity], id: EntityId| rows.iter().any(|row| row.id == id);
    assert!(
        holds(&pack.results, fixture.anchor)
            && holds(&pack.neighbors, fixture.readable)
            && holds(&pack.neighbors, fixture.withheld),
        "FIXTURE: the walk hydrates the anchor and both neighbors before the reader's filter",
    );
    read.filter_context_pack(&mut pack)
        .expect("the agent's filter");
    assert!(
        holds(&pack.results, fixture.anchor)
            && holds(&pack.neighbors, fixture.readable)
            && !holds(&pack.neighbors, fixture.withheld),
        "FIXTURE: the filter keeps the anchor and the base neighbor and withholds the \
         second-world one",
    );
    assert_eq!(
        (pack.stats.entities_hydrated, pack.stats.neighbors_hydrated),
        (pack.results.len(), pack.neighbors.len()),
        "FAILBEFORE ROOM-PACK-MEMBER-COUNT: the filtered pack counts the rows it keeps",
    );
}
