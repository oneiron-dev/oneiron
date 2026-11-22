//! L9-44 (ARCH-0005a #erase-refcount-open, ASTRA-R2-002): a `blob.version` claim goes only with
//! its artifact or its version. A replica that first syncs after a lone claim delete never learns
//! the claim's (artifact, content hash) pair, so the artifact's later delete there keeps the
//! bytes. Engine ruling 13 Nov 17:56: the owner's delete of a live artifact's lone version claim
//! runs as that version's release, and its receipt says so; an agent under a delete Grant and a
//! batch writer are refused, and the refusal names the way out.
//!
//! Red on main: the agent's and the batch writer's deletes land, and the owner's delete takes the
//! claim alone (receipt `user_delete`, the version and its bytes stay). The artifact-delete
//! control passes on main too. The later-replica half is `it_sync`'s
//! `sync_blob_version_claim_release`.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test
//! blob_version_claim_release`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{MemoryError, SafeDeleteReason};
use oneiron::registry::ENTITY_TYPE_ASSET;
use oneiron::task_verb::sdk::invoke;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{DeleteReason, EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use serde_json::json;

const FIRST: &[u8] = b"L9-44 bytes only the first version holds";
const SECOND: &[u8] = b"L9-44 bytes only the second version holds";

/// The refusal text of the ledger guard, as the delete door returns it.
const REFUSAL: &str = "goes with its version";

fn at(t: u64) -> TimeRange {
    TimeRange { start: t, end: t }
}

/// A personal vault whose bound owner uploaded one artifact with two versions, and an enabled
/// agent holding a Grant that names `read` and `delete`.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    agent: EntityId,
    artifact: EntityId,
    first_claim: EntityId,
    second_claim: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    // A delete signs its receipt with this install's key.
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    // The owner's agent Grant act is carried by this install's live machine profile.
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let (owner, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    let agent = agent_with_grant(&vault, &owner_proof, &["read", "delete"]);
    let artifact = EntityId::now();
    vault
        .put_blob_artifact(
            &artifact,
            &BlobArtifactBody::new("l9-44.bin", "application/octet-stream"),
            at(10),
            10,
        )
        .expect("the owner's artifact");
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    let mut claims = Vec::new();
    for (n, bytes) in [FIRST, SECOND].into_iter().enumerate() {
        let learned = 11 + n as u64;
        let version = vault
            .append_blob_artifact_version(
                &artifact,
                bytes,
                &BlobVersionProvenance::UserUpload,
                actor,
                at(learned),
                learned,
            )
            .expect("the owner uploads a version");
        claims.push(version.claim_id);
    }
    Fixture {
        _dir: dir,
        vault,
        owner,
        agent,
        artifact,
        first_claim: claims[0],
        second_claim: claims[1],
    }
}

/// An enabled agent the owner creates and gives one Grant naming `verbs`.
fn agent_with_grant(vault: &Vault, owner_proof: &AuthenticatedOwner, verbs: &[&str]) -> EntityId {
    let agent = EntityId::now();
    create_agent_definition_as(
        vault,
        owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": "version_claim_delete_agent",
                "desc": "Version claim delete test agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates an enabled, active agent definition");
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
    let minted = mint_agent_grant_as(
        vault,
        owner_proof,
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
    .expect("owner mints the agent a Grant");
    assert!(minted.grant.confers, "the agent's Grant confers");
    agent
}

impl Fixture {
    /// Whether the claim still reads as a live row.
    fn claim_live(&self, claim: &EntityId) -> bool {
        self.vault.get_claim(claim).expect("claim read").is_some()
            && !self.vault.is_deleted_shell(claim).expect("shell read")
    }

    /// How many versions the artifact's chain holds.
    fn versions(&self) -> usize {
        self.vault
            .blob_artifact_versions(&self.artifact)
            .expect("versions")
            .len()
    }

    /// Whether an ASSET row holding exactly `bytes` is stored here.
    fn stores_bytes(&self, bytes: &[u8]) -> bool {
        self.vault
            .entities_in_learned_range(0, u64::MAX)
            .expect("entity scan")
            .into_iter()
            .any(|id| {
                self.vault
                    .get_raw(&id)
                    .expect("raw read")
                    .is_some_and(|raw| {
                        raw.first() == Some(&ENTITY_TYPE_ASSET)
                            && raw.get(ENTITY_METADATA_HEADER_LEN..) == Some(bytes)
                    })
            })
    }
}

/// The agent calls the `vault.delete` verb on `id`.
fn agent_deletes(fx: &Fixture, id: &EntityId) -> Result<serde_json::Value, MemoryError> {
    invoke(
        &fx.vault.memory(fx.agent, EdgeActorClass::Agent),
        "vault.delete",
        json!({ "entity_ref": id.to_hex(), "reason": "user_delete" }),
    )
}

#[test]
fn an_agents_lone_version_claim_delete_is_refused() {
    let fx = fixture();
    let refused = agent_deletes(&fx, &fx.first_claim);
    match &refused {
        Err(error) => assert!(
            error.message.contains(REFUSAL),
            "the refusal names the way out: {error:?}"
        ),
        Ok(receipt) => panic!("an agent deleted a live artifact's version claim: {receipt}"),
    }
    assert!(fx.claim_live(&fx.first_claim), "the refused claim stays");
    assert_eq!(fx.versions(), 2, "the refused delete released no version");
    assert!(
        fx.stores_bytes(FIRST),
        "the refused delete released no bytes"
    );
}

#[test]
fn a_batch_writers_lone_version_claim_delete_is_refused() {
    let fx = fixture();
    let refused = fx.vault.batch().delete(&fx.first_claim).commit();
    match &refused {
        Err(error) => assert!(
            format!("{error:?}").contains(REFUSAL),
            "the refusal names the way out: {error:?}"
        ),
        Ok(()) => panic!("a batch writer deleted a live artifact's version claim"),
    }
    assert!(fx.claim_live(&fx.first_claim), "the refused claim stays");
    assert_eq!(fx.versions(), 2);
    assert!(fx.stores_bytes(FIRST));
}

#[test]
fn the_owners_lone_version_claim_delete_runs_as_the_version_release() {
    let fx = fixture();
    let receipt = fx
        .vault
        .memory(fx.owner, EdgeActorClass::Human)
        .safe_delete(&fx.first_claim.to_hex(), SafeDeleteReason::UserDelete)
        .expect("the owner's delete is never refused");
    assert!(receipt.existed, "{receipt:?}");
    assert_eq!(
        receipt.reason, "blob_version_release",
        "the receipt says the delete ran as the version's release: {receipt:?}"
    );
    assert!(
        fx.vault
            .get_raw(&fx.first_claim)
            .expect("raw read")
            .is_none(),
        "the claim went with its version"
    );
    assert_eq!(
        fx.versions(),
        1,
        "the version the claim records was released"
    );
    assert!(!fx.stores_bytes(FIRST), "the released version's bytes went");
    assert!(
        fx.claim_live(&fx.second_claim),
        "the other version's claim stays"
    );
    assert!(fx.stores_bytes(SECOND), "the other version's bytes stay");
    assert!(
        fx.vault.get_raw(&fx.artifact).expect("raw read").is_some(),
        "the artifact stays"
    );
}

/// Control (passes on main too): once the artifact is deleted, its bytes are gone and its version
/// claims are no longer guarded, so a batch writer's delete of one lands.
#[test]
fn an_artifact_delete_frees_its_version_claims_and_bytes() {
    let fx = fixture();
    fx.vault
        .delete_entity_with_reason(&fx.artifact, DeleteReason::UserHardDelete)
        .expect("the artifact's delete");
    assert!(!fx.stores_bytes(FIRST) && !fx.stores_bytes(SECOND));
    fx.vault
        .batch()
        .delete(&fx.first_claim)
        .commit()
        .expect("a deleted artifact's version claim deletes");
    assert!(
        fx.vault
            .get_raw(&fx.first_claim)
            .expect("raw read")
            .is_none()
    );
}
