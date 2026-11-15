//! The owner-approved vault-shape Actor create lands (FIX-LIST
//! VAULT-SHAPE-ACTOR-CREATE-EMPTY-PROVENANCE).
//!
//! The shape's declared definition used to carry an empty provenance map,
//! which the agent-definition codec refuses, so applying a shape that adds
//! an Actor ended Refused with `InvalidAgentDefBody`. The shape now stamps
//! the revalidated owner as the definition's author (`definedVia:
//! vault_shape`) and creates it through the owner's create door.

use std::sync::Arc;

use oneiron::agent_def::AgentCeiling;
use oneiron::authority::ActSurface;
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::vault_shape::{
    ShapeApplier, ShapeApplyRequest, ShapeCeiling, ShapeChange, ShapeItemState, ShapeRow,
    ShapeSeed, ShapeTarget,
};
use oneiron::{EntityId, Vault, VaultConfig};
use rmpv::Value as RmpValue;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const AGENT_ID: &str = "shape.actor.provenance";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    proof: AuthenticatedOwner,
    // Dropped after the vault.
    _dir: tempfile::TempDir,
}

/// A process-owned device vault with its embedded owner authenticated.
fn fixture() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    Ok(Fixture {
        vault,
        owner,
        proof,
        _dir: dir,
    })
}

/// A seed that adds one Actor at the proposed ceiling.
fn seed() -> ShapeSeed {
    ShapeSeed {
        rows: vec![ShapeRow::Actor {
            agent_id: AGENT_ID.to_owned(),
            ceiling: ShapeCeiling::Proposed,
            enabled: true,
        }],
    }
}

/// The text a provenance map holds under `key`.
fn provenance_text<'a>(provenance: &'a RmpValue, key: &str) -> Option<&'a str> {
    let RmpValue::Map(entries) = provenance else {
        return None;
    };
    entries.iter().find_map(|(found, value)| {
        if found.as_str() == Some(key) {
            value.as_str()
        } else {
            None
        }
    })
}

#[test]
fn shape_actor_create_lands_with_owner_provenance() -> TestResult {
    let fixture = fixture()?;
    let plan = fixture.vault.plan_shape(Some(&seed()))?;
    assert_eq!(plan.items.len(), 1, "the seed adds one Actor");
    let item = &plan.items[0];
    assert_eq!(item.change, ShapeChange::Create);
    assert_eq!(
        item.target,
        ShapeTarget::Actor {
            agent_id: AGENT_ID.to_owned(),
        }
    );
    assert!(item.door.is_some(), "the Actor create names its door");

    let now = fixture.vault.now_recorded_at();
    let applied = fixture.vault.apply_shape(
        ShapeApplier::Owner {
            owner: &fixture.proof,
            slips: None,
            surface: ActSurface::ThisInstall,
        },
        &ShapeApplyRequest {
            plan,
            approve: Vec::new(),
            conversation_learning: None,
        },
        now,
        &mut |_| Ok(true),
    )?;
    assert!(
        applied.done,
        "a Receipted item lands without the owner's word"
    );
    assert_eq!(applied.items.len(), 1);
    let ShapeItemState::Landed { receipt, .. } = &applied.items[0].state else {
        panic!(
            "the Actor create lands, got {:?}",
            applied.items[0].state
        );
    };

    let id = EntityId::from_hex(receipt).expect("the receipt names the new definition");
    let definition = fixture
        .vault
        .get_agent_definition(&id)?
        .expect("the landed definition reads back");
    assert_eq!(definition.agent_id, AGENT_ID);
    assert_eq!(definition.ceiling, AgentCeiling::Proposed);
    assert!(definition.enabled);
    let owner_hex = fixture.owner.to_hex();
    assert_eq!(
        provenance_text(&definition.provenance, "author"),
        Some(owner_hex.as_str()),
        "the shape stamps the revalidated owner as the author"
    );
    assert_eq!(
        provenance_text(&definition.provenance, "definedVia"),
        Some("vault_shape"),
        "the shape names itself as the defining door"
    );
    Ok(())
}

#[test]
fn shape_actor_create_settles_the_seed() -> TestResult {
    let fixture = fixture()?;
    let plan = fixture.vault.plan_shape(Some(&seed()))?;
    let now = fixture.vault.now_recorded_at();
    fixture.vault.apply_shape(
        ShapeApplier::Owner {
            owner: &fixture.proof,
            slips: None,
            surface: ActSurface::ThisInstall,
        },
        &ShapeApplyRequest {
            plan,
            approve: Vec::new(),
            conversation_learning: None,
        },
        now,
        &mut |_| Ok(true),
    )?;
    let again = fixture.vault.plan_shape(Some(&seed()))?;
    assert!(
        again.items.is_empty(),
        "the landed Actor satisfies the seed, got {:?}",
        again.items
    );
    Ok(())
}
