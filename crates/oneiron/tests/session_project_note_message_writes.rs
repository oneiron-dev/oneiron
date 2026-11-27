//! SESSION-PROJECT-NOTE-MESSAGE-PLACEMENT PR A, the write side: a handle bound to an
//! attached session's folder for its writes (`Memory::placing_in_session_workspace`) places a
//! note it writes in the folder's project, and so is a turn the write mints with its messages,
//! settling the birth stamp's audience the witness doors already settle. A placement the
//! caller's credential does not cover refuses the write. Placement is read through the
//! `stored_project` test door, which already serves every kind.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test
//! session_project_note_message_writes`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{HostSlipIssuer, VerifiedSlip};
use oneiron::claim::default_project_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{ScopeAxis, ScopeId};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, Memory, WitnessReceipt, WitnessTurn};
use oneiron::note::TakeTarget;
use oneiron::registry::ENTITY_TYPE_FACET;
use oneiron::session_project::WorkspaceBindRequest;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::room_facet_set::create_owner_project;
use oneiron::test_doors::witness_project::stamped_project;
use oneiron::verbs::{DiaryEntryRequest, self_memory_diary_write};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The digest of the folder bound to `alpha`.
const MAIN_DIGEST: &str = "blake3:a0b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9f";
/// A folder nobody bound.
const UNBOUND_DIGEST: &str =
    "blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const CHALLENGE: &[u8] = b"oneiron-request:session-project-note-message-writes";

/// A rooted vault whose owner made `alpha` and `beta` under the root and bound the folder
/// `MAIN_DIGEST` to `alpha`. The vault closes before its directory goes.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    proof: AuthenticatedOwner,
    issuer: HostSlipIssuer,
    alpha: EntityId,
    beta: EntityId,
    _dir: tempfile::TempDir,
}

fn open() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner)?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let root = vault.root_project()?;
    vault.sign_owner_project(&proof, &vault.owner_project_signer(&issuer)?, root)?;
    let facet = EntityId::now();
    vault.put_entity(
        &facet,
        ENTITY_TYPE_FACET,
        TimeRange { start: 1, end: 1 },
        1,
        &rmp_serde::to_vec_named(&json!({ "name": "session write facet" }))?,
    )?;
    let alpha = project_under(&vault, &issuer, &proof, owner, root, facet)?;
    let beta = project_under(&vault, &issuer, &proof, owner, root, facet)?;
    let binding = vault.bind_workspace_as_owner(
        &proof,
        Some(oneiron::authority::ActSurface::ThisInstall),
        WorkspaceBindRequest {
            folder_digest: MAIN_DIGEST.to_owned(),
            project: alpha,
            label: Some("alpha".to_owned()),
        },
    )?;
    assert_eq!(
        binding.project,
        Some(alpha),
        "FIXTURE: the owner binds the folder"
    );
    Ok(Fixture {
        vault,
        owner,
        proof,
        issuer,
        alpha,
        beta,
        _dir: dir,
    })
}

/// An owner-born project under `parent`, sliced to `facet`.
fn project_under(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    proof: &AuthenticatedOwner,
    owner: EntityId,
    parent: EntityId,
    facet: EntityId,
) -> TestResult<EntityId> {
    let id = EntityId::now();
    let mut record = ProjectRecord::new(id, Some(parent), vault.root_project()?, owner)?;
    record.slice.facet = Some(facet);
    record.depth_remaining = 1;
    create_owner_project(
        vault,
        issuer,
        proof,
        &vault.owner_project_signer(issuer)?,
        owner,
        id,
        &record,
    )?;
    Ok(id)
}

impl Fixture {
    /// The owner's handle, bound for its writes to the folder `folder_digest` when given.
    fn writer(&self, folder_digest: Option<&str>) -> Memory<'_> {
        let memory = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .with_owner_authorship(&self.proof);
        match folder_digest {
            Some(digest) => memory.placing_in_session_workspace(&[digest.to_owned()]),
            None => memory,
        }
    }
}

/// A credential minted for the owner as a `human` with `audience` as its slip audience,
/// verified with its holder's signature.
fn owner_credential(fixture: &Fixture, seed: u8, audience: ScopeAxis<ScopeId>) -> VerifiedSlip {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let root = fixture
        .vault
        .ensure_host_root_slip(&fixture.issuer)
        .expect("host root");
    let mut claims = root.claims;
    claims.slip_id = [seed; 32];
    claims.parent_id = None;
    claims.holder_ref = fixture.owner.to_hex();
    claims.binding_key = key.verifying_key().to_bytes();
    claims.actor_class = Some("human".to_owned());
    claims.scope.audience = audience;
    claims.records = BTreeSet::new();
    let slip = fixture
        .vault
        .mint_capability_slip(&fixture.issuer, claims)
        .expect("mint the owner credential");
    let signature = key
        .sign(&slip.binding_transcript(CHALLENGE).expect("transcript"))
        .to_bytes();
    fixture
        .vault
        .verify_capability_slip(&fixture.issuer.public_key(), &slip, CHALLENGE, &signature)
        .expect("verify the owner credential")
}

/// One visible user MESSAGE of `content` in a fresh turn of `conversation`, as `vault.witness`
/// takes it without a project.
fn plain_turn(conversation: &str, content: &str) -> WitnessTurn {
    let value = json!({
        "conversation_ref": conversation,
        "messages": [{
            "author": "user",
            "message_type": "dialogue",
            "content": content,
            "is_visible": true,
            "order": 0,
        }],
        "occurred_at": 900,
    });
    serde_json::from_value(value).expect("the witness turn shape decodes")
}

/// [`plain_turn`] plus the row's optional project, attached on the wire the way a facade caller
/// sends it.
fn turn_with_project(conversation: &str, content: &str, project: EntityId) -> WitnessTurn {
    let turn = plain_turn(conversation, content);
    let mut value = serde_json::to_value(&turn).expect("a witness turn serializes");
    value["project"] = json!(project.to_hex());
    match serde_json::from_value::<WitnessTurn>(value) {
        Ok(turn) => turn,
        Err(error) => panic!("vault.witness turns carry an optional project: {error}"),
    }
}

/// One visible user MESSAGE of `content` at `order`, with the caller-fixed conversation, TURN
/// and MESSAGE ids an exact retry or an append names.
fn fixed_turn(
    conversation: &str,
    content: &str,
    turn: EntityId,
    message: EntityId,
    order: u32,
) -> WitnessTurn {
    let value = json!({
        "conversation_ref": conversation,
        "turn_ref": turn.to_hex(),
        "messages": [{
            "id": message.to_hex(),
            "author": "user",
            "message_type": "dialogue",
            "content": content,
            "is_visible": true,
            "order": order,
        }],
        "occurred_at": 900,
    });
    serde_json::from_value(value).expect("the fixed witness turn shape decodes")
}

/// The MESSAGE the witness wrote, as its stamped row.
fn first_message(receipt: &WitnessReceipt) -> EntityId {
    let message = receipt
        .messages
        .first()
        .expect("the witness writes one MESSAGE row");
    EntityId::from_hex(&message.id).expect("the message record ref parses")
}

#[test]
fn a_bound_handles_create_note_lands_in_the_folders_project() -> TestResult {
    let fixture = open()?;
    let receipt = fixture
        .writer(Some(MAIN_DIGEST))
        .create_note(
            "research",
            "a session-placed note about the alpha milestone",
        )
        .map_err(|error| format!("vault.notes.create: {error:?}"))?;
    let note = EntityId::from_hex(&receipt.id_hex)?;
    assert_eq!(
        stamped_project(&fixture.vault, note)?,
        Some(fixture.alpha),
        "a P-bound handle's create_note lands in P"
    );
    assert_ne!(
        stamped_project(&fixture.vault, note)?,
        Some(fixture.beta),
        "a P-bound handle's create_note does not land in Q"
    );
    Ok(())
}

#[test]
fn a_bound_handles_take_and_diary_entry_land_in_the_folders_project() -> TestResult {
    let fixture = open()?;
    let memory = fixture.writer(Some(MAIN_DIGEST));
    let take = memory
        .author_take(
            TakeTarget::Subject(fixture.owner),
            "a take on the owner's alpha work, placed by the session",
        )
        .map_err(|error| format!("vault.notes.author_take: {error:?}"))?;
    let entry = self_memory_diary_write(
        &memory,
        DiaryEntryRequest {
            content: "a diary entry written inside the alpha folder session".to_owned(),
            kind: None,
        },
    )
    .map_err(|error| format!("self.memory.diary: {error:?}"))?;
    assert_eq!(
        stamped_project(&fixture.vault, EntityId::from_hex(&take.id_hex)?)?,
        Some(fixture.alpha),
        "a P-bound handle's take lands in P"
    );
    assert_eq!(
        stamped_project(&fixture.vault, EntityId::from_hex(&entry.entry_id)?)?,
        Some(fixture.alpha),
        "a P-bound handle's diary entry lands in P"
    );
    Ok(())
}

#[test]
fn a_bound_handles_minted_turn_and_messages_land_in_the_folders_project() -> TestResult {
    let fixture = open()?;
    let conversation = EntityId::now().to_hex();
    let receipt = fixture
        .writer(Some(MAIN_DIGEST))
        .witness(&plain_turn(
            &conversation,
            "the alpha session speaks its first turn",
        ))
        .map_err(|error| format!("vault.witness: {error:?}"))?;
    assert_eq!(
        stamped_project(&fixture.vault, receipt.turn_id)?,
        Some(fixture.alpha),
        "a P-bound handle's minted TURN lands in P"
    );
    assert_eq!(
        stamped_project(&fixture.vault, first_message(&receipt))?,
        Some(fixture.alpha),
        "a P-bound handle's minted MESSAGE lands in P"
    );
    Ok(())
}

#[test]
fn appending_to_a_default_born_turn_keeps_new_messages_at_the_default() -> TestResult {
    let fixture = open()?;
    let conversation = EntityId::now().to_hex();
    let turn = EntityId::now();
    let first = EntityId::now();
    fixture
        .writer(None)
        .witness(&fixed_turn(
            &conversation,
            "the default-born turn opens",
            turn,
            first,
            0,
        ))
        .map_err(|error| format!("vault.witness mints: {error:?}"))?;
    assert_eq!(
        stamped_project(&fixture.vault, turn)?,
        Some(default_project_id()),
        "the turn minted with no session is born at the default project"
    );
    let second = EntityId::now();
    fixture
        .writer(Some(MAIN_DIGEST))
        .witness(&fixed_turn(
            &conversation,
            "the session appends to the default turn",
            turn,
            second,
            1,
        ))
        .map_err(|error| format!("vault.witness appends: {error:?}"))?;
    assert_eq!(
        stamped_project(&fixture.vault, second)?,
        Some(default_project_id()),
        "a MESSAGE appended to a default-born TURN stays at the default project"
    );
    assert_eq!(
        stamped_project(&fixture.vault, turn)?,
        Some(default_project_id()),
        "appending from a session does not move the TURN off the default project"
    );
    Ok(())
}

#[test]
fn an_explicit_project_wins_over_the_session_placement() -> TestResult {
    let fixture = open()?;
    let conversation = EntityId::now().to_hex();
    let receipt = fixture
        .writer(Some(MAIN_DIGEST))
        .witness(&turn_with_project(
            &conversation,
            "the caller names beta from inside alpha",
            fixture.beta,
        ))
        .map_err(|error| format!("vault.witness: {error:?}"))?;
    assert_eq!(
        stamped_project(&fixture.vault, receipt.turn_id)?,
        Some(fixture.beta),
        "an explicit project wins over the session placement for the TURN"
    );
    assert_eq!(
        stamped_project(&fixture.vault, first_message(&receipt))?,
        Some(fixture.beta),
        "an explicit project wins over the session placement for the MESSAGE"
    );
    Ok(())
}

#[test]
fn handles_with_no_folder_or_an_unbound_folder_keep_the_default_project() -> TestResult {
    let fixture = open()?;
    for folder in [None, Some(UNBOUND_DIGEST)] {
        let memory = fixture.writer(folder);
        let note = memory
            .create_note("research", "a note with no session placement")
            .map_err(|error| format!("vault.notes.create: {error:?}"))?;
        assert_eq!(
            stamped_project(&fixture.vault, EntityId::from_hex(&note.id_hex)?)?,
            Some(default_project_id()),
            "a NOTE with no session placement keeps the default project"
        );
        let conversation = EntityId::now().to_hex();
        let receipt = memory
            .witness(&plain_turn(
                &conversation,
                "a turn with no session placement",
            ))
            .map_err(|error| format!("vault.witness: {error:?}"))?;
        assert_eq!(
            stamped_project(&fixture.vault, receipt.turn_id)?,
            Some(default_project_id()),
            "a TURN with no session placement keeps the default project"
        );
        assert_eq!(
            stamped_project(&fixture.vault, first_message(&receipt))?,
            Some(default_project_id()),
            "a MESSAGE with no session placement keeps the default project"
        );
    }
    Ok(())
}

#[test]
fn a_placement_the_credential_does_not_cover_refuses_the_write() -> TestResult {
    let fixture = open()?;
    let proof = owner_credential(
        &fixture,
        0x51,
        ScopeAxis::Some(BTreeSet::from([ScopeId(fixture.beta)])),
    );
    let memory = fixture.writer(Some(MAIN_DIGEST)).with_read_proof(&proof);
    let error = memory
        .create_note(
            "research",
            "a note the uncovered session placement refuses quillharpabortmarker",
        )
        .expect_err("a placement the credential does not cover refuses the note write");
    assert_eq!(
        error.code, MEMORY_CODE_FORBIDDEN,
        "the refused note write answers FORBIDDEN"
    );
    assert!(
        error.message.contains(&fixture.alpha.to_hex()),
        "the note refusal names the session project: {}",
        error.message,
    );
    let conversation = EntityId::now().to_hex();
    let turn = EntityId::now();
    let message = EntityId::now();
    let error = memory
        .witness(&fixed_turn(
            &conversation,
            "a turn the uncovered session placement refuses",
            turn,
            message,
            0,
        ))
        .expect_err("a placement the credential does not cover refuses the witness write");
    assert_eq!(
        error.code, MEMORY_CODE_FORBIDDEN,
        "the refused witness write answers FORBIDDEN"
    );
    assert!(
        error.message.contains(&fixture.alpha.to_hex()),
        "the witness refusal names the session project: {}",
        error.message,
    );
    assert!(
        fixture.vault.get_raw(&turn)?.is_none(),
        "the refused witness stored no TURN"
    );
    assert!(
        fixture.vault.get_raw(&message)?.is_none(),
        "the refused witness stored no MESSAGE"
    );
    fixture
        .writer(None)
        .create_note(
            "research",
            "a control note that lands quillharpcontrolmarker",
        )
        .map_err(|error| format!("vault.notes.create control: {error:?}"))?;
    let control = fixture
        .writer(None)
        .query_bm25("quillharpcontrolmarker", 10)
        .map_err(|error| format!("vault.query_bm25 control: {error:?}"))?
        .value;
    assert!(!control.is_empty(), "the control note's text is searchable");
    let refused = fixture
        .writer(None)
        .query_bm25("quillharpabortmarker", 10)
        .map_err(|error| format!("vault.query_bm25 refused: {error:?}"))?
        .value;
    assert!(
        refused.is_empty(),
        "the refused note stored no searchable text: {refused:?}"
    );
    Ok(())
}
