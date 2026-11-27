//! FIX SESSION-PROJECT-HOOK-TRANSCRIPT-PLACEMENT, the hand-over side: a hook transcript
//! naming its session's folder in `folder_digests` lands its TURNs and MESSAGEs in that
//! folder's bound project, as the local import lands a log read in that folder (Engine ANSWER
//! HOOK-TRANSCRIPT-PLACEMENT-BEFORE-B, E-AGENT = (a)). A granted agent whose presented
//! transport credential does not cover the bound project is refused before any log is read,
//! and nothing lands at the default instead; the owner, or a credential that covers the
//! project, lands there. Placement is read through the `stamped_project` test door, MESSAGE
//! ids through `imported_message_rows`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test
//! session_project_hook_transcript`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::io::Write as _;
use std::sync::Arc;

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole, VerifiedSlip};
use oneiron::claim::default_project_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::ingest::history::{HistoryImportCaller, HistorySource, HookTranscriptImportRequest};
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN};
use oneiron::registry::ENTITY_TYPE_FACET;
use oneiron::session_project::WorkspaceBindRequest;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::history_import_rows::{ImportedMessageRows, imported_message_rows};
use oneiron::test_doors::room_facet_set::create_owner_project;
use oneiron::test_doors::witness_project::stamped_project;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_contracts::entity_id::derived_domains::HISTORY_CONVERSATION;
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The digest of the folder bound to `alpha`.
const MAIN_DIGEST: &str = "blake3:a0b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9f";
/// A folder nobody bound.
const UNBOUND_DIGEST: &str =
    "blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
/// A second valid digest nobody bound, for the three-digest refusal.
const THIRD_DIGEST: &str =
    "blake3:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

const CHALLENGE: &[u8] = b"oneiron-request:session-project-hook-transcript";

/// The verb a granted agent's Grant names to carry a hand-over.
const HOOK_TRANSCRIPT_VERB: &str = "vault.imports.hook_transcript";

/// A rooted vault whose owner made `alpha` and `beta` under the root and bound the folder
/// `MAIN_DIGEST` to `alpha`, with a named agent whose live Grant names the hand-over verb.
/// Copied from `session_project_history_import.rs` (plus `beta`) and
/// `agent_act_grant_lists_read.rs` (install profile, agent principal, Grant). The vault closes
/// before its directory goes.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    proof: AuthenticatedOwner,
    issuer: HostSlipIssuer,
    alpha: EntityId,
    beta: EntityId,
    agent: EntityId,
    dir: tempfile::TempDir,
}

fn open() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
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
        Some(ActSurface::ThisInstall),
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
    let agent = vault.ensure_agent_principal("session-project-hook-transcript-agent")?;
    mint_hook_transcript_grant(&vault, &proof, agent)?;
    Ok(Fixture {
        vault,
        owner,
        proof,
        issuer,
        alpha,
        beta,
        agent,
        dir,
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

/// The owner's Grant naming the hand-over verb (and `read`, which a conferring Grant carries)
/// for `agent`.
fn mint_hook_transcript_grant(
    vault: &Vault,
    proof: &AuthenticatedOwner,
    agent: EntityId,
) -> TestResult {
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "read".to_owned(),
        HOOK_TRANSCRIPT_VERB.to_owned(),
    ]));
    let minted = mint_agent_grant_as(
        vault,
        proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
            check_in_ref: None,
        },
    )
    .map_err(|error| format!("FIXTURE: the owner mints the hand-over Grant: {error:?}"))?;
    assert!(minted.grant.confers, "FIXTURE: the hand-over Grant confers");
    Ok(())
}

/// A credential minted for the fixture's agent with `audience` as its slip audience, verified
/// with its holder's signature. `session_project_note_message_writes.rs`'s `owner_credential`
/// with the holder as the agent.
fn agent_credential(fixture: &Fixture, seed: u8, audience: ScopeAxis<ScopeId>) -> VerifiedSlip {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let root = fixture
        .vault
        .ensure_host_root_slip(&fixture.issuer)
        .expect("host root");
    let mut claims = root.claims;
    claims.slip_id = [seed; 32];
    claims.parent_id = None;
    claims.holder_ref = fixture.agent.to_hex();
    claims.binding_key = key.verifying_key().to_bytes();
    claims.actor_class = Some("agent".to_owned());
    claims.scope.audience = audience;
    claims.records = BTreeSet::new();
    let slip = fixture
        .vault
        .mint_capability_slip(&fixture.issuer, claims)
        .expect("mint the agent credential");
    let signature = key
        .sign(&slip.binding_transcript(CHALLENGE).expect("transcript"))
        .to_bytes();
    fixture
        .vault
        .verify_capability_slip(&fixture.issuer.public_key(), &slip, CHALLENGE, &signature)
        .expect("verify the agent credential")
}

/// A fresh 36-char session or message id: an `EntityId`'s 32 hex cut and dashed as a
/// v4-shaped id, which the hook transcript's Claude Code session check takes.
fn dashed_id() -> String {
    let hex = EntityId::now().to_hex();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// `bytes` gzip-compressed, in standard base64.
fn gzip_base64(bytes: &[u8]) -> String {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).expect("gzip write");
    let compressed = encoder.finish().expect("gzip finish");
    base64::engine::general_purpose::STANDARD.encode(compressed)
}

/// One hand-over's session: fresh session and message ids with the request that carries them.
struct HandOver {
    msg1: String,
    msg2: String,
    request: HookTranscriptImportRequest,
}

/// One Claude Code main log with a fresh session id: one user and one assistant record, each
/// naming an absolute temp `cwd`, gzip-compressed in standard base64, carried with
/// `folder_digests`. The record shape copies the Claude Code decoder's own tests: a user line
/// with a string content and an assistant line with a text block.
fn hand_over(fixture: &Fixture, folder_digests: Vec<String>) -> HandOver {
    let session = dashed_id();
    let msg1 = dashed_id();
    let msg2 = dashed_id();
    let cwd = fixture.dir.path().to_string_lossy();
    let user = json!({
        "parentUuid": null,
        "isSidechain": false,
        "userType": "external",
        "cwd": &cwd,
        "sessionId": &session,
        "type": "user",
        "message": {"role": "user", "content": format!("repot the basil in {session}")},
        "uuid": &msg1,
        "timestamp": "2026-09-25T06:00:00.000Z",
    })
    .to_string();
    let assistant = json!({
        "parentUuid": &msg1,
        "isSidechain": false,
        "userType": "external",
        "cwd": &cwd,
        "sessionId": &session,
        "type": "assistant",
        "message": {
            "role": "assistant",
            "model": "claude-test",
            "content": [{"type": "text", "text": format!("the basil is repotted in {session}")}],
        },
        "uuid": &msg2,
        "timestamp": "2026-09-25T06:00:20.000Z",
    })
    .to_string();
    let log = format!("{user}\n{assistant}\n");
    let request = HookTranscriptImportRequest {
        session,
        transcript_gzip_base64: gzip_base64(log.as_bytes()),
        subagents: Vec::new(),
        source: None,
        folder_digests,
    };
    HandOver {
        msg1,
        msg2,
        request,
    }
}

/// The CONVERSATION a Claude Code session lands as, as the import derives it.
fn conversation_id(session: &str) -> TestResult<EntityId> {
    Ok(EntityId::derive(
        HISTORY_CONVERSATION,
        &[
            HistorySource::ClaudeCode.source_id().as_bytes(),
            session.as_bytes(),
        ],
    )?)
}

/// Nothing of `hand` landed: neither MESSAGE has ledger rows and its CONVERSATION is absent.
fn assert_nothing_landed(fixture: &Fixture, hand: &HandOver) -> TestResult {
    for msg_id in [&hand.msg1, &hand.msg2] {
        assert!(
            imported_message_rows(&fixture.vault, HistorySource::ClaudeCode, msg_id)?.is_none(),
            "nothing of the refused session landed: {msg_id} has no ledger rows"
        );
    }
    let conversation = conversation_id(&hand.request.session)?;
    assert!(
        fixture.vault.get_raw(&conversation)?.is_none(),
        "nothing of the refused session landed: its CONVERSATION is absent"
    );
    Ok(())
}

/// Land one fresh session and recover the two TURNs and two MESSAGEs it wrote.
fn land(
    fixture: &Fixture,
    caller: HistoryImportCaller<'_>,
    presented: Option<&VerifiedSlip>,
    hand: &HandOver,
) -> TestResult<[ImportedMessageRows; 2]> {
    let view = fixture
        .vault
        .import_hook_transcript(caller, presented, &hand.request)?;
    assert_eq!(view.conversations.len(), 1, "one conversation: {view:?}");
    let conversation = &view.conversations[0];
    assert_eq!(
        (conversation.new, conversation.refused),
        (2, 0),
        "both messages land new: {view:?}"
    );
    let read = |id: &str| -> TestResult<ImportedMessageRows> {
        let rows = imported_message_rows(&fixture.vault, HistorySource::ClaudeCode, id)?
            .unwrap_or_else(|| panic!("the hand-over landed {id}"));
        assert_eq!(rows.conversation.to_hex(), view.conversation);
        Ok(rows)
    };
    let rows = [read(&hand.msg1)?, read(&hand.msg2)?];
    assert_ne!(
        rows[0].turn, rows[1].turn,
        "each speaker mints a separate TURN"
    );
    Ok(rows)
}

fn assert_placement(
    fixture: &Fixture,
    rows: [ImportedMessageRows; 2],
    project: EntityId,
) -> TestResult {
    for row in rows {
        assert_eq!(
            stamped_project(&fixture.vault, row.turn)?,
            Some(project),
            "a handed-over TURN lands in the expected project"
        );
        assert_eq!(
            stamped_project(&fixture.vault, row.message)?,
            Some(project),
            "a handed-over MESSAGE lands in the expected project"
        );
    }
    Ok(())
}

#[test]
fn an_owner_hand_over_naming_a_bound_folder_lands_its_turns_and_messages_in_the_folders_project()
-> TestResult {
    let fixture = open()?;
    let hand = hand_over(&fixture, vec![MAIN_DIGEST.to_owned()]);
    let rows = land(
        &fixture,
        HistoryImportCaller::Owner(&fixture.proof),
        None,
        &hand,
    )?;
    assert_placement(&fixture, rows, fixture.alpha)
}

#[test]
fn a_hand_over_with_no_folder_digests_or_an_unbound_folder_lands_at_the_default_project()
-> TestResult {
    let fixture = open()?;
    for digests in [Vec::new(), vec![UNBOUND_DIGEST.to_owned()]] {
        let hand = hand_over(&fixture, digests);
        let rows = land(
            &fixture,
            HistoryImportCaller::Owner(&fixture.proof),
            None,
            &hand,
        )?;
        assert_placement(&fixture, rows, default_project_id())?;
    }
    Ok(())
}

/// Before PR B (#10607) every session reads every row; after B this holds only because the
/// hand-over was placed, so its red runs after both merge.
#[test]
fn a_bound_session_reads_a_hand_over_placed_in_its_folders_project() -> TestResult {
    let fixture = open()?;
    let hand = hand_over(&fixture, vec![MAIN_DIGEST.to_owned()]);
    let rows = land(
        &fixture,
        HistoryImportCaller::Owner(&fixture.proof),
        None,
        &hand,
    )?;
    let session = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .in_session_workspace(&[MAIN_DIGEST.to_owned()]);
    for row in rows {
        for id in [row.turn, row.message] {
            let read = session
                .get_entity(&id.to_hex())
                .map_err(|error| format!("vault.get {}: {error:?}", id.to_hex()))?;
            assert!(
                read.value.is_some(),
                "the bound session point-reads the placed row {}",
                id.to_hex()
            );
        }
    }
    Ok(())
}

#[test]
fn a_granted_agent_whose_credential_does_not_cover_the_folders_project_is_refused_and_nothing_lands()
-> TestResult {
    let fixture = open()?;
    let hand = hand_over(&fixture, vec![MAIN_DIGEST.to_owned()]);
    let slip = agent_credential(
        &fixture,
        0x51,
        ScopeAxis::Some(BTreeSet::from([ScopeId(fixture.beta)])),
    );
    for presented in [Some(&slip), None] {
        let error = fixture
            .vault
            .import_hook_transcript(
                HistoryImportCaller::GrantedAgent(fixture.agent),
                presented,
                &hand.request,
            )
            .expect_err("a hand-over the credential does not cover is refused");
        assert_eq!(
            error.code, MEMORY_CODE_FORBIDDEN,
            "the refused hand-over answers FORBIDDEN: {error:?}"
        );
        assert!(
            error.message.contains(&fixture.alpha.to_hex()),
            "the refusal names the session project: {}",
            error.message,
        );
        assert!(
            error
                .suggestions
                .iter()
                .any(|hint| hint.contains("owner hand the log over")),
            "the refusal says to hand the log over under a covering credential: {error:?}"
        );
    }
    assert_nothing_landed(&fixture, &hand)?;
    Ok(())
}

#[test]
fn a_granted_agent_whose_credential_covers_the_folders_project_lands_there() -> TestResult {
    let fixture = open()?;
    let cases = [
        (
            0x52,
            ScopeAxis::Some(BTreeSet::from([ScopeId(fixture.alpha)])),
        ),
        (0x53, ScopeAxis::All),
    ];
    for (seed, audience) in cases {
        let hand = hand_over(&fixture, vec![MAIN_DIGEST.to_owned()]);
        let slip = agent_credential(&fixture, seed, audience);
        let rows = land(
            &fixture,
            HistoryImportCaller::GrantedAgent(fixture.agent),
            Some(&slip),
            &hand,
        )?;
        assert_placement(&fixture, rows, fixture.alpha)?;
    }
    Ok(())
}

#[test]
fn a_granted_agent_hand_over_with_no_folder_digests_lands_at_the_default_as_before() -> TestResult {
    let fixture = open()?;
    let hand = hand_over(&fixture, Vec::new());
    let slip = agent_credential(
        &fixture,
        0x54,
        ScopeAxis::Some(BTreeSet::from([ScopeId(fixture.beta)])),
    );
    let rows = land(
        &fixture,
        HistoryImportCaller::GrantedAgent(fixture.agent),
        Some(&slip),
        &hand,
    )?;
    assert_placement(&fixture, rows, default_project_id())
}

#[test]
fn a_malformed_or_a_third_folder_digest_is_refused_before_anything_lands() -> TestResult {
    let fixture = open()?;
    for digests in [
        vec!["not-a-digest".to_owned()],
        vec![
            MAIN_DIGEST.to_owned(),
            UNBOUND_DIGEST.to_owned(),
            THIRD_DIGEST.to_owned(),
        ],
    ] {
        let hand = hand_over(&fixture, digests);
        let error = fixture
            .vault
            .import_hook_transcript(
                HistoryImportCaller::Owner(&fixture.proof),
                None,
                &hand.request,
            )
            .expect_err("a hand-over with bad folder digests is refused");
        assert_eq!(
            error.code, MEMORY_CODE_BAD_REQUEST,
            "the refused hand-over answers BAD_REQUEST: {error:?}"
        );
        assert_nothing_landed(&fixture, &hand)?;
    }
    Ok(())
}
