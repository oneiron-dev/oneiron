//! SGN06-WHO-MAY-SEND = B (lead 17 Nov 07:0x), the red half. An agent may
//! send for a signing principal only under the standing Grant the owner gave
//! that agent for it. Before the ruling the principal's own row decided: any
//! agent whose Gate admitted the send could send for a principal at
//! `autonomous_in_envelope`. The guard: the owner's approve-once press
//! releases one send even from an agent he gave no Grant (side ruling 3).
//!
//! This file uses only the API main already has, so it builds on both trees:
//! the first test fails on main (the send is delivered) and passes on the
//! head; the guard passes on both.

use std::sync::Arc;

use oneiron::authority::HostSlipIssuer;
use oneiron::blob_artifact::esign::{
    DocumentStatus, EsignCreateRequest, EsignDispatchRequest, EsignDispatchView, EsignDocument,
    SigningAutonomy, SigningPrincipal,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::MemoryResult;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::test_support::{bind_host_actor, bind_host_owner};
use oneiron::verbs::{AgentDefinitionCreateRequest, create_agent_definition_as};
use oneiron::write_envelope::EffectDigest;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const T0: u64 = 1_800_000_000;
const DAY: u64 = 86_400;
const ESIGN_VERBS: [&str; 4] = ["send_for_signature", "remind", "extend", "void"];

fn original_pdf() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf"
    ))
}

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    issuer: HostSlipIssuer,
    owner: EntityId,
    /// The PERSON the documents are sent for.
    principal: EntityId,
    /// An agent the e-sign policy lets send on the e-sign channel.
    agent: EntityId,
    /// An agent no policy Grant covers: the Gate holds its every send.
    unbound: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    /// A vault on a manual clock at `T0`: its embedded owner, a principal
    /// PERSON, two enabled agents, and a policy that lets the owner and the
    /// first agent act on the e-sign channel.
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let clock = ManualClock::new(T0);
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open(dir.path(), config)?;
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let at = TimeRange { start: T0, end: T0 };
        let owner = vault.ensure_embedded_owner_actor()?;
        vault.put_entity(
            &owner,
            oneiron::registry::ENTITY_TYPE_PERSON,
            at,
            T0,
            b"owner",
        )?;
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        bind_host_owner(&vault, &issuer, owner)?;
        let principal = EntityId::now();
        vault.put_entity(
            &principal,
            oneiron::registry::ENTITY_TYPE_PERSON,
            at,
            T0,
            b"principal",
        )?;
        let proof = owner_proof(&vault, owner)?;
        let agent = create_agent(&vault, &proof, "fixture.esign.sender")?;
        let unbound = create_agent(&vault, &proof, "fixture.esign.unbound")?;
        let mut scoped_grants = Vec::new();
        for actor in [owner, agent] {
            for verb in ESIGN_VERBS {
                scoped_grants.push(json!({
                    "actor_ref": actor.to_hex(),
                    "effector": format!("external:{verb}"),
                    "scope": oneiron::test_support::effect_preset(),
                    "selectors": {"channel": "esign"},
                }));
            }
        }
        let policy = json!({
            "schema_version": "1.2", "pack_id": "esign-principal-binding-test",
            "pack_version": "v1", "min_engine_version": "0.0.0",
            "defaults": {"criticality": "normal", "sensitivity": "normal"},
            "rules": [],
            "actor_ceilings": [
                {"actor_class": "human", "actor_ref": owner.to_hex(), "ceiling": "auto"},
                {"actor_class": "agent", "actor_ref": agent.to_hex(), "ceiling": "auto"},
                {"actor_class": "agent", "actor_ref": unbound.to_hex(), "ceiling": "auto"},
            ],
            "scoped_grants": scoped_grants,
        });
        oneiron::test_support::put_policy_manifest_bytes(
            &vault,
            EntityId::now(),
            &rmp_serde::to_vec_named(&policy)?,
        )?;
        Ok(Self {
            vault,
            _clock: clock,
            issuer,
            owner,
            principal,
            agent,
            unbound,
            _dir: dir,
        })
    }

    fn proof(&self) -> TestResult<AuthenticatedOwner> {
        owner_proof(&self.vault, self.owner)
    }

    /// A one-recipient document the owner drafts on a fresh PDF, naming no
    /// principal, with its recipient's link already issued.
    fn draft(&self) -> TestResult<EntityId> {
        let at = TimeRange { start: T0, end: T0 };
        let document = EntityId::now();
        self.vault.put_blob_artifact(
            &document,
            &oneiron::blob_artifact::BlobArtifactBody::new("agreement.pdf", "application/pdf"),
            at,
            T0,
        )?;
        self.vault.append_blob_artifact_version(
            &document,
            original_pdf(),
            &oneiron::blob_artifact::BlobVersionProvenance::UserUpload,
            oneiron::write_envelope::WriteActor::new(self.owner, EdgeActorClass::Human),
            at,
            T0,
        )?;
        let draft: EsignDocument = serde_json::from_value(draft_json(document))?;
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .esign_create(&EsignCreateRequest {
                document_ref: document.to_hex(),
                draft,
                qr_pdf_download: false,
            })?;
        self.vault
            .issue_esign_capabilities(&self.proof()?, document)?;
        Ok(document)
    }

    /// `agent`'s send of `document` for `on_behalf_of`, with the host key
    /// bound to the agent for the call.
    fn agent_send(
        &self,
        agent: EntityId,
        document: EntityId,
        on_behalf_of: Option<EntityId>,
        key: &str,
    ) -> TestResult<MemoryResult<EsignDispatchView>> {
        bind_host_actor(&self.vault, &self.issuer, agent, "agent")?;
        let sent = self
            .vault
            .memory(agent, EdgeActorClass::Agent)
            .esign_send_for_signature(&EsignDispatchRequest {
                document_ref: document.to_hex(),
                recipient_count: 1,
                on_behalf_of: on_behalf_of.map(|principal| principal.to_hex()),
                idempotency_key: Some(key.to_owned()),
            });
        bind_host_owner(&self.vault, &self.issuer, self.owner)?;
        Ok(sent)
    }

    fn status(&self, document: EntityId) -> TestResult<DocumentStatus> {
        Ok(self.vault.esign_document(document)?.status)
    }
}

fn owner_proof(vault: &Vault, owner: EntityId) -> TestResult<AuthenticatedOwner> {
    Ok(vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?)
}

/// An enabled agent definition the owner creates.
fn create_agent(vault: &Vault, proof: &AuthenticatedOwner, agent_id: &str) -> TestResult<EntityId> {
    let id = EntityId::now();
    create_agent_definition_as(
        vault,
        proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: id,
            definition: serde_json::from_value(json!({
                "agent_id": agent_id,
                "desc": "e-sign principal binding fixture",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))?,
        },
    )?;
    Ok(id)
}

/// The draft as JSON, so this file builds on a tree whose document has no
/// principal field.
fn draft_json(document: EntityId) -> Value {
    json!({
        "schema_version": 1,
        "kind": "document",
        "title": "Agreement",
        "sequential": false,
        "expires_at": T0 + 90 * DAY,
        "items": [{"artifact_ref": document.to_hex(), "original_version": 1}],
        "recipients": [{
            "id": EntityId::now().to_hex(),
            "email": "owen@example.com",
            "name": "Owen",
            "role": "approver",
            "order": 0,
            "expires_at": T0 + 90 * DAY,
            "principal_ref": null,
            "automated": false,
        }],
        "fields": [],
        "full_trail_appendix": true,
    })
}

/// The effect digest a held dispatch names, as hex.
fn effect_digest(view: &EsignDispatchView) -> TestResult<EffectDigest> {
    let hex = view
        .approval_digest
        .as_deref()
        .ok_or_else(|| format!("a held send names its approval digest: {view:?}"))?;
    let hex = hex.get(hex.len().saturating_sub(64)..).unwrap_or(hex);
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(
            hex.get(2 * index..2 * index + 2)
                .ok_or("the approval digest is 32 bytes of hex")?,
            16,
        )?;
    }
    Ok(EffectDigest::from_bytes(bytes))
}

#[test]
fn an_agent_send_for_a_principal_it_holds_no_grant_for_is_refused() -> TestResult {
    let fx = Fixture::new()?;
    fx.vault.set_signing_principals(
        &fx.proof()?,
        &[SigningPrincipal {
            principal_ref: fx.principal.to_hex(),
            autonomy: SigningAutonomy::AutonomousInEnvelope,
            automated_sign_action: false,
        }],
    )?;
    let document = fx.draft()?;

    // The Gate admits the agent's own send (its policy Grant covers it), and
    // the principal's row is at its top rung. The owner never gave this agent
    // a Grant to act for the principal, so the send does not go out.
    let sent = fx.agent_send(fx.agent, document, Some(fx.principal), "send-unbound")?;
    if let Ok(view) = &sent {
        assert_ne!(
            view.outcome, "delivered_to_channel",
            "an agent with no Grant for the principal sends nothing for it: {view:?}"
        );
    }
    assert_eq!(
        fx.status(document)?,
        DocumentStatus::Draft,
        "the refused send leaves the document a draft: {sent:?}"
    );
    Ok(())
}

#[test]
fn the_owner_press_releases_an_unbound_agent_send() -> TestResult {
    let fx = Fixture::new()?;
    let document = fx.draft()?;

    // No policy Grant covers this agent's send and the owner gave it no
    // Grant for the principal: the Gate holds the send for the owner.
    let held = fx.agent_send(fx.unbound, document, Some(fx.principal), "send-pressed")??;
    assert_ne!(
        held.outcome, "delivered_to_channel",
        "an unbound agent's send waits for the owner: {held:?}"
    );
    assert_eq!(fx.status(document)?, DocumentStatus::Draft);

    // The owner's approve-once press releases that one send: the retry under
    // the same key goes out.
    fx.vault.approve_once(&fx.proof()?, effect_digest(&held)?)?;
    let released = fx.agent_send(fx.unbound, document, Some(fx.principal), "send-pressed")??;
    assert_eq!(
        released.outcome, "delivered_to_channel",
        "the press releases the held send: {released:?}"
    );
    assert_eq!(fx.status(document)?, DocumentStatus::Pending);

    // The press made no standing Grant: the agent's next act asks again.
    let next = fx.draft()?;
    let again = fx.agent_send(fx.unbound, next, Some(fx.principal), "send-next")??;
    assert_ne!(
        again.outcome, "delivered_to_channel",
        "the next send waits for the owner again: {again:?}"
    );
    assert!(
        again.approval_digest.is_some(),
        "the next send is held for a press of its own: {again:?}"
    );
    Ok(())
}
