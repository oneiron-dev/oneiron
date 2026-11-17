//! SGN06-WHO-MAY-SEND = B (lead 17 Nov 07:0x): the owner's per-agent
//! standing Grant for a signing principal, checked at each use. The rung
//! decides what the agent may do for the principal: draft (`draft`,
//! `send_with_approval`) or send inside a volume envelope
//! (`autonomous_in_envelope`); the Grant admits only its own agent, a
//! revoke ends it, and an act is for the principal its document names.
//! Green only: main has no Grant to apply (the red half is
//! esign_principal_binding.rs).

use std::sync::Arc;

use oneiron::authority::HostSlipIssuer;
use oneiron::blob_artifact::esign::{
    DocumentStatus, EsignAutonomy, EsignAutonomyRequest, EsignCreateRequest, EsignDispatchRequest,
    EsignDispatchView, EsignDocument, EsignDraftView, EsignSendEnvelope, SigningAutonomy,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::MemoryResult;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::test_support::{bind_host_actor, bind_host_owner};
use oneiron::verbs::{AgentDefinitionCreateRequest, create_agent_definition_as};
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
    clock: Arc<ManualClock>,
    issuer: HostSlipIssuer,
    owner: EntityId,
    /// The PERSON the documents are sent for.
    principal: EntityId,
    /// An agent the e-sign policy lets send on the e-sign channel.
    agent: EntityId,
    /// A second agent the same policy lets send.
    other: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    /// A vault on a manual clock at `T0`: its embedded owner, a principal
    /// PERSON, two enabled agents, and a policy that lets the owner and both
    /// agents act on the e-sign channel.
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
        let other = create_agent(&vault, &proof, "fixture.esign.other")?;
        let mut scoped_grants = Vec::new();
        for actor in [owner, agent, other] {
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
            "schema_version": "1.2", "pack_id": "esign-principal-grants-test",
            "pack_version": "v1", "min_engine_version": "0.0.0",
            "defaults": {"criticality": "normal", "sensitivity": "normal"},
            "rules": [],
            "actor_ceilings": [
                {"actor_class": "human", "actor_ref": owner.to_hex(), "ceiling": "auto"},
                {"actor_class": "agent", "actor_ref": agent.to_hex(), "ceiling": "auto"},
                {"actor_class": "agent", "actor_ref": other.to_hex(), "ceiling": "auto"},
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
            clock,
            issuer,
            owner,
            principal,
            agent,
            other,
            _dir: dir,
        })
    }

    fn proof(&self) -> TestResult<AuthenticatedOwner> {
        owner_proof(&self.vault, self.owner)
    }

    /// A fresh one-page PDF artifact the owner uploaded.
    fn artifact(&self) -> TestResult<EntityId> {
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
        Ok(document)
    }

    /// `actor`'s draft of a one-recipient document on `document`, naming
    /// `principal`, with the host key bound to it for the call.
    fn create_as(
        &self,
        actor: EntityId,
        class: EdgeActorClass,
        document: EntityId,
        principal: Option<EntityId>,
    ) -> TestResult<MemoryResult<EsignDraftView>> {
        let mut draft = draft_json(document);
        if let Some(principal) = principal {
            draft["principal_ref"] = json!(principal.to_hex());
        }
        let draft: EsignDocument = serde_json::from_value(draft)?;
        if class != EdgeActorClass::Human {
            bind_host_actor(&self.vault, &self.issuer, actor, "agent")?;
        }
        let created = self
            .vault
            .memory(actor, class)
            .esign_create(&EsignCreateRequest {
                document_ref: document.to_hex(),
                draft,
                qr_pdf_download: false,
            });
        bind_host_owner(&self.vault, &self.issuer, self.owner)?;
        Ok(created)
    }

    /// A document the owner drafts for the principal, with its recipient's
    /// link already issued.
    fn draft(&self) -> TestResult<EntityId> {
        let document = self.artifact()?;
        self.create_as(
            self.owner,
            EdgeActorClass::Human,
            document,
            Some(self.principal),
        )??;
        self.vault
            .issue_esign_capabilities(&self.proof()?, document)?;
        Ok(document)
    }

    /// The owner's rung for `agent` acting for the principal.
    fn apply(
        &self,
        agent: EntityId,
        rung: SigningAutonomy,
        envelope: Option<EsignSendEnvelope>,
    ) -> TestResult<EsignAutonomy> {
        Ok(self.vault.apply_esign_autonomy(
            &self.proof()?,
            &EsignAutonomyRequest {
                agent,
                principal: self.principal,
                rung,
                envelope,
            },
        )?)
    }

    /// A second PERSON no Grant names.
    fn stranger(&self) -> TestResult<EntityId> {
        let stranger = EntityId::now();
        self.vault.put_entity(
            &stranger,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: T0, end: T0 },
            T0,
            b"stranger",
        )?;
        Ok(stranger)
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

fn delivered(sent: &MemoryResult<EsignDispatchView>) -> bool {
    matches!(sent, Ok(view) if view.outcome == "delivered_to_channel")
}

const TWO_A_DAY: EsignSendEnvelope = EsignSendEnvelope {
    max_actions: 2,
    window_secs: DAY,
};

#[test]
fn an_autonomous_grant_lands_its_agent_send_until_the_window_is_full() -> TestResult {
    let fx = Fixture::new()?;
    let chosen = fx.apply(
        fx.agent,
        SigningAutonomy::AutonomousInEnvelope,
        Some(TWO_A_DAY),
    )?;
    assert!(
        chosen.grant_ref.is_some(),
        "the rung holds a Grant: {chosen:?}"
    );
    let [first, second, third] = [fx.draft()?, fx.draft()?, fx.draft()?];

    for (document, key) in [(first, "send-1"), (second, "send-2")] {
        let sent = fx.agent_send(fx.agent, document, None, key)?;
        assert!(
            delivered(&sent),
            "a send inside the envelope lands: {sent:?}"
        );
        assert_eq!(fx.status(document)?, DocumentStatus::Pending);
    }
    let full = fx.agent_send(fx.agent, third, None, "send-3")?;
    assert!(
        !delivered(&full),
        "the third send in one day is refused: {full:?}"
    );
    assert_eq!(fx.status(third)?, DocumentStatus::Draft);

    fx.clock.set(T0 + DAY);
    let next = fx.agent_send(fx.agent, third, None, "send-3-next-day")?;
    assert!(delivered(&next), "a new window takes the send: {next:?}");
    Ok(())
}

#[test]
fn a_grant_admits_only_its_own_agent() -> TestResult {
    let fx = Fixture::new()?;
    fx.apply(
        fx.agent,
        SigningAutonomy::AutonomousInEnvelope,
        Some(TWO_A_DAY),
    )?;
    let document = fx.draft()?;

    let sent = fx.agent_send(fx.other, document, None, "send-other")?;
    assert!(
        !delivered(&sent),
        "another agent's send for the principal is refused: {sent:?}"
    );
    assert_eq!(fx.status(document)?, DocumentStatus::Draft);

    let own = fx.agent_send(fx.agent, document, None, "send-own")?;
    assert!(delivered(&own), "the Grant's own agent sends: {own:?}");
    Ok(())
}

#[test]
fn a_revoked_grant_stops_the_next_send() -> TestResult {
    let fx = Fixture::new()?;
    let chosen = fx.apply(
        fx.agent,
        SigningAutonomy::AutonomousInEnvelope,
        Some(TWO_A_DAY),
    )?;
    let grant_ref = chosen.grant_ref.ok_or("the rung holds a Grant")?;
    let [first, second] = [fx.draft()?, fx.draft()?];
    let sent = fx.agent_send(fx.agent, first, None, "send-1")?;
    assert!(delivered(&sent), "the live Grant sends: {sent:?}");

    fx.vault.revoke_consent_grant(&fx.proof()?, &grant_ref)?;
    let after = fx.agent_send(fx.agent, second, None, "send-2")?;
    assert!(
        !delivered(&after),
        "a revoked Grant sends nothing: {after:?}"
    );
    assert_eq!(fx.status(second)?, DocumentStatus::Draft);

    // The owner's same choice again mints the Grant afresh.
    fx.apply(
        fx.agent,
        SigningAutonomy::AutonomousInEnvelope,
        Some(TWO_A_DAY),
    )?;
    let again = fx.agent_send(fx.agent, second, None, "send-2-again")?;
    assert!(delivered(&again), "the re-applied Grant sends: {again:?}");
    Ok(())
}

#[test]
fn a_draft_rung_grant_drafts_but_never_sends() -> TestResult {
    let fx = Fixture::new()?;
    let chosen = fx.apply(fx.agent, SigningAutonomy::Draft, None)?;
    assert!(
        chosen.grant_ref.is_some(),
        "the draft rung holds a Grant: {chosen:?}"
    );
    let document = fx.artifact()?;
    let drafted = fx.create_as(
        fx.agent,
        EdgeActorClass::Agent,
        document,
        Some(fx.principal),
    )?;
    assert!(drafted.is_ok(), "the draft rung drafts: {drafted:?}");
    fx.vault.issue_esign_capabilities(&fx.proof()?, document)?;

    let sent = fx.agent_send(fx.agent, document, None, "send-drafted")?;
    assert!(!delivered(&sent), "the draft rung never sends: {sent:?}");
    assert_eq!(fx.status(document)?, DocumentStatus::Draft);

    // Send-with-approval holds the same Grant: still no send of its own.
    let approval = fx.apply(fx.agent, SigningAutonomy::SendWithApproval, None)?;
    assert_eq!(
        approval.grant_ref, chosen.grant_ref,
        "one Grant for both rungs"
    );
    let sent = fx.agent_send(fx.agent, document, None, "send-approval")?;
    assert!(
        !delivered(&sent),
        "send-with-approval waits for the press: {sent:?}"
    );
    Ok(())
}

#[test]
fn an_agent_drafts_only_for_a_principal_its_grant_names() -> TestResult {
    let fx = Fixture::new()?;
    let agent_draft = |principal: Option<EntityId>| -> TestResult<MemoryResult<EsignDraftView>> {
        let document = fx.artifact()?;
        fx.create_as(fx.agent, EdgeActorClass::Agent, document, principal)
    };

    let none = agent_draft(Some(fx.principal))?;
    assert!(none.is_err(), "no rung, no draft: {none:?}");
    fx.apply(fx.agent, SigningAutonomy::ScopedRead, None)?;
    let read_only = agent_draft(Some(fx.principal))?;
    assert!(
        read_only.is_err(),
        "scoped_read drafts nothing: {read_only:?}"
    );

    fx.apply(fx.agent, SigningAutonomy::Draft, None)?;
    let unnamed = agent_draft(None)?;
    assert!(
        unnamed.is_err(),
        "an agent's draft names its principal: {unnamed:?}"
    );
    let stranger = agent_draft(Some(fx.stranger()?))?;
    assert!(
        stranger.is_err(),
        "a principal the Grant does not name is refused: {stranger:?}"
    );
    let named = agent_draft(Some(fx.principal))?;
    assert!(
        named.is_ok(),
        "the named principal's draft lands: {named:?}"
    );

    // A human drafts as before, with or without a principal.
    let document = fx.artifact()?;
    let owner_draft = fx.create_as(fx.owner, EdgeActorClass::Human, document, None)?;
    assert!(
        owner_draft.is_ok(),
        "the owner drafts as before: {owner_draft:?}"
    );
    Ok(())
}

#[test]
fn an_on_behalf_of_other_than_the_document_principal_is_refused() -> TestResult {
    let fx = Fixture::new()?;
    fx.apply(
        fx.agent,
        SigningAutonomy::AutonomousInEnvelope,
        Some(TWO_A_DAY),
    )?;
    let stranger = fx.stranger()?;
    let document = fx.draft()?;

    let agent = fx.agent_send(fx.agent, document, Some(stranger), "send-stranger")?;
    assert!(
        !delivered(&agent),
        "an agent's act for another principal is refused: {agent:?}"
    );
    let owner = fx
        .vault
        .memory(fx.owner, EdgeActorClass::Human)
        .esign_send_for_signature(&EsignDispatchRequest {
            document_ref: document.to_hex(),
            recipient_count: 1,
            on_behalf_of: Some(stranger.to_hex()),
            idempotency_key: Some("owner-stranger".into()),
        });
    assert!(
        !delivered(&owner),
        "the owner's act names the document's principal too: {owner:?}"
    );
    assert_eq!(fx.status(document)?, DocumentStatus::Draft);

    let named = fx.agent_send(fx.agent, document, Some(fx.principal), "send-named")?;
    assert!(
        delivered(&named),
        "the document's own principal sends: {named:?}"
    );
    Ok(())
}
