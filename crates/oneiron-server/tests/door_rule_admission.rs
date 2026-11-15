//! The check a host-door row's door runs before the row's pre hooks
//! (`row_door_admits`, FIX 1763) admits the same callers under every proof
//! kind, before and after the proof table (UC-01 PR 0a): a guard, green on
//! main and on every later UC-01 PR.
//!
//! One row per proof kind the rows name today, plus one row per check of
//! the old hand list of verb names, which 0a moves into the rows. That is
//! one row or more per rule of the table, so a kind folded into a shared
//! rule keeps who it admits. Each row is judged for three callers, each on
//! its own slip with its holder proof:
//! - `owner`: this install's host root, a self-hosted vault's owner;
//! - `agent`: a registered agent principal on its own slip (actor class
//!   `agent`, read, propose and write), holding no Grant;
//! - `unbound`: a slip naming a principal the vault does not know, with no
//!   actor class.
//!
//! The table below is what main admits. A mismatch lists every row's
//! observed answers at once. `vault.coach.training_offers.run`
//! (`engine_controller`) is left out: its kind is `substrate_reader`'s own
//! fn, and Setting stage 2 deletes its 14 rows.
//!
//! Deterministic: in-process vault and server, no HTTP, no models.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --test door_rule_admission`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::http::{HeaderMap, HeaderValue};
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::door_rule_admission::row_door_admits;
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Admitted before the row's hooks.
const IN: bool = true;
/// Refused before the row's hooks.
const OUT: bool = false;

/// `(kind or hand-list check, row, owner, agent, unbound)`, as main admits.
const ROWS: &[(&str, &str, bool, bool, bool)] = &[
    // The owner's proof.
    ("owner", "ai.reply", IN, OUT, OUT),
    // A person: the owner, or a live person on their own human slip.
    ("shared_person", "vault.code.waits.receipt", IN, OUT, OUT),
    (
        "trusted_contact_person",
        "vault.trusted_contacts.concern.asks",
        IN,
        OUT,
        OUT,
    ),
    // A member: as a person, bound as one.
    (
        "workflow_member",
        "vault.workflows.dispatch_bound",
        IN,
        OUT,
        OUT,
    ),
    ("check_in_holder", "vault.check_in.answer", IN, OUT, OUT),
    // The owner, else a person or agent on its own verified slip.
    ("substrate_reader", "vault.imports.get", IN, IN, OUT),
    ("run_reader", "vault.budgets.lease", IN, IN, OUT),
    ("skill_reader", "vault.skills.get", IN, IN, OUT),
    ("import_canceller", "vault.imports.cancel", IN, IN, OUT),
    ("skill_forker", "vault.skills.fork", IN, IN, OUT),
    // The owner, else the credential's own actor.
    ("claim_settler", "vault.claims.review", IN, IN, OUT),
    ("consent_revoker", "vault.consent.revoke", IN, IN, OUT),
    (
        "model_binding_proposer",
        "vault.models.bindings.propose",
        IN,
        IN,
        OUT,
    ),
    // The credential's own actor.
    (
        "origin_publish",
        "vault.code.origin.publish.approve",
        IN,
        IN,
        OUT,
    ),
    ("diary_reader", "self.memory.diary.pinned", IN, IN, OUT),
    ("facade_actor", "crawl", IN, IN, OUT),
    ("artifact_asker", "vault.artifacts.admit", IN, IN, OUT),
    ("code_import", "vault.code.imports.create", IN, IN, OUT),
    (
        "slide_reviewer",
        "vault.artifacts.review_slides",
        IN,
        IN,
        OUT,
    ),
    ("image_editor", "vault.artifacts.image.edit", IN, IN, OUT),
    (
        "hand list: share_doors::principal",
        "vault.shares.view",
        IN,
        IN,
        OUT,
    ),
    (
        "hand list: weave_doors::own_caller",
        "vault.weave.lens",
        IN,
        IN,
        OUT,
    ),
    // The credential's own actor, on a credential that is not channel-bound.
    (
        "code_export_preview",
        "vault.code.export.preview",
        IN,
        IN,
        OUT,
    ),
    (
        "review_policy",
        "vault.code.merge_queue.review_policy.get",
        IN,
        IN,
        OUT,
    ),
    ("view_editor", "vault.code.views.edit", IN, IN, OUT),
    (
        "checkout_holder",
        "vault.code.checkout.holder.bind",
        IN,
        IN,
        OUT,
    ),
    // An owner-grade credential.
    ("media_owner_grade", "ai.embed", IN, OUT, OUT),
    ("video_job_owner_grade", "ai.video.cancel", IN, OUT, OUT),
    // The caller, then the usage-repair writer's admission for the verb.
    (
        "usage_repair_list",
        "vault.usage.events.undecodable",
        IN,
        OUT,
        OUT,
    ),
    (
        "usage_repair_remove",
        "vault.usage.events.remove_undecodable",
        IN,
        OUT,
        OUT,
    ),
    (
        "usage_repair_receipts",
        "vault.usage.repair.receipts",
        IN,
        OUT,
        OUT,
    ),
    // The rules that stay one kind each.
    ("off_record", "self.off_record.execute", IN, IN, OUT),
    (
        "off_record_room",
        "vault.off_record.rooms.confirm_save",
        OUT,
        OUT,
        OUT,
    ),
    ("voice_bank", "vault.voices.inspect", IN, IN, OUT),
    (
        "booking_owner_act",
        "vault.booking.availability",
        IN,
        OUT,
        OUT,
    ),
    ("packs_setup", "vault.packs.put", IN, IN, OUT),
    ("decision_holder", "self.decisions.asks", OUT, IN, OUT),
    ("hyde_caller", "vault.retrieval.hyde.complete", IN, IN, OUT),
    (
        "guest_document_reader",
        "vault.guests.export_envelope",
        OUT,
        OUT,
        OUT,
    ),
    (
        "tradeoff_picker",
        "vault.skills.optimize.tradeoff_asks",
        IN,
        IN,
        OUT,
    ),
    ("artifact_publisher", "vault.artifacts.publish", IN, IN, OUT),
    ("model_step_caller", "ai.steps.receipt", IN, IN, OUT),
    ("policy_putter", "vault.gate.policy.put", IN, OUT, OUT),
    (
        "ramp_demoter",
        "vault.consent.graduation.demote",
        IN,
        OUT,
        OUT,
    ),
    ("grants_answer", "self.grants.answer", IN, OUT, OUT),
    ("credential_holder", "self.credential.attenuate", IN, IN, IN),
    ("foreign_code", "execute_code", IN, OUT, OUT),
    ("verdict_asker", "ai.verdict", IN, IN, IN),
    (
        "hand list: graph_ask_doors::asker",
        "vault.graph.ask",
        IN,
        IN,
        IN,
    ),
    (
        "eval_authoring",
        "vault.evals.authoring.execute",
        IN,
        OUT,
        OUT,
    ),
    ("saved_query", "self.saved_query.evaluate", IN, OUT, OUT),
    // A person who also binds an actor (the old hand list's weave labels).
    (
        "hand list: weave_doors::person_lens",
        "vault.weave.link.wrong",
        IN,
        OUT,
        OUT,
    ),
];

/// How a slip's holder proves possession of it.
enum Holder {
    /// The host root: the issuer signs its binding proof.
    Root,
    /// A minted slip: its holder's own key signs the binding transcript.
    Key(SigningKey),
}

/// A slip and the proof of its holder.
struct Credential {
    slip: CapabilitySlip,
    holder: Holder,
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    server: Arc<SyncServer>,
    issuer: HostSlipIssuer,
    owner: Credential,
    agent: Credential,
    unbound: Credential,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A slip minted under `root`'s issuer for `holder_ref`, with `actor_class`,
/// read, propose and write (never owner grade), held by the key `seed`.
fn mint(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    root: &CapabilitySlip,
    holder_ref: String,
    actor_class: Option<&str>,
    seed: u8,
) -> TestResult<Credential> {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let mut claims = root.claims.clone();
    claims.parent_id = None;
    claims.holder_ref = holder_ref;
    claims.binding_key = key.verifying_key().to_bytes();
    claims.actor_class = actor_class.map(str::to_owned);
    claims.scope = Scope::top();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "read".to_owned(),
        "propose".to_owned(),
        "write".to_owned(),
    ]));
    claims.slip_id = [seed; 32];
    Ok(Credential {
        slip: vault.mint_capability_slip(issuer, claims)?,
        holder: Holder::Key(key),
    })
}

fn setup() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some("door-rule-admission".into()),
            ..Default::default()
        },
    )?);
    let issuer = vault.load_host_slip_issuer()?;
    let root = vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let agent_ref = vault.ensure_agent_principal("door-rule-admission-agent")?;
    let agent = mint(
        &vault,
        &issuer,
        &root,
        agent_ref.to_hex(),
        Some("agent"),
        0x71,
    )?;
    let unbound = mint(&vault, &issuer, &root, EntityId::now().to_hex(), None, 0x72)?;
    Ok(Fixture {
        _dir: dir,
        vault,
        server,
        issuer,
        owner: Credential {
            slip: root,
            holder: Holder::Root,
        },
        agent,
        unbound,
    })
}

/// The request headers `credential` presents: its token and a fresh holder
/// proof.
fn headers(fixture: &Fixture, credential: &Credential) -> TestResult<HeaderMap> {
    let timestamp = fixture.vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature = match &credential.holder {
        Holder::Root => hex(&fixture
            .issuer
            .binding_proof(&credential.slip, challenge.as_bytes())?),
        Holder::Key(key) => {
            let transcript = credential.slip.binding_transcript(challenge.as_bytes())?;
            hex(&key.sign(&transcript).to_bytes())
        }
    };
    let binding = json!({"timestamp": timestamp, "nonce": nonce, "signature": signature});
    let mut map = HeaderMap::new();
    map.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {}", credential.slip.to_token()?))?,
    );
    map.insert(
        "x-oneiron-binding",
        HeaderValue::from_str(&binding.to_string())?,
    );
    Ok(map)
}

/// Every row admits before its hooks exactly the callers main admits. A
/// mismatch names every row's observed answers.
#[test]
fn each_proof_kind_admits_the_callers_main_admits() -> TestResult {
    let fixture = setup()?;
    let mut observed = Vec::new();
    let mut mismatched = 0;
    for &(kind, verb, owner, agent, unbound) in ROWS {
        let mut answers = Vec::new();
        for (who, credential, expected) in [
            ("owner", &fixture.owner, owner),
            ("agent", &fixture.agent, agent),
            ("unbound", &fixture.unbound, unbound),
        ] {
            let answer = row_door_admits(&fixture.server, &headers(&fixture, credential)?, verb);
            if answer.is_ok() != expected {
                mismatched += 1;
            }
            let shown = match &answer {
                Ok(()) => "IN".to_owned(),
                Err(refusal) => format!("OUT ({refusal})"),
            };
            let mark = if answer.is_ok() == expected {
                ""
            } else {
                " <- expected otherwise"
            };
            answers.push(format!("    {who}: {shown}{mark}"));
        }
        observed.push(format!("  {kind} ({verb}):\n{}", answers.join("\n")));
    }
    assert!(
        mismatched == 0,
        "{mismatched} answers differ from main's table:\n{}",
        observed.join("\n")
    );
    Ok(())
}

/// A credential's refusal is the row check's own: each caller is
/// authenticated, so no answer above is a credential refusal.
#[test]
fn every_caller_is_authenticated() -> TestResult {
    let fixture = setup()?;
    for (who, credential) in [
        ("owner", &fixture.owner),
        ("agent", &fixture.agent),
        ("unbound", &fixture.unbound),
    ] {
        for &(_, verb, ..) in ROWS {
            if let Err(refusal) =
                row_door_admits(&fixture.server, &headers(&fixture, credential)?, verb)
            {
                assert!(
                    !refusal.starts_with("credential:"),
                    "{who} on {verb}: {refusal}"
                );
            }
        }
    }
    Ok(())
}
