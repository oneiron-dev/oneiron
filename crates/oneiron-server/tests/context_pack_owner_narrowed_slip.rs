//! The owner's own narrowed slip is the owner's credential on the context
//! pack ([CONVERSATION-HOME-OWNER-NARROW-SLIP]; Engine ANSWERS
//! OWNER-NARROW-SLIP-HOME = A and OWNER-NARROW-SLIP-CLAMP = B, 21 Nov).
//!
//! A device slip the owner holds, narrowed by its own holder to the base
//! world, is homed in this vault and is the owner's own session while the
//! owner exemption holds for its key. Its pack serves the stamped claims of
//! this vault that its key reads (search, recall and hydrate already served
//! them). It may name another vault's home and assert owner presence, and
//! in a room it is in, it is the room's proven owner reader. Its world
//! caveat still bounds every row. On the base each of these four cases
//! fails: the pack homed the slip in the unnamed vault and clamped it as an
//! unknown party, public-only. Two guards: an agent's credential on the
//! owner's PERSON, and the owner's narrowed slip handed to another key,
//! stay delegated. Each is homed in the unnamed vault and refused owner
//! presence.
//!
//! Deterministic: in-process vault and router (`oneshot`, no TCP ports, no
//! sleeps, no models, no embedder). Fixture pattern copied from
//! `context_pack_conversation_home.rs` (stamped claims, a room of this vault)
//! and `mcp_caveated_reader.rs` (a slip narrowed by its own holder to a
//! world).
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test context_pack_owner_narrowed_slip`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::on_engine_stack;
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, SlipCaveat, holder_proof_challenge,
};
use oneiron::claim::base_world_id;
use oneiron::conversation::{ConversationBody, ConversationKind};
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CONTEXT_PACK: &str = "/v1/core/context-pack";
/// Another vault's authority id, as the home rule names it.
const OTHER: [u8; 32] = [0x42; 32];
/// The unnamed vault's id ([`oneiron::ConversationHome::UNNAMED`]) as the
/// pack's disclosure block names it: 32 zero bytes, 64 hex.
const UNNAMED_HOME: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// When the seeded claims and their subject were learned and hold.
const LEARNED_AT: u64 = 1_780_000_000;
/// The word every seeded claim holds, which no other row holds.
const SHARED_WORD: &str = "lanternwick";
/// The one word each seeded claim alone holds.
const UNSTAMPED_WORD: &str = "juniper";
const PUBLIC_WORD: &str = "sorrel";
const PRIVATE_WORD: &str = "wren";
const SENSITIVE_WORD: &str = "lark";
const ELSEWHERE_WORD: &str = "heron";
/// The seeded claims' predicate, which is not Tier A.
const PREDICATE: &str = "profile.note";

/// A slip and the key its holder proves it with.
struct Holder {
    slip: CapabilitySlip,
    key: SigningKey,
}

struct Host {
    _dir: tempfile::TempDir,
    app: Router,
    vault: Arc<Vault>,
    owner: EntityId,
    member: EntityId,
    room: EntityId,
    /// The owner's device slip, narrowed by its own holder to the base world.
    narrowed: Holder,
    /// An agent's credential on the owner's PERSON, narrowed the same way.
    agent_on_owner: Holder,
    /// The owner's narrowed slip handed on to another key.
    handed_on: Holder,
    unstamped: EntityId,
    public: EntityId,
    private_stamped: EntityId,
    sensitive_stamped: EntityId,
    /// A claim stamped private in a world the narrowed slip does not reach.
    elsewhere: EntityId,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// One seeded claim about `subject`, holding `text`, stamped `sensitivity`
/// when named, in `world` when named (else the base world), and indexed for
/// text retrieval.
fn seed_claim(
    vault: &Vault,
    id: &EntityId,
    subject: EntityId,
    text: &str,
    sensitivity: Option<&str>,
    world: Option<EntityId>,
) -> TestResult {
    let mut body = ClaimBody::new(
        PREDICATE,
        ClaimSubject::Entity(subject),
        rmpv::Value::from(text),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    body.world = world;
    if let Some(band) = sensitivity {
        body.scope = Some(rmpv::Value::Map(vec![(
            rmpv::Value::from("sensitivity"),
            rmpv::Value::from(band),
        )]));
    }
    vault.put_claim(
        id,
        &body,
        TimeRange {
            start: LEARNED_AT,
            end: LEARNED_AT,
        },
        LEARNED_AT,
    )?;
    vault.batch().text(id, &[("body", text)]).commit()?;
    Ok(())
}

fn put_person(vault: &Vault, label: &[u8]) -> TestResult<EntityId> {
    let id = EntityId::now();
    vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange {
            start: LEARNED_AT,
            end: LEARNED_AT,
        },
        LEARNED_AT,
        label,
    )?;
    Ok(id)
}

/// A slip for `holder` as `class`, cut from the root's claims with its top
/// scope and bound to a fresh key: the mint itself, uncaveated.
fn mint(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    root: &CapabilitySlip,
    holder: EntityId,
    class: &str,
    seed: u8,
) -> TestResult<Holder> {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let mut claims = root.claims.clone();
    claims.parent_id = None;
    claims.holder_ref = holder.to_hex();
    claims.binding_key = key.verifying_key().to_bytes();
    claims.actor_class = Some(class.to_owned());
    claims.scope = Scope::top();
    claims.slip_id = [seed; 32];
    let slip = vault.mint_capability_slip(issuer, claims)?;
    Ok(Holder { slip, key })
}

/// `holder`'s slip narrowed by its own holder to the base world: a world
/// caveat, the same key, so it is no longer owner-grade and not handed on.
fn narrowed_to_base_world(holder: Holder) -> TestResult<Holder> {
    let mut slip = holder.slip;
    let mut ceiling = Scope::top();
    ceiling.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
    slip.attenuate(
        SlipCaveat {
            scope: Some(ceiling),
            ..Default::default()
        },
        &holder.key,
    )?;
    Ok(Holder {
        slip,
        key: holder.key,
    })
}

impl Host {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.embedding_model = None;
        config.dimensions = 4;
        let vault = Arc::new(Vault::open_owned(dir.path(), config)?);
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let owner = vault.ensure_embedded_owner_actor()?;
        // One PERSON the claims hang off, and one more PERSON seating the
        // room beside the owner.
        let subject = put_person(&vault, b"narrowed slip subject")?;
        let member = put_person(&vault, b"room member")?;
        // Four claims about one PERSON in the base world, each findable by
        // the shared word and its own word.
        let unstamped = EntityId::from_bytes([0x61; 16])?;
        seed_claim(
            &vault,
            &unstamped,
            subject,
            &format!("{SHARED_WORD} {UNSTAMPED_WORD}"),
            None,
            None,
        )?;
        let public = EntityId::from_bytes([0x62; 16])?;
        seed_claim(
            &vault,
            &public,
            subject,
            &format!("{SHARED_WORD} {PUBLIC_WORD}"),
            Some("public"),
            None,
        )?;
        let private_stamped = EntityId::from_bytes([0x63; 16])?;
        seed_claim(
            &vault,
            &private_stamped,
            subject,
            &format!("{SHARED_WORD} {PRIVATE_WORD}"),
            Some("private"),
            None,
        )?;
        let sensitive_stamped = EntityId::from_bytes([0x64; 16])?;
        seed_claim(
            &vault,
            &sensitive_stamped,
            subject,
            &format!("{SHARED_WORD} {SENSITIVE_WORD}"),
            Some("sensitive"),
            None,
        )?;
        let server = Arc::new(SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("context-pack-owner-narrowed-slip".into()),
                ..Default::default()
            },
        )?);
        let issuer = vault.load_host_slip_issuer()?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let proof = vault
            .memory(owner, EdgeActorClass::Human)
            .embedded_owner("vault.disclosure.home.set")?;
        // A fifth claim, stamped private, in a world the narrowed slip's
        // caveat leaves out.
        let other_world = vault.create_world(&proof, "Narrowed slip's other world", LEARNED_AT)?;
        let elsewhere = EntityId::from_bytes([0x65; 16])?;
        seed_claim(
            &vault,
            &elsewhere,
            subject,
            &format!("{SHARED_WORD} {ELSEWHERE_WORD}"),
            Some("private"),
            Some(other_world),
        )?;
        // A room of this vault seating the owner and one more member.
        let room = EntityId::now();
        vault.create_conversation(
            room,
            &ConversationBody {
                kind: ConversationKind::Group,
                member_ids: vec![owner, member],
                ..Default::default()
            },
            WriteActor::new(owner, EdgeActorClass::Human),
            vault.now_recorded_at(),
        )?;
        // The owner's device credential, narrowed by its own holder.
        let narrowed = narrowed_to_base_world(mint(&vault, &issuer, &root, owner, "human", 0x71)?)?;
        // An agent's credential on the owner's PERSON: the same holder, but
        // not the owner's own credential (a PERSON may act as class agent).
        let agent_on_owner =
            narrowed_to_base_world(mint(&vault, &issuer, &root, owner, "agent", 0x72)?)?;
        // The owner's narrowed slip handed on to another key: whoever proves
        // it now is a delegate of the owner, not the owner.
        let next_key = SigningKey::from_bytes(&[0x73; 32]);
        let mut handed_on_slip = narrowed.slip.clone();
        handed_on_slip.attenuate_to(
            SlipCaveat::default(),
            &narrowed.key,
            next_key.verifying_key().to_bytes(),
        )?;
        let handed_on = Holder {
            slip: handed_on_slip,
            key: next_key,
        };
        let app = build_app(server);
        Ok(Self {
            _dir: dir,
            app,
            vault,
            owner,
            member,
            room,
            narrowed,
            agent_on_owner,
            handed_on,
            unstamped,
            public,
            private_stamped,
            sensitive_stamped,
            elsewhere,
        })
    }

    fn binding(&self, holder: &Holder) -> TestResult<String> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let transcript = holder.slip.binding_transcript(&challenge)?;
        let signature = holder.key.sign(&transcript).to_bytes();
        Ok(
            json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&signature)})
                .to_string(),
        )
    }

    async fn pack_as(&self, holder: &Holder, body: Value) -> TestResult<(StatusCode, Value)> {
        let request = Request::post(CONTEXT_PACK)
            .header(
                "authorization",
                format!("Bearer {}", holder.slip.to_token()?),
            )
            .header("x-oneiron-binding", self.binding(holder)?)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let answer: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            panic!(
                "{CONTEXT_PACK} answered no JSON: {}",
                String::from_utf8_lossy(&bytes)
            )
        });
        Ok((status, answer))
    }
}

fn result_ids(pack: &Value) -> Vec<String> {
    pack["results"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row["id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn speakers(pack: &Value) -> Vec<String> {
    pack["interlocutors"]
        .as_array()
        .map(|stamps| {
            stamps
                .iter()
                .filter_map(|stamp| stamp["speaker"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn the_owners_narrowed_slip_reads_its_stamped_claims_in_its_pack() -> TestResult {
    on_engine_stack(|| async {
        let host = Host::new()?;
        let (status, pack) = host
            .pack_as(&host.narrowed, json!({"query": SHARED_WORD, "limit": 10}))
            .await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner's narrowed slip answers 200: {pack}"
        );
        let ids = result_ids(&pack);
        assert!(
            ids.contains(&host.private_stamped.to_hex()),
            "the owner's narrowed slip reads the private stamped claim of this vault: {pack}"
        );
        assert!(
            ids.contains(&host.sensitive_stamped.to_hex()),
            "the owner's narrowed slip reads the sensitive stamped claim of this vault: {pack}"
        );
        assert!(
            pack["disclosure"].is_null(),
            "the owner's own session homed here is not clamped: {pack}"
        );
        assert!(
            ids.contains(&host.unstamped.to_hex()) && ids.contains(&host.public.to_hex()),
            "the owner's narrowed slip still reads the unstamped and public claims: {pack}"
        );
        assert!(
            !ids.contains(&host.elsewhere.to_hex()),
            "the slip's world caveat still bounds its rows: no claim of the other world: {pack}"
        );
        Ok(())
    })
}

#[test]
fn the_owners_narrowed_slip_may_name_another_vaults_home() -> TestResult {
    on_engine_stack(|| async {
        let host = Host::new()?;
        let home = hex(&OTHER);
        let (status, pack) = host
            .pack_as(
                &host.narrowed,
                json!({"query": SHARED_WORD, "limit": 10, "conversation_home": home}),
            )
            .await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner's narrowed slip may home its pack in another vault: {pack}"
        );
        assert_eq!(
            pack["disclosure"]["home"],
            json!(home),
            "the pack names the home vault it was homed in: {pack}"
        );
        let ids = result_ids(&pack);
        assert!(
            ids.contains(&host.unstamped.to_hex()),
            "homed elsewhere, the owner's narrowed slip still reads the unstamped claim: {pack}"
        );
        assert!(
            !ids.contains(&host.private_stamped.to_hex()),
            "homed in an uncleared vault, the private stamped claim stays out: {pack}"
        );
        Ok(())
    })
}

#[test]
fn the_owners_narrowed_slip_may_assert_owner_presence() -> TestResult {
    on_engine_stack(|| async {
        let host = Host::new()?;
        let (status, pack) = host
            .pack_as(
                &host.narrowed,
                json!({
                    "query": SHARED_WORD,
                    "limit": 10,
                    "interlocutors": {"owner_present": true},
                }),
            )
            .await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner's narrowed slip may assert owner presence: {pack}"
        );
        Ok(())
    })
}

#[test]
fn the_owners_narrowed_slip_is_the_proven_reader_of_its_room() -> TestResult {
    on_engine_stack(|| async {
        let host = Host::new()?;
        let (status, pack) = host
            .pack_as(
                &host.narrowed,
                json!({
                    "query": SHARED_WORD,
                    "limit": 10,
                    "conversation_id": host.room.to_hex(),
                }),
            )
            .await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner's narrowed slip reads its own room: {pack}"
        );
        let speakers = speakers(&pack);
        assert!(
            speakers.contains(&host.member.to_hex()),
            "precondition: the room's other member is stamped as a party: {pack}"
        );
        assert!(
            !speakers.contains(&host.owner.to_hex()),
            "the owner reading through its narrowed slip is the room's reader, not a party: {pack}"
        );
        Ok(())
    })
}

#[test]
fn an_agent_credential_on_the_owners_person_stays_delegated() -> TestResult {
    on_engine_stack(|| async {
        let host = Host::new()?;
        let (status, pack) = host
            .pack_as(
                &host.agent_on_owner,
                json!({"query": SHARED_WORD, "limit": 10}),
            )
            .await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "an agent's credential on the owner's PERSON answers 200: {pack}"
        );
        assert_eq!(
            pack["disclosure"]["home"],
            json!(UNNAMED_HOME),
            "an agent's credential on the owner's PERSON is homed in the unnamed vault: {pack}"
        );
        let ids = result_ids(&pack);
        assert!(
            !ids.contains(&host.private_stamped.to_hex())
                && !ids.contains(&host.sensitive_stamped.to_hex()),
            "an agent's credential on the owner's PERSON reads no stamped claim: {pack}"
        );
        let (status, body) = host
            .pack_as(
                &host.agent_on_owner,
                json!({
                    "query": SHARED_WORD,
                    "limit": 10,
                    "interlocutors": {"owner_present": true},
                }),
            )
            .await?;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "an agent's credential on the owner's PERSON may not assert owner presence: {body}"
        );
        assert!(
            body.to_string().contains("interlocutors.owner_present"),
            "the refusal names the owner_present control, got: {body}"
        );
        Ok(())
    })
}

#[test]
fn the_owners_narrowed_slip_handed_to_another_key_stays_delegated() -> TestResult {
    on_engine_stack(|| async {
        let host = Host::new()?;
        let (status, pack) = host
            .pack_as(&host.handed_on, json!({"query": SHARED_WORD, "limit": 10}))
            .await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner's slip in another key's hand answers 200: {pack}"
        );
        assert_eq!(
            pack["disclosure"]["home"],
            json!(UNNAMED_HOME),
            "the owner's slip in another key's hand is homed in the unnamed vault: {pack}"
        );
        let ids = result_ids(&pack);
        assert!(
            !ids.contains(&host.private_stamped.to_hex())
                && !ids.contains(&host.sensitive_stamped.to_hex()),
            "the owner's slip in another key's hand reads no stamped claim: {pack}"
        );
        let (status, body) = host
            .pack_as(
                &host.handed_on,
                json!({
                    "query": SHARED_WORD,
                    "limit": 10,
                    "interlocutors": {"owner_present": true},
                }),
            )
            .await?;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "the owner's slip in another key's hand may not assert owner presence: {body}"
        );
        assert!(
            body.to_string().contains("interlocutors.owner_present"),
            "the refusal names the owner_present control, got: {body}"
        );
        Ok(())
    })
}
