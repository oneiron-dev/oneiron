//! Share-view home clearance (L5-02 PR 3 finding 1), public API only.
//!
//! A brief's view-only share credential is homed in no conversation of this
//! vault: its key is `ScopedReadActorKey::homed_unnamed`, so a pin of a
//! stamped claim renders `redacted` with no quote outside a room turn.
//! Unstamped pins still read with their quotes. The stamped-pin assertions
//! are red on the base (the view-only key read and quoted the stamped claim)
//! and green on the head.
//!
//! Fixture: an owner's vault with two claims (unstamped, sensitive), one
//! source NOTE carrying both quotes, one brief NOTE pinning both, one share
//! of that brief to an outside recipient, the recipient's redeemed view-only
//! credential, and the recipient's view of the brief. Deterministic:
//! in-process vault, no server, no models, no embedder.
//!
//! Run with: `cargo test --locked -p oneiron --all-features --test home_clearance_share_view`

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::access_grant::AccessGrantStatus;
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, VerifiedSlip, pairing_binding_transcript_pinned,
};
use oneiron::claim::{PointRead, ScopedRead};
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::Memory;
use oneiron::note::TakeTarget;
use oneiron::policy_manifest_doors::{
    PolicyGrantMapEntry, PolicyGrantValue, PolicyManifestPut, PolicyManifestRead,
    PolicyScopedGrantRow, policy_manifests_as_owner, put_policy_manifest_as_owner,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::share::Share;
use oneiron::verbs::{
    BriefCitationFollowRequest, ShareViewRequest, follow_brief_citation_as_caller,
    view_shared_brief_as_caller,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// When the seeded claims and their subject were learned and hold.
const LEARNED_AT: u64 = 1_780_000_000;
/// The seeded claims' predicate, which is not Tier A.
const PREDICATE: &str = "profile.note";
/// The source NOTE's text, carrying both pin quotes.
const SOURCE_TEXT: &str = "control quote / secret quote";
/// The unstamped pin's quote, the first span of the source.
const CONTROL_QUOTE: &str = "control quote";
/// The unstamped span's length, the stamped span's start, and the source end.
const CONTROL_LEN: usize = 13;
const SECRET_START: usize = 16;
const SECRET_END: usize = 28;
/// The brief NOTE's markdown.
const BRIEF_MARKDOWN: &str = "# Shared brief\nA control and a secret.";
/// The view link's credential lifetime, in seconds.
const VIEW_SLIP_LIFETIME: u64 = 3_600;
/// Holder-proof challenges are fixed bytes.
const VIEW_CHALLENGE: &[u8] = b"share view read";
const OWNER_CHALLENGE: &[u8] = b"share view owner read";

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    recipient: EntityId,
    verified_view: VerifiedSlip,
    unstamped: EntityId,
    sensitive_stamped: EntityId,
    share: EntityId,
}

/// One seeded claim about `subject`, holding `text`, stamped `sensitivity`
/// when named, and indexed for text retrieval.
fn seed_claim(
    vault: &Vault,
    id: &EntityId,
    subject: EntityId,
    text: &str,
    sensitivity: Option<&str>,
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

/// Whether `lane` serves `id` by point read: a withheld row reads as `None`,
/// exactly like a missing one.
fn lane_reads(lane: &ScopedRead, id: &EntityId) -> TestResult<bool> {
    let read = lane.read(&[PointRead::id(*id)], None)?;
    Ok(read.value.into_iter().next().flatten().is_some())
}

/// The owner's standing permission to create a brief share on the shared
/// channel, through the public owner policy door.
fn permit_brief_share(vault: &Vault, owner: EntityId) -> TestResult {
    let proof = vault
        .memory(owner, EdgeActorClass::Human)
        .embedded_owner("vault.shares.create")?;
    let view =
        policy_manifests_as_owner(vault, &proof, &PolicyManifestRead { manifest_ref: None })?;
    let default = view
        .manifests
        .iter()
        .find(|entry| entry.manifest_ref == view.default_manifest_ref)
        .ok_or("default policy manifest missing")?;
    let mut manifest = default.manifest.clone();
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["effect".to_owned()]));
    let selectors = PolicyGrantValue::Map(vec![PolicyGrantMapEntry {
        key: PolicyGrantValue::String("channel".to_owned()),
        value: PolicyGrantValue::String("shared_brief".to_owned()),
    }]);
    let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
    rows.push(PolicyScopedGrantRow {
        actor_class: None,
        actor_ref: Some(owner.to_hex()),
        effector: "external:share_brief".to_owned(),
        scope,
        selectors: Some(selectors),
        budget: None,
        receipt_required: false,
    });
    manifest.scoped_grants = Some(rows);
    put_policy_manifest_as_owner(
        vault,
        &proof,
        PolicyManifestPut {
            manifest_ref: Some(default.manifest_ref.clone()),
            expected_body_hash: Some(default.body_hash.clone()),
            manifest,
        },
    )?;
    Ok(())
}

/// The recipient's verified view-only credential for `share`: its link is
/// issued, redeemed with a fresh binding key, and holder-verified.
fn issue_and_redeem_view(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    issuer_actor: &WriteActor,
    share: EntityId,
    recipient: EntityId,
) -> TestResult<VerifiedSlip> {
    let link = vault.issue_share_view_link(
        issuer,
        issuer_actor,
        share,
        EdgeActorClass::Human,
        VIEW_SLIP_LIFETIME,
    )?;
    let holder = SigningKey::from_bytes(&[0x77; 32]);
    let binding = holder.verifying_key().to_bytes();
    let holder_ref = recipient.to_hex();
    let transcript =
        pairing_binding_transcript_pinned(&link.code, &binding, &holder_ref, link.pin.as_ref())?;
    let signature = holder.sign(&transcript).to_bytes();
    let slip = vault.redeem_pairing_link(issuer, &link.code, &holder_ref, binding, &signature)?;
    let transcript = slip.binding_transcript(VIEW_CHALLENGE)?;
    let signature = holder.sign(&transcript).to_bytes();
    Ok(vault.verify_capability_slip(&issuer.public_key(), &slip, VIEW_CHALLENGE, &signature)?)
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.embedding_model = None;
        config.dimensions = 4;
        let vault = Vault::open_owned(dir.path(), config)?;
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        let owner = vault.ensure_embedded_owner_actor()?;
        let subject = EntityId::now();
        vault.put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            LEARNED_AT,
            b"share view subject",
        )?;
        let recipient = EntityId::now();
        vault.put_entity(
            &recipient,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            LEARNED_AT,
            b"share recipient",
        )?;
        let unstamped = EntityId::from_bytes([0x51; 16])?;
        seed_claim(&vault, &unstamped, subject, "lanternwick juniper", None)?;
        let sensitive_stamped = EntityId::from_bytes([0x54; 16])?;
        seed_claim(
            &vault,
            &sensitive_stamped,
            subject,
            "lanternwick lark",
            Some("sensitive"),
        )?;
        let issuer = vault.load_host_slip_issuer()?;
        let owner_slip = vault.ensure_host_root_slip(&issuer)?;
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let owner_memory = vault.memory(owner, EdgeActorClass::Human);
        owner_memory.bless_brief_kind()?;
        let source = owner_memory
            .author_take(TakeTarget::Subject(subject), SOURCE_TEXT)?
            .id_hex;
        let source = EntityId::from_hex(&source)?;
        let pin_unstamped = vault.pin_note_span(source, unstamped, 0, CONTROL_LEN)?;
        let pin_stamped =
            vault.pin_note_span(source, sensitive_stamped, SECRET_START, SECRET_END)?;
        let brief = owner_memory
            .author_brief(BRIEF_MARKDOWN, &[pin_unstamped, pin_stamped])?
            .id_hex;
        let brief = EntityId::from_hex(&brief)?;
        permit_brief_share(&vault, owner)?;
        let share_id = EntityId::now();
        let issuer_actor = WriteActor::new(owner, EdgeActorClass::Human);
        vault.create_share(
            &share_id,
            &issuer_actor,
            &Share {
                recipient_ref: recipient,
                brief_ref: brief.to_hex(),
                world_refs: BTreeSet::new(),
                facet_refs: BTreeSet::new(),
                include_unscoped: true,
                status: AccessGrantStatus::Active,
                created_at: vault.now_recorded_at(),
                revoked_at: None,
                expires_at: None,
                mention: None,
            },
        )?;
        let verified_view =
            issue_and_redeem_view(&vault, &issuer, &issuer_actor, share_id, recipient)?;
        Ok(Self {
            _dir: dir,
            vault,
            issuer,
            owner_slip,
            recipient,
            verified_view,
            unstamped,
            sensitive_stamped,
            share: share_id,
        })
    }

    fn viewer_memory(&self) -> Memory<'_> {
        self.vault
            .memory(self.recipient, EdgeActorClass::Human)
            .with_read_proof(&self.verified_view)
    }

    /// The owner's credential lane: un-homed, reading every claim on its own.
    fn owner_lane(&self) -> TestResult<ScopedRead<'_>> {
        let proof = self
            .issuer
            .binding_proof(&self.owner_slip, OWNER_CHALLENGE)?;
        let verified = self.vault.verify_capability_slip(
            &self.issuer.public_key(),
            &self.owner_slip,
            OWNER_CHALLENGE,
            &proof,
        )?;
        let Some(key) = self.vault.credential_read_key(&verified)? else {
            panic!("the owner credential grants a read");
        };
        Ok(self.vault.scoped_read(key))
    }
}

#[test]
fn share_view_redacts_stamped_pin_quote() -> TestResult {
    let fixture = Fixture::new()?;
    let viewer = fixture.viewer_memory();
    let rendered = view_shared_brief_as_caller(
        &viewer,
        ShareViewRequest {
            share_ref: fixture.share.to_hex(),
            narrowing: None,
        },
    )?;
    let view = rendered
        .value
        .ok_or("the share resolves for its recipient")?;
    assert_eq!(
        view.citations.len(),
        2,
        "the recipient resolves both pins: {view:?}"
    );
    let unstamped = &view.citations[0];
    assert!(
        !unstamped.redacted,
        "control: the unstamped pin reads for the share viewer: {view:?}"
    );
    assert_eq!(
        unstamped.quote.as_deref(),
        Some(CONTROL_QUOTE),
        "control: the unstamped pin keeps its quote: {view:?}"
    );
    assert_eq!(
        unstamped.claim_ref,
        fixture.unstamped.to_hex(),
        "control: the unstamped pin names its claim: {view:?}"
    );
    let stamped = &view.citations[1];
    assert!(
        stamped.redacted,
        "the stamped pin redacts for the share viewer: {view:?}"
    );
    assert_eq!(
        stamped.quote, None,
        "the stamped pin keeps no quote: {view:?}"
    );
    Ok(())
}

#[test]
fn follow_citation_redacts_stamped_pin_quote() -> TestResult {
    let fixture = Fixture::new()?;
    let viewer = fixture.viewer_memory();
    let followed = follow_brief_citation_as_caller(
        &viewer,
        BriefCitationFollowRequest {
            share_ref: fixture.share.to_hex(),
            claim_ref: fixture.sensitive_stamped.to_hex(),
            narrowing: None,
        },
    )?;
    let citation = followed
        .value
        .ok_or("the stamped pin follows for its recipient")?;
    assert!(
        citation.redacted,
        "the followed stamped pin redacts: {citation:?}"
    );
    assert_eq!(
        citation.quote, None,
        "the followed stamped pin keeps no quote: {citation:?}"
    );
    Ok(())
}

#[test]
fn owner_lane_reads_both_claims_by_id() -> TestResult {
    let fixture = Fixture::new()?;
    let lane = fixture.owner_lane()?;
    assert!(
        lane_reads(&lane, &fixture.unstamped)?,
        "control: the owner lane reads the unstamped claim"
    );
    assert!(
        lane_reads(&lane, &fixture.sensitive_stamped)?,
        "control: the owner lane reads the sensitive stamped claim"
    );
    Ok(())
}
