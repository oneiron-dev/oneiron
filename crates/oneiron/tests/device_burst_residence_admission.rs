#![cfg(oneiron_test_support)]
//! #9226 review round 2 and #9691 review round 1: an own device's update that
//! a residence socket sent to a window it promoted. Its rows pass the home's
//! row admission (`admit_promoted_device_window_update`), and its burst is
//! held under the device's authority as that admission read it
//! (`admit_device_residence_update`), not as the burst core's later writer
//! reads it:
//! - a grant narrowed between the two leaves the held batch not standing, so
//!   the writer that persists its replay lands nothing (case 1 of
//!   BURST-REPLAY-ROUND2-TESTS);
//! - a batch held from a residence socket and rejected at review is the same
//!   batch when the device sends the same bytes again on a full-window
//!   socket: its Rejected receipt answers them (case 5;
//!   BURST-DEVICE-KIND-SPLITS-RECEIPT).
//!
//! The device's update edits a CLAIM the home already holds, as the residence
//! lane allows; its source is an empty window document, which the row
//! admission forks and imports the update into.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test device_burst_residence_admission`.

use std::collections::BTreeSet;
use std::sync::Arc;

use loro::{ExportMode, LoroDoc, VersionVector};
use oneiron::authority::{HostSlipIssuer, PeerMachine, VerifiedSlip};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, ScopeAxis, ScopeId,
    own_device_residence_scope,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_WORLD};
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::sync::federation_burst::{
    BurstPeer, DeviceBurstAdmission, DevicePeer, FederationBurstBaseline, FederationBurstOutcome,
    FederationBurstPolicy, FederationBurstReceipt, FederationBurstWorkState, PromotedRowAdmission,
    admit_device_residence_update, admit_device_window_update, admit_promoted_device_window_update,
    ready_device_work,
};
use oneiron::sync::{
    SyncSelector, SyncSelectorWorld, WindowKey, put_selector_test_federation_grant,
};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::device_burst_work_stands::device_burst_work_stands;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, Vault,
    VaultConfig,
};
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const NOW: u64 = 1_700_000_000;

/// The stored row's metadata header ahead of its body.
const ROW_HEADER_LEN: usize = 25;

/// A home whose owner paired a device: the owner's own-device grant, the
/// device's Write credential minted under it and proved on its connection,
/// the residence selector naming that grant, and a CLAIM in a world for the
/// device to edit.
struct Home {
    _dir: TempDir,
    clock: Arc<ManualClock>,
    vault: Vault,
    owner: AuthenticatedOwner,
    grant_id: EntityId,
    grant: FederationGrant,
    device: DevicePeer,
    proof: VerifiedSlip,
    selector: SyncSelector,
    window: WindowKey,
    claim: EntityId,
}

/// A paired device's home whose owner set the device's baseline to
/// `writes_per_sec`; `unusual_rate` routes a burst over it.
fn home(writes_per_sec: f64, unusual_rate: FederationBurstOutcome) -> TestResult<Home> {
    let dir = TempDir::new()?;
    let clock = ManualClock::new(NOW);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config)?;
    let owner_id = vault.ensure_embedded_owner_actor()?;
    let owner =
        vault.authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())?;
    let at = TimeRange {
        start: NOW,
        end: NOW,
    };

    // The CLAIM the device edits: a fact in a world, about a PERSON.
    let world = EntityId::now();
    vault.put_entity(&world, ENTITY_TYPE_WORLD, at, NOW, b"world")?;
    let subject = EntityId::now();
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, at, NOW, b"subject")?;
    let mut body = ClaimBody::new(
        "test.device_burst_residence",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("world fact"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("a claim body");
    body.world = Some(world);
    let claim = EntityId::now();
    vault.put_claim(&claim, &body, at, NOW)?;

    // The owner's own-device grant, as pairing provisions it: the grant the
    // device's residence selector names and its slip carries.
    let grant_id = EntityId::now();
    let grant = FederationGrant::new(
        own_device_residence_scope(),
        owner_id,
        FederationGrantRole::Owner,
        FederationGrantPreset::Owner,
    );
    put_selector_test_federation_grant(&vault, &grant_id, &grant, NOW)?;

    // The device's Write credential: the owner's slip under that grant, cut
    // from the host root and proved on the device's connection.
    let issuer = HostSlipIssuer::from_secret(b"device-burst-residence-test-host-secret")?;
    let root = vault.ensure_host_root_slip(&issuer)?;
    let slip_id = [0x51; 32];
    let issued_at = vault.capability_slip_now()?;
    let mut claims = root.claims.clone();
    claims.slip_id = slip_id;
    claims.holder_ref = owner_id.to_hex();
    claims.actor_class = Some("human".into());
    claims.issued_at = issued_at;
    claims.expires_at = issued_at + 3_600;
    claims.ttl_secs = 3_600;
    claims.grant_ref = Some(grant_id.to_hex());
    let slip = vault.mint_capability_slip(&issuer, claims)?;
    let challenge = b"device-burst-residence-admission";
    let binding = issuer.binding_proof(&slip, challenge)?;
    let proof = vault.verify_capability_slip(&issuer.public_key(), &slip, challenge, &binding)?;

    let device = DevicePeer::of_connection(PeerMachine::Unknown, Some(slip_id));
    vault.set_federation_burst_policy(
        &owner,
        BurstPeer::Device(&device),
        FederationBurstPolicy {
            baseline: Some(FederationBurstBaseline {
                name: "paired device".into(),
                writes_per_sec,
                structural_streak: 1.0,
            }),
            unusual_rate,
            unusual_streak: FederationBurstOutcome::IsolateAndPropose,
        },
    )?;
    let selector = SyncSelector::new(grant_id, owner_id, SyncSelectorWorld::All, vec![], vec![]);
    Ok(Home {
        _dir: dir,
        clock,
        vault,
        owner,
        grant_id,
        grant,
        device,
        proof,
        selector,
        window: WindowKey::for_world(NOW, world),
        claim,
    })
}

/// Re-encodes a CLAIM body with a new confidence: an edit of the record that
/// keeps its identity, predicate, value and world.
fn with_confidence(body: &[u8], confidence: f32) -> TestResult<Vec<u8>> {
    let rmpv::Value::Map(mut entries) = rmpv::decode::read_value(&mut &body[..])? else {
        return Err("a claim body is a map".into());
    };
    let slot = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("conf"))
        .ok_or("a claim body carries its confidence")?;
    slot.1 = rmpv::Value::F32(confidence);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &rmpv::Value::Map(entries))?;
    Ok(out)
}

impl Home {
    /// The device's edit of the CLAIM to `confidence`, as one residence
    /// update: the row's stored header over the edited body, written into
    /// the window's entities map.
    fn edit(&self, confidence: f32) -> TestResult<Vec<u8>> {
        let raw = self.vault.get_raw(&self.claim)?.ok_or("the claim row")?;
        let mut blob = raw[..ROW_HEADER_LEN].to_vec();
        blob.extend(with_confidence(&raw[ROW_HEADER_LEN..], confidence)?);
        let doc = LoroDoc::new();
        doc.get_map("entities").insert(&self.claim.to_hex(), blob)?;
        doc.commit();
        Ok(doc.export(ExportMode::updates(&VersionVector::new()))?)
    }

    /// The home's row admission of `update`, as a residence socket's UPDATE
    /// arm runs it.
    fn admit_rows(&self, update: &[u8]) -> oneiron::Result<PromotedRowAdmission> {
        admit_promoted_device_window_update(
            &self.vault,
            &self.device,
            &LoroDoc::new(),
            (own_device_residence_scope(), &self.selector, &self.proof),
            update,
        )
    }

    /// The burst core's judgement of `update`, held under `admission`.
    fn hold(
        &self,
        update: &[u8],
        admission: PromotedRowAdmission,
    ) -> TestResult<DeviceBurstAdmission> {
        Ok(admit_device_residence_update(
            &self.vault,
            &self.device,
            &self.window,
            update,
            &[self.claim],
            admission,
        )?)
    }

    fn receipt(&self, batch_ref: &str) -> TestResult<FederationBurstReceipt> {
        Ok(self.vault.federation_burst_disposition_as_owner(
            &self.owner,
            BurstPeer::Device(&self.device),
            batch_ref,
        )?)
    }
}

/// Case 1 (#9226 review round 2, P1 1): the owner narrows the grant after the
/// residence arm's row admission read it and before the burst core's writer
/// holds the update. The batch is held under the authority that admitted its
/// rows, so the writer that would persist it finds it no longer standing.
/// Green-only: the round-1 head 9cc1dbcc293d has neither door.
#[test]
fn a_residence_update_whose_grant_narrows_after_its_row_admission_does_not_stand() -> TestResult {
    let home = home(1.0, FederationBurstOutcome::Defer)?;

    // With nothing changed between the two, the batch stands.
    let update = home.edit(0.5)?;
    let admission = home.admit_rows(&update)?;
    let work = match home.hold(&update, admission)? {
        DeviceBurstAdmission::Allow(work) => work,
        other => panic!("one edit at the device's baseline is allowed: {other:?}"),
    };
    assert!(
        work.promoted(),
        "a residence socket's update is replayed as one"
    );
    assert!(
        device_burst_work_stands(&home.vault, &work)?,
        "an update held under the authority that admitted its rows stands"
    );
    work.complete(&home.vault)?;

    // The next edit's rows pass; then the owner narrows the grant in place
    // to one other world, before the burst core holds the update.
    home.clock.set(NOW + 2);
    let update = home.edit(0.75)?;
    let admission = home.admit_rows(&update)?;
    let mut narrowed = home.grant.clone();
    narrowed.authority_scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(EntityId::now())]));
    put_selector_test_federation_grant(&home.vault, &home.grant_id, &narrowed, NOW + 2)?;
    let work = match home.hold(&update, admission)? {
        DeviceBurstAdmission::Allow(work) => work,
        other => panic!("one edit at the device's baseline is allowed: {other:?}"),
    };
    assert!(
        !device_burst_work_stands(&home.vault, &work)?,
        "an update whose grant narrowed after its row admission does not stand in the persist's writer"
    );
    assert!(
        home.admit_rows(&update).is_err(),
        "the narrowed grant no longer admits the edit's row"
    );
    Ok(())
}

/// Case 5 (#9691 review round 1, BURST-DEVICE-KIND-SPLITS-RECEIPT): the owner
/// rejects at review a device's update isolated on its residence socket. The
/// device sends the same bytes again on a full-window (v13) socket once its
/// rate is back: they are the same batch, and its Rejected receipt answers
/// them; nothing is admitted afresh. Red at 7db0e1f57c87, where the
/// residence kind hashed apart from the full-window kind.
#[test]
fn a_residence_batch_rejected_at_review_stays_rejected_over_the_full_window_lane() -> TestResult {
    // A baseline far under one write a second: one edit is a burst.
    let home = home(0.001, FederationBurstOutcome::IsolateAndPropose)?;
    let update = home.edit(0.5)?;
    let admission = home.admit_rows(&update)?;
    let (batch_ref, bundle_ref) = match home.hold(&update, admission)? {
        DeviceBurstAdmission::IsolateAndPropose {
            batch_ref,
            bundle_ref,
        } => (batch_ref, bundle_ref),
        other => panic!("an edit over the device's baseline is isolated: {other:?}"),
    };
    home.vault
        .reject_federation_burst_review(&home.owner, &bundle_ref)?;
    assert_eq!(
        home.receipt(&batch_ref)?.state,
        FederationBurstWorkState::Rejected
    );

    home.clock.set(NOW + 2);
    let again = admit_device_window_update(
        &home.vault,
        &home.device,
        &home.window,
        &update,
        &[home.claim],
    )?;
    assert!(
        matches!(
            &again,
            DeviceBurstAdmission::Settled {
                batch_ref: settled,
                state: FederationBurstWorkState::Rejected,
            } if *settled == batch_ref
        ),
        "the same bytes over the full-window lane are answered by the rejected batch's receipt: {again:?}"
    );
    assert!(
        ready_device_work(&home.vault)?.is_empty(),
        "the drain hands out no rejected batch"
    );
    assert_eq!(
        home.receipt(&batch_ref)?.state,
        FederationBurstWorkState::Rejected
    );
    Ok(())
}
