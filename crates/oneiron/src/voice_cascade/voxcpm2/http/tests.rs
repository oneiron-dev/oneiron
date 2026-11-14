use super::*;
use crate::llm::media::{AiOperation, MediaCaps};
use crate::llm::run_admission::{
    BudgetLine, KeyCustody, LeaseUnit, MemoryReceipts, OfferBinding, OfferRoute, Payer,
    RunAdmission, RunDeclaration, WireSeat, offer_id, offer_place,
};
use crate::llm::{
    CallClass, CallEnvelope, CallPurpose, ModelId, ModelLocality, ModelTierRef, ResponseFormat,
    TierPrecedence,
};
use crate::voice_identity::ref_bank::{
    VoiceRefOrigin, VoiceRefPack, VoiceRefSubjectKind, VoiceRenderDecision,
};
use std::net::TcpListener;

/// The host's rung for the worker: each render is one `ai.speech` call on
/// it, admitted under one run with room for every render here.
fn worker_seat() -> WireSeat {
    let model = ModelId::new(format!("local/{MODEL}@pinned-revision")).expect("worker model id");
    let route = OfferRoute::new("voxcpm2-worker", "loopback").expect("worker route");
    let offer = OfferBinding {
        offer: offer_id(
            &model,
            &offer_place(ModelLocality::OwnServer, route.origin()),
        ),
        model,
        route,
        locality: ModelLocality::OwnServer,
        payer: Payer::Local,
        credential_binding: None,
        catalog_revision: None,
        custody: KeyCustody::Keyless,
        rates: vec![],
        payer_person: None,
    };
    let envelope = CallEnvelope {
        scope: Default::default(),
        purpose: CallPurpose::Voice,
        class: CallClass::BestEffort,
        tier: TierPrecedence::for_purpose(&CallPurpose::Voice, ModelTierRef("global".into())),
        response_format: ResponseFormat::Text,
        locality: ModelLocality::OwnServer,
        host_keyless: false,
        host_paid: false,
        seat_effort: None,
    };
    let run = RunAdmission::new(
        format!("voxcpm2-test:{}", EntityId::now().to_hex()),
        RunDeclaration::undeclared(BudgetLine {
            limit_units: 1_000_000,
            reserve_units: 10_000,
            unit: LeaseUnit::tokens(),
        }),
        None,
        Arc::new(MemoryReceipts::default()),
    );
    WireSeat::new(
        run,
        offer,
        envelope,
        MediaCaps::for_operation(AiOperation::Speech),
    )
}

#[test]
fn queued_render_after_withdrawal_never_uploads_deleted_reference() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let vault = Arc::new(vault);
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id()?,
        &crate::gate::default_policy_manifest().unwrap(),
    )?;
    let owner = EntityId::now();
    vault.record_voice_render_consent(&VoiceRenderDecision {
        event_id: "queued-grant".into(),
        voice_id: "queued-voice".into(),
        subject: owner,
        subject_kind: VoiceRefSubjectKind::Person,
        recorded_by: owner,
        occurred_at: 1,
        reach: ModelLocality::OwnServer,
        basis: Some(
            crate::voice_identity::VoiceConsentBasis::ConversationalNotice {
                notice: "render".into(),
            },
        ),
        state: crate::voice_identity::VoiceConsentState::Granted,
    })?;
    vault.store_voice_ref_pack(&VoiceRefPack {
        version: 1,
        id: "queued-ref".into(),
        voice_id: "queued-voice".into(),
        owner,
        origin: VoiceRefOrigin::Captured {
            consent_event_ref: "queued-grant".into(),
        },
        clips: vec![VoiceRegisterClip {
            register: "neutral".into(),
            media_type: "audio/wav".into(),
            audio: b"RIFF0000WAVEfmt ".to_vec(),
            transcript: "reference".into(),
        }],
    })?;
    let (cloned, fence) = vault.prepare_fenced_voice_clone(
        "queued-voice",
        TARGET,
        false,
        ModelLocality::OwnServer,
    )?;
    let limits = crate::gate::voice_serving::VoiceServingRows::decode(
        &crate::gate::voice_serving::VoiceServingRows::seeded(),
    )
    .expect("seeded limits")
    .vault;
    let warm = WarmTarget {
        limits,
        model: MODEL.into(),
        checkpoint: "pin".into(),
        boot_id: "test-boot".into(),
        sample_rate: 48_000,
    };
    let target = RenderTarget {
        voice_id: cloned.voice_id,
        register: "neutral".into(),
        fence,
        limits,
        warm,
    };
    let generation = GenerationEpoch {
        session: uuid::Uuid::new_v4(),
        value: 1,
    };
    let (sender, work) = mpsc::sync_channel(2);
    let (results, receiver) = mpsc::sync_channel(2);
    sender
        .send(VoxCpm2Work {
            generation,
            sequence: 0,
            operation: VoxCpm2Operation::Start {
                target: Box::new(target),
            },
        })
        .map_err(|_| invalid("test queue"))?;
    sender
        .send(VoxCpm2Work {
            generation,
            sequence: 1,
            operation: VoxCpm2Operation::Render {
                text: "not uploadable".into(),
            },
        })
        .map_err(|_| invalid("test queue"))?;
    drop(sender);
    vault.withdraw_voice_consent(&crate::voice_identity::VoiceWithdrawalRequest {
        event_id: "queued-withdrawal".into(),
        subject_ref: owner,
        recorded_by_ref: owner,
        occurred_at: 10,
        purposes: vec![crate::voice_identity::VoicePrintPurpose::LiveInterlocutor],
        basis: crate::voice_identity::VoiceConsentBasis::ConversationalNotice {
            notice: "withdraw".into(),
        },
    })?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let url = Url::parse(&format!("http://{}/render", listener.local_addr()?))
        .map_err(|_| invalid("test URL"))?;
    let client = Client::builder()
        .timeout(Duration::from_millis(200))
        .build()
        .map_err(|_| invalid("test client"))?;
    let seat = worker_seat();
    let worker =
        thread::spawn(move || run_worker(vault, &seat, client, url, "t".repeat(32), work, results));
    assert!(matches!(
        receiver.recv_timeout(Duration::from_secs(2)),
        Ok(VoxCpm2Event::Failed { submission: 1, .. })
    ));
    worker.join().map_err(|_| invalid("worker panic"))?;
    assert!(
        listener.accept().is_err(),
        "withdrawn reference must never be uploaded"
    );
    Ok(())
}
