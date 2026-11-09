use oneiron::error::Result;
use oneiron::voice_identity::ref_bank::*;
use oneiron::{EntityId, ModelLocality, Vault, VaultConfig};

fn open() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("create vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    (dir, vault)
}

fn pack(id: &str, voice_id: &str, owner: EntityId, origin: VoiceRefOrigin) -> VoiceRefPack {
    VoiceRefPack {
        version: 1,
        id: id.into(),
        voice_id: voice_id.into(),
        owner,
        origin,
        clips: vec![VoiceRegisterClip {
            register: "neutral".into(),
            media_type: "audio/wav".into(),
            audio: vec![1, 2, 3],
            transcript: "reference".into(),
        }],
    }
}

#[test]
fn withdrawing_owner_deletes_identity_packs_and_target_pointers() -> Result<()> {
    let (_dir, vault) = open();
    let owner = EntityId::now();
    // A captured pack is banked under the subject's current render grant,
    // which names the farthest target its refs may reach.
    vault.record_voice_render_consent(&VoiceRenderDecision {
        event_id: "grant-owner".into(),
        voice_id: "voice".into(),
        subject: owner,
        subject_kind: VoiceRefSubjectKind::Person,
        recorded_by: owner,
        occurred_at: 1,
        reach: ModelLocality::OwnServer,
        basis: Some(
            oneiron::voice_identity::VoiceConsentBasis::ConversationalNotice {
                notice: "grant".into(),
            },
        ),
        state: oneiron::voice_identity::VoiceConsentState::Granted,
    })?;
    let captured = VoiceRefOrigin::Captured {
        consent_event_ref: "grant-owner".into(),
    };
    vault.store_voice_ref_pack(&pack("source", "voice", owner, captured))?;
    let request = vault.prepare_voice_clone("voice", "host", false, ModelLocality::OwnServer)?;
    vault.record_voice_target_clone(&request, "provider-id", 1, false)?;
    vault.withdraw_voice_consent(&oneiron::voice_identity::VoiceWithdrawalRequest {
        event_id: "withdraw-owner".into(),
        subject_ref: owner,
        recorded_by_ref: owner,
        occurred_at: 10,
        purposes: vec![oneiron::voice_identity::VoicePrintPurpose::LiveInterlocutor],
        basis: oneiron::voice_identity::VoiceConsentBasis::ConversationalNotice {
            notice: "withdraw".into(),
        },
    })?;
    assert!(vault.voice_identity("voice")?.is_none());
    assert!(vault.voice_ref_pack("source")?.is_none());
    assert!(
        vault
            .voice_target_clone("voice", "host", false, ModelLocality::OwnServer)?
            .is_none()
    );
    Ok(())
}
