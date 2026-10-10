use oneiron::error::Result;
use oneiron::voice_identity::ref_bank::*;
use oneiron::{EntityId, Vault, VaultConfig};

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
fn designed_captured_and_generated_packs_belong_to_a_vault_identity() -> Result<()> {
    let (_dir, vault) = open();
    let (_other_dir, other) = open();
    let owner = EntityId::now();
    let designed = pack(
        "design",
        "voice-1",
        owner,
        VoiceRefOrigin::Designed {
            vendor: "design-tool".into(),
        },
    );
    let captured = pack("capture", "voice-2", owner, VoiceRefOrigin::Captured);
    let generated = pack("generated", "voice-1", owner, VoiceRefOrigin::Generated);
    assert!(vault.store_voice_ref_pack(&generated).is_err());
    assert!(vault.voice_identity("voice-1")?.is_none());
    vault.store_voice_ref_pack(&designed)?;
    vault.store_voice_ref_pack(&captured)?;
    vault.store_voice_ref_pack(&generated)?;
    vault.store_voice_ref_pack(&generated)?; // idempotent retry
    assert_eq!(
        vault.voice_identity("voice-1")?.unwrap().pack_ids,
        vec!["design", "generated"]
    );
    assert_eq!(
        vault.voice_identity("voice-2")?.unwrap().pack_ids,
        vec!["capture"]
    );
    assert_eq!(
        vault.voice_ref_pack("generated")?.unwrap().origin,
        VoiceRefOrigin::Generated
    );
    assert!(other.voice_identity("voice-1")?.is_none());
    let mut changed = generated;
    changed.clips[0].audio.push(4);
    assert!(vault.store_voice_ref_pack(&changed).is_err());
    changed.id = "another".into();
    changed.owner = EntityId::now();
    assert!(vault.store_voice_ref_pack(&changed).is_err());
    Ok(())
}

#[test]
fn withdrawing_owner_deletes_identity_packs_and_target_pointers() -> Result<()> {
    let (_dir, vault) = open();
    let owner = EntityId::now();
    vault.store_voice_ref_pack(&pack("source", "voice", owner, VoiceRefOrigin::Captured))?;
    let request = vault.prepare_voice_clone("voice", "host", false)?;
    vault.record_voice_target_clone(&request, "provider-id", 1)?;
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
    assert!(vault.voice_target_clone("voice", "host", false)?.is_none());
    Ok(())
}
