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
    vault.record_voice_render_consent(&VoiceRenderDecision {
        event_id: "grant-voice-2".into(),
        voice_id: "voice-2".into(),
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
    let captured = pack(
        "capture",
        "voice-2",
        owner,
        VoiceRefOrigin::Captured {
            consent_event_ref: "grant-voice-2".into(),
        },
    );
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

/// Withdrawing the voice print's consent withdraws recognition only
/// (VOICE-WITHDRAW-ENGINE-WIPE-RENDER-GAPS; canon arch-0061: "Withdrawing
/// voice consent deletes the voiceprint and its samples, and keeps the
/// consent record"). The render bank stays under its own consent: the
/// identity, its packs, the target pointer, the render grant and its
/// history. Its own withdrawal is what drops the pointer, and it hands the
/// pointer back so the host can delete the vendor's clone.
#[test]
fn withdrawing_recognition_keeps_the_render_bank_until_its_own_withdrawal() -> Result<()> {
    let (_dir, vault) = open();
    let owner = EntityId::now();
    let render =
        |event_id: &str, occurred_at: u64, state: oneiron::voice_identity::VoiceConsentState| {
            VoiceRenderDecision {
                event_id: event_id.into(),
                voice_id: "voice".into(),
                subject: owner,
                subject_kind: VoiceRefSubjectKind::Person,
                recorded_by: owner,
                occurred_at,
                reach: ModelLocality::OwnServer,
                basis: Some(
                    oneiron::voice_identity::VoiceConsentBasis::ConversationalNotice {
                        notice: event_id.into(),
                    },
                ),
                state,
            }
        };
    // A captured pack is banked under the subject's current render grant,
    // which names the farthest target its refs may reach.
    let grant = render(
        "grant-owner",
        1,
        oneiron::voice_identity::VoiceConsentState::Granted,
    );
    vault.record_voice_render_consent(&grant)?;
    let captured = VoiceRefOrigin::Captured {
        consent_event_ref: "grant-owner".into(),
    };
    vault.store_voice_ref_pack(&pack("source", "voice", owner, captured))?;
    let request = vault.prepare_voice_clone("voice", "host", false, ModelLocality::OwnServer)?;
    let target = vault.record_voice_target_clone(&request, "provider-id", 1, false)?;
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
    assert!(vault.voice_identity("voice")?.is_some());
    assert!(vault.voice_ref_pack("source")?.is_some());
    assert_eq!(
        vault
            .voice_target_clone("voice", "host", false, ModelLocality::OwnServer)?
            .map(|(record, _)| record),
        Some(target.clone())
    );
    // The grant's event is still in the render history: recorded again, it
    // replays its stored receipt.
    assert!(vault.record_voice_render_consent(&grant)?.replayed);
    let withdrawn = vault.record_voice_render_consent(&render(
        "withdraw-render",
        20,
        oneiron::voice_identity::VoiceConsentState::Withdrawn,
    ))?;
    assert_eq!(withdrawn.newly_evicted, vec![target]);
    Ok(())
}
