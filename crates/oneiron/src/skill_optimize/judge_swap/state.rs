//! Retained judge-swap state, noise cells and owner notifications.
//! Entry function: `noise_cell`.
//! State keys and receipt vocabulary remain defined in `super`.

use super::*;

/// The scoring subject the incumbent's retest noise is kept under: the
/// shipped `judge` SKILL (FIX 8079), a row the learning projection can write
/// its claim about.
pub(super) fn scorer() -> Result<EntityId> {
    EntityId::derive(
        crate::entity_id::derived_domains::BOOTSTRAP_SKILL,
        &[JUDGE_SKILL_ID.as_bytes()],
    )
}

/// The cell [`record_retest`] keeps the incumbent's noise in.
pub(super) fn noise_cell(incumbent: &str) -> Result<LearningCell> {
    Ok(LearningCell::new(LearningPredicate::RetestNoise, scorer()?)
        .executor(incumbent.to_owned())
        .axis(NOISE_AXIS.to_owned()))
}

/// The swap's or the re-pin's notice: one finding in each owner's inbox, or
/// with a hands-on policy one ask to rate the swap's disagreements.
pub(super) fn notify_owners(vault: &Vault, receipt: &str, ask: bool, at: u64) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        for owner in crate::policy_model::owners_in_txn(vault, &*txn)? {
            vault.record_notification_in_txn(
                txn,
                &crate::inbox::NotificationEvent {
                    kind: if ask {
                        crate::inbox::NotificationKind::Ask
                    } else {
                        crate::inbox::NotificationKind::Finding
                    },
                    source: crate::inbox::NotificationSource {
                        producer: JUDGE_SWAP_NOTIFICATION_PRODUCER.to_owned(),
                        event: format!("{receipt}:{}", owner.to_hex()),
                        result: Some(receipt.to_owned()),
                        ..crate::inbox::NotificationSource::default()
                    },
                    subject_refs: Vec::new(),
                    recipient: Some(owner),
                    created_at: at,
                    origin_conversation: None,
                },
            )?;
        }
        Ok(())
    })
}

pub(super) fn load<T: DeserializeOwned>(vault: &Vault, key: &str) -> Result<Option<T>> {
    vault
        .sync_state_get(key)?
        .map(|bytes| {
            serde_json::from_slice(&bytes).map_err(|_| Error::CorruptedIndex("judge swap state"))
        })
        .transpose()
}

pub(super) fn save<T: Serialize>(vault: &Vault, key: &str, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::CorruptedIndex("judge swap state"))?;
    vault.sync_state_put(key, &bytes)
}
