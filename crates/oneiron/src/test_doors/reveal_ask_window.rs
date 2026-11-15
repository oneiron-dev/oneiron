//! Drives one secret reveal ask with a set window and the owner's answer.

use crate::error::Error;
use crate::ports::ShortIdStoreRead;

/// What one reveal ask did: the window it was filed with, and the owner's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevealWindowRun {
    /// The filed ask's `expires_at - created_at`, in seconds.
    pub window_secs: u64,
    /// `Ok(())` when the owner's answer stood; `Err(text)` with the error's Display text when it was refused.
    pub answer: std::result::Result<(), String>,
}

/// A fresh vault: when `window` is `Some`, the owner first sets `secrets.reveal.ask_window_secs` to it; an agent
/// then asks to reveal one registered secret, the store clock moves `answer_after_secs` seconds on, and the owner
/// answers the ask once.
pub fn answer_reveal_after(
    window: Option<u64>,
    answer_after_secs: u64,
) -> crate::Result<RevealWindowRun> {
    const START: u64 = 1_000_000;
    let directory = tempfile::tempdir()?;
    let store_clock = crate::ports::ManualClock::new(START);
    let mut config = crate::VaultConfig::device();
    config.store_clock = store_clock.bundle();
    let vault = crate::Vault::open(directory.path(), config)?;
    let owner_id = vault
        .ensure_embedded_owner_actor()
        .map_err(|error| Error::InvalidConfig(format!("embedded owner: {error:?}")))?;
    let owner = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    if let Some(w) = window {
        let request = crate::setting::SetSetting {
            key: "secrets.reveal.ask_window_secs".into(),
            item: None,
            scope: crate::setting::SettingScope::Vault,
            mode: crate::setting::SettingMode::Value,
            value: Some(serde_json::json!(w)),
            expected_revision: None,
            why: None,
            check_in_ref: None,
        };
        match vault.set_setting(crate::setting::SettingCaller::Owner(&owner), request)? {
            crate::setting::SetSettingOutcome::Applied { .. } => {}
            crate::setting::SetSettingOutcome::Pending { .. } => {
                return Err(Error::InvalidConfig(
                    "the owner's window change waits on a check-in".into(),
                ));
            }
        }
    }
    let registration = crate::secret_custody::OwnerSecretRegistration {
        name: "reveal-window-secret",
        class: crate::secret_custody::CustodyClass::CustodyPortable,
        device_only: false,
        rung: crate::secret_custody::CustodyTier::T1Leased,
        bindings: vec![crate::secret_custody::RequestedBinding {
            effector: "test-effector".to_owned(),
            tier_ceiling: Some(crate::secret_custody::CustodyTier::T1Leased),
            scopes: vec!["read".to_owned()],
        }],
        manifest: None,
        value: b"test-secret-value",
    };
    let registered = vault.register_secret_as_owner(&owner, &registration, START)?;
    let handle = {
        let txn = vault.store.env.read_txn()?;
        ShortIdStoreRead::port_short_id_reference(&vault.store, &txn, &registered.secret_id)?
            .map(|(name, _)| name)
            .ok_or(Error::InvariantViolation(
                "the registered secret has no handle",
            ))?
    };
    let agent = vault.new_entity_id()?;
    let asker = crate::secret_custody::RevealAsker::new(agent, None, None);
    let reveal = vault.reveal_secret(&asker, &handle, "the test needs the value")?;
    let asks = vault.secret_reveals(&owner, false, 10)?;
    let ask = asks
        .iter()
        .find(|ask| ask.receipt.reveal == reveal)
        .ok_or(Error::InvariantViolation("the filed reveal is not listed"))?;
    let window_secs = ask.expires_at.saturating_sub(ask.receipt.asked_at);
    let digest = *ask
        .once_digest
        .as_ref()
        .ok_or(Error::InvariantViolation("the open ask has no digest"))?
        .as_bytes();
    store_clock.set(START.saturating_add(answer_after_secs));
    let answer = match vault.answer_secret_reveal(
        &owner,
        &reveal,
        &digest,
        crate::secret_custody::SecretRevealAnswer::Once,
    ) {
        Ok(_) => Ok(()),
        Err(error) => Err(error.to_string()),
    };
    Ok(RevealWindowRun {
        window_secs,
        answer,
    })
}

/// A fresh vault where the owner sets `secrets.reveal.ask_window_secs` to `value`: the door's own result.
pub fn set_reveal_window(value: u64) -> crate::Result<()> {
    const START: u64 = 1_000_000;
    let directory = tempfile::tempdir()?;
    let store_clock = crate::ports::ManualClock::new(START);
    let mut config = crate::VaultConfig::device();
    config.store_clock = store_clock.bundle();
    let vault = crate::Vault::open(directory.path(), config)?;
    let owner_id = vault
        .ensure_embedded_owner_actor()
        .map_err(|error| Error::InvalidConfig(format!("embedded owner: {error:?}")))?;
    let owner = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let request = crate::setting::SetSetting {
        key: "secrets.reveal.ask_window_secs".into(),
        item: None,
        scope: crate::setting::SettingScope::Vault,
        mode: crate::setting::SettingMode::Value,
        value: Some(serde_json::json!(value)),
        expected_revision: None,
        why: None,
        check_in_ref: None,
    };
    match vault.set_setting(crate::setting::SettingCaller::Owner(&owner), request)? {
        crate::setting::SetSettingOutcome::Applied { .. } => Ok(()),
        crate::setting::SetSettingOutcome::Pending { .. } => Err(Error::InvalidConfig(
            "the owner's window change waits on a check-in".into(),
        )),
    }
}
