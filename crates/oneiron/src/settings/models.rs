//! The owner's model settings (OF-305): the standing quota fallbacks. Each
//! one names the model that a parked offer's calls go to while that offer is
//! parked, and is set when the owner answers a quota question
//! `use_fallback`. This is owner policy, kept apart from the deployment's
//! runtime cooldowns: a checkpoint keeps it, and a restore keeps the live
//! vault's rows. Both are catalogue keys (`settings::setting_keys`): the
//! fallbacks are the family `models.owner_fallback` (item: the offer's key),
//! and the Responses `store` switch (OF-602) is `models.responses_store`.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::setting::{EngineSetting, SetSetting, SettingCaller};

use super::setting_keys::{MODEL_OWNER_FALLBACK, RESPONSES_STORE};

/// The domain an answered quota question's reference is derived in: a
/// question is a runtime row, not an entity, so its change row names it by
/// this id.
const QUOTA_QUESTION_DOMAIN: &[u8] = b"oneiron.models.quota_question.v1";

/// Whether `item` is an offer's key: 64 lowercase hex.
pub(super) fn is_offer_key(item: &str) -> bool {
    item.len() == 64
        && item
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl Vault {
    /// The engine id of the model the owner named for the offer whose key is
    /// `offer` (hex64), for use while that offer is parked. `None` if the
    /// owner named none.
    ///
    /// # Errors
    ///
    /// An `offer` that is not an offer's key, and storage errors.
    pub fn model_fallback(&self, offer: &str) -> Result<Option<String>> {
        let rtxn = self.store.env.read_txn()?;
        Ok(MODEL_OWNER_FALLBACK
            .read_in_txn(self, &rtxn, &[], Some(offer))?
            .value)
    }

    /// The owner's `use_fallback` answer to the quota question on the offer
    /// whose key is `offer` (hex64), asked at `asked_at`: names `model` (an
    /// engine model id) as that offer's fallback while it is parked. The
    /// engine applies the answer (DESIGN 1.2 step 3): the change row's setter
    /// names the answered question, by an id derived from the offer's key and
    /// `asked_at`. The caller checked that the owner answered.
    ///
    /// # Errors
    ///
    /// An `offer` that is not an offer's key, and storage errors.
    pub fn answer_model_fallback(&self, offer: &str, asked_at: u64, model: &str) -> Result<()> {
        let question = EntityId::derive(
            QUOTA_QUESTION_DOMAIN,
            &[offer.as_bytes(), &asked_at.to_be_bytes()],
        )?;
        let mut request = SetSetting::vault_value(
            MODEL_OWNER_FALLBACK.spec.name,
            serde_json::Value::String(model.to_owned()),
        );
        request.item = Some(offer.to_owned());
        request.why = Some("the owner's use_fallback answer to a quota question".to_owned());
        self.set_setting(
            SettingCaller::Engine(EngineSetting::answer(question)),
            request,
        )?;
        Ok(())
    }

    /// Whether the owner lets a provider keep each Responses turn (`store`),
    /// so a reconnected socket resumes its chain. Off by default, and off
    /// for a row that does not decode.
    pub fn responses_store(&self) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        Ok(RESPONSES_STORE.read_in_txn(self, &rtxn, &[], None)?.value)
    }
}
