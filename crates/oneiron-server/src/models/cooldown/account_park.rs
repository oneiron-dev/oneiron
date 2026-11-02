//! One spent account parks all its offers (FIX 564). Prepaid credit is the
//! account's, not one model's: a refusal for spent credit parks the account
//! its offer is billed to (its origin and whose key pays), so every offer
//! bound to it rests at once, each model without its own refusal first. The
//! account's park is the offer's own rest, kept in an account row beside the
//! offers' rests in the same table. A spent window stays the offer's: a
//! provider may meter a window per model.
use oneiron::Vault;
use oneiron::llm::SpentKind;
use oneiron::llm::run_admission::OfferBinding;

use super::{PREFIX, QUESTION_PREFIX, QuotaQuestion, Rest};

/// The account rows, beside the offers' rests and the owner's questions.
const ACCOUNT_PREFIX: &str = "models:offer-cooldown:v1:account:";

/// The id of the account `offer` is billed to: its origin and whose key pays.
pub(super) fn id(offer: &OfferBinding) -> String {
    let mut digest = blake3::Hasher::new();
    for part in [
        offer.route.origin(),
        offer.credential_binding.as_deref().unwrap_or_default(),
    ] {
        digest.update(part.as_bytes());
        digest.update(&[0]);
    }
    digest.finalize().to_hex().to_string()
}

/// Where the park of the account `id` is kept.
pub(super) fn row(id: &str) -> String {
    format!("{ACCOUNT_PREFIX}{id}")
}

/// Whether `rest` parks its offer's whole account: spent prepaid credit.
pub(super) fn parks_account(rest: &Rest) -> bool {
    rest.spent == Some(SpentKind::Credit)
}

/// Keeps `rest` as the park of `offer`'s account in `txn`. A park already
/// running longer stays.
pub(super) fn park_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    offer: &OfferBinding,
    rest: Rest,
) -> oneiron::Result<()> {
    let row = row(&id(offer));
    let running = vault
        .sync_state_get_in_write_txn(txn, &row)?
        .and_then(|bytes| rmp_serde::from_slice::<Rest>(&bytes).ok());
    if running.is_some_and(|running| running.until >= rest.until) {
        return Ok(());
    }
    let bytes = rmp_serde::to_vec_named(&rest)
        .map_err(|_| oneiron::Error::InvariantViolation("encode an account's park"))?;
    vault.sync_state_put_in_write_txn(txn, &row, &bytes)
}

/// The owner's answer put the account `id` back in rotation: its park ends,
/// and so does every offer's own credit rest under it, each closing its
/// open question, since one top-up serves them all.
pub(super) fn unpark(vault: &Vault, id: &str) -> oneiron::Result<()> {
    vault.sync_state_delete(&row(id))?;
    for key in vault.sync_state_keys_with_prefix(QUESTION_PREFIX)? {
        let question = vault
            .sync_state_get(&key)?
            .and_then(|bytes| rmp_serde::from_slice::<QuotaQuestion>(&bytes).ok());
        let Some(question) = question.filter(|question| question.account.as_deref() == Some(id))
        else {
            continue;
        };
        vault.sync_state_delete(&format!("{PREFIX}{}", question.id))?;
        vault.sync_state_delete(&key)?;
    }
    Ok(())
}
