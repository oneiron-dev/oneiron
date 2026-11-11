//! The host wallet an owner's agent Grant names (FIX 7766, Engine 19:59 =
//! A), in the one codec the Grant body and the owner's signed mint act both
//! use.
//!
//! The key rides an owner's Access agent Grant only, and only when he named
//! a wallet; every other body and act writes no key, so each earlier one
//! keeps its bytes. Its value is the map `{issuer, id}` in that order, two
//! nonempty strings the host issued and the engine compares byte for byte.

use oneiron_contracts::wallet::WalletRef;
use rmpv::Value;

/// The key that carries a Grant's or a mint act's wallet; absent when it
/// names none.
pub const KEY_WALLET_REF: &str = "wallet_ref";

/// The keys of a wallet's value, in their canonical order.
const WALLET_REF_KEYS: [&str; 2] = ["issuer", "id"];

/// The canonical value of a valid wallet: `{issuer, id}`.
#[must_use]
pub fn wallet_ref_value(wallet: &WalletRef) -> Value {
    Value::Map(vec![
        (
            Value::from(WALLET_REF_KEYS[0]),
            Value::from(wallet.issuer.as_str()),
        ),
        (
            Value::from(WALLET_REF_KEYS[1]),
            Value::from(wallet.id.as_str()),
        ),
    ])
}

/// Decodes [`wallet_ref_value`]'s form, fail-closed: exactly its two keys in
/// order, each a nonempty string, nothing else.
#[must_use]
pub fn decode_wallet_ref_value(value: &Value) -> Option<WalletRef> {
    let Value::Map(entries) = value else {
        return None;
    };
    let [(issuer_key, issuer), (id_key, id)] = entries.as_slice() else {
        return None;
    };
    if issuer_key.as_str() != Some(WALLET_REF_KEYS[0])
        || id_key.as_str() != Some(WALLET_REF_KEYS[1])
    {
        return None;
    }
    let wallet = WalletRef {
        issuer: issuer.as_str()?.to_owned(),
        id: id.as_str()?.to_owned(),
    };
    wallet.is_valid().then_some(wallet)
}
