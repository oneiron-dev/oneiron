//! The `wallet_ref` key of the FEDERATION_GRANT body (FIX 7766, Engine 19:59
//! = A): the host wallet an owner names for the work his agent's grant
//! funds, in the one codec his signed mint act uses too
//! (`oneiron_authority::federation::wallet_ref`). Only an owner's Access
//! agent grant carries the key, and only when he named a wallet; every other
//! body, and an agent grant without one, encodes exactly as before and
//! decodes as naming none. The wallet is a spend parameter the grant's
//! funded work inherits, never a permission axis.

use oneiron_authority::federation::{WalletRef, decode_wallet_ref_value, wallet_ref_value};
use rmpv::Value;

use super::FederationGrant;
use crate::error::Result;
use crate::federation::FederationGrantKind;
use crate::federation::codec::{invalid_grant, optional_value};

pub(super) const KEY_WALLET_REF: &str = "wallet_ref";

/// The body entry of `grant`'s wallet, when it names one.
pub(super) fn body_entry(grant: &FederationGrant) -> Option<(Value, Value)> {
    grant
        .wallet_ref
        .as_ref()
        .map(|wallet| (Value::from(KEY_WALLET_REF), wallet_ref_value(wallet)))
}

/// The wallet a body names; none when the key is absent. A malformed value
/// refuses the body.
pub(super) fn decode_body_entry(entries: &[(Value, Value)]) -> Result<Option<WalletRef>> {
    optional_value(entries, KEY_WALLET_REF)
        .map(|value| decode_wallet_ref_value(value).ok_or_else(invalid_grant))
        .transpose()
}

/// A wallet rides an owner's Access agent grant only, both its parts
/// nonempty.
pub(super) fn validate(grant: &FederationGrant) -> Result<()> {
    let Some(wallet) = &grant.wallet_ref else {
        return Ok(());
    };
    if !grant.owner_agent || grant.kind != FederationGrantKind::Access || !wallet.is_valid() {
        return Err(invalid_grant());
    }
    Ok(())
}
