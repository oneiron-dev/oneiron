//! Joining the home from an empty vault (FIX 3375). A vault with no
//! authority root has no genesis to sign its machine request for, nor the
//! home's storage id its checkpoint adoption needs. So before it redeems,
//! the device reads the checkpoint pin the owner's link keeps from the home
//! (`POST /v1/core/pairing/pin`, the pin redeem would answer) and verifies
//! it ([`verify_join_pin`]): its digest is the one the link names, and each
//! of its key bindings names its storage id and genesis and verifies under
//! its own owner root. The storage id and genesis come from that pin alone.
//! `device enrol` then creates a fresh store under the storage id
//! (`OpenOptions::adopt_storage_id`), enrols for the genesis, and checks the
//! pin and slip the redeem answers against them ([`check_answered`]). The
//! first sync adopts the image the pin names, pinning the owner root it was
//! built under first, and fills the vault. Any field that does not match
//! refuses, naming it ([`JoinRefusal`], Engine 04:4x).

use oneiron::authority::{AuthorityCheckpointPin, PairingPinRef};

/// The home a device joins from an empty vault, as its verified pin names it.
pub(crate) struct JoinPin {
    /// The pin, verified against the owner's link.
    pub(crate) pin: AuthorityCheckpointPin,
}

impl JoinPin {
    /// The home's authority genesis: the vault id the machine request signs.
    pub(crate) fn genesis(&self) -> [u8; 32] {
        self.pin.genesis
    }
}

/// Which field of the home a join refused on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JoinRefusal {
    /// The pin is not the one the owner's link names.
    Pin,
    /// The home's storage id.
    StorageId,
    /// The home's authority genesis.
    Genesis,
    /// The owner root the pin's key bindings verify under.
    OwnerRoot,
}

impl std::fmt::Display for JoinRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let field = match self {
            Self::Pin => "checkpoint pin",
            Self::StorageId => "storage id",
            Self::Genesis => "genesis",
            Self::OwnerRoot => "owner root",
        };
        write!(
            f,
            "joining from an empty vault refused: the home's {field} is not the one the owner's \
             pairing link pins; ask the owner for a new link"
        )
    }
}

impl std::error::Error for JoinRefusal {}

/// Checks `pin` against `named`, the reference the owner's link carries: its
/// digest is the link's, and each key binding names the pin's storage id and
/// genesis and verifies under its root, a root of the pin's policy. A pin
/// with no binding has nothing the owner root signed and refuses.
pub(crate) fn verify_join_pin(
    pin: AuthorityCheckpointPin,
    named: &PairingPinRef,
) -> Result<JoinPin, JoinRefusal> {
    if !named.names(&pin) {
        return Err(JoinRefusal::Pin);
    }
    if pin.bindings.is_empty() {
        return Err(JoinRefusal::OwnerRoot);
    }
    for binding in &pin.bindings {
        if binding.vault_id != pin.vault_id {
            return Err(JoinRefusal::StorageId);
        }
        if binding.genesis != pin.genesis {
            return Err(JoinRefusal::Genesis);
        }
        if pin.policy.root(&binding.root).is_none() || binding.verify(&binding.root).is_err() {
            return Err(JoinRefusal::OwnerRoot);
        }
    }
    Ok(JoinPin { pin })
}

/// Checks what the redeem answered against the pin the join verified: the
/// pin it returns and the vault its slip names.
pub(crate) fn check_answered(
    join: &JoinPin,
    answered: Option<&AuthorityCheckpointPin>,
    slip_vault_id: [u8; 32],
) -> Result<(), JoinRefusal> {
    let answered = answered.ok_or(JoinRefusal::Pin)?;
    if answered.vault_id != join.pin.vault_id {
        return Err(JoinRefusal::StorageId);
    }
    if answered.genesis != join.pin.genesis || slip_vault_id != join.pin.genesis {
        return Err(JoinRefusal::Genesis);
    }
    if answered.policy != join.pin.policy || answered.bindings != join.pin.bindings {
        return Err(JoinRefusal::OwnerRoot);
    }
    if *answered != join.pin {
        return Err(JoinRefusal::Pin);
    }
    Ok(())
}

/// Reads the pin the owner's `link` keeps from the home and verifies it. A
/// link that keeps no pin names no storage id or genesis a vault could join
/// from empty.
pub(crate) fn fetch_join_pin(link: &str) -> anyhow::Result<JoinPin> {
    #[derive(serde::Deserialize)]
    struct PendingPin {
        pin: AuthorityCheckpointPin,
    }

    let (origin, code, _, pin_ref) = oneiron::authority::parse_pinned_pairing_link(link.trim())
        .map_err(|_| {
            anyhow::anyhow!(
                "the pairing link does not parse; pass the one-line link `oneiron token pair \
                 --machine yours` printed on the home"
            )
        })?;
    let named = pin_ref.ok_or_else(|| {
        anyhow::anyhow!(
            "this vault has no authority root yet, and the pairing link pins no checkpoint: a \
             device joins from an empty vault only with a link from a home that keeps an \
             attested checkpoint; otherwise it enrols a copy of its home's vault"
        )
    })?;
    let mut base = reqwest::Url::parse(&origin)
        .map_err(|_| anyhow::anyhow!("the pairing link's origin is not a URL"))?;
    anyhow::ensure!(
        super::redeemable(&base),
        "the pairing link's origin must be https://, or http:// on this machine"
    );
    if !base.path().ends_with('/') {
        base.set_path(&format!("{}/", base.path()));
    }
    let response = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(super::REDEEM_TIMEOUT)
        .build()?
        .post(base.join("v1/core/pairing/pin")?)
        .json(&serde_json::json!({ "code": code }))
        .send()
        .map_err(|error| anyhow::anyhow!("read the pairing link's pin at {origin}: {error}"))?;
    let status = response.status();
    anyhow::ensure!(
        status.is_success(),
        "the home holds no pin for this pairing link ({status}): it may be spent or expired; \
         ask the owner for a new one"
    );
    let read: PendingPin = response
        .json()
        .map_err(|_| anyhow::anyhow!("the home answered {status} with no pin"))?;
    verify_join_pin(read.pin, &named).map_err(Into::into)
}
