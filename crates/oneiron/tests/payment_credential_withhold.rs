//! L8-60 (RULING L8-60-PAYMENT-MARKER = A, 14 Nov; CROSS-ARCH-0019
//! `#fence-unproven`, the owner's pick A on OSH-5): on a host whose runner
//! fence is unproven, the engine withholds payment credentials. Every other
//! credential stays reachable at its rung, and the self-hoster may lift the
//! withholding.
//!
//! The owner marks which credential pays; a key a scan found as a Stripe key
//! is one until he says otherwise. Both value doors refuse a payment
//! credential with `payment_credential_withheld` while the fence is
//! unproven and the withholding stands: the bound door every T0 and T1
//! binding release passes (driven here through the public T0 door
//! `inject_secret_record_at_door`) and the reveal door an agent's granted
//! reveal reads through.
//!
//! The file uses only main's public items and its test doors, so it builds
//! on main too.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test payment_credential_withhold`
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::payment_credential as door;
use oneiron::{EntityId, Error, Vault, VaultConfig};

/// The effector the fixture credential is bound to: a shop connector.
const SHOP_EFFECTOR: &str = "connector:shop";
/// The model connection a granted reveal delivers to.
const MODEL_CONNECTION: &str = "model:agent:0123456789abcdef0123456789abcdef";
/// A credential value with no provider prefix.
const PLAIN_VALUE: &[u8] = b"owen-shop-token-v1";
/// The value of a credential a scan found as a Stripe key; the scan kind,
/// not the value, is the label hint.
const STRIPE_VALUE: &[u8] = b"owen-stripe-fixture-value";

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Fixture {
    vault: Vault,
    owner: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    let owner_id = vault.ensure_embedded_owner_actor()?;
    let owner =
        vault.authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())?;
    Ok(Fixture {
        vault,
        owner,
        _dir: dir,
    })
}

/// The value the public T0 door hands its operation for `secret`, or the
/// door's refusal. The operation sees the value only when the door admits.
fn present_at_bound_door(vault: &Vault, secret: &EntityId) -> Result<Vec<u8>, Error> {
    let mut seen = None;
    vault.inject_secret_record_at_door(secret, SHOP_EFFECTOR, &mut |value: &[u8]| {
        seen = Some(value.to_vec());
        Ok(())
    })?;
    Ok(seen.unwrap_or_default())
}

/// Whether `err` is the typed `payment_credential_withheld` refusal, by its
/// wire name.
fn withheld(err: &Error) -> bool {
    serde_json::to_value(err.kind())
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .as_deref()
        == Some("payment_credential_withheld")
}

#[test]
fn a_payment_credential_the_owner_marked_is_withheld_at_the_bound_door_on_an_unfenced_host()
-> TestResult {
    let fx = fixture()?;
    let secret = door::register_bound_secret(&fx.vault, "owen-shop", PLAIN_VALUE, SHOP_EFFECTOR)?;
    door::seed_release(&fx.vault, false, false);
    door::mark_payment_credential(&fx.vault, &fx.owner, &secret, Some(true))?;

    let err = present_at_bound_door(&fx.vault, &secret)
        .expect_err("a marked payment credential is withheld on an unfenced host");
    assert!(
        withheld(&err),
        "the refusal is not payment_credential_withheld: {err:?}"
    );
    Ok(())
}

#[test]
fn a_payment_credential_the_owner_marked_is_withheld_at_the_reveal_door_on_an_unfenced_host()
-> TestResult {
    let fx = fixture()?;
    let secret = door::register_bound_secret(&fx.vault, "owen-shop", PLAIN_VALUE, SHOP_EFFECTOR)?;
    door::seed_release(&fx.vault, false, false);
    door::mark_payment_credential(&fx.vault, &fx.owner, &secret, Some(true))?;

    let err = door::reveal_value_len(&fx.vault, &secret, MODEL_CONNECTION)
        .expect_err("a granted reveal of a marked payment credential is withheld");
    assert!(
        withheld(&err),
        "the refusal is not payment_credential_withheld: {err:?}"
    );
    Ok(())
}

#[test]
fn the_serve_flag_lifts_the_withholding_of_a_marked_payment_credential() -> TestResult {
    let fx = fixture()?;
    let secret = door::register_bound_secret(&fx.vault, "owen-shop", PLAIN_VALUE, SHOP_EFFECTOR)?;
    door::seed_release(&fx.vault, false, true);
    door::mark_payment_credential(&fx.vault, &fx.owner, &secret, Some(true))?;

    assert_eq!(present_at_bound_door(&fx.vault, &secret)?, PLAIN_VALUE);
    assert_eq!(
        door::reveal_value_len(&fx.vault, &secret, MODEL_CONNECTION)?,
        PLAIN_VALUE.len()
    );
    Ok(())
}

#[test]
fn a_marked_payment_credential_is_released_on_a_host_whose_runner_fence_is_proven() -> TestResult {
    let fx = fixture()?;
    let secret = door::register_bound_secret(&fx.vault, "owen-shop", PLAIN_VALUE, SHOP_EFFECTOR)?;
    door::seed_release(&fx.vault, true, false);
    door::mark_payment_credential(&fx.vault, &fx.owner, &secret, Some(true))?;

    assert_eq!(present_at_bound_door(&fx.vault, &secret)?, PLAIN_VALUE);
    assert_eq!(
        door::reveal_value_len(&fx.vault, &secret, MODEL_CONNECTION)?,
        PLAIN_VALUE.len()
    );
    Ok(())
}

#[test]
fn an_unmarked_credential_is_released_at_its_rung_on_an_unfenced_host() -> TestResult {
    let fx = fixture()?;
    let secret = door::register_bound_secret(&fx.vault, "owen-shop", PLAIN_VALUE, SHOP_EFFECTOR)?;
    door::seed_release(&fx.vault, false, false);

    assert_eq!(present_at_bound_door(&fx.vault, &secret)?, PLAIN_VALUE);
    assert_eq!(
        door::reveal_value_len(&fx.vault, &secret, MODEL_CONNECTION)?,
        PLAIN_VALUE.len()
    );
    Ok(())
}

#[test]
fn a_scanned_stripe_key_is_withheld_until_the_owner_marks_it_not_a_payment_credential() -> TestResult
{
    let fx = fixture()?;
    let secret =
        door::register_bound_secret(&fx.vault, "owen-stripe", STRIPE_VALUE, SHOP_EFFECTOR)?;
    door::record_scan_kind(&fx.vault, &secret, "stripe_key")?;
    door::seed_release(&fx.vault, false, false);

    // Unmarked, the label hint pre-fills the mark: a Stripe key pays.
    let err = present_at_bound_door(&fx.vault, &secret)
        .expect_err("a scanned Stripe key is a payment credential until the owner says not");
    assert!(
        withheld(&err),
        "the refusal is not payment_credential_withheld: {err:?}"
    );

    // The owner's answer wins over the hint.
    door::mark_payment_credential(&fx.vault, &fx.owner, &secret, Some(false))?;
    assert_eq!(present_at_bound_door(&fx.vault, &secret)?, STRIPE_VALUE);

    // Cleared, the hint answers again.
    door::mark_payment_credential(&fx.vault, &fx.owner, &secret, None)?;
    let err = present_at_bound_door(&fx.vault, &secret)
        .expect_err("a cleared mark falls back to the label hint");
    assert!(
        withheld(&err),
        "the refusal is not payment_credential_withheld: {err:?}"
    );
    Ok(())
}
