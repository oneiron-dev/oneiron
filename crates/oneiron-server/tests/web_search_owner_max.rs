//! The owner's `connectors.web.search_max_results` (restriction wave 19, C73 = B; Engine
//! RULING 03:53 16 Nov): a search on the owner's own provider key asks its provider for up to
//! the owner's maximum, cut to the provider's documented ceiling; a search on the deploy's
//! backend key (our cash) keeps 10, whatever the owner set. Zero is refused.
//!
//! Reaches the count `call_listing` sends through `oneiron_server::test_doors::web_search_count`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --test web_search_owner_max`.
#![cfg(oneiron_test_support)]

use oneiron::consent::AuthenticatedOwner;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::web_connector::{WebKeySource, WebProvider, WebSearchInput};
use oneiron::{Vault, VaultConfig};
use oneiron_server::test_doors::web_search_count::search_count;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const KEY: &str = "connectors.web.search_max_results";

fn open_vault() -> Result<(tempfile::TempDir, Vault, AuthenticatedOwner), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    Ok((dir, vault, proof))
}

fn ask(max_results: Option<u32>) -> WebSearchInput {
    WebSearchInput {
        query: "oneiron".into(),
        max_results,
    }
}

fn set_owner_max(
    vault: &Vault,
    proof: &AuthenticatedOwner,
    value: u32,
) -> oneiron::Result<SetSettingOutcome> {
    vault.set_setting(
        SettingCaller::Owner(proof),
        SetSetting::vault_value(KEY, serde_json::json!(value)),
    )
}

/// With no row an owner-key search asks for at most 10. After the owner sets 50, an ask of 50
/// goes out as 50 on Exa, Octen, context.dev and Tinyfish, and as 20 on Tavily and Brave (their
/// documented maxima); an ask of 200 goes out as 50; an absent ask still goes out as 5.
#[test]
fn an_owner_key_search_asks_for_the_owners_maximum() -> TestResult {
    let (_dir, vault, proof) = open_vault()?;
    assert_eq!(
        search_count(&vault, WebKeySource::User, WebProvider::Exa, &ask(Some(50)))?,
        10,
        "guard: with no row an owner-key search asks for at most 10"
    );
    let outcome = set_owner_max(&vault, &proof, 50)?;
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "the owner's raise applies"
    );
    for (provider, sent) in [
        (WebProvider::Exa, 50),
        (WebProvider::Octen, 50),
        (WebProvider::ContextDev, 50),
        (WebProvider::Tinyfish, 50),
        (WebProvider::Tavily, 20),
        (WebProvider::Brave, 20),
    ] {
        assert_eq!(
            search_count(&vault, WebKeySource::User, provider, &ask(Some(50)))?,
            sent,
            "raised: an ask of 50 on {provider:?} goes out as {sent}"
        );
    }
    assert_eq!(
        search_count(
            &vault,
            WebKeySource::User,
            WebProvider::Exa,
            &ask(Some(200))
        )?,
        50,
        "raised: an ask past the owner's maximum goes out as the maximum"
    );
    assert_eq!(
        search_count(&vault, WebKeySource::User, WebProvider::Exa, &ask(None))?,
        5,
        "raised: an absent ask still goes out as 5"
    );
    Ok(())
}

/// A backend-key search is our cash: after the owner sets 50 it still asks for at most 10.
#[test]
fn a_backend_key_search_keeps_ten() -> TestResult {
    let (_dir, vault, proof) = open_vault()?;
    set_owner_max(&vault, &proof, 50)?;
    for provider in [
        WebProvider::Tavily,
        WebProvider::Exa,
        WebProvider::Brave,
        WebProvider::Tinyfish,
        WebProvider::ContextDev,
        WebProvider::Octen,
    ] {
        assert_eq!(
            search_count(&vault, WebKeySource::Backend, provider, &ask(Some(50)))?,
            10,
            "a backend-key search on {provider:?} keeps 10"
        );
    }
    Ok(())
}

/// The owner's set of 0 is refused, and an owner-key search then still asks for at most 10.
#[test]
fn a_zero_search_maximum_is_refused() -> TestResult {
    let (_dir, vault, proof) = open_vault()?;
    match set_owner_max(&vault, &proof, 0) {
        Err(oneiron::Error::InvalidConfig(text)) => {
            assert_eq!(
                text, "a page maximum is at least one row",
                "zero is refused"
            );
        }
        Err(other) => {
            return Err(format!("zero is refused as invalid config, not {other:?}").into());
        }
        Ok(_) => return Err("a zero search maximum is refused".into()),
    }
    assert_eq!(
        search_count(&vault, WebKeySource::User, WebProvider::Exa, &ask(Some(50)))?,
        10,
        "refused: an owner-key search still asks for at most 10"
    );
    Ok(())
}
