//! A device in opened mode asks its home for text it never opened: the home
//! ranks the ask under the device's own sync credential, the owner's paired
//! slip, and an unopened NOTE whose text matches is among the candidates the
//! home's page search hands its window and selector checks (FIX-LIST
//! [DEVICE-HOME-SEARCH-MISSES-UNOPENED-NOTE]; E2E SYNC-04, jobs 23 and 24,
//! Fri 13 Nov 2026).
//!
//! In SYNC-04 the home's owner creates two `research` NOTEs, pairs a device
//! (`token pair --actor-class human --machine yours`, then `device enrol`),
//! and the device's thin index lists both. The device's text search through
//! its home then answers `{"source":"home","complete":true,"hits":[]}` for
//! the unopened NOTE's words over a 10 s poll. The home's
//! `residence.search` reads under `credential_read_key` of the socket's
//! slip, ranks with `home_search_page_candidates`, then drops a candidate
//! whose window the root lists not, or that the selector does not select
//! (oneiron-server `livequery/residence/pages.rs` 75-122). `complete` only
//! says the scan ended, so the reply does not say which step dropped it.
//!
//! These cases take the first step alone, under the credential the device
//! holds, and print every probe on failure:
//! - the vault's unscoped text search (the fixture: the NOTE is indexed);
//! - the scoped text search under the device credential's read key;
//! - the page candidates at the second the home's request names, and a day
//!   later (a time cut on a row learned this second);
//! - the window the candidate is listed under, against the NOTE row's own.
//!
//! A pass here moves the defect to the root window list or the selector; a
//! failure names the step in its probe line.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test home_search_unopened_note`
#![cfg(oneiron_test_support)]
#![cfg(feature = "sync")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActSurface, HostSlipIssuer, MachineOwnership, MachineRole, PairingLink, PairingPrincipal,
    VerifiedSlip,
};
use oneiron::claim::ScopedReadActorKey;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::Scope;
use oneiron::sync::residence::{home_search_page_candidates, residence_window_for_blob};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

/// SYNC-04's fixture texts and the query that names the unopened one.
const OPENED_TEXT: &str = "Opened project body: jade lantern.";
const UNOPENED_TEXT: &str = "Unopened project body: opal lantern.";
const QUERY: &str = "opal lantern";
/// The depth a home's page search ranks first (`MAX_SEARCH_LIMIT` or more).
const PAGE_WINDOW: usize = 64;
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:home-search-unopened-note";

/// A rooted home whose embedded owner created SYNC-04's two NOTEs.
struct Home {
    vault: Vault,
    _dir: tempfile::TempDir,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    unopened: EntityId,
}

fn home() -> Home {
    let dir = tempfile::tempdir().expect("home vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("home vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let (owner, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    let memory = vault.memory(owner, EdgeActorClass::Human);
    memory
        .create_note("research", OPENED_TEXT)
        .expect("owner creates the opened NOTE");
    let unopened = memory
        .create_note("research", UNOPENED_TEXT)
        .expect("owner creates the unopened NOTE");
    let unopened = EntityId::from_hex(&unopened.id_hex).expect("NOTE id");
    Home {
        vault,
        _dir: dir,
        issuer,
        owner,
        owner_proof,
        unopened,
    }
}

/// The owner's own human principal, as `token pair --actor-class human`
/// names it.
fn owner_principal(owner: EntityId) -> PairingPrincipal {
    PairingPrincipal {
        holder_ref: Some(owner.to_hex()),
        actor_class: Some("human".to_owned()),
        ..PairingPrincipal::default()
    }
}

/// Redeems `link` with a fresh binding key and proves possession, as a
/// device that enrols does.
fn redeem(home: &Home, link: &PairingLink, binding_seed: u8) -> VerifiedSlip {
    let holder = home.owner.to_hex();
    let signing_key = SigningKey::from_bytes(&[binding_seed; 32]);
    let binding_key = signing_key.verifying_key().to_bytes();
    let transcript = oneiron::authority::pairing_binding_transcript_pinned(
        &link.code,
        &binding_key,
        &holder,
        link.pin.as_ref(),
    )
    .expect("device pairing transcript");
    let slip = home
        .vault
        .redeem_pairing_link(
            &home.issuer,
            &link.code,
            &holder,
            binding_key,
            &signing_key.sign(&transcript).to_bytes(),
        )
        .expect("device redeems the owner's pairing link");
    let signature = signing_key
        .sign(
            &slip
                .binding_transcript(REQUEST_CHALLENGE)
                .expect("device request transcript"),
        )
        .to_bytes();
    home.vault
        .verify_capability_slip(
            &home.issuer.public_key(),
            &slip,
            REQUEST_CHALLENGE,
            &signature,
        )
        .expect("device proves possession of its credential")
}

/// Every step's answer for the unopened NOTE, printed on failure.
#[derive(Debug)]
struct Probe {
    unopened: String,
    /// The NOTE row's own window (`residence_window_for_blob`).
    row_window: String,
    as_of: u64,
    /// `Vault::search_text`, unscoped.
    unscoped_hits: Vec<String>,
    /// `ScopedRead::search_text` under the device credential's key.
    scoped_hits: Result<Vec<String>, String>,
    /// `home_search_page_candidates` at `as_of`: (id, window), exhausted.
    page_at_request: Result<(Vec<(String, String)>, bool), String>,
    /// The same a day past `as_of`.
    page_a_day_later: Result<(Vec<(String, String)>, bool), String>,
}

impl Probe {
    fn page_lists_unopened(&self) -> bool {
        matches!(&self.page_at_request, Ok((hits, _))
            if hits.iter().any(|(id, _)| *id == self.unopened))
    }

    fn page_window_of_unopened(&self) -> Option<&str> {
        match &self.page_at_request {
            Ok((hits, _)) => hits
                .iter()
                .find(|(id, _)| *id == self.unopened)
                .map(|(_, window)| window.as_str()),
            Err(_) => None,
        }
    }
}

fn page(
    vault: &Vault,
    key: &ScopedReadActorKey,
    as_of: u64,
) -> Result<(Vec<(String, String)>, bool), String> {
    home_search_page_candidates(
        vault,
        key.clone(),
        QUERY,
        PAGE_WINDOW,
        None,
        as_of,
        None,
        None,
    )
    .map(|(hits, exhausted)| {
        (
            hits.into_iter()
                .map(|(id, _, window)| (id.to_hex(), window.as_str().to_owned()))
                .collect(),
            exhausted,
        )
    })
    .map_err(|error| format!("{error:?}"))
}

/// Runs every probe for the device credential `slip` on `home`.
fn probe(home: &Home, slip: &VerifiedSlip) -> Probe {
    let key = home
        .vault
        .credential_read_key(slip)
        .expect("device credential read key")
        .expect("the owner's device credential grants read");
    let raw = home
        .vault
        .get_raw(&home.unopened)
        .expect("NOTE row read")
        .expect("the unopened NOTE row is held at home");
    let as_of = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("wall clock past the epoch")
        .as_secs();
    let unscoped_hits = home
        .vault
        .search_text(QUERY, 10)
        .expect("unscoped text search")
        .into_iter()
        .map(|hit| hit.id.to_hex())
        .collect();
    let scoped_hits = home
        .vault
        .scoped_read(key.clone())
        .search_text(QUERY, 10, None)
        .map(|found| found.value.into_iter().map(|hit| hit.id.to_hex()).collect())
        .map_err(|error| format!("{error:?}"));
    Probe {
        unopened: home.unopened.to_hex(),
        row_window: residence_window_for_blob(&raw)
            .expect("NOTE row window")
            .as_str()
            .to_owned(),
        as_of,
        unscoped_hits,
        scoped_hits,
        page_at_request: page(&home.vault, &key, as_of),
        page_a_day_later: page(&home.vault, &key, as_of.saturating_add(86_400)),
    }
}

/// The promise each case checks, with the probe line on failure.
fn assert_home_page_ranks_unopened(probe: &Probe) {
    assert!(
        probe.unscoped_hits.contains(&probe.unopened),
        "FIXTURE: the home's own text index holds the unopened NOTE: {probe:#?}"
    );
    assert!(
        probe.page_lists_unopened(),
        "the home's page search under the device's own credential ranks the unopened NOTE: {probe:#?}"
    );
    assert_eq!(
        probe.page_window_of_unopened(),
        Some(probe.row_window.as_str()),
        "the candidate names the window its row is listed in: {probe:#?}"
    );
}

/// The owner's pairing link with every axis open, as `token pair` without
/// `--machine` makes it.
#[test]
fn owner_pairing_credential_home_page_search_ranks_an_unopened_note() {
    let home = home();
    let link = home
        .vault
        .issue_owner_pairing_link(
            &home.issuer,
            &home.owner_proof,
            Scope::top(),
            3_600,
            owner_principal(home.owner),
        )
        .expect("owner issues a pairing link for their own principal");
    let slip = redeem(&home, &link, 0x41);
    assert_home_page_ranks_unopened(&probe(&home, &slip));
}

/// The owner's machine pairing link, `--machine yours`, as SYNC-04's device
/// enrols with.
#[test]
fn owner_machine_link_credential_home_page_search_ranks_an_unopened_note() {
    let home = home();
    let link = home
        .vault
        .issue_machine_pairing_link(
            &home.issuer,
            &home.owner_proof,
            ActSurface::ThisInstall,
            Scope::top(),
            3_600,
            owner_principal(home.owner),
            MachineOwnership::Yours,
        )
        .expect("owner issues a machine pairing link for their own device");
    let slip = redeem(&home, &link, 0x42);
    assert_home_page_ranks_unopened(&probe(&home, &slip));
}
