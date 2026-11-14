//! Census L3-28A (ARCH-0044 H424): the standing outbound grant reads by
//! principal and by grant id are served from two derived indexes instead of
//! decoding every standing consent Grant row per call. The indexes change no
//! answer: after mints (two rows under one id, one id under two principals,
//! a Grant row that is no outbound grant), revokes, a re-mint, and a reopen
//! that rebuilds the dropped indexes, each read answers as the full scan
//! answers, and the index answers it (no fallback). A timing line compares
//! the two reads at 2,000 grants.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test outbound_grant_index -- --nocapture`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::{Duration, Instant};

use oneiron::consent::AuthenticatedOwner;
use oneiron::consent_graduation::RampScope;
use oneiron::genui::GrantMintIntentScope;
use oneiron::outbound_grant::StandingOutboundGrant;
use oneiron::test_doors::outbound_grant_index as doors;
use oneiron::test_doors::untangle_regressions::open_test_vault_with;
use oneiron::{EntityId, Vault, VaultConfig};

const OWEN: &str = "principal:owen";
const YUKI: &str = "principal:yuki";
const NOBODY: &str = "principal:nobody";

fn owner(vault: &Vault) -> AuthenticatedOwner {
    let actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(
            actor,
            "principal:owner",
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .expect("authenticate owner")
}

fn id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("grant id")
}

fn verb_class(verb_class: &str) -> GrantMintIntentScope {
    GrantMintIntentScope::VerbClass {
        verb_class: verb_class.to_owned(),
    }
}

fn channel(channel: &str) -> GrantMintIntentScope {
    GrantMintIntentScope::Channel {
        channel: channel.to_owned(),
    }
}

/// Each principal's and each id's read: the index answers (no fallback), and
/// its answer is the full scan's.
fn assert_index_answers_as_scan(vault: &Vault, principals: &[&str], ids: &[EntityId]) {
    for principal in principals {
        let scanned = doors::scanned_grants_for_principal(vault, principal).expect("scan");
        let indexed = doors::indexed_grants_for_principal(vault, principal).expect("index");
        assert_eq!(
            indexed.as_ref(),
            Some(&scanned),
            "principal {principal}: the index answers as the scan"
        );
    }
    for id in ids {
        assert!(
            doors::indexed_grants_with_id(vault, id)
                .expect("index")
                .is_some(),
            "grant {id:?}: the id index answers"
        );
        assert_eq!(
            vault.get_standing_outbound_grant(id).expect("served read"),
            doors::scanned_grant(vault, id).expect("scan"),
            "grant {id:?}: the served read answers as the scan"
        );
    }
}

#[test]
fn index_answers_as_the_scan_through_mints_revokes_and_a_reopen() {
    let (dir, vault) = open_test_vault_with(VaultConfig::device());
    assert!(
        doors::index_complete(&vault).expect("flag"),
        "open builds the index"
    );
    let owner = owner(&vault);
    let x = id(0x51);
    let y = id(0x52);
    let z = id(0x53);
    let minted = doors::mint_standing_outbound_grants(
        &vault,
        &owner,
        &[
            (x, OWEN.to_owned(), verb_class("send")),
            (x, OWEN.to_owned(), channel("email")),
            (y, OWEN.to_owned(), verb_class("send")),
            (z, YUKI.to_owned(), verb_class("send")),
            (x, YUKI.to_owned(), channel("discord")),
        ],
    )
    .expect("mint");
    // A standing consent Grant row that is no outbound grant indexes nothing.
    let ramp = RampScope::new("send_email", "client_followup", OWEN).expect("ramp scope");
    vault
        .create_standing_grant(&owner, ramp.to_grant_bound().expect("bound"))
        .expect("a ramp grant");
    let principals = [OWEN, YUKI, NOBODY];
    let ids = [x, y, z, id(0x54)];
    assert_index_answers_as_scan(&vault, &principals, &ids);
    assert_eq!(
        doors::scanned_grants_for_principal(&vault, OWEN)
            .expect("scan")
            .len(),
        3
    );
    assert_eq!(
        doors::indexed_grants_with_id(&vault, &x)
            .expect("index")
            .map(|grants| grants.len()),
        Some(3),
        "id x holds three rows: two of owen's, one of yuki's"
    );
    assert_eq!(
        vault.get_standing_outbound_grant(&id(0x54)).expect("read"),
        None
    );

    // Revoke x's rows one by one: the read keeps the live one, then the
    // first revoked row in Grant row order, as the scan does.
    let x_rows: Vec<&StandingOutboundGrant> = minted.iter().filter(|grant| grant.id == x).collect();
    for grant in &x_rows {
        vault
            .revoke_consent_grant(&owner, &grant.grant_ref())
            .expect("revoke");
        assert_index_answers_as_scan(&vault, &principals, &ids);
    }
    let read = vault
        .get_standing_outbound_grant(&x)
        .expect("read")
        .expect("x");
    assert!(!read.is_active(), "every row of x is revoked");

    // A re-mint of the same bound is the same Grant row, live again.
    doors::mint_standing_outbound_grants(&vault, &owner, &[(x, OWEN.to_owned(), channel("email"))])
        .expect("re-mint");
    assert_index_answers_as_scan(&vault, &principals, &ids);
    assert!(
        vault
            .get_standing_outbound_grant(&x)
            .expect("read")
            .expect("x")
            .is_active()
    );

    // A vault older than the index: the reads fall back to the scan, and
    // the next open rebuilds the index from the Grant rows.
    doors::drop_index(&vault).expect("drop");
    assert!(!doors::index_complete(&vault).expect("flag"));
    assert_eq!(
        doors::indexed_grants_for_principal(&vault, OWEN).expect("index"),
        None
    );
    assert_eq!(
        doors::indexed_grants_with_id(&vault, &x).expect("index"),
        None
    );
    assert_eq!(
        vault.get_standing_outbound_grant(&x).expect("read"),
        doors::scanned_grant(&vault, &x).expect("scan")
    );
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("reopen");
    assert!(
        doors::index_complete(&vault).expect("flag"),
        "the reopen rebuilds the index"
    );
    assert_index_answers_as_scan(&vault, &principals, &ids);
}

#[test]
fn index_and_scan_reads_timed_at_two_thousand_grants() {
    const PRINCIPALS: u16 = 200;
    const PER_PRINCIPAL: u16 = 10;
    let (_dir, vault) = open_test_vault_with(VaultConfig::device());
    let owner = owner(&vault);
    let principals: Vec<String> = (0..PRINCIPALS)
        .map(|n| format!("principal:owen-{n:03}"))
        .collect();
    let mut ids = Vec::new();
    let mut batch = Vec::new();
    for (p, principal) in principals.iter().enumerate() {
        for k in 0..PER_PRINCIPAL {
            let mut bytes = [0x7A; 16];
            bytes[..2].copy_from_slice(&u16::try_from(p).expect("p").to_be_bytes());
            bytes[2..4].copy_from_slice(&k.to_be_bytes());
            let grant = EntityId::from_bytes(bytes).expect("grant id");
            ids.push(grant);
            batch.push((grant, principal.clone(), verb_class("send")));
        }
        if batch.len() >= 500 {
            doors::mint_standing_outbound_grants(&vault, &owner, &batch).expect("mint");
            batch.clear();
        }
    }
    doors::mint_standing_outbound_grants(&vault, &owner, &batch).expect("mint");
    let read_ids: Vec<EntityId> = ids
        .iter()
        .step_by(usize::from(PER_PRINCIPAL))
        .copied()
        .collect();

    let (mut principal_index, mut principal_scan) = (Duration::ZERO, Duration::ZERO);
    for principal in &principals {
        let started = Instant::now();
        let indexed = doors::indexed_grants_for_principal(&vault, principal).expect("index");
        principal_index += started.elapsed();
        let started = Instant::now();
        let scanned = doors::scanned_grants_for_principal(&vault, principal).expect("scan");
        principal_scan += started.elapsed();
        assert_eq!(scanned.len(), usize::from(PER_PRINCIPAL));
        assert_eq!(indexed, Some(scanned), "principal {principal}");
    }
    let (mut id_index, mut id_scan) = (Duration::ZERO, Duration::ZERO);
    for grant in &read_ids {
        let started = Instant::now();
        let served = vault
            .get_standing_outbound_grant(grant)
            .expect("served read");
        id_index += started.elapsed();
        let started = Instant::now();
        let scanned = doors::scanned_grant(&vault, grant).expect("scan");
        id_scan += started.elapsed();
        assert!(served.is_some());
        assert_eq!(served, scanned, "grant {grant:?}");
    }
    eprintln!(
        "DIAG outbound-grant-index grants={} principal_reads={} principal_index_ms={} principal_scan_ms={} id_reads={} id_index_ms={} id_scan_ms={}",
        ids.len(),
        principals.len(),
        principal_index.as_millis(),
        principal_scan.as_millis(),
        read_ids.len(),
        id_index.as_millis(),
        id_scan.as_millis(),
    );
}
