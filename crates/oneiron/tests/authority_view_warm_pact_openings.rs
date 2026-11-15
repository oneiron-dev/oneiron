//! FIX 23233 [AUTHORITY-HIT-READS-PACT-CUSTODY]: a warm authority view hit
//! re-checks each live pact's scope commitment in the caller's snapshot
//! (FIX 11730, FIX 22382). The warm reads of one authority generation read
//! a live pact's scope opening from custody once, not on every read.
//!
//! The fixture is the two-vault Connect of `tests/inquiry_edge.rs`: the
//! company Owner accepts the member's offer, so the company's vault holds
//! one Active pact and that pact's live opening key.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test authority_view_warm_pact_openings`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::authority::{
    AuthorityVaultId, FederationPactStatus, HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::inquiry::InquiryEdgeRequest;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::authority_view_grant::custody_entry_reads;
use oneiron::{EntityId, Vault, VaultConfig};

/// The company's name, as the member's edge reads it.
const COMPANY: &str = "Acme";
/// The member's name, as the company's reciprocal WORLD reads it.
const MEMBER: &str = "owen";
/// How many warm reads the bar counts over.
const WARM_READS: usize = 10;

/// One rooted vault with its owner bound to its own host.
struct Side {
    vault: Vault,
    proof: AuthenticatedOwner,
    issuer: HostSlipIssuer,
    vault_id: AuthorityVaultId,
    _dir: tempfile::TempDir,
}

/// A vault rooted under a host of its own (`seed`), its engine machines and
/// install profile provisioned and its owner bound, as a host does.
fn side(seed: u8) -> Side {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = HostSlipIssuer::from_seed(&[seed; HOST_ISSUER_SEED_BYTES]).expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's machine profile");
    let owner: EntityId = vault.ensure_embedded_owner_actor().expect("owner actor");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("owner bound");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let vault_id = vault
        .authority_fold()
        .expect("authority fold")
        .vault_id
        .expect("a rooted vault has an id");
    Side {
        vault,
        proof,
        issuer,
        vault_id,
        _dir: dir,
    }
}

#[test]
fn ten_warm_reads_with_one_live_pact_open_at_most_one_custody_entry() {
    let member = side(0x11);
    let company = side(0x22);

    let edge = member
        .vault
        .mint_inquiry_edge(
            &member.proof,
            &InquiryEdgeRequest::member_defaults(company.vault_id, COMPANY),
        )
        .expect("the member mints the inquiry edge");
    let reciprocal = company
        .vault
        .mint_inquiry_edge_reciprocal_grant(&company.proof, member.vault_id, MEMBER)
        .expect("the company Owner mints the reciprocal grant");
    let offer = member
        .vault
        .propose_connect_as(
            &member.proof,
            &member.issuer,
            edge.grant,
            company.vault_id,
            edge.pact_direction().expect("the edge's direction"),
            reciprocal
                .pact_direction()
                .expect("the reciprocal grant's direction"),
        )
        .expect("the member offers the Connect");

    // From here every custody read on this thread is the company vault's:
    // the member's vault is not touched again.
    let before_accept = custody_entry_reads();
    let (company_pact, _counter) = company
        .vault
        .accept_connect_as(&company.proof, &company.issuer, reciprocal.grant, &offer)
        .expect("the company Owner accepts");
    assert_eq!(company_pact.status, FederationPactStatus::Active);
    assert_eq!(
        company
            .vault
            .federation_scope_commitment_mismatches()
            .expect("the first read after the accept"),
        Vec::<[u8; 32]>::new(),
        "the pact's folded scope matches its commitment",
    );
    let warm = custody_entry_reads();
    assert!(
        warm > before_accept,
        "the first read after the accept re-checks the live pact under its opening, read from custody",
    );

    for read in 0..WARM_READS {
        assert_eq!(
            company
                .vault
                .federation_scope_commitment_mismatches()
                .expect("a warm read"),
            Vec::<[u8; 32]>::new(),
            "warm read {read} holds no pact inactive",
        );
    }
    let opened = custody_entry_reads() - warm;
    assert!(
        opened <= 1,
        "{WARM_READS} warm reads of one authority generation opened {opened} custody entries; the bar is one",
    );
}
