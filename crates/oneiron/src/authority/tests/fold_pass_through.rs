//! A sealed AUTHORITY_LOG row whose overlay record does not open on this
//! install still lands, as structure only: its signer, sequence and parents
//! fold, and nothing it made counts (census L5-22 1a-iii;
//! RULING PLAN-L5-22-ERASED-ROWS = A).

use super::support::*;
use super::*;
use crate::authority::fold_engine::{FoldLocalInputs, fold_authority_log_inner};
use crate::federation::Scope;

/// A slip mint's claims over `vault_id`: `records` and `channels` name
/// bounds, so the row seals and passes through without its overlay record.
fn mint_claims(
    slip_id: [u8; 32],
    vault_id: AuthorityVaultId,
    parent_id: Option<[u8; 32]>,
) -> SlipClaims {
    SlipClaims {
        slip_id,
        vault_id,
        parent_id,
        holder_ref: "pass-through-holder".to_owned(),
        binding_key: ed_key(17).verifying_key().to_bytes(),
        scope: Scope::default(),
        issued_at: 100,
        expires_at: 200,
        ttl_secs: 100,
        single_use: false,
        records: BTreeSet::from(["payroll-key".to_owned()]),
        channels: BTreeSet::from(["git.receive-pack".to_owned()]),
        actor_class: None,
        org_ref: None,
        grant_ref: None,
        invitation_ref: None,
        share_ref: None,
        delegation: None,
        comm: None,
        trusted_contact: None,
        seat_claim: None,
    }
}

/// The owner's slip mint over `claims` at `seq`, parented on `parent`.
fn mint_entry(
    owner: &SigningKey,
    vault_id: AuthorityVaultId,
    parent: AuthorityEntryHash,
    seq: u64,
    claims: SlipClaims,
) -> AuthorityLogEntry {
    sign_ed(
        unsigned_entry(
            Some(vault_id),
            seq,
            vec![parent],
            AuthorityOp::SlipMint(SlipMintAction {
                claims,
                renews: None,
                minting_member: None,
            }),
            authority_key_from_ed(owner),
            100 + seq,
        ),
        owner,
    )
}

/// G, the owner's sealed mint M at seq 1 over G, and the owner's open mint
/// N at seq 2 over M: the rows the pass-through tests fold.
struct PassThroughFixture {
    owner_key: AuthorityKey,
    genesis: AuthorityLogEntry,
    mint: AuthorityLogEntry,
    mint_hash: AuthorityEntryHash,
    mint_slip: [u8; 32],
    mint_closed: FoldRow,
    next: AuthorityLogEntry,
    next_hash: AuthorityEntryHash,
    next_slip: [u8; 32],
}

fn pass_through_fixture() -> PassThroughFixture {
    let owner = ed_key(60);
    let genesis = genesis_entry(60, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let genesis_hash = authority_entry_hash(&genesis).unwrap();
    let mint_slip = [61; 32];
    let mint = mint_entry(
        &owner,
        vault_id,
        genesis_hash,
        1,
        mint_claims(mint_slip, vault_id, None),
    );
    let mint_hash = authority_entry_hash(&mint).unwrap();
    let sealed = encode_authority_log_entry_body(&mint).expect("the mint seals");
    let public =
        verify_authority_public_row(&sealed).expect("the sealed mint verifies as structure");
    let next_slip = [62; 32];
    let next = mint_entry(
        &owner,
        vault_id,
        mint_hash,
        2,
        mint_claims(next_slip, vault_id, None),
    );
    let next_hash = authority_entry_hash(&next).unwrap();
    PassThroughFixture {
        owner_key: authority_key_from_ed(&owner),
        genesis,
        mint,
        mint_hash,
        mint_slip,
        mint_closed: FoldRow::PassThrough(public),
        next,
        next_hash,
        next_slip,
    }
}

/// A vault-door fold over `rows`. The fold entry the authority tests use
/// takes whole entries, so the pass-through tests call
/// [`fold_authority_log_inner`] directly, the only vault-door entry over
/// rows.
fn fold_rows(rows: &[FoldRow]) -> AuthorityFold {
    fold_authority_log_inner(
        rows,
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
        folded_device_can_authority_consent,
        FoldLocalInputs::VAULT_DOOR,
    )
}

#[test]
fn a_sealed_mint_that_does_not_open_places_the_log_and_grants_nothing() {
    let fixture = pass_through_fixture();
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let rows = vec![
        FoldRow::Open(fixture.genesis.clone()),
        fixture.mint_closed.clone(),
        FoldRow::Open(fixture.next.clone()),
    ];
    let fold = fold_rows(&rows);
    assert!(fold.pass_through_entries.contains(&fixture.mint_hash));
    assert!(!fold.valid_entries.contains(&fixture.mint_hash));
    assert!(fold.valid_entries.contains(&genesis_hash));
    assert!(fold.valid_entries.contains(&fixture.next_hash));
    assert!(fold.slips.mints.contains_key(&fixture.next_slip));
    assert!(!fold.slips.mints.contains_key(&fixture.mint_slip));
    assert_eq!(fold.append_heads, BTreeSet::from([fixture.next_hash]));
    assert_eq!(fold.append_sequences[&fixture.owner_key], 2);
    assert!(fold.issues.is_empty(), "{:?}", fold.issues);
}

#[test]
fn the_same_mint_opened_counts_as_before() {
    let fixture = pass_through_fixture();
    let rows = vec![
        FoldRow::Open(fixture.genesis.clone()),
        FoldRow::Open(fixture.mint.clone()),
        FoldRow::Open(fixture.next.clone()),
    ];
    let fold = fold_rows(&rows);
    assert!(fold.valid_entries.contains(&fixture.mint_hash));
    assert!(fold.valid_entries.contains(&fixture.next_hash));
    assert!(fold.slips.mints.contains_key(&fixture.mint_slip));
    assert!(fold.slips.mints.contains_key(&fixture.next_slip));
    assert!(fold.pass_through_entries.is_empty());
}

#[test]
fn a_sealed_mint_alone_is_the_head() {
    let fixture = pass_through_fixture();
    let rows = vec![
        FoldRow::Open(fixture.genesis.clone()),
        fixture.mint_closed.clone(),
    ];
    let fold = fold_rows(&rows);
    assert_eq!(fold.append_heads, BTreeSet::from([fixture.mint_hash]));
    assert_eq!(fold.append_sequences[&fixture.owner_key], 1);
    assert!(!fold.valid_entries.contains(&fixture.mint_hash));
    assert!(fold.pass_through_entries.contains(&fixture.mint_hash));
}

#[test]
fn a_sealed_mint_at_a_stale_sequence_is_refused_and_its_child_never_folds() {
    let owner = ed_key(60);
    let genesis = genesis_entry(60, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let genesis_hash = authority_entry_hash(&genesis).unwrap();
    // The sealed mint at seq 0, the owner's own genesis sequence: strict
    // sequence fails.
    let stale = mint_entry(
        &owner,
        vault_id,
        genesis_hash,
        0,
        mint_claims([61; 32], vault_id, None),
    );
    let stale_hash = authority_entry_hash(&stale).unwrap();
    let sealed = encode_authority_log_entry_body(&stale).expect("the mint seals");
    let public =
        verify_authority_public_row(&sealed).expect("the sealed mint verifies as structure");
    let child = mint_entry(
        &owner,
        vault_id,
        stale_hash,
        2,
        mint_claims([62; 32], vault_id, None),
    );
    let child_hash = authority_entry_hash(&child).unwrap();
    let rows = vec![
        FoldRow::Open(genesis),
        FoldRow::PassThrough(public),
        FoldRow::Open(child),
    ];
    let fold = fold_rows(&rows);
    assert!(!fold.valid_entries.contains(&stale_hash));
    assert!(!fold.pass_through_entries.contains(&stale_hash));
    assert!(
        fold.issues
            .contains(&AuthorityFoldIssue::NonMonotonicSeq(stale_hash))
    );
    assert!(!fold.valid_entries.contains(&child_hash));
    assert!(!fold.pass_through_entries.contains(&child_hash));
    assert!(
        fold.issues
            .contains(&AuthorityFoldIssue::InvalidAncestry(child_hash))
    );
}

#[test]
fn a_child_that_needs_the_hidden_mint_does_not_count() {
    let fixture = pass_through_fixture();
    let owner = ed_key(60);
    let vault_id = genesis_vault_id(&fixture.genesis).unwrap();
    // C names M's slip as its parent slip, and carries no records or
    // channels, so it stays unsealed and folds open.
    let child_slip = [63; 32];
    let mut claims = mint_claims(child_slip, vault_id, Some(fixture.mint_slip));
    claims.records.clear();
    claims.channels.clear();
    let child = mint_entry(&owner, vault_id, fixture.mint_hash, 2, claims);
    let child_hash = authority_entry_hash(&child).unwrap();
    let rows = vec![
        FoldRow::Open(fixture.genesis),
        fixture.mint_closed,
        FoldRow::Open(child),
    ];
    let fold = fold_rows(&rows);
    assert!(!fold.valid_entries.contains(&child_hash));
    assert!(!fold.slips.mints.contains_key(&child_slip));
    assert!(
        fold.issues
            .contains(&AuthorityFoldIssue::InvalidEntry(child_hash))
    );
}
