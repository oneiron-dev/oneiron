//! Authority-fold work stays bounded, and the store doors keep a log inside
//! the bounds (H72, W2-T3).
use super::support::*;
use super::*;

fn confirm_op(n: usize) -> AuthorityOp {
    let mut confirm_id = [0xC0; 32];
    confirm_id[..8].copy_from_slice(&(n as u64).to_be_bytes());
    let mut nonce = [0xC0; 16];
    nonce[..8].copy_from_slice(&(n as u64).to_be_bytes());
    AuthorityOp::FederationConfirm(AuthorityConfirmAction {
        kind: AuthorityConfirmKind::Accept,
        confirm_id,
        peer_vault_id: [77; 32],
        epoch: 1,
        nonce,
    })
}

/// `len` FederationConfirm rows in one chain under `parent`, each signed by
/// `seed`'s key and naming the row before it plus `extra(n)`.
fn confirm_chain(
    genesis: &AuthorityLogEntry,
    seed: u8,
    len: usize,
    extra: impl Fn(usize) -> Vec<AuthorityEntryHash>,
) -> Vec<AuthorityLogEntry> {
    let signing = ed_key(seed);
    let vault_id = genesis_vault_id(genesis).unwrap();
    let mut parent = authority_entry_hash(genesis).unwrap();
    let mut chain = Vec::with_capacity(len);
    for n in 0..len {
        let mut parents = extra(n);
        parents.push(parent);
        let entry = sign_ed(
            unsigned_entry(
                Some(vault_id),
                n as u64 + 1,
                parents,
                confirm_op(n),
                authority_key_from_ed(&signing),
                3,
            ),
            &signing,
        );
        parent = authority_entry_hash(&entry).unwrap();
        chain.push(entry);
    }
    chain
}

fn assert_folds_closed(fold: &AuthorityFold) {
    assert!(fold.authority_log_past_bound());
    assert!(
        fold.vault_root_is_conflicted(),
        "a refused log fails closed"
    );
    assert!(fold.vault_id.is_none() && fold.roster.is_empty() && fold.valid_entries.is_empty());
}

/// Bug repro: a key the vault never enrolled signs a chain naming the vault
/// id. Past the row bound the fold refuses the whole log before any work and
/// fails closed. Past the handoff bound it does the same.
#[test]
fn a_self_signed_chain_past_the_row_bound_folds_closed() {
    let genesis = genesis_entry(60, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let mut entries = vec![genesis.clone()];
    entries.extend(confirm_chain(
        &genesis,
        201,
        MAX_AUTHORITY_FOLD_ENTRIES,
        |_| vec![],
    ));
    assert_folds_closed(&fold_authority_log(&entries));

    let stranger = ed_key(203);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let mut entries = vec![genesis.clone()];
    for n in 0..=MAX_AUTHORITY_FOLD_HANDOFFS {
        entries.push(sign_ed(
            unsigned_entry(
                Some(vault_id),
                n as u64 + 1,
                vec![authority_entry_hash(&genesis).unwrap()],
                AuthorityOp::ReRoot {
                    new_device: device(
                        authority_key_from_ed(&ed_key(n as u8)),
                        ROLE_OWNER,
                        AuthorityTier::Software,
                    ),
                },
                authority_key_from_ed(&stranger),
                3,
            ),
            &stranger,
        ));
    }
    assert_folds_closed(&fold_authority_log(&entries));
}

/// Bug repro: under the row bound, a chain whose rows each name missing
/// parents inflates every row's ancestry. The index stops at its edge bound
/// and the fold fails closed instead of building the rest.
#[test]
fn a_chain_naming_missing_parents_past_the_edge_bound_folds_closed() {
    let genesis = genesis_entry(63, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let missing = |n: usize| {
        (0..MAX_PARENTS - 1)
            .map(|k| {
                let mut hash = [0xEE; 32];
                hash[..8].copy_from_slice(&(n as u64).to_be_bytes());
                hash[8] = k as u8;
                hash
            })
            .collect()
    };
    let mut entries = vec![genesis.clone()];
    entries.extend(confirm_chain(&genesis, 204, 1024, missing));
    assert!(entries.len() < MAX_AUTHORITY_FOLD_ENTRIES);
    assert_folds_closed(&fold_authority_log(&entries));
}

/// Positive control: one signer's full bound of rows in a single chain, the
/// shape every local writer produces, still folds with every row valid.
#[test]
fn a_signers_full_bound_still_folds() {
    let genesis = genesis_entry(61, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let mut entries = vec![genesis.clone()];
    entries.extend(confirm_chain(
        &genesis,
        61,
        MAX_AUTHORITY_ROWS_PER_SIGNER - 1,
        |_| vec![],
    ));
    let fold = fold_authority_log(&entries);
    assert!(!fold.authority_log_past_bound() && !fold.vault_root_is_conflicted());
    assert_eq!(fold.valid_entries.len(), MAX_AUTHORITY_ROWS_PER_SIGNER);
}

/// Substrate invariant: the store door refuses a signer's row past its bound
/// with a typed error and writes nothing. A row that only restricts still
/// lands for that signer, and another signer still writes.
#[test]
fn a_signer_at_its_bound_is_refused_but_restrictions_and_other_signers_land() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let genesis = genesis_entry(64, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let mut chain = confirm_chain(&genesis, 64, MAX_AUTHORITY_ROWS_PER_SIGNER, |_| vec![]);
    let over = chain.pop().unwrap();
    let at = TimeRange { start: 1, end: 1 };
    let mut rows = vec![(genesis.clone(), at, 1)];
    rows.extend(chain.iter().map(|entry| (entry.clone(), at, 1)));
    vault.put_authority_log_entries(&rows).unwrap();
    let stored = vault
        .count_entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
        .unwrap();
    assert_eq!(stored, MAX_AUTHORITY_ROWS_PER_SIGNER as u64);

    let err = vault.put_authority_log_entry(&over, at, 1).unwrap_err();
    assert_eq!(err.kind(), crate::error::ErrorKind::AuthorityLogFull);
    assert_eq!(
        vault
            .count_entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
            .unwrap(),
        stored
    );

    let owner = ed_key(64);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let head = authority_entry_hash(chain.last().unwrap()).unwrap();
    let revoke = sign_ed(
        unsigned_entry(
            Some(vault_id),
            MAX_AUTHORITY_ROWS_PER_SIGNER as u64 + 1,
            vec![head],
            AuthorityOp::SlipRevoke { slip_id: [9; 32] },
            authority_key_from_ed(&owner),
            3,
        ),
        &owner,
    );
    vault.put_authority_log_entry(&revoke, at, 1).unwrap();
    let other = confirm_chain(&genesis, 65, 1, |_| vec![head]);
    vault.put_authority_log_entry(&other[0], at, 1).unwrap();
    assert_eq!(
        vault
            .count_entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
            .unwrap(),
        stored + 2
    );
}

#[test]
fn fold_scale_probe() {
    for len in [512, 1024, 2048, 4096] {
        let genesis = genesis_entry(62, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
        let mut entries = vec![genesis.clone()];
        entries.extend(confirm_chain(&genesis, 62, len - 1, |_| vec![]));
        let started = Instant::now();
        let fold = fold_authority_log(&entries);
        eprintln!(
            "PROBE legit {len}: {:?} valid {} past_bound {}",
            started.elapsed(),
            fold.valid_entries.len(),
            fold.authority_log_past_bound()
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let genesis = genesis_entry(66, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let at = TimeRange { start: 1, end: 1 };
    let mut rows = vec![(genesis.clone(), at, 1)];
    rows.extend(
        confirm_chain(&genesis, 66, 2047, |_| vec![])
            .into_iter()
            .map(|entry| (entry, at, 1)),
    );
    let started = Instant::now();
    vault.put_authority_log_entries(&rows).unwrap();
    eprintln!("PROBE put 2048 rows: {:?}", started.elapsed());
    let started = Instant::now();
    let fold = vault.authority_fold().unwrap();
    eprintln!(
        "PROBE vault fold 2048: {:?} valid {}",
        started.elapsed(),
        fold.valid_entries.len()
    );
}
