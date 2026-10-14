//! Authority-fold work stays bounded, and the store doors keep a log inside
//! the bounds (H72, W2-T3).
use super::machine_identity::{host, request_for};
use super::support::*;
use super::*;
use crate::authority::log_budget::{authority_signer_label, with_rows_per_signer_for_test};

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
/// with a typed error naming the signer, and writes nothing. A row that only
/// restricts still lands for that signer, and another signer still writes.
#[test]
fn a_signer_at_its_bound_is_refused_but_restrictions_and_other_signers_land() {
    const BOUND: usize = 16;
    with_rows_per_signer_for_test(BOUND, || {
        let dir = tempfile::tempdir().unwrap();
        let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
        let genesis = genesis_entry(64, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
        let mut chain = confirm_chain(&genesis, 64, BOUND, |_| vec![]);
        let over = chain.pop().unwrap();
        let at = TimeRange { start: 1, end: 1 };
        let mut rows = vec![(genesis.clone(), at, 1)];
        rows.extend(chain.iter().map(|entry| (entry.clone(), at, 1)));
        vault.put_authority_log_entries(&rows).unwrap();
        let stored = vault
            .count_entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
            .unwrap();
        assert_eq!(stored, BOUND as u64);

        let err = vault.put_authority_log_entry(&over, at, 1).unwrap_err();
        assert_eq!(err.kind(), crate::error::ErrorKind::AuthorityLogFull);
        let owner = ed_key(64);
        let label = authority_signer_label(&authority_key_from_ed(&owner));
        assert!(err.to_string().contains(&label), "{err}");
        assert_eq!(
            vault
                .count_entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
                .unwrap(),
            stored
        );

        let vault_id = genesis_vault_id(&genesis).unwrap();
        let head = authority_entry_hash(chain.last().unwrap()).unwrap();
        let revoke = sign_ed(
            unsigned_entry(
                Some(vault_id),
                BOUND as u64 + 1,
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
    });
}

fn claims_numbered(template: &SlipClaims, n: usize) -> SlipClaims {
    let mut claims = template.clone();
    claims.slip_id = [0x5A; 32];
    claims.slip_id[..8].copy_from_slice(&(n as u64).to_be_bytes());
    claims.holder_ref = "oauth-holder".to_owned();
    claims
}

/// Bug repro (the OAuth bound): every OAuth exchange mints one slip row
/// signed by the host root. Past its per-signer bound and the fold's row
/// bound, exchanges still mint and the owner's machine stays theirs: the
/// slip issuer's slip rows count toward no bound. After a host move the new
/// root mints past every bound too, and the old root's rows stay uncounted.
#[test]
fn oauth_exchanges_past_every_bound_still_mint_and_the_machines_stay_mine() {
    const BOUND: usize = 4;
    let host = host();
    let machine = request_for(host.vault_id, EntityId::now(), &ed_key(71));
    host.vault
        .enroll_machine(
            &host.issuer,
            &host.owner,
            &machine,
            MachineRole::Owned(MachineOwnership::Yours),
        )
        .unwrap();
    with_rows_per_signer_for_test(BOUND, || {
        let root = host.vault.ensure_host_root_slip(&host.issuer).unwrap();
        // Ten times the fold's row bound, all signed by the host root.
        for n in 0..40 * BOUND {
            host.vault
                .mint_oauth_capability_slip(
                    &host.issuer,
                    claims_numbered(&root.claims, n),
                    3600,
                    None,
                )
                .unwrap();
        }
        let fold = host.vault.authority_fold().unwrap();
        assert!(!fold.authority_log_past_bound() && !fold.vault_root_is_conflicted());
        assert!(fold.slips.mints.len() > 40 * BOUND);
        assert!(
            fold.machine(machine.machine)
                .is_some_and(FoldedMachine::is_mine)
        );
    });
    let next = HostSlipIssuer::from_secret(b"next host root placeholder words").unwrap();
    host.vault.re_root_host(&host.issuer, &next).unwrap();
    with_rows_per_signer_for_test(BOUND, || {
        let root = host.vault.ensure_host_root_slip(&next).unwrap();
        for n in 0..10 * BOUND {
            host.vault
                .mint_oauth_capability_slip(
                    &next,
                    claims_numbered(&root.claims, 1000 + n),
                    3600,
                    None,
                )
                .unwrap();
        }
        let fold = host.vault.authority_fold().unwrap();
        assert!(!fold.authority_log_past_bound() && !fold.vault_root_is_conflicted());
        assert!(
            fold.machine(machine.machine)
                .is_some_and(FoldedMachine::is_mine)
        );
    });
}

/// The slip issuer's chain of slip rows, minted on top of `root`.
fn issuer_slip_chain(
    signer: &HostSlipIssuer,
    root: &CapabilitySlip,
    parent: AuthorityEntryHash,
    first_seq: u64,
    len: usize,
) -> Vec<AuthorityLogEntry> {
    let mut parent = parent;
    (0..len)
        .map(|n| {
            let entry = signer
                .sign_entry(
                    Some(root.claims.vault_id),
                    first_seq + n as u64,
                    vec![parent],
                    AuthorityOp::SlipMint(SlipMintAction {
                        claims: claims_numbered(&root.claims, n),
                    }),
                    root.claims.issued_at,
                )
                .unwrap();
            parent = authority_entry_hash(&entry).unwrap();
            entry
        })
        .collect()
}

/// Structural: the slip issuer's slip rows count toward neither the fold's
/// row bound nor its ancestor-pair bound, however many there are, even under
/// rows that do count. The same rows signed by a key no owner admitted count
/// in full and fold closed.
#[test]
fn the_slip_issuers_slip_rows_count_toward_no_fold_bound() {
    const BOUND: usize = 4;
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    let issuer = crate::test_support::test_host_issuer();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    let base: Vec<_> = {
        let txn = vault.store.env.read_txn().unwrap();
        authority_log_rows_in_txn(&vault.store, &txn)
            .unwrap()
            .into_iter()
            .map(|(_, body)| decode_authority_log_entry_body(&body).unwrap())
            .collect()
    };
    let base_fold = fold_authority_log(&base);
    let head = *base_fold.append_heads.iter().next().unwrap();
    let next_seq = base_fold.append_sequences[&issuer.public_key()] + 1;
    let slips = issuer_slip_chain(&issuer, &root, head, next_seq, 64 * BOUND);
    let mut entries = base.clone();
    entries.extend(slips.iter().cloned());
    // Counted rows on top of the slip chain: each one's ancestry holds every
    // slip row, which would pass the pair bound many times over.
    let mut parent = authority_entry_hash(slips.last().unwrap()).unwrap();
    for n in 0..BOUND {
        let entry = issuer
            .sign_entry(
                Some(root.claims.vault_id),
                next_seq + (64 * BOUND + n) as u64,
                vec![parent],
                confirm_op(n),
                root.claims.issued_at,
            )
            .unwrap();
        parent = authority_entry_hash(&entry).unwrap();
        entries.push(entry);
    }
    with_rows_per_signer_for_test(BOUND, || {
        let fold = fold_authority_log(&entries);
        assert!(!fold.authority_log_past_bound(), "{:?}", fold.issues);
        assert_eq!(fold.valid_entries.len(), entries.len());
        let by_hash: BTreeMap<_, _> = entries
            .iter()
            .map(|entry| (authority_entry_hash(entry).unwrap(), entry.clone()))
            .collect();
        let uncounted = crate::authority::log_budget::uncounted_rows(&by_hash);
        assert_eq!(uncounted.len(), slips.len() + 1, "the root mint too");

        let stranger = HostSlipIssuer::from_secret(b"stranger placeholder words").unwrap();
        let mut foreign = base.clone();
        foreign.extend(issuer_slip_chain(&stranger, &root, head, 1, 64 * BOUND));
        let fold = fold_authority_log(&foreign);
        assert_eq!(
            fold.authority_log_bound_signer(),
            Some(&stranger.public_key())
        );
        assert_folds_closed(&fold);
    });
}

/// Substrate invariant: the slip issuers are owner keys only. Slip ops
/// signed by an agent key the host enrolled, or by the key of a machine the
/// owner holds as theirs, count toward that signer's bound as any other row
/// does. Its revocation still lands past the bound.
#[test]
fn agent_and_machine_keys_slip_ops_count_toward_their_bounds() {
    const BOUND: usize = 4;
    for machine in [false, true] {
        let host = host();
        let signing = ed_key(72);
        let key = authority_key_from_ed(&signing);
        let at = TimeRange { start: 1, end: 1 };
        if machine {
            let request = request_for(host.vault_id, EntityId::now(), &signing);
            host.vault
                .enroll_machine(
                    &host.issuer,
                    &host.owner,
                    &request,
                    MachineRole::Owned(MachineOwnership::Yours),
                )
                .unwrap();
        } else {
            let enroll = crate::authority::slip_vault::next_entry(
                &host.issuer,
                &host.vault.authority_fold().unwrap(),
                AuthorityOp::EnrollDevice {
                    device: device(key.clone(), ROLE_AGENT, AuthorityTier::Software),
                },
                host.vault.now_recorded_at(),
            )
            .unwrap();
            host.vault.put_authority_log_entry(&enroll, at, 1).unwrap();
        }
        let root = host.vault.ensure_host_root_slip(&host.issuer).unwrap();
        let row = |seq: u64, op| {
            let heads = host.vault.authority_fold().unwrap().append_heads;
            sign_ed(
                unsigned_entry(
                    Some(host.vault_id),
                    seq,
                    heads.into_iter().collect(),
                    op,
                    key.clone(),
                    1,
                ),
                &signing,
            )
        };
        with_rows_per_signer_for_test(BOUND, || {
            for n in 0..BOUND {
                let mint = AuthorityOp::SlipMint(SlipMintAction {
                    claims: claims_numbered(&root.claims, n),
                });
                host.vault
                    .put_authority_log_entry(&row(n as u64 + 1, mint), at, 1)
                    .unwrap();
            }
            let over = AuthorityOp::SlipMint(SlipMintAction {
                claims: claims_numbered(&root.claims, BOUND),
            });
            let err = host
                .vault
                .put_authority_log_entry(&row(BOUND as u64 + 1, over), at, 1)
                .unwrap_err();
            assert_eq!(
                err.kind(),
                crate::error::ErrorKind::AuthorityLogFull,
                "machine {machine}"
            );
            assert!(err.to_string().contains(&authority_signer_label(&key)));
            let revoke = AuthorityOp::SlipRevoke { slip_id: [3; 32] };
            host.vault
                .put_authority_log_entry(&row(BOUND as u64 + 2, revoke), at, 1)
                .unwrap();
        });
    }
}

/// Oracle comparison: every key a fold holds as a live owner, which is what
/// `require_host` accepts as the slip issuer, is in the structural issuer
/// set. The random logs hold owner enrollments, re-roots, and revocations of
/// owner keys, alone or cosigned, that the fold accepts or refuses.
#[test]
fn every_live_owner_a_fold_holds_is_a_slip_issuer() {
    let mut revoked_owners = 0;
    for seed in 0..400_u64 {
        let entries = super::fold_schedule::random_log(&mut StdRng::seed_from_u64(seed));
        let issuers = crate::authority::log_budget::slip_issuers(entries.iter());
        for fold in [
            fold_authority_log(&entries),
            fold_legacy_authority_log(&entries),
        ] {
            for (key, folded) in &fold.roster {
                if roster_has_live_owner(&fold.roster, key) {
                    assert!(issuers.contains(key), "seed {seed}");
                }
                revoked_owners += usize::from(folded.revoked && folded.roles & ROLE_OWNER != 0);
            }
        }
    }
    assert!(revoked_owners > 50, "{revoked_owners} revoked owner keys");
}
