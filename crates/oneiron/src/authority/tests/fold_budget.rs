//! Authority-fold work stays bounded, and the store doors keep a log inside
//! the bounds (H72, W2-T3).
use super::machine_identity::{host, request_for};
use super::support::*;
use super::*;
use crate::authority::log_budget::{
    authority_signer_label, fold_memory_floor, fold_projected_bytes,
    with_fold_memory_floor_for_test, with_physical_memory_for_test, with_rows_per_signer_for_test,
};

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

/// Bug repro (H72, rule 5): a key the vault never enrolled signs a chain
/// naming the vault id, or more handoffs than one fold used to probe. The
/// fold reads all of it and keeps the vault's root, with none of the
/// stranger's rows valid. Under a memory floor the chain's fold would pass,
/// it refuses the whole log, fails closed and names the floor.
#[test]
fn a_self_signed_chain_folds_until_its_memory_floor() {
    const LEN: usize = 64;
    let genesis = genesis_entry(60, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let mut entries = vec![genesis.clone()];
    entries.extend(confirm_chain(&genesis, 201, LEN, |_| vec![]));
    let fold = fold_authority_log(&entries);
    assert!(!fold.authority_log_past_bound() && fold.vault_id.is_some());
    assert_eq!(fold.valid_entries.len(), 1);
    let floor = fold_projected_bytes(LEN + 1, (LEN * (LEN + 1) / 2) as u64) - 1;
    let fold = with_fold_memory_floor_for_test(floor, || fold_authority_log(&entries));
    assert_folds_closed(&fold);
    assert_eq!(fold.authority_log_memory_floor(), Some(floor));

    let stranger = ed_key(203);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let mut entries = vec![genesis.clone()];
    for n in 0..=2 * DEFAULT_AUTHORITY_LOG_HEADROOM_HANDOFFS as usize {
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
    let fold = fold_authority_log(&entries);
    assert!(!fold.authority_log_past_bound() && fold.vault_id.is_some());
    assert_eq!(fold.valid_entries.len(), 1);
}

/// Bug repro: a chain whose rows each name missing parents inflates every
/// row's ancestry. Each missing parent costs the fold as a row's does, so
/// under a floor the plain chain's fold fits, the index stops at the floor
/// and the fold fails closed instead of building the rest.
#[test]
fn a_chain_naming_missing_parents_folds_closed_at_the_memory_floor() {
    const LEN: usize = 64;
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
    let floor = fold_projected_bytes(LEN + 1, (LEN * (LEN + 1) / 2) as u64);
    with_fold_memory_floor_for_test(floor, || {
        let mut entries = vec![genesis.clone()];
        entries.extend(confirm_chain(&genesis, 204, LEN, |_| vec![]));
        assert!(!fold_authority_log(&entries).authority_log_past_bound());
        let mut entries = vec![genesis.clone()];
        entries.extend(confirm_chain(&genesis, 204, LEN, missing));
        assert_folds_closed(&fold_authority_log(&entries));
    });
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

/// Bug repro (rule 5): the owner's own rows in one chain, under the row
/// bound but past the ancestor-pair bound, made the fold refuse the log, so
/// the owner could neither sign a next row nor use an owner verb. The fold
/// holds every row, the owner's verbs work, and the log raises its headroom
/// check once for each row it crossed: counted rows and ancestor pairs.
#[test]
fn the_owners_one_chain_past_the_ancestor_bound_folds_and_owner_verbs_work() {
    const BOUND: usize = 16;
    let host = host();
    let person = crate::vault::embedded_owner_actor_id().unwrap();
    let subject = EntityId::from_bytes([0x5A; 16]).unwrap();
    host.vault
        .put_entity(
            &subject,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"subject",
        )
        .unwrap();
    with_rows_per_signer_for_test(BOUND, || {
        // 3 * BOUND rows in one chain: under main's 4 * BOUND row bound,
        // past its 2 * BOUND^2 ancestor pairs.
        for n in 0..3 * BOUND {
            let entry = crate::authority::slip_vault::next_entry(
                &host.issuer,
                &host.vault.authority_fold().unwrap(),
                confirm_op(n),
                host.vault.now_recorded_at(),
            )
            .unwrap_or_else(|err| panic!("the owner's row {n} signs on the fold: {err}"));
            host.vault
                .put_authority_log_entry(&entry, TimeRange { start: 1, end: 1 }, 1)
                .unwrap();
        }
        let fold = host.vault.authority_fold().unwrap();
        assert!(!fold.authority_log_past_bound() && !fold.vault_root_is_conflicted());
        host.vault
            .memory(person, crate::EdgeActorClass::Human)
            .safe_delete(&subject.to_hex(), crate::SafeDeleteReason::UserDelete)
            .expect("owner verbs work past the ancestor bound");
        let checks = host.vault.authority_log_checks().unwrap();
        assert_eq!(
            checks
                .iter()
                .map(|check| (check.kind, check.scope))
                .collect::<Vec<_>>(),
            [
                (
                    AuthorityLogCheck::FOLD_HEADROOM,
                    Some(AuthorityLogCheck::ROWS)
                ),
                (
                    AuthorityLogCheck::FOLD_HEADROOM,
                    Some(AuthorityLogCheck::ANCESTOR_PAIRS)
                ),
            ],
            "{checks:?}"
        );
    });
}

/// Done-means (Engine on #1508): with no row, the memory floor is the
/// machine's, a quarter of its physical memory from 1 GiB up to the 8 GiB
/// cap, so a small machine's fold refuses at its own floor; the policy row
/// overrides it.
#[test]
fn a_small_machine_folds_under_its_own_floor_and_the_row_overrides_it() {
    const GIB: u64 = 1024 * 1024 * 1024;
    let row = |bytes| AuthorityObservationPolicy {
        log_fold_memory_floor_bytes: bytes,
        ..AuthorityObservationPolicy::default()
    };
    for (physical, floor) in [
        (2 * GIB, GIB),
        (4 * GIB, GIB),
        (12 * GIB, 3 * GIB),
        (64 * GIB, 8 * GIB),
    ] {
        with_physical_memory_for_test(physical, || {
            assert_eq!(fold_memory_floor(None), floor, "{physical}");
            assert_eq!(fold_memory_floor(Some(&row(None))), floor, "{physical}");
            assert_eq!(fold_memory_floor(Some(&row(Some(5 * GIB)))), 5 * GIB);
        });
    }
}

/// Done-means (rule 5, H72): the one count the fold refuses is its memory
/// floor, a policy row. A vault whose log's fold would pass it holds no
/// root, its typed issue names the floor, and owner verbs are refused with
/// it; raising the row restores them.
#[test]
fn a_log_past_its_memory_floor_names_the_floor_and_raising_the_row_restores_it() {
    let host = host();
    let person = crate::vault::embedded_owner_actor_id().unwrap();
    let subject = EntityId::from_bytes([0x5B; 16]).unwrap();
    host.vault
        .put_entity(
            &subject,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"subject",
        )
        .unwrap();
    let delete = || {
        host.vault
            .memory(person, crate::EdgeActorClass::Human)
            .safe_delete(&subject.to_hex(), crate::SafeDeleteReason::UserDelete)
    };
    let floor = fold_projected_bytes(1, 0);
    host.vault
        .set_authority_observation_policy(AuthorityObservationPolicy {
            log_fold_memory_floor_bytes: Some(floor),
            ..AuthorityObservationPolicy::default()
        })
        .unwrap();
    let fold = host.vault.authority_fold().unwrap();
    assert_eq!(fold.authority_log_memory_floor(), Some(floor));
    assert!(fold.vault_root_is_conflicted());
    let err = delete().unwrap_err();
    assert!(
        err.to_string()
            .contains(&format!("memory floor of {floor} bytes")),
        "{err}"
    );
    host.vault
        .set_authority_observation_policy(AuthorityObservationPolicy::default())
        .unwrap();
    delete().expect("owner verbs work under the default floor");
}

/// Substrate invariant (rule 5): a key no slip issuer vouches for, here an
/// admin the owner admitted, stores up to the `authority_log_signer_bound`
/// policy row. Its next row waits with a typed error naming it, nothing is
/// written, and the log raises its typed check. Its first revocation of a
/// device the fold holds live lands; a revocation of a key the fold never
/// held, a second revocation of the same device, and a machine removal the
/// fold would never apply wait. The waiting row lands once the owner
/// cosigns it, and the owner's own rows never meet the bound.
#[test]
fn a_signer_past_its_bound_waits_but_live_restrictions_and_owner_rows_land() {
    const BOUND: usize = 8;
    let host = host();
    let request = request_for(host.vault_id, EntityId::now(), &ed_key(66));
    host.vault
        .enroll_machine(
            &host.issuer,
            &host.owner,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
        )
        .unwrap();
    let at = TimeRange { start: 1, end: 1 };
    let fold = || host.vault.authority_fold().unwrap();
    let owner_row = |op| {
        crate::authority::slip_vault::next_entry(
            &host.issuer,
            &fold(),
            op,
            host.vault.now_recorded_at(),
        )
        .unwrap()
    };
    let signing = ed_key(65);
    let admin = authority_key_from_ed(&signing);
    host.vault
        .put_authority_log_entry(
            &owner_row(AuthorityOp::EnrollDevice {
                device: device(admin.clone(), ROLE_ADMIN, AuthorityTier::Software),
            }),
            at,
            1,
        )
        .unwrap();
    let admin_row = |seq: usize, op, cosigned: bool| {
        let entry = unsigned_entry(
            Some(host.vault_id),
            seq as u64,
            fold().append_heads.iter().copied().collect(),
            op,
            admin.clone(),
            3,
        );
        if cosigned {
            host_cosigned(entry, &signing, &host.issuer)
        } else {
            sign_ed(entry, &signing)
        }
    };
    let stored = || {
        host.vault
            .count_entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
            .unwrap()
    };
    let label = authority_signer_label(&admin);
    host.vault
        .set_authority_observation_policy(AuthorityObservationPolicy {
            log_signer_bound: BOUND as u64,
            ..AuthorityObservationPolicy::default()
        })
        .unwrap();
    for n in 0..BOUND {
        host.vault
            .put_authority_log_entry(&admin_row(n + 1, confirm_op(n), false), at, 1)
            .unwrap();
    }
    let before = stored();
    let over = admin_row(BOUND + 1, confirm_op(BOUND), false);
    let err = host
        .vault
        .put_authority_log_entry(&over, at, 1)
        .unwrap_err();
    assert_eq!(err.kind(), crate::error::ErrorKind::AuthorityLogFull);
    assert!(err.to_string().contains(&label), "{err}");
    assert_eq!(stored(), before);
    let checks = host.vault.authority_log_checks().unwrap();
    assert!(
        checks.contains(&AuthorityLogCheck {
            kind: AuthorityLogCheck::SIGNER_BOUND,
            scope: None,
            signer: Some(label),
            count: BOUND as u64,
            threshold: BOUND as u64,
        }),
        "{checks:?}"
    );

    let waits = |entry: AuthorityLogEntry| {
        let err = host
            .vault
            .put_authority_log_entry(&entry, at, 1)
            .unwrap_err();
        assert_eq!(err.kind(), crate::error::ErrorKind::AuthorityLogFull);
    };
    waits(admin_row(
        BOUND + 1,
        AuthorityOp::RevokeDevice {
            revoked_key: authority_key_from_ed(&ed_key(67)),
        },
        false,
    ));
    // The fold applies a machine revision only from an owner key, a slip
    // issuer, so the admin's removal of a live machine restricts nothing
    // and waits (review round 6, Astra F1).
    let current = fold()
        .machine(request.machine)
        .unwrap()
        .head()
        .profile
        .clone();
    waits(admin_row(
        BOUND + 1,
        AuthorityOp::MachineProfile(MachineProfile {
            role: MachineRole::Removed,
            revision: current.revision + 1,
            ..current
        }),
        false,
    ));
    // Its first revocation of a device the fold holds live lands; the same
    // revocation again waits, whether the fold applied the first or not.
    let revoke = AuthorityOp::RevokeDevice {
        revoked_key: host.issuer.public_key(),
    };
    host.vault
        .put_authority_log_entry(&admin_row(BOUND + 1, revoke.clone(), false), at, 1)
        .unwrap();
    waits(admin_row(BOUND + 2, revoke, false));
    host.vault
        .put_authority_log_entry(&admin_row(BOUND + 2, confirm_op(BOUND), true), at, 1)
        .unwrap();
    for n in 0..=BOUND {
        host.vault
            .put_authority_log_entry(&owner_row(confirm_op(100 + n)), at, 1)
            .unwrap();
    }
    assert_eq!(stored(), before + 2 + BOUND as u64 + 1);
    assert!(!fold().authority_log_past_bound());
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
        // Five times the fold's row bound, all signed by the host root.
        for n in 0..20 * BOUND {
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
        assert!(fold.slips.mints.len() > 20 * BOUND);
        assert!(fold.machine(machine.machine).is_some_and(RosterHead::mine));
    });
    let next = HostSlipIssuer::from_secret(b"next host root placeholder words").unwrap();
    host.vault.re_root_host(&host.issuer, &next).unwrap();
    with_rows_per_signer_for_test(BOUND, || {
        let root = host.vault.ensure_host_root_slip(&next).unwrap();
        for n in 0..5 * BOUND {
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
        assert!(fold.machine(machine.machine).is_some_and(RosterHead::mine));
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

/// Structural: the slip issuer's slip rows count toward none of the fold's
/// ancestor pairs, however many there are, even under rows that do count.
/// The same rows signed by a key no owner admitted count in full, and the
/// fold still reads them.
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
        let counted_rows = (entries.len() - uncounted.len()) as u64;
        assert!(
            fold.counted_ancestor_pairs <= counted_rows * (counted_rows - 1) / 2,
            "{}",
            fold.counted_ancestor_pairs
        );

        let stranger = HostSlipIssuer::from_secret(b"stranger placeholder words").unwrap();
        let mut foreign = base.clone();
        foreign.extend(issuer_slip_chain(&stranger, &root, head, 1, 64 * BOUND));
        let fold = fold_authority_log(&foreign);
        assert!(!fold.authority_log_past_bound() && fold.vault_id.is_some());
        let stranger_rows = (64 * BOUND) as u64;
        assert!(
            fold.counted_ancestor_pairs >= stranger_rows * (stranger_rows - 1) / 2,
            "{}",
            fold.counted_ancestor_pairs
        );
    });
}

/// `entry` signed by `signing` and cosigned by the host's key.
fn host_cosigned(
    mut entry: AuthorityLogEntry,
    signing: &SigningKey,
    host: &HostSlipIssuer,
) -> AuthorityLogEntry {
    entry.cosigns = vec![AuthoritySignature {
        suite: AuthoritySignatureSuite::Ed25519,
        public_key: host.public_key(),
        signature: vec![0; 64],
    }];
    let transcript = authority_transcript(&entry).unwrap();
    entry.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
    entry.cosigns[0].signature = host.sign_mesh(&transcript).to_vec();
    entry
}

/// Bug repro: no door stores a row that no owner, admin or install key
/// signed, and a key that is not a slip issuer stores no more than its
/// bound of its own rows. An agent key the host enrolled, or the key of a
/// machine the owner holds as theirs, once stored slip revokes and actor
/// revocations without end, through sync and then through the public local
/// door (review round 2, F2), and the fold counted each one, so past the
/// fold's row bound the owner's vault failed closed. The fold applies none
/// of them, so rows the key signs alone are held at the local door too.
/// Rows the host cosigns are the owner's work and land past the key's
/// bound (rule 5). An install key's own world edits wait past its bound,
/// and a handoff the key signs waits whoever cosigns it.
#[test]
fn agent_and_machine_keys_rows_land_only_with_the_owner_or_under_their_bound() {
    const BOUND: usize = 8;
    for machine in [false, true] {
        let host = host();
        let witness = request_for(host.vault_id, EntityId::now(), &ed_key(71));
        host.vault
            .enroll_machine(
                &host.issuer,
                &host.owner,
                &witness,
                MachineRole::Owned(MachineOwnership::Yours),
            )
            .unwrap();
        let signing = ed_key(72);
        let key = authority_key_from_ed(&signing);
        let at = TimeRange { start: 1, end: 1 };
        let own_machine = EntityId::now();
        if machine {
            let request = request_for(host.vault_id, own_machine, &signing);
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
        let mut parent = *host
            .vault
            .authority_fold()
            .unwrap()
            .append_heads
            .iter()
            .next()
            .unwrap();
        let row = |seq: usize, parent: AuthorityEntryHash, op, cosigned: bool| {
            let entry = unsigned_entry(
                Some(host.vault_id),
                seq as u64,
                vec![parent],
                op,
                key.clone(),
                1,
            );
            if cosigned {
                host_cosigned(entry, &signing, &host.issuer)
            } else {
                sign_ed(entry, &signing)
            }
        };
        let assert_held = |err: crate::error::Error| {
            assert_eq!(
                err.kind(),
                crate::error::ErrorKind::AuthorityLogSignerPending,
                "machine {machine}: {err}"
            );
        };
        let stored = || host.vault.export_signed_authority_history().unwrap().len();
        let before = stored();
        let assert_waits = |err: crate::error::Error| {
            assert_eq!(
                err.kind(),
                crate::error::ErrorKind::AuthorityLogFull,
                "machine {machine}: {err}"
            );
            assert!(err.to_string().contains(&authority_signer_label(&key)));
        };
        let mut seq = 0;
        with_rows_per_signer_for_test(BOUND, || {
            for n in 0..BOUND + 2 {
                seq += 1;
                let op = match n % 3 {
                    0 => AuthorityOp::SlipMint(SlipMintAction {
                        claims: claims_numbered(&root.claims, n),
                    }),
                    1 => AuthorityOp::SlipRevoke {
                        slip_id: claims_numbered(&root.claims, n - 1).slip_id,
                    },
                    _ => AuthorityOp::RevokeActor {
                        authority_key: key.clone(),
                        epoch: n as u64,
                    },
                };
                let alone = row(seq, parent, op.clone(), false);
                assert_held(
                    host.vault
                        .put_authority_log_entry(&alone, at, 1)
                        .unwrap_err(),
                );
                let entry = row(seq, parent, op, true);
                host.vault.put_authority_log_entry(&entry, at, 1).unwrap();
                parent = authority_entry_hash(&entry).unwrap();
            }
            let fold = host.vault.authority_fold().unwrap();
            assert!(
                !fold.authority_log_past_bound(),
                "machine {machine}: {:?}",
                fold.issues
            );
            assert!(fold.machine(witness.machine).is_some_and(RosterHead::mine));
            assert_eq!(stored() - before, BOUND + 2, "machine {machine}");
            if machine {
                seq += 1;
                let world = EntityId::now();
                let edit = row(
                    seq,
                    parent,
                    AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                        world,
                        act: owner_act(host.owner.actor(), world),
                        machine: own_machine,
                        settings: WorldPrivacy::default(),
                    }),
                    false,
                );
                assert_waits(
                    host.vault
                        .put_authority_log_entry(&edit, at, 1)
                        .unwrap_err(),
                );
            }
        });
        let handoff = AuthorityOp::ReRoot {
            new_device: device(
                authority_key_from_ed(&ed_key(73)),
                ROLE_OWNER,
                AuthorityTier::Software,
            ),
        };
        let alone = row(seq + 1, parent, handoff.clone(), false);
        assert_held(
            host.vault
                .put_authority_log_entry(&alone, at, 1)
                .unwrap_err(),
        );
        assert_waits(
            host.vault
                .put_authority_log_entry(&row(seq + 1, parent, handoff, true), at, 1)
                .unwrap_err(),
        );
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
        let issuers = crate::authority::log_budget::slip_issuers(&entries);
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

fn put_replicated_row(vault: &crate::Vault, entry: &AuthorityLogEntry) -> crate::error::Result<()> {
    vault
        .batch()
        .put_replicated(
            &authority_log_entity_id(entry)?,
            ENTITY_TYPE_AUTHORITY_LOG,
            TimeRange { start: 1, end: 1 },
            1,
            &encode_authority_log_entry_body(entry)?,
        )
        .commit()
}

/// Bug repro (review round 1): a pre-handoff rotation names the key that
/// signs the handoff. Through sync the rotation lands, but the vault fold
/// holds the rotated key nowhere until that handoff verifies, so the handoff
/// waited for its signer for ever. The rotated owner key is a slip issuer by
/// the log's structure, so the handoff lands and the new host stands.
#[test]
fn a_handoff_signed_by_a_rotated_owner_key_lands_through_sync() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    let old = ed_key(115);
    let next = ed_key(116);
    let host = HostSlipIssuer::from_secret(b"rotated handoff placeholder words").unwrap();
    let genesis = genesis_entry(115, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let rotation = rotate_entry(id, &genesis, &old, authority_key_from_ed(&old), 116, 1);
    let handoff = sign_ed(
        unsigned_entry(
            Some(id),
            0,
            vec![authority_entry_hash(&rotation).unwrap()],
            AuthorityOp::ReRoot {
                new_device: device(
                    host.public_key(),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
            authority_key_from_ed(&next),
            3,
        ),
        &next,
    );
    vault
        .put_authority_log_entry(&genesis, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
    put_replicated_row(&vault, &rotation).unwrap();
    mature_observed_widen(&vault, &rotation);
    put_replicated_row(&vault, &handoff).unwrap();
    let fold = vault.authority_fold().unwrap();
    assert!(
        fold.valid_entries
            .contains(&authority_entry_hash(&handoff).unwrap())
    );
    assert!(roster_has_live_owner(&fold.roster, &host.public_key()));
}

/// Bug repro (Bugbot, #1449): a genesis vouched for itself while every
/// stored root was its key, so the root key's second genesis with a new
/// nonce, from a client that initializes again or a replayed init, was
/// stored at the local door and the fold read two roots, conflicted. A
/// genesis now vouches for itself only in a log that holds none: another
/// waits typed. The replicated door already refused it as a foreign vault's
/// root, since a genesis names its own vault. At both doors the same genesis
/// again changes nothing, and the owner's rows still land.
#[test]
fn the_root_keys_second_genesis_waits_and_its_first_again_changes_nothing() {
    let at = TimeRange { start: 1, end: 1 };
    let genesis = genesis_entry(132, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let mut second = genesis.clone();
    if let AuthorityOp::Genesis { genesis_nonce, .. } = &mut second.op {
        *genesis_nonce = [0x5A; 32];
    }
    let second = sign_ed(second, &ed_key(132));
    assert_ne!(
        authority_entry_hash(&second).unwrap(),
        authority_entry_hash(&genesis).unwrap()
    );
    for replicated in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
        let put = |entry: &AuthorityLogEntry| {
            if replicated {
                put_replicated_row(&vault, entry)
            } else {
                vault.put_authority_log_entry(entry, at, 1).map(drop)
            }
        };
        vault.put_authority_log_entry(&genesis, at, 1).unwrap();
        let err = put(&second).unwrap_err();
        assert_eq!(
            err.kind(),
            if replicated {
                crate::error::ErrorKind::InvalidAuthorityLogBody
            } else {
                crate::error::ErrorKind::AuthorityLogSignerPending
            }
        );
        put(&genesis).unwrap();
        for entry in confirm_chain(&genesis, 132, 2, |_| Vec::new()) {
            put(&entry).unwrap();
        }
        assert_eq!(
            vault
                .count_entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
                .unwrap(),
            3
        );
        let fold = vault.authority_fold().unwrap();
        assert!(!fold.vault_root_is_conflicted(), "replicated: {replicated}");
        assert_eq!(fold.vault_id, Some(genesis_vault_id(&genesis).unwrap()));
        assert_eq!(fold.valid_entries.len(), 3);
    }
}

/// Bug repro (review round 1): in a pre-handoff line an admin key, with an
/// agent's cosign for quorum, enrolls an owner, who hands off to the host.
/// The fold accepts the line, so `require_host` accepts that host; the
/// issuer set once missed it, because no owner key signed the owner's
/// enrollment, and counted every one of its slip mints.
#[test]
fn a_host_an_admin_admitted_line_hands_off_to_is_a_slip_issuer() {
    let [owner, admin, agent, second] = [120, 121, 122, 123].map(ed_key);
    let host = HostSlipIssuer::from_secret(b"admin line host placeholder words").unwrap();
    let genesis = genesis_entry(120, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let row = |parent: &AuthorityLogEntry,
               seq,
               op,
               signer: &SigningKey,
               cosigner: Option<&SigningKey>| {
        let entry = unsigned_entry(
            Some(id),
            seq,
            vec![authority_entry_hash(parent).unwrap()],
            op,
            authority_key_from_ed(signer),
            2,
        );
        match cosigner {
            Some(cosigner) => cosign_ed(entry, signer, cosigner),
            None => sign_ed(entry, signer),
        }
    };
    let enroll = |key: &SigningKey, roles| AuthorityOp::EnrollDevice {
        device: device(authority_key_from_ed(key), roles, AuthorityTier::Software),
    };
    let admitted = row(&genesis, 1, enroll(&admin, ROLE_ADMIN), &owner, None);
    let enrolled = row(
        &admitted,
        2,
        enroll(&agent, ROLE_AGENT),
        &owner,
        Some(&admin),
    );
    let promoted = row(
        &enrolled,
        1,
        enroll(&second, ROLE_OWNER | ROLE_ADMIN),
        &admin,
        Some(&agent),
    );
    let handoff = row(
        &promoted,
        1,
        AuthorityOp::ReRoot {
            new_device: device(
                host.public_key(),
                ROLE_OWNER | ROLE_ADMIN,
                AuthorityTier::Software,
            ),
        },
        &second,
        Some(&admin),
    );
    let entries = vec![genesis, admitted, enrolled, promoted, handoff.clone()];
    let fold = fold_authority_log(&entries);
    assert!(
        fold.valid_entries
            .contains(&authority_entry_hash(&handoff).unwrap())
    );
    assert!(roster_has_live_owner(&fold.roster, &host.public_key()));
    let issuers = crate::authority::log_budget::slip_issuers(&entries);
    assert!(issuers.contains(&host.public_key()));
    assert!(!issuers.contains(&authority_key_from_ed(&admin)));

    // Review round 2 (F1): the same line arrives through sync, parents
    // first. The admin's promotion once waited for ever, as no owner key
    // signed it; an admitter's signature vouches for it now.
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    vault
        .put_authority_log_entry(&entries[0], TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
    for entry in &entries[1..] {
        put_replicated_row(&vault, entry).unwrap();
        if !matches!(entry.op, AuthorityOp::ReRoot { .. }) {
            mature_observed_widen(&vault, entry);
        }
    }
    let fold = vault.authority_fold().unwrap();
    assert!(roster_has_live_owner(&fold.roster, &host.public_key()));
}

/// Bug repro (review round 2, F5): a genesis an admin-only key signs is a
/// consent root the fold accepts. The issuer set once read only an owner
/// genesis, so it held no key of this line, and the store door refused its
/// owner's first handoff as past the bound. The admin genesis now admits,
/// and the complete line imports with its host a slip issuer.
#[test]
fn an_admin_genesis_line_imports_with_its_host_a_slip_issuer() {
    let [admin, owner] = [124, 125].map(ed_key);
    let host = HostSlipIssuer::from_secret(b"admin genesis host placeholder words").unwrap();
    let mut genesis = genesis_entry(124, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    if let AuthorityOp::Genesis { device, .. } = &mut genesis.op {
        device.roles = ROLE_ADMIN;
    }
    let genesis = sign_ed(genesis, &admin);
    let id = genesis_vault_id(&genesis).unwrap();
    let enrolled = sign_ed(
        unsigned_entry(
            Some(id),
            1,
            vec![authority_entry_hash(&genesis).unwrap()],
            AuthorityOp::EnrollDevice {
                device: device(
                    authority_key_from_ed(&owner),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
            authority_key_from_ed(&admin),
            2,
        ),
        &admin,
    );
    let handoff = cosign_ed(
        unsigned_entry(
            Some(id),
            1,
            vec![authority_entry_hash(&enrolled).unwrap()],
            AuthorityOp::ReRoot {
                new_device: device(
                    host.public_key(),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
            authority_key_from_ed(&owner),
            3,
        ),
        &owner,
        &admin,
    );
    let entries = vec![genesis, enrolled, handoff];
    let issuers = crate::authority::log_budget::slip_issuers(&entries);
    assert!(issuers.contains(&host.public_key()));
    assert!(!issuers.contains(&authority_key_from_ed(&admin)));
    let history: Vec<_> = entries
        .iter()
        .map(|entry| encode_authority_log_entry_body(entry).unwrap())
        .collect();
    let dir = tempfile::tempdir().unwrap();
    let target = crate::Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    target.import_signed_authority_history(&history).unwrap();
    let fold = target.authority_fold().unwrap();
    assert!(!fold.authority_log_past_bound() && !fold.vault_root_is_conflicted());
}

/// Bug repro (review round 1): a complete signed history imports in any
/// order. The store door reads the slip issuers from the rows already
/// staged, so a history given slips first charged the issuer's slip rows
/// until its genesis was staged, and stopped at the bound. The import now
/// stages parents first.
#[test]
fn a_complete_history_imports_past_the_bound_in_any_order() {
    const BOUND: usize = 4;
    let source = host();
    let root = source.vault.ensure_host_root_slip(&source.issuer).unwrap();
    for n in 0..10 * BOUND {
        source
            .vault
            .mint_oauth_capability_slip(
                &source.issuer,
                claims_numbered(&root.claims, n),
                3600,
                None,
            )
            .unwrap();
    }
    let mut history = source.vault.export_signed_authority_history().unwrap();
    history.reverse();
    let dir = tempfile::tempdir().unwrap();
    let target = crate::Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    with_rows_per_signer_for_test(BOUND, || target.import_signed_authority_history(&history))
        .unwrap();
    let fold = target.authority_fold().unwrap();
    assert!(!fold.authority_log_past_bound() && !fold.vault_root_is_conflicted());
    assert!(fold.slips.mints.len() > 10 * BOUND);
}

/// Bug repro (review round 2, F4): issuer membership is read from the whole
/// log, not from a row's own ancestry. A history whose owner admission is
/// only a sibling of that owner's slip rows, given slips first, charged the
/// slips until the admission was staged and stopped at the bound. The
/// import now stages the rows the issuer set rests on first.
#[test]
fn a_history_whose_issuer_admission_is_a_sibling_imports_in_any_order() {
    const BOUND: usize = 4;
    let [owner, next] = [126, 127].map(ed_key);
    let genesis = genesis_entry(126, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let root = authority_entry_hash(&genesis).unwrap();
    let handoff = sign_ed(
        unsigned_entry(
            Some(id),
            1,
            vec![root],
            AuthorityOp::ReRoot {
                new_device: device(
                    authority_key_from_ed(&next),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
            authority_key_from_ed(&owner),
            2,
        ),
        &owner,
    );
    let mut history = vec![encode_authority_log_entry_body(&genesis).unwrap()];
    let mut parent = root;
    for n in 0..10 * BOUND {
        let mut slip_id = [0x5A; 32];
        slip_id[..8].copy_from_slice(&(n as u64).to_be_bytes());
        let slip = sign_ed(
            unsigned_entry(
                Some(id),
                n as u64 + 1,
                vec![parent],
                AuthorityOp::SlipRevoke { slip_id },
                authority_key_from_ed(&next),
                3,
            ),
            &next,
        );
        parent = authority_entry_hash(&slip).unwrap();
        history.push(encode_authority_log_entry_body(&slip).unwrap());
    }
    history.push(encode_authority_log_entry_body(&handoff).unwrap());
    let dir = tempfile::tempdir().unwrap();
    let target = crate::Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    with_rows_per_signer_for_test(BOUND, || target.import_signed_authority_history(&history))
        .unwrap();
    assert!(!target.authority_fold().unwrap().authority_log_past_bound());
}

/// Imports `history` into a fresh vault and folds it.
fn imported(history: &[Vec<u8>]) -> AuthorityFold {
    let dir = tempfile::tempdir().unwrap();
    let target = crate::Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    target.import_signed_authority_history(history).unwrap();
    target.authority_fold().unwrap()
}

/// Bug repro (review round 3, Astra F1): a structural row signed by a key
/// whose admission is only its sibling, given before that admission, was
/// held at the import's own door, and the import aborted. A row now waits
/// for the rows that let a key vouch for it, so every order imports to the
/// fold the parents-first order gives.
#[test]
fn a_revision_whose_signers_admission_is_a_sibling_imports_in_any_order() {
    let [owner, next] = [128, 129].map(ed_key);
    let genesis = genesis_entry(128, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let root = authority_entry_hash(&genesis).unwrap();
    let handoff = sign_ed(
        unsigned_entry(
            Some(id),
            1,
            vec![root],
            AuthorityOp::ReRoot {
                new_device: device(
                    authority_key_from_ed(&next),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
            authority_key_from_ed(&owner),
            2,
        ),
        &owner,
    );
    let machine = EntityId::now();
    let request = request_for(id, machine, &ed_key(130));
    let profile = sign_ed(
        unsigned_entry(
            Some(id),
            1,
            vec![root],
            AuthorityOp::MachineProfile(MachineProfile {
                machine,
                owner: EntityId::now(),
                machine_key: request.machine_key,
                encryption_key: request.encryption_key,
                role: MachineRole::Owned(MachineOwnership::Yours),
                revision: 1,
                machine_proof: request.machine_proof,
                seen_world_edits: BTreeSet::new(),
            }),
            authority_key_from_ed(&next),
            3,
        ),
        &next,
    );
    let folds: Vec<_> = [
        [&genesis, &handoff, &profile],
        [&genesis, &profile, &handoff],
        [&profile, &handoff, &genesis],
    ]
    .iter()
    .map(|order| {
        let history: Vec<_> = order
            .iter()
            .map(|entry| encode_authority_log_entry_body(entry).unwrap())
            .collect();
        imported(&history)
    })
    .collect();
    for fold in &folds {
        assert_eq!(fold.valid_entries, folds[0].valid_entries);
        assert_eq!(fold.roster, folds[0].roster);
        assert_eq!(fold.machines, folds[0].machines);
    }
}

/// Bug repro (review round 3, Astra F4): an import staged every structural
/// row ahead of the rest. A machine revision at sequence n + 2 so staged
/// before its signer's binding at n + 1, its sibling, and the binding was
/// first observed below that floor: it folded as a rollback
/// (`NonMonotonicSeq`) and was lost without an error. Each signer's rows
/// now stage by sequence, so every order imports to the fold the
/// parents-first order gives, the binding in it.
#[test]
fn a_lower_sequence_sibling_of_a_revision_imports_in_any_order() {
    use super::machine_fold::{host_entry, profile_op};
    let host = host();
    let agent = ed_key(93);
    let fold = host.vault.authority_fold().unwrap();
    let seq = fold.append_sequences[&host.issuer.public_key()] + 1;
    let enroll = host_entry(
        &host,
        seq,
        &fold.append_heads,
        AuthorityOp::EnrollDevice {
            device: device(
                authority_key_from_ed(&agent),
                ROLE_AGENT,
                AuthorityTier::Software,
            ),
        },
        None,
    );
    let parents = BTreeSet::from([authority_entry_hash(&enroll).unwrap()]);
    let bind = host_entry(
        &host,
        seq + 1,
        &parents,
        AuthorityOp::BindActor {
            authority_key: authority_key_from_ed(&agent),
            actor_ref: EntityId::from_bytes([0x71; 16]).unwrap(),
            actor_class: "system".into(),
            epoch: 1,
        },
        Some(&agent),
    );
    let profile = host_entry(
        &host,
        seq + 2,
        &parents,
        profile_op(&host, EntityId::now(), &ed_key(94)),
        None,
    );
    let at = TimeRange { start: 2, end: 2 };
    host.vault
        .put_authority_log_entries(&[
            (enroll, at, 2),
            (bind.clone(), at, 2),
            (profile.clone(), at, 2),
        ])
        .unwrap();
    let bound = authority_entry_hash(&bind).unwrap();
    assert!(
        host.vault
            .authority_fold()
            .unwrap()
            .valid_entries
            .contains(&bound)
    );

    let hash_of = |row: &Vec<u8>| {
        authority_entry_hash(&decode_authority_log_entry_body(row).unwrap()).unwrap()
    };
    let [bind_row, profile_row] =
        [&bind, &profile].map(|entry| encode_authority_log_entry_body(entry).unwrap());
    let mut parents_first: Vec<_> = host
        .vault
        .export_signed_authority_history()
        .unwrap()
        .into_iter()
        .filter(|row| ![bound, authority_entry_hash(&profile).unwrap()].contains(&hash_of(row)))
        .collect();
    let mut profile_first = parents_first.clone();
    parents_first.extend([bind_row.clone(), profile_row.clone()]);
    profile_first.extend([profile_row, bind_row]);
    let mut reversed = parents_first.clone();
    reversed.reverse();
    let folds = [parents_first, profile_first, reversed].map(|history| imported(&history));
    for fold in &folds {
        assert!(
            fold.valid_entries.contains(&bound),
            "the binding folded as a rollback: {:?}",
            fold.issues
        );
        assert!(
            fold.actor_bindings
                .contains_key(&authority_key_from_ed(&agent))
        );
        assert_eq!(fold.valid_entries, folds[0].valid_entries);
        assert_eq!(fold.machines, folds[0].machines);
    }
}

/// Bug repro (review round 4, Sol F2 and Astra F3): where a row's parent
/// and its signer's sequences disagreed, the import broke the sequence edge
/// at the row given first. A misordered slip revoke beside a binding so
/// staged the owner's machine revision ahead of the binding, which then
/// folded as a rollback. The import breaks a parent edge first: the door
/// never needs a row's parents stored, but a row first observed below its
/// signer's sequence is lost.
#[test]
fn a_binding_beside_a_misordered_sibling_imports_in_any_order() {
    use super::machine_fold::{host_entry, profile_op};
    let hash = |entry: &AuthorityLogEntry| authority_entry_hash(entry).unwrap();
    let host = host();
    let agent = ed_key(95);
    let fold = host.vault.authority_fold().unwrap();
    let (seq, heads) = (
        fold.append_sequences[&host.issuer.public_key()],
        fold.append_heads.clone(),
    );
    let enroll = host_entry(
        &host,
        seq + 1,
        &heads,
        AuthorityOp::EnrollDevice {
            device: device(
                authority_key_from_ed(&agent),
                ROLE_AGENT,
                AuthorityTier::Software,
            ),
        },
        None,
    );
    let enrolled = BTreeSet::from([hash(&enroll)]);
    let bind = host_entry(
        &host,
        seq + 2,
        &enrolled,
        AuthorityOp::BindActor {
            authority_key: authority_key_from_ed(&agent),
            actor_ref: EntityId::from_bytes([0x72; 16]).unwrap(),
            actor_class: "system".into(),
            epoch: 1,
        },
        Some(&agent),
    );
    let revoke = |seq, parents: &BTreeSet<_>, byte| {
        host_entry(
            &host,
            seq,
            parents,
            AuthorityOp::SlipRevoke {
                slip_id: [byte; 32],
            },
            None,
        )
    };
    let later = revoke(seq + 3, &heads, 0x5b);
    let misordered = revoke(seq + 1, &BTreeSet::from([hash(&later)]), 0x5c);
    let profile = host_entry(
        &host,
        seq + 4,
        &enrolled,
        profile_op(&host, EntityId::now(), &ed_key(96)),
        None,
    );
    let at = TimeRange { start: 2, end: 2 };
    let new_rows = [&enroll, &bind, &later, &misordered, &profile];
    for entry in new_rows {
        host.vault
            .put_authority_log_entries(&[(entry.clone(), at, 2)])
            .unwrap();
    }
    assert!(
        host.vault
            .authority_fold()
            .unwrap()
            .valid_entries
            .contains(&hash(&bind))
    );

    let added: BTreeSet<_> = new_rows.iter().copied().map(hash).collect();
    let rest: Vec<_> = host
        .vault
        .export_signed_authority_history()
        .unwrap()
        .into_iter()
        .filter(|row| !added.contains(&hash(&decode_authority_log_entry_body(row).unwrap())))
        .collect();
    let body = |entry: &&AuthorityLogEntry| encode_authority_log_entry_body(entry).unwrap();
    let mut parents_first = rest.clone();
    parents_first.extend(new_rows.iter().map(body));
    let mut profile_first = rest;
    profile_first.extend(new_rows.iter().rev().map(body));
    let mut reversed = profile_first.clone();
    reversed.reverse();
    let folds = [parents_first, profile_first, reversed].map(|history| imported(&history));
    for fold in &folds {
        assert!(
            fold.valid_entries.contains(&hash(&bind)),
            "the binding folded as a rollback: {:?}",
            fold.issues
        );
        assert_eq!(fold.valid_entries, folds[0].valid_entries);
    }
}

/// Bug repro (review round 5, Astra F4): when every row left waited on an
/// edge, the import took the lowest sequence a sequence edge alone held
/// back, ahead of a lower one a parent edge held back too. An agent's
/// binding so staged after the agent's next row and folded as a rollback,
/// and the import still succeeded, without the binding. The order now takes
/// the lowest sequence either way, and the import folds as the source does.
#[test]
fn a_binding_held_by_both_edges_imports_before_its_signers_later_rows() {
    let hash = |entry: &AuthorityLogEntry| authority_entry_hash(entry).unwrap();
    let [owner, first, second, admin] = [150, 151, 152, 153].map(ed_key);
    let genesis = genesis_entry(150, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let signed = |signer: &SigningKey, seq, parent, op, cosigner: Option<&SigningKey>| {
        let entry = unsigned_entry(
            Some(id),
            seq,
            vec![parent],
            op,
            authority_key_from_ed(signer),
            10 + seq,
        );
        match cosigner {
            Some(cosigner) => cosign_ed(entry, signer, cosigner),
            None => sign_ed(entry, signer),
        }
    };
    let enroll = |key: &SigningKey, roles| AuthorityOp::EnrollDevice {
        device: device(authority_key_from_ed(key), roles, AuthorityTier::Software),
    };
    let revoke = |seed| AuthorityOp::RevokeActor {
        authority_key: authority_key_from_ed(&ed_key(seed)),
        epoch: 1,
    };
    let enroll_first = signed(&owner, 1, hash(&genesis), enroll(&first, ROLE_AGENT), None);
    // Two live devices need a quorum: the first agent cosigns.
    let enroll_second = signed(
        &owner,
        2,
        hash(&enroll_first),
        enroll(&second, ROLE_AGENT),
        Some(&first),
    );
    let base = hash(&enroll_second);
    let other = signed(&second, 4, base, revoke(160), Some(&owner));
    let bind = signed(
        &first,
        2,
        hash(&other),
        AuthorityOp::BindActor {
            authority_key: authority_key_from_ed(&first),
            actor_ref: EntityId::from_bytes([0x73; 16]).unwrap(),
            actor_class: "system".into(),
            epoch: 1,
        },
        Some(&owner),
    );
    let later = signed(&first, 3, base, revoke(161), Some(&owner));
    let admits = signed(&first, 5, base, enroll(&admin, ROLE_ADMIN), Some(&owner));
    let early_first = signed(&first, 1, base, revoke(162), Some(&admin));
    let early_second = signed(&second, 1, base, revoke(163), Some(&admin));

    let dir = tempfile::tempdir().unwrap();
    let source = crate::Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    let at = TimeRange { start: 1, end: 1 };
    for entry in [
        &genesis,
        &enroll_first,
        &enroll_second,
        &other,
        &bind,
        &later,
        &admits,
        &early_first,
        &early_second,
    ] {
        source.put_authority_log_entry(entry, at, 1).unwrap();
    }
    let expected = source.authority_fold().unwrap();
    assert!(
        expected.valid_entries.contains(&hash(&bind)),
        "{:?}",
        expected.issues
    );

    let history = source.export_signed_authority_history().unwrap();
    let mut reversed = history.clone();
    reversed.reverse();
    for history in [history, reversed] {
        let fold = imported(&history);
        assert!(
            fold.valid_entries.contains(&hash(&bind)),
            "the binding folded as a rollback: {:?}",
            fold.issues
        );
        assert_eq!(fold.valid_entries, expected.valid_entries);
    }
}

/// H72 (the Engine's census): the public batch door staged rows in the
/// caller's order, so a batch that gave a row before the enrollment that
/// admits its signer, or before its genesis, was held whole. It stages them
/// parents first and each signer's by sequence, and returns the ids in the
/// caller's order.
#[test]
fn a_batch_given_children_first_lands_whole() {
    let [owner, admin] = [134, 135].map(ed_key);
    let genesis = genesis_entry(134, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let admission = sign_ed(
        unsigned_entry(
            Some(id),
            1,
            vec![authority_entry_hash(&genesis).unwrap()],
            AuthorityOp::EnrollDevice {
                device: device(
                    authority_key_from_ed(&admin),
                    ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
            authority_key_from_ed(&owner),
            2,
        ),
        &owner,
    );
    let child = sign_ed(
        unsigned_entry(
            Some(id),
            1,
            vec![authority_entry_hash(&admission).unwrap()],
            AuthorityOp::SlipRevoke {
                slip_id: [0x5d; 32],
            },
            authority_key_from_ed(&admin),
            3,
        ),
        &admin,
    );
    let rows = [child, admission, genesis];
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    let at = TimeRange { start: 1, end: 1 };
    let batch: Vec<_> = rows.iter().map(|entry| (entry.clone(), at, 1)).collect();
    let ids = vault.put_authority_log_entries(&batch).unwrap();
    let expected: Vec<_> = rows
        .iter()
        .map(|entry| authority_log_entity_id(entry).unwrap())
        .collect();
    assert_eq!(ids, expected);
    assert_eq!(
        vault
            .entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
            .unwrap()
            .len(),
        3
    );
}

/// Bug repro (review round 4, Astra F2): a handoff cosigned by the owner
/// was staged as soon as the cosign vouched for it, before the admission
/// that makes its signer a slip issuer, and the door refused it as a
/// non-issuer's handoff, aborting the import. A handoff now also waits for
/// its signer's issuer grant.
#[test]
fn a_cosigned_handoff_imports_after_its_signers_admission() {
    let [owner, candidate, successor] = [131, 132, 133].map(ed_key);
    let genesis = genesis_entry(131, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let root = authority_entry_hash(&genesis).unwrap();
    let admission = sign_ed(
        unsigned_entry(
            Some(id),
            1,
            vec![root],
            AuthorityOp::EnrollDevice {
                device: device(
                    authority_key_from_ed(&candidate),
                    ROLE_OWNER,
                    AuthorityTier::Software,
                ),
            },
            authority_key_from_ed(&owner),
            2,
        ),
        &owner,
    );
    let mut handoff = unsigned_entry(
        Some(id),
        1,
        vec![root],
        AuthorityOp::ReRoot {
            new_device: device(
                authority_key_from_ed(&successor),
                ROLE_OWNER | ROLE_ADMIN,
                AuthorityTier::Software,
            ),
        },
        authority_key_from_ed(&candidate),
        3,
    );
    handoff.cosigns = vec![AuthoritySignature {
        suite: AuthoritySignatureSuite::Ed25519,
        public_key: authority_key_from_ed(&owner),
        signature: vec![0; 64],
    }];
    let transcript = authority_transcript(&handoff).unwrap();
    handoff.signer.signature = candidate.sign(&transcript).to_bytes().to_vec();
    handoff.cosigns[0].signature = owner.sign(&transcript).to_bytes().to_vec();
    let folds = [
        [&genesis, &admission, &handoff],
        [&genesis, &handoff, &admission],
        [&handoff, &admission, &genesis],
    ]
    .map(|order| {
        let history: Vec<_> = order
            .iter()
            .map(|entry| encode_authority_log_entry_body(entry).unwrap())
            .collect();
        imported(&history)
    });
    for fold in &folds {
        assert_eq!(fold.valid_entries, folds[0].valid_entries);
        assert_eq!(fold.roster, folds[0].roster);
    }
}

/// Bug repro (review round 4, Astra F1; round 5, Astra F3), under rule 5:
/// the owner's rows past the per-signer bound land, a demotion among them
/// with a counted sibling of the same sequence, and an admission another
/// admitter signs on the demotion. The history imports in either order to
/// the fold that holds the demotion: the demotion's equal-sequence sibling
/// stages with it.
#[test]
fn the_owners_rows_past_the_signer_bound_land_and_import_in_any_order() {
    const BOUND: usize = 16;
    let host = host();
    let request = request_for(host.vault_id, EntityId::now(), &ed_key(76));
    host.vault
        .enroll_machine(
            &host.issuer,
            &host.owner,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
        )
        .unwrap();
    let at = TimeRange { start: 1, end: 1 };
    let fold = || host.vault.authority_fold().unwrap();
    let next = |op| {
        crate::authority::slip_vault::next_entry(
            &host.issuer,
            &fold(),
            op,
            host.vault.now_recorded_at(),
        )
        .unwrap()
    };
    let admin = ed_key(77);
    let admit = |key: &SigningKey| AuthorityOp::EnrollDevice {
        device: device(
            authority_key_from_ed(key),
            ROLE_ADMIN,
            AuthorityTier::Software,
        ),
    };
    host.vault
        .put_authority_log_entry(&next(admit(&admin)), at, 1)
        .unwrap();
    with_rows_per_signer_for_test(BOUND, || {
        let current = fold()
            .machine(request.machine)
            .unwrap()
            .head()
            .profile
            .clone();
        let demote = AuthorityOp::MachineProfile(MachineProfile {
            role: MachineRole::Owned(MachineOwnership::WorkSchool),
            revision: current.revision + 1,
            ..current
        });
        let mut sibling = None;
        for n in 0..=BOUND {
            let (confirm, demotion) = (next(confirm_op(n)), next(demote.clone()));
            host.vault.put_authority_log_entry(&confirm, at, 1).unwrap();
            sibling = Some(demotion);
        }
        let demotion = sibling.unwrap();
        host.vault
            .put_authority_log_entry(&demotion, at, 1)
            .unwrap();
        let on_demotion = sign_ed(
            unsigned_entry(
                Some(host.vault_id),
                1,
                vec![authority_entry_hash(&demotion).unwrap()],
                admit(&ed_key(78)),
                authority_key_from_ed(&admin),
                2,
            ),
            &admin,
        );
        host.vault
            .put_authority_log_entry(&on_demotion, at, 1)
            .unwrap();
        let history = host.vault.export_signed_authority_history().unwrap();
        let mut reversed = history.clone();
        reversed.reverse();
        for history in [history, reversed] {
            let fold = imported(&history);
            assert!(!fold.authority_log_past_bound());
            assert_eq!(
                fold.machine(request.machine).unwrap().head().profile.role,
                MachineRole::Owned(MachineOwnership::WorkSchool)
            );
        }
    });
}

/// Bug repro (review rounds 2 and 3): two replicas past the owner's old
/// bound each demote one machine from the same head, and one of them then
/// removes it. The door judged the second demotion against the machine as
/// this vault already held it, demoted or removed, so refused it as full,
/// and a later removal on its line was stranded. The owner's revisions now
/// meet no bound (rule 5): both demotions and the removal land past the
/// signer bound, in either order.
#[test]
fn concurrent_demotions_of_one_machine_land_past_the_signer_bound() {
    const BOUND: usize = 8;
    let host = host();
    let request = request_for(host.vault_id, EntityId::now(), &ed_key(74));
    host.vault
        .enroll_machine(
            &host.issuer,
            &host.owner,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
        )
        .unwrap();
    let at = TimeRange { start: 1, end: 1 };
    let next = |op| {
        crate::authority::slip_vault::next_entry(
            &host.issuer,
            &host.vault.authority_fold().unwrap(),
            op,
            host.vault.now_recorded_at(),
        )
        .unwrap()
    };
    with_rows_per_signer_for_test(BOUND, || {
        for n in 0..=BOUND {
            host.vault
                .put_authority_log_entry(&next(confirm_op(n)), at, 1)
                .unwrap();
        }
        let current = host
            .vault
            .authority_fold()
            .unwrap()
            .machine(request.machine)
            .unwrap()
            .head()
            .profile
            .clone();
        let revision = |class, revision| {
            AuthorityOp::MachineProfile(MachineProfile {
                role: MachineRole::Owned(class),
                revision,
                ..current.clone()
            })
        };
        let first = next(revision(MachineOwnership::WorkSchool, current.revision + 1));
        let second = next(revision(MachineOwnership::Rented, current.revision + 1));
        assert_eq!(first.parent_hashes, second.parent_hashes);
        host.vault.put_authority_log_entry(&first, at, 1).unwrap();
        host.vault
            .set_machine_role(
                &host.issuer,
                &host.owner,
                request.machine,
                MachineRole::Removed,
            )
            .unwrap();
        host.vault.put_authority_log_entry(&second, at, 1).unwrap();
        let fold = host.vault.authority_fold().unwrap();
        assert!(!fold.authority_log_past_bound());
        assert!(
            fold.machine(request.machine)
                .is_some_and(|machine| machine.head().removed)
        );
    });
}

/// Bug repro (review round 2, F3): each held row re-read and re-verified the
/// whole stored log, so a peer's held rows, retried on every pass, cost the
/// vault that scan each time. The doors read the stored log once per
/// authority generation.
#[test]
fn held_rows_read_the_stored_log_once_per_generation() {
    let host = host();
    let root = host.vault.ensure_host_root_slip(&host.issuer).unwrap();
    for n in 0..16 {
        host.vault
            .mint_oauth_capability_slip(&host.issuer, claims_numbered(&root.claims, n), 3600, None)
            .unwrap();
    }
    let agent = ed_key(75);
    let enroll = crate::authority::slip_vault::next_entry(
        &host.issuer,
        &host.vault.authority_fold().unwrap(),
        AuthorityOp::EnrollDevice {
            device: device(
                authority_key_from_ed(&agent),
                ROLE_AGENT,
                AuthorityTier::Software,
            ),
        },
        host.vault.now_recorded_at(),
    )
    .unwrap();
    host.vault
        .put_authority_log_entry(&enroll, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
    let parent = authority_entry_hash(&enroll).unwrap();
    let builds = crate::authority::log_budget::door_view_builds_for_test();
    for n in 0..32 {
        let held = sign_ed(
            unsigned_entry(
                Some(host.vault_id),
                n + 1,
                vec![parent],
                confirm_op(n as usize),
                authority_key_from_ed(&agent),
                3,
            ),
            &agent,
        );
        let err = put_replicated_row(&host.vault, &held).unwrap_err();
        assert_eq!(
            err.kind(),
            crate::error::ErrorKind::AuthorityLogSignerPending
        );
    }
    assert!(crate::authority::log_budget::door_view_builds_for_test() - builds <= 1);
}

/// Bug repro (review round 3, F1): an install key vouched for any world
/// edit, whatever machine it named, and an admitter's signature vouched for
/// one too, though the fold applies a world edit only from the install key
/// of the machine it names. Such rows are held; the machine's own edit
/// lands.
#[test]
fn a_world_edit_lands_only_from_its_own_machines_install_key() {
    let host = host();
    let [first, second] = [76, 77].map(|seed| {
        let request = request_for(host.vault_id, EntityId::now(), &ed_key(seed));
        host.vault
            .enroll_machine(
                &host.issuer,
                &host.owner,
                &request,
                MachineRole::Owned(MachineOwnership::Yours),
            )
            .unwrap();
        request.machine
    });
    let install = ed_key(76);
    let edit = |machine| {
        let fold = host.vault.authority_fold().unwrap();
        let key = authority_key_from_ed(&install);
        let seq = fold.append_sequences.get(&key).map_or(1, |seq| seq + 1);
        let world = EntityId::now();
        let entry = unsigned_entry(
            fold.vault_id,
            seq,
            fold.append_heads.iter().copied().collect(),
            AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                world,
                act: owner_act(host.owner.actor(), world),
                machine,
                settings: WorldPrivacy::default(),
            }),
            key,
            3,
        );
        (
            sign_ed(entry.clone(), &install),
            host_cosigned(entry, &install, &host.issuer),
        )
    };
    let at = TimeRange { start: 1, end: 1 };
    for entry in [edit(second).0, edit(second).1] {
        let err = host
            .vault
            .put_authority_log_entry(&entry, at, 1)
            .unwrap_err();
        assert_eq!(
            err.kind(),
            crate::error::ErrorKind::AuthorityLogSignerPending
        );
    }
    host.vault
        .put_authority_log_entry(&edit(first).0, at, 1)
        .unwrap();
}

/// Rule 5 (Engine check): the owner's work never waits and the fold reads
/// all of it, so the log raises one typed headroom check per policy row it
/// reaches: its counted rows, and its slip issuers' handoffs. Each is a row
/// the owner may move.
#[test]
fn the_log_raises_one_headroom_check_per_policy_row() {
    const BOUND: usize = 4;
    let headroom = |vault: &crate::Vault| {
        vault
            .authority_log_checks()
            .unwrap()
            .into_iter()
            .filter(|check| check.kind == AuthorityLogCheck::FOLD_HEADROOM)
            .map(|check| (check.scope.unwrap(), check.count, check.threshold))
            .collect::<Vec<_>>()
    };
    let at = TimeRange { start: 1, end: 1 };
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let genesis = genesis_entry(68, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let mut rows = vec![(genesis.clone(), at, 1)];
    rows.extend(
        confirm_chain(&genesis, 68, BOUND - 1, |_| vec![])
            .into_iter()
            .map(|entry| (entry, at, 1)),
    );
    let half = rows.pop().unwrap();
    with_rows_per_signer_for_test(BOUND, || {
        vault.put_authority_log_entries(&rows).unwrap();
        assert!(headroom(&vault).is_empty());
        vault.put_authority_log_entries(&[half]).unwrap();
        assert_eq!(
            headroom(&vault),
            vec![(AuthorityLogCheck::ROWS, BOUND as u64, BOUND as u64)]
        );
    });

    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let genesis = genesis_entry(69, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    vault.put_authority_log_entry(&genesis, at, 1).unwrap();
    let (mut signer, mut parent) = (ed_key(69), authority_entry_hash(&genesis).unwrap());
    let at_row = DEFAULT_AUTHORITY_LOG_HEADROOM_HANDOFFS;
    for n in 1..=at_row {
        assert!(headroom(&vault).is_empty(), "{n} handoffs");
        let next = ed_key(170 + n as u8);
        let handoff = sign_ed(
            unsigned_entry(
                Some(vault_id),
                1,
                vec![parent],
                AuthorityOp::ReRoot {
                    new_device: device(
                        authority_key_from_ed(&next),
                        ROLE_OWNER | ROLE_ADMIN,
                        AuthorityTier::Software,
                    ),
                },
                authority_key_from_ed(&signer),
                2,
            ),
            &signer,
        );
        vault.put_authority_log_entry(&handoff, at, 1).unwrap();
        (signer, parent) = (next, authority_entry_hash(&handoff).unwrap());
    }
    assert_eq!(
        headroom(&vault),
        vec![(AuthorityLogCheck::HANDOFFS, at_row, at_row)]
    );
    // Each threshold is a policy row the owner may move.
    vault
        .set_authority_observation_policy(AuthorityObservationPolicy {
            log_headroom_handoffs: at_row + 1,
            ..AuthorityObservationPolicy::default()
        })
        .unwrap();
    assert!(headroom(&vault).is_empty());
}

/// Substrate invariant: an observation policy row written before the log's
/// bounds existed (three u64be), or before its fold's pair and memory rows
/// (six), still reads, with the missing rows' defaults.
#[test]
fn a_policy_row_written_before_the_signer_bound_reads_with_its_default() {
    use crate::side_table::RawValue;
    let raw = |values: &[u64]| -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.to_be_bytes())
            .collect()
    };
    let read = |values: &[u64]| {
        let policy = AuthorityObservationPolicy::from_raw(&raw(values)).unwrap();
        [
            policy.stale_roster_window_secs,
            policy.ingest_window_secs,
            policy.ingest_check_threshold,
            policy.log_signer_bound,
            policy.log_headroom_rows,
            policy.log_headroom_handoffs,
            policy.log_headroom_ancestor_pairs,
            // No row: the machine's floor.
            policy.log_fold_memory_floor_bytes.unwrap_or(0),
        ]
    };
    assert_eq!(
        read(&[10, 20, 30]),
        [
            10,
            20,
            30,
            DEFAULT_AUTHORITY_LOG_SIGNER_BOUND,
            DEFAULT_AUTHORITY_LOG_HEADROOM_ROWS,
            DEFAULT_AUTHORITY_LOG_HEADROOM_HANDOFFS,
            DEFAULT_AUTHORITY_LOG_HEADROOM_ANCESTOR_PAIRS,
            0,
        ]
    );
    assert_eq!(
        read(&[10, 20, 30, 40, 50, 60]),
        [
            10,
            20,
            30,
            40,
            50,
            60,
            DEFAULT_AUTHORITY_LOG_HEADROOM_ANCESTOR_PAIRS,
            0,
        ]
    );
}
