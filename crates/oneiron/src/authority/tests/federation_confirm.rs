//! Federation-confirm replay and live-roster binding laws.
use super::support::*;
use super::*;

fn confirm(
    parent: &AuthorityLogEntry,
    genesis: &AuthorityLogEntry,
    seed: u8,
    seq: u64,
    id: u8,
    nonce: u8,
) -> AuthorityLogEntry {
    let signing = ed_key(seed);
    sign_ed(
        unsigned_entry(
            Some(genesis_vault_id(genesis).unwrap()),
            seq,
            vec![authority_entry_hash(parent).unwrap()],
            AuthorityOp::FederationConfirm(AuthorityConfirmAction {
                kind: AuthorityConfirmKind::Accept,
                confirm_id: [id; 32],
                peer_vault_id: [77; 32],
                epoch: 1,
                nonce: [nonce; 16],
            }),
            authority_key_from_ed(&signing),
            3,
        ),
        &signing,
    )
}

#[test]
fn federation_confirm_consumes_ids_nonces_and_requires_live_roster() {
    let genesis = genesis_entry(21, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let first = confirm(&genesis, &genesis, 21, 1, 1, 1);
    for (id, nonce) in [(1, 2), (2, 1), (1, 1)] {
        let replay = confirm(&first, &genesis, 21, 2, id, nonce);
        let fold = fold_authority_log(&[replay.clone(), first.clone(), genesis.clone()]);
        assert!(
            fold.valid_entries
                .contains(&authority_entry_hash(&first).unwrap())
        );
        assert!(
            !fold
                .valid_entries
                .contains(&authority_entry_hash(&replay).unwrap())
        );
        assert_eq!(fold.federation_confirms.len(), 1);
    }
    let outsider = confirm(&first, &genesis, 22, 2, 2, 2);
    let fold = fold_authority_log(&[genesis, first, outsider.clone()]);
    assert!(
        !fold
            .valid_entries
            .contains(&authority_entry_hash(&outsider).unwrap())
    );
}

#[test]
fn federation_confirm_sibling_replay_is_permutation_independent() {
    let genesis = genesis_entry(21, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let a = confirm(&genesis, &genesis, 21, 1, 1, 1);
    let b = confirm(&genesis, &genesis, 21, 2, 2, 1);
    let first = fold_authority_log(&[genesis.clone(), a.clone(), b.clone()]);
    let second = fold_authority_log(&[b.clone(), genesis, a.clone()]);
    assert_eq!(first, second);
    assert_eq!(first.federation_confirms.len(), 1);
    let hashes = [
        authority_entry_hash(&a).unwrap(),
        authority_entry_hash(&b).unwrap(),
    ];
    assert_eq!(
        hashes
            .iter()
            .filter(|h| first.valid_entries.contains(*h))
            .count(),
        1
    );
}

#[test]
fn federation_confirm_codec_all_kinds_and_zero_rejection() {
    let genesis = genesis_entry(21, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    for kind in [
        AuthorityConfirmKind::Accept,
        AuthorityConfirmKind::Rescope,
        AuthorityConfirmKind::A2aConnect,
        AuthorityConfirmKind::Revoke,
    ] {
        let mut entry = confirm(&genesis, &genesis, 21, 1, 1, 1);
        let AuthorityOp::FederationConfirm(ref mut action) = entry.op else {
            unreachable!()
        };
        action.kind = kind;
        entry = sign_ed(entry, &ed_key(21));
        let bytes = encode_authority_log_entry_body(&entry).unwrap();
        assert_eq!(decode_authority_log_entry_body(&bytes).unwrap(), entry);
        for zero_id in [false, true] {
            let mut bad = entry.clone();
            let AuthorityOp::FederationConfirm(ref mut action) = bad.op else {
                unreachable!()
            };
            if zero_id {
                action.confirm_id = [0; 32];
            } else {
                action.nonce = [0; 16];
            }
            assert!(encode_authority_log_entry_body(&bad).is_err());
        }
    }
}
