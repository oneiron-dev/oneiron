use rand_core::{OsRng, RngCore};

use super::*;

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// A throwaway passphrase made in the test; never a real one.
fn test_passphrase() -> (String, KitPassphrase) {
    let text = hex(&random::<12>());
    let passphrase = KitPassphrase::new(&text).unwrap();
    (text, passphrase)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn issue<'a>(
    homes: [PieceHome; 3],
    vault_id: [u8; 32],
    passphrase: Option<&'a KitPassphrase>,
) -> KitIssue<'a> {
    KitIssue {
        vault_id,
        homes,
        passphrase,
        cost: PassphraseCost::FLOOR,
        only_machine: false,
    }
}

fn machine() -> EntityId {
    EntityId::now()
}

const PAPER: PieceHome = PieceHome::RecoveryCode(CodeKeeping::Paper);

/// Pieces travel as the owner keeps them: an export for machines, persons and keys, and the
/// typed text for codes.
fn carried(piece: &KitPiece) -> KitPiece {
    match piece.home() {
        Some(PieceHome::RecoveryCode(_)) => {
            KitPiece::from_recovery_code(piece.recovery_code().reveal()).unwrap()
        }
        _ => KitPiece::import(piece.export().as_bytes()).unwrap(),
    }
}

const BODY_AT: usize = 21 + 18;

#[test]
fn a_kit_with_no_person_and_no_security_key_issues_and_restores_on_a_hosted_vault() {
    let hosted = crate::config::VaultPrivacyConfig {
        posture: crate::config::HostingPrivacyPosture::Hosted,
        data_key_custody: crate::config::VaultDataKeyCustody::HostManagedKms {
            key_ref: "host-key-ref".into(),
        },
    };
    let (vault_id, seed) = (random(), random());
    let (_, passphrase) = test_passphrase();
    let homes = [PieceHome::ThisMachine, PAPER, PieceHome::Passphrase];
    let request = issue(homes, vault_id, Some(&passphrase));
    assert_eq!(
        issue_vault_key_kit(&hosted, &request, &seed).unwrap_err(),
        KitError::PrivacyModeRequired
    );
    let kit = issue_recovery_root_kit(&request, &seed).unwrap();
    assert_eq!(kit.manifest().coverage, KitCoverage::SurvivesMachineLoss);
    let pieces = kit.into_pieces();
    assert_eq!(pieces.len(), 2);
    // The laptop is stolen: the printed code and the passphrase rebuild the seed.
    let typed = KitPiece::from_recovery_code(pieces[1].recovery_code().reveal()).unwrap();
    let restored = restore_kit(
        vault_id,
        KitSecretKind::RecoveryRoot,
        &[&typed],
        Some(&passphrase),
    )
    .unwrap();
    assert_eq!(*restored.into_bytes(), seed);
}

#[test]
fn every_pair_of_pieces_restores_whatever_the_homes() {
    let posture = crate::config::VaultPrivacyConfig::default();
    let triples = [
        [
            PieceHome::ThisMachine,
            PieceHome::OtherMachine(machine()),
            PieceHome::RecoveryCode(CodeKeeping::OwnEmail),
        ],
        [PAPER, PieceHome::TrustedPerson, PieceHome::Passphrase],
        [
            PieceHome::Passphrase,
            PieceHome::ThisMachine,
            PieceHome::SecurityKey,
        ],
        [
            PieceHome::RecoveryCode(CodeKeeping::PasswordManager),
            PAPER,
            PieceHome::TrustedPerson,
        ],
    ];
    for homes in triples {
        let (vault_id, key) = (random(), random());
        let (_, passphrase) = test_passphrase();
        let has_passphrase = homes.contains(&PieceHome::Passphrase);
        let request = issue(
            homes.clone(),
            vault_id,
            has_passphrase.then_some(&passphrase),
        );
        let pieces = issue_vault_key_kit(&posture, &request, &key)
            .unwrap()
            .into_pieces();
        let stored: Vec<KitPiece> = pieces.iter().map(carried).collect();
        for i in 0..3 {
            for j in i + 1..3 {
                let mut given = Vec::new();
                let mut with_passphrase = None;
                for x in [i, j] {
                    if homes[x] == PieceHome::Passphrase {
                        with_passphrase = Some(&passphrase);
                    } else {
                        let at = stored.iter().position(|p| p.x() as usize == x + 1).unwrap();
                        given.push(&stored[at]);
                    }
                }
                let restored =
                    restore_kit(vault_id, KitSecretKind::VaultKey, &given, with_passphrase)
                        .unwrap_or_else(|e| panic!("{homes:?} pair {i},{j}: {e}"));
                assert_eq!(*restored.as_bytes(), key, "{homes:?} pair {i},{j}");
            }
        }
    }
}

#[test]
fn the_passphrase_and_every_public_byte_restore_nothing() {
    let (vault_id, kit_id) = (random(), KitId(random()));
    let (_, passphrase) = test_passphrase();
    let homes = [PieceHome::ThisMachine, PAPER, PieceHome::Passphrase];
    let request = issue(homes, vault_id, Some(&passphrase));
    let cost = Some(PassphraseCost::FLOOR);
    let (first, second) = (random(), random());
    assert_ne!(first, second);
    let a = issue_with_id(
        KitSecretKind::RecoveryRoot,
        &request,
        &first,
        3,
        cost,
        kit_id,
    )
    .unwrap();
    let b = issue_with_id(
        KitSecretKind::RecoveryRoot,
        &request,
        &second,
        3,
        cost,
        kit_id,
    )
    .unwrap();
    // Everything a host, cloud or peer may hold about the kit is the manifest, and it is the
    // same for two different secrets: with the passphrase it is one point on either line.
    assert_eq!(a.manifest(), b.manifest());
    for (kit, secret) in [(a, first), (b, second)] {
        assert_eq!(
            restore_kit(
                vault_id,
                KitSecretKind::RecoveryRoot,
                &[],
                Some(&passphrase)
            )
            .unwrap_err(),
            KitError::NeedTwoPieces
        );
        let pieces = kit.into_pieces();
        let restored = restore_kit(
            vault_id,
            KitSecretKind::RecoveryRoot,
            &[&pieces[1]],
            Some(&passphrase),
        )
        .unwrap();
        assert_eq!(*restored.as_bytes(), secret);
    }
}

#[test]
fn a_wrong_passphrase_fails_exactly_like_a_bad_piece() {
    let (vault_id, seed) = (random(), random());
    let (_, passphrase) = test_passphrase();
    let (_, wrong) = test_passphrase();
    let homes = [PieceHome::ThisMachine, PAPER, PieceHome::Passphrase];
    let pieces = issue_recovery_root_kit(&issue(homes, vault_id, Some(&passphrase)), &seed)
        .unwrap()
        .into_pieces();
    let kind = KitSecretKind::RecoveryRoot;
    let wrong_passphrase = restore_kit(vault_id, kind, &[&pieces[1]], Some(&wrong)).unwrap_err();
    // A code altered behind a valid check, with the right passphrase.
    let mut bytes = pieces[1].export().as_bytes().to_vec();
    bytes[BODY_AT + 6] ^= 1;
    let check = piece::check(&bytes[BODY_AT..BODY_AT + 47]);
    bytes[BODY_AT + 47..].copy_from_slice(&check);
    let altered = KitPiece::import(&bytes).unwrap();
    let altered_piece = restore_kit(vault_id, kind, &[&altered], Some(&passphrase)).unwrap_err();
    let all_three =
        restore_kit(vault_id, kind, &[&pieces[0], &pieces[1]], Some(&wrong)).unwrap_err();
    assert_eq!(wrong_passphrase, KitError::NoMatch);
    assert_eq!(altered_piece, wrong_passphrase);
    assert_eq!(all_three, wrong_passphrase);
}

#[test]
fn one_piece_copies_another_vault_or_another_kit_restore_nothing() {
    // Kept from the kit before homes: the threshold and the vault and kit binding.
    let (vault_id, seed) = (random(), random());
    let homes = [PieceHome::ThisMachine, PAPER, PieceHome::TrustedPerson];
    let request = issue(homes, vault_id, None);
    let pieces = issue_recovery_root_kit(&request, &seed)
        .unwrap()
        .into_pieces();
    let other = issue_recovery_root_kit(&request, &seed)
        .unwrap()
        .into_pieces();
    let copy = carried(&pieces[0]);
    let kind = KitSecretKind::RecoveryRoot;
    let refused =
        |given: &[&KitPiece], vault_id| restore_kit(vault_id, kind, given, None).unwrap_err();
    assert_eq!(refused(&[&pieces[0]], vault_id), KitError::NeedTwoPieces);
    assert_eq!(
        refused(&[&pieces[0], &copy], vault_id),
        KitError::NeedTwoPieces
    );
    assert_eq!(
        refused(&[&pieces[0], &pieces[1]], random()),
        KitError::NoMatch
    );
    assert_eq!(
        refused(&[&pieces[0], &other[1]], vault_id),
        KitError::MixedKits
    );
}

#[test]
fn two_pieces_on_one_machine_are_refused() {
    let (vault_id, seed) = (random(), random());
    let (_, passphrase) = test_passphrase();
    let laptop = machine();
    let refused = [
        (
            [PieceHome::ThisMachine, PAPER, PieceHome::ThisMachine],
            KitError::SameMachineTwice,
        ),
        (
            [
                PieceHome::OtherMachine(laptop),
                PAPER,
                PieceHome::OtherMachine(laptop),
            ],
            KitError::SameMachineTwice,
        ),
        (
            [PieceHome::Passphrase, PAPER, PieceHome::Passphrase],
            KitError::PassphraseTwice,
        ),
        // A code file beside a machine's piece, when the owner has another machine.
        (
            [
                PieceHome::ThisMachine,
                PieceHome::RecoveryCode(CodeKeeping::FileOn(KitMachine::ThisMachine)),
                PieceHome::OtherMachine(laptop),
            ],
            KitError::SameMachineTwice,
        ),
        (
            [
                PieceHome::OtherMachine(laptop),
                PieceHome::RecoveryCode(CodeKeeping::FileOn(KitMachine::Other(laptop))),
                PAPER,
            ],
            KitError::SameMachineTwice,
        ),
    ];
    for (homes, error) in refused {
        let request = issue(homes, vault_id, Some(&passphrase));
        assert_eq!(issue_recovery_root_kit(&request, &seed).unwrap_err(), error);
    }
    // Codes, people and keys are separate items; two other machines are two places.
    for homes in [
        [PAPER, PAPER, PieceHome::TrustedPerson],
        [PieceHome::TrustedPerson, PieceHome::TrustedPerson, PAPER],
        [PieceHome::SecurityKey, PieceHome::SecurityKey, PAPER],
        [
            PieceHome::OtherMachine(laptop),
            PieceHome::OtherMachine(machine()),
            PieceHome::ThisMachine,
        ],
    ] {
        issue_recovery_root_kit(&issue(homes, vault_id, None), &seed).unwrap();
    }
}

#[test]
fn a_one_machine_kit_with_fewer_than_two_pieces_away_reports_the_warning() {
    let (vault_id, seed) = (random(), random());
    let saved_here = PieceHome::RecoveryCode(CodeKeeping::FileOn(KitMachine::ThisMachine));
    let homes = [PieceHome::ThisMachine, saved_here, PAPER];
    // With another machine, two pieces on this one are refused.
    let mut request = issue(homes, vault_id, None);
    assert_eq!(
        issue_recovery_root_kit(&request, &seed).unwrap_err(),
        KitError::SameMachineTwice
    );
    // On the owner's only machine the kit issues, and says theft would lock it.
    request.only_machine = true;
    let kit = issue_recovery_root_kit(&request, &seed).unwrap();
    assert_eq!(
        kit.manifest().coverage,
        KitCoverage::FewerThanTwoAway {
            machine: KitMachine::ThisMachine,
            away: 1
        }
    );
    // Emailed and printed: theft leaves two pieces.
    let homes = [
        PieceHome::ThisMachine,
        PieceHome::RecoveryCode(CodeKeeping::OwnEmail),
        PAPER,
    ];
    let kit = issue_recovery_root_kit(&issue(homes, vault_id, None), &seed).unwrap();
    assert_eq!(kit.manifest().coverage, KitCoverage::SurvivesMachineLoss);
}

#[test]
fn a_v1_share_is_refused() {
    let mut v1 = b"oneiron/backup-share/v1\0".to_vec();
    v1.push(1);
    v1.extend_from_slice(&random::<112>());
    assert_eq!(KitPiece::import(&v1).unwrap_err(), KitError::InvalidPiece);
}

#[test]
fn debug_and_exports_never_print_piece_material() {
    let (vault_id, seed) = (random(), random());
    let (text, passphrase) = test_passphrase();
    let homes = [PieceHome::ThisMachine, PAPER, PieceHome::Passphrase];
    let kit = issue_recovery_root_kit(&issue(homes, vault_id, Some(&passphrase)), &seed).unwrap();
    let mut printed = vec![format!("{kit:?}"), format!("{passphrase:?}")];
    let mut material = vec![hex(&seed), format!("{seed:?}"), text];
    for piece in kit.into_pieces() {
        let export = piece.export();
        let code = piece.recovery_code();
        let y = &export.as_bytes()[BODY_AT + 6..BODY_AT + 38];
        material.extend([
            hex(y),
            format!("{y:?}"),
            hex(export.as_bytes()),
            code.reveal().to_owned(),
            code.reveal().replace('-', ""),
        ]);
        printed.extend([
            format!("{piece:?}"),
            format!("{piece:#?}"),
            format!("{export:?}"),
            format!("{code:?}"),
        ]);
        let restored = restore_kit(
            vault_id,
            KitSecretKind::RecoveryRoot,
            &[&piece],
            Some(&passphrase),
        )
        .unwrap();
        printed.push(format!("{restored:?}"));
    }
    for line in &printed {
        for secret in &material {
            assert!(!line.contains(secret.as_str()), "{line}");
        }
        // A 32-byte array would print as 32 comma-separated numbers.
        assert!(line.matches(", ").count() < 31, "{line}");
    }
}

#[test]
fn argon2id_below_the_floor_is_refused() {
    for (memory_mib, passes) in [(32, 3), (64, 2), (96, 3), (2048, 3), (64, 9)] {
        assert_eq!(
            PassphraseCost::new(memory_mib, passes).unwrap_err(),
            KitError::PassphraseCost
        );
    }
    // A piece that asks for 32 MiB and 2 passes, behind a valid check.
    let (vault_id, seed) = (random(), random());
    let (_, passphrase) = test_passphrase();
    let homes = [PieceHome::ThisMachine, PAPER, PieceHome::Passphrase];
    let pieces = issue_recovery_root_kit(&issue(homes, vault_id, Some(&passphrase)), &seed)
        .unwrap()
        .into_pieces();
    let mut bytes = pieces[0].export().as_bytes().to_vec();
    assert_eq!(bytes[BODY_AT + 1], 0x63);
    bytes[BODY_AT + 1] = 0x52;
    let check = piece::check(&bytes[BODY_AT..BODY_AT + 47]);
    bytes[BODY_AT + 47..].copy_from_slice(&check);
    assert_eq!(
        KitPiece::import(&bytes).unwrap_err(),
        KitError::InvalidPiece
    );
}

#[test]
fn a_code_typed_back_by_hand_restores_and_a_typo_is_named() {
    let (vault_id, seed) = (random(), random());
    let homes = [PieceHome::ThisMachine, PAPER, PieceHome::TrustedPerson];
    let pieces = issue_recovery_root_kit(&issue(homes, vault_id, None), &seed)
        .unwrap()
        .into_pieces();
    let code = pieces[1].recovery_code();
    assert_eq!(code.reveal().len(), 80 + 19);
    // Lower case, spaces for dashes, and the look-alike letters for 0 and 1.
    let typed: String = code
        .reveal()
        .chars()
        .map(|c| match c {
            '-' => ' ',
            '0' => 'o',
            '1' => 'l',
            c => c.to_ascii_lowercase(),
        })
        .collect();
    let read = KitPiece::from_recovery_code(&typed).unwrap();
    let restored = restore_kit(
        vault_id,
        KitSecretKind::RecoveryRoot,
        &[&pieces[0], &read],
        None,
    )
    .unwrap();
    assert_eq!(*restored.as_bytes(), seed);
    let mut typo: Vec<char> = code.reveal().chars().collect();
    typo[40] = if typo[40] == 'Z' { 'Y' } else { 'Z' };
    let typo: String = typo.into_iter().collect();
    assert_eq!(
        KitPiece::from_recovery_code(&typo).unwrap_err(),
        KitError::CodeChecksum
    );
}

#[test]
fn the_piece_format_matches_an_independent_implementation() {
    // Codes computed from CONTRACT-P6A's format text by a separate Python implementation
    // (libargon2 through argon2-cffi 25.1.0, blake3-py), 2026-10-14, from synthetic inputs.
    // The passphrase is typed decomposed here; the vector used the composed form.
    let vault_id: [u8; 32] = std::array::from_fn(|i| i as u8 + 1);
    let secret: [u8; 32] = std::array::from_fn(|i| i as u8 + 0x40);
    let passphrase = KitPassphrase::new("placeholder vector cafe\u{301}").unwrap();
    let homes = [PieceHome::ThisMachine, PAPER, PieceHome::Passphrase];
    let request = issue(homes, vault_id, Some(&passphrase));
    let kit_id = KitId([0x0a, 0x0b, 0x0c, 0x0d]);
    let cost = Some(PassphraseCost::FLOOR);
    let kind = KitSecretKind::RecoveryRoot;
    let pieces = issue_with_id(kind, &request, &secret, 3, cost, kit_id)
        .unwrap()
        .into_pieces();
    let codes: Vec<String> = pieces
        .iter()
        .map(|piece| piece.recovery_code().reveal().to_owned())
        .collect();
    assert_eq!(
        codes,
        [
            "BNHG-M2RC-1PHA-0ZWG-MQK1-W4SR-GK0V-XAH2-Z1FS-3YJW-86A9-XMDB-ZTA2-5FYT-395G-7JCA-X0ZS-0EN5-Q4WB-0D86",
            "BSHG-M2RC-1PFS-GE7Y-KMCF-DVX8-S13V-N6WK-75QW-J72E-EZ7X-GGXM-1ZCA-N22B-TDTE-FJCA-X0ZS-0EN5-Q4W3-SGJS",
        ]
    );
}

#[test]
fn a_code_forged_by_someone_who_knows_the_passphrase_counts_one_stored_piece() {
    // Astra's fixture on #1424 (Engine ruling 2026-10-14): whoever knows the passphrase
    // can write a code for a secret they chose, and with one stored piece the only tag is
    // theirs. Restore cannot refuse it; it must say only one stored piece vouches, so the
    // caller matches the vault's signed record. Same synthetic kit as above.
    let vault_id: [u8; 32] = std::array::from_fn(|i| i as u8 + 1);
    let genuine: [u8; 32] = std::array::from_fn(|i| i as u8 + 0x40);
    let chosen: [u8; 32] = std::array::from_fn(|i| i as u8 + 0xa0);
    let passphrase = KitPassphrase::new("placeholder vector cafe\u{301}").unwrap();
    let kind = KitSecretKind::RecoveryRoot;
    let forged = KitPiece::from_recovery_code(
        "BNHG-M2RC-1QNY-JDPS-XJQN-EPKH-SP4F-FRVB-P4BD-HCRN-13EX-F672-PZEP-QXMK-AC14-MFV1-TFBW-G9WJ-0AZK-5FEV",
    )
    .unwrap();
    let restored = restore_kit(vault_id, kind, &[&forged], Some(&passphrase)).unwrap();
    assert_eq!(*restored.as_bytes(), chosen);
    assert_eq!(restored.stored_pieces(), 1);
    let request = issue(
        [PieceHome::ThisMachine, PAPER, PieceHome::Passphrase],
        vault_id,
        Some(&passphrase),
    );
    let pieces = issue_with_id(
        kind,
        &request,
        &genuine,
        3,
        Some(PassphraseCost::FLOOR),
        KitId([0x0a, 0x0b, 0x0c, 0x0d]),
    )
    .unwrap()
    .into_pieces();
    let restored = restore_kit(vault_id, kind, &[&pieces[0], &pieces[1]], None).unwrap();
    assert_eq!(*restored.as_bytes(), genuine);
    assert_eq!(restored.stored_pieces(), 2);
}

#[test]
fn published_field_vector_restores_a_key() {
    // GF(256)/0x11b: secret 0x53, slope 0xca gives y(1)=0x99,
    // y(2)=0xdc, y(3)=0x16. This pins interoperability, not just self-roundtrip.
    let vault_id = [1; 32];
    let kit_id = KitId([2; 4]);
    let kind = KitSecretKind::VaultKey;
    let tag = *tag(&vault_id, kind, 0, None, kit_id, &[0x53; 32]);
    let share = |x: u8, y: u8| {
        KitPiece::issued(
            PieceHome::TrustedPerson,
            piece::Point {
                x,
                kind,
                passphrase_x: 0,
                cost: None,
                kit_id,
                y: Zeroizing::new([y; 32]),
                tag: Zeroizing::new(tag),
            },
        )
    };
    let (first, second, third) = (share(1, 0x99), share(2, 0xdc), share(3, 0x16));
    for pair in [[&first, &second], [&first, &third], [&second, &third]] {
        assert_eq!(
            *restore_kit(vault_id, kind, &pair, None).unwrap().as_bytes(),
            [0x53; 32]
        );
    }
}
