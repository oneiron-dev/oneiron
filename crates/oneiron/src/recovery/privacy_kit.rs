//! Vault-scoped 2-of-3 offline recovery kits; no person-level master secret.
//!
//! A kit carries one 32-byte secret: a vault's data key, or the world recovery root
//! seed. Shamir over GF(2^8), degree 1, bytewise; the point x (1, 2 or 3) is only the
//! point. Beside it sits the home the owner picked. The host and the cloud have no home.
//! The passphrase piece stores nothing: its point is Argon2id(passphrase), and the line is
//! fitted through it and the secret, so the passphrase alone (or with any public byte) is
//! one point and opens nothing, and testing a guess needs a stored piece. The issuing
//! machine's own piece lives in its device-only key slots (`store`, FIX 2063).
use rand_core::{OsRng, RngCore};
use unicode_normalization::{IsNormalized, UnicodeNormalization, is_nfc_quick};
use zeroize::{Zeroize, Zeroizing};

use crate::EntityId;

mod piece;
mod store;
#[cfg(test)]
mod tests;

pub use piece::{KitId, KitPiece, PieceExport, RecoveryCode};
pub(crate) use store::{
    KitPiecePair, KitPieceStore, join_kept_piece, recovery_root_pending_piece_install,
    recovery_root_piece_install, vault_key_piece_install,
};

const SALT_CONTEXT: &str = "oneiron/kit/v2/passphrase-salt";
const TAG_CONTEXT: &str = "oneiron/kit/v2/tag";

pub use crate::store::recovery_kit::{
    CodeKeeping, IssuedKit, KitCoverage, KitError, KitIssue, KitMachine, KitManifest,
    KitPassphrase, KitSecretKind, PassphraseCost, PieceHome, RestoredKitSecret,
};

/// Issues a kit for a vault's data key on any valid custody, a hosted one included: the
/// owner's will to keep a copy counts wherever the vault runs (owner, 10-19). The kit is
/// a copy, never a claim of host-blindness ([`KitSecretKind::VaultKey`] says what it does
/// not do). This does not implement an unratified sealed-envelope VEK-rotation protocol.
pub fn issue_vault_key_kit(
    posture: &crate::config::VaultPrivacyConfig,
    issue: &KitIssue<'_>,
    vault_key: &[u8; 32],
) -> Result<IssuedKit, KitError> {
    if posture.validate().is_err() {
        return Err(KitError::InvalidCustodyConfig);
    }
    issue_kit(KitSecretKind::VaultKey, issue, vault_key)
}

/// Issues a kit for the world recovery root seed, on any posture: the host never holds a
/// piece, so a hosted vault's kit is host-blind too.
pub fn issue_recovery_root_kit(
    issue: &KitIssue<'_>,
    seed: &[u8; 32],
) -> Result<IssuedKit, KitError> {
    issue_kit(KitSecretKind::RecoveryRoot, issue, seed)
}

fn issue_kit(
    kind: KitSecretKind,
    issue: &KitIssue<'_>,
    secret: &[u8; 32],
) -> Result<IssuedKit, KitError> {
    check_homes(&issue.homes, issue.only_machine)?;
    let passphrase_x = issue
        .homes
        .iter()
        .position(|home| *home == PieceHome::Passphrase)
        .map_or(0, |i| i as u8 + 1);
    let cost = match (passphrase_x, issue.passphrase) {
        (0, None) => None,
        (0, Some(_)) => return Err(KitError::PassphraseUnused),
        (_, None) => return Err(KitError::PassphraseMissing),
        (_, Some(_)) => Some(issue.cost),
    };
    if issue.vault_id == [0; 32] || *secret == [0; 32] {
        return Err(KitError::InvalidSecret);
    }
    let mut kit_id = [0; 4];
    OsRng
        .try_fill_bytes(&mut kit_id)
        .map_err(|_| KitError::EntropyUnavailable)?;
    if kit_id == [0; 4] {
        return Err(KitError::EntropyUnavailable);
    }
    issue_with_id(kind, issue, secret, passphrase_x, cost, KitId(kit_id))
}

/// The rest of issue, once the kit id is drawn.
fn issue_with_id(
    kind: KitSecretKind,
    issue: &KitIssue<'_>,
    secret: &[u8; 32],
    passphrase_x: u8,
    mut cost: Option<PassphraseCost>,
    kit_id: KitId,
) -> Result<IssuedKit, KitError> {
    let mut slope = Zeroizing::new([0u8; 32]);
    match (&mut cost, issue.passphrase) {
        (Some(cost), Some(passphrase)) => {
            // A device that cannot afford the asked memory steps down toward FLOOR, never
            // below it; the pieces and the manifest carry the cost actually used.
            let point = loop {
                match passphrase_point(&issue.vault_id, kind, kit_id, *cost, passphrase) {
                    Err(KitError::PassphraseStretch)
                        if cost.memory_mib > PassphraseCost::FLOOR.memory_mib =>
                    {
                        cost.memory_mib /= 2;
                    }
                    point => break point?,
                }
            };
            let inv = inverse(passphrase_x);
            for ((slope, point), secret) in slope.iter_mut().zip(point.iter()).zip(secret) {
                *slope = multiply(point ^ secret, inv);
            }
        }
        _ => OsRng
            .try_fill_bytes(&mut slope[..])
            .map_err(|_| KitError::EntropyUnavailable)?,
    }
    let tag = tag(&issue.vault_id, kind, passphrase_x, cost, kit_id, secret);
    let mut pieces = Vec::with_capacity(3);
    for (x, home) in (1u8..).zip(&issue.homes) {
        if *home == PieceHome::Passphrase {
            continue;
        }
        pieces.push(KitPiece::issued(
            home.clone(),
            piece::Point {
                x,
                kind,
                passphrase_x,
                cost,
                kit_id,
                y: Zeroizing::new(std::array::from_fn(|i| secret[i] ^ multiply(slope[i], x))),
                tag: Zeroizing::new(*tag),
            },
        ));
    }
    Ok(IssuedKit {
        manifest: KitManifest {
            kit_id,
            kind,
            homes: issue.homes.clone(),
            cost,
            coverage: coverage(&issue.homes),
        },
        pieces,
    })
}

/// Rebuilds a kit's secret from at least two distinct points: stored pieces, plus the
/// passphrase when given. Every point given must lie on one line, and the tag must match.
/// The vault id comes from the vault being restored. The result opens that vault's key
/// custody or recovery root; it confers no authority-log widening.
pub fn restore_kit(
    vault_id: [u8; 32],
    kind: KitSecretKind,
    pieces: &[&KitPiece],
    passphrase: Option<&KitPassphrase>,
) -> Result<RestoredKitSecret, KitError> {
    let Some(first) = pieces.first() else {
        return Err(KitError::NeedTwoPieces);
    };
    let first = first.point();
    if vault_id == [0; 32] {
        return Err(KitError::InvalidSecret);
    }
    let rebuilt;
    let mut points: Vec<(u8, &[u8; 32])> = Vec::with_capacity(3);
    // A piece that disagrees with the first is noted, not returned at once: the passphrase
    // work below runs either way, so an altered piece fails after the same work as a wrong
    // passphrase. Kind and kit id are public facts about the pieces and fail first.
    let mut mismatch = false;
    for piece in pieces {
        let point = piece.point();
        if point.kind != kind {
            return Err(KitError::WrongKind);
        }
        if point.kit_id != first.kit_id {
            return Err(KitError::MixedKits);
        }
        if point.passphrase_x != first.passphrase_x
            || point.cost != first.cost
            || point.tag != first.tag
        {
            mismatch = true;
            continue;
        }
        match points.iter().find(|(x, _)| *x == point.x) {
            Some((_, y)) if **y == *point.y => {}
            Some(_) => mismatch = true,
            None => points.push((point.x, &point.y)),
        }
    }
    let stored_pieces = points.len() as u8;
    if let Some(passphrase) = passphrase {
        // Only pieces that all agree the kit has no passphrase piece say so.
        let Some(cost) = first.cost else {
            return Err(if mismatch {
                KitError::NoMatch
            } else {
                KitError::PassphraseUnused
            });
        };
        rebuilt = passphrase_point(&vault_id, kind, first.kit_id, cost, passphrase)?;
        points.push((first.passphrase_x, &rebuilt));
    }
    if mismatch {
        return Err(KitError::NoMatch);
    }
    let [(x1, y1), (x2, y2), ..] = points[..] else {
        return Err(KitError::NeedTwoPieces);
    };
    let inv = inverse(x1 ^ x2);
    let slope = Zeroizing::new(std::array::from_fn::<_, 32, _>(|i| {
        multiply(y1[i] ^ y2[i], inv)
    }));
    let secret = Zeroizing::new(std::array::from_fn::<_, 32, _>(|i| {
        y1[i] ^ multiply(slope[i], x1)
    }));
    let mut diff = 0u8;
    for (x, y) in &points {
        for ((y, secret), slope) in y.iter().zip(secret.iter()).zip(slope.iter()) {
            diff |= y ^ secret ^ multiply(*slope, *x);
        }
    }
    let expected = tag(
        &vault_id,
        kind,
        first.passphrase_x,
        first.cost,
        first.kit_id,
        &secret,
    );
    for (a, b) in expected.iter().zip(first.tag.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 || *secret == [0; 32] {
        return Err(KitError::NoMatch);
    }
    Ok(RestoredKitSecret {
        kind,
        kit_id: first.kit_id,
        bytes: secret,
        reissue_advised: first
            .cost
            .is_some_and(|cost| cost.below(&PassphraseCost::DEFAULT)),
        stored_pieces,
    })
}

/// A second passphrase is refused, and so are two pieces on one machine. One exception,
/// as the owner ruled: on the owner's only machine, this machine's piece beside a code
/// file on it is issued, and coverage reports the warning; that machine already holds what
/// the kit opens. Codes, people and security keys may repeat: each is a separate item or
/// person.
fn check_homes(homes: &[PieceHome; 3], only_machine: bool) -> Result<(), KitError> {
    let count = |home: &PieceHome| homes.iter().filter(|other| *other == home).count();
    if count(&PieceHome::Passphrase) > 1 {
        return Err(KitError::PassphraseTwice);
    }
    if count(&PieceHome::ThisMachine) > 1 {
        return Err(KitError::SameMachineTwice);
    }
    let machines: Vec<KitMachine> = homes.iter().filter_map(PieceHome::machine).collect();
    let only_this_machine = only_machine
        && machines
            .iter()
            .all(|machine| *machine == KitMachine::ThisMachine);
    for (i, machine) in machines.iter().enumerate() {
        if !only_this_machine && machines[i + 1..].contains(machine) {
            return Err(KitError::SameMachineTwice);
        }
    }
    Ok(())
}

/// For each machine holding a piece, this machine first, the pieces that survive its loss.
fn coverage(homes: &[PieceHome; 3]) -> KitCoverage {
    let mut machines: Vec<KitMachine> = homes.iter().filter_map(PieceHome::machine).collect();
    machines.sort_by_key(|machine| *machine != KitMachine::ThisMachine);
    for machine in machines {
        let away = homes
            .iter()
            .filter(|home| home.machine() != Some(machine))
            .count();
        if away < 2 {
            return KitCoverage::FewerThanTwoAway {
                machine,
                away: away as u8,
            };
        }
    }
    KitCoverage::SurvivesMachineLoss
}

/// The passphrase's Shamir point. The salt binds the vault, the kind and the kit id, so
/// every kit gets its own point and its own line.
fn passphrase_point(
    vault_id: &[u8; 32],
    kind: KitSecretKind,
    kit_id: KitId,
    cost: PassphraseCost,
    passphrase: &KitPassphrase,
) -> Result<Zeroizing<[u8; 32]>, KitError> {
    let mut salt = blake3::Hasher::new_derive_key(SALT_CONTEXT);
    salt.update(vault_id);
    salt.update(&[piece::kind_bit(kind)]);
    salt.update(&kit_id.0);
    oneiron_crypto::stretch_passphrase(&passphrase.0, &cost.argon2(), salt.finalize().as_bytes())
        .map_err(|_| KitError::PassphraseStretch)
}

/// The kit's self-check, shared by every piece: it binds the vault, the kind, the
/// passphrase point's place, the cost and the kit id to the secret.
fn tag(
    vault_id: &[u8; 32],
    kind: KitSecretKind,
    passphrase_x: u8,
    cost: Option<PassphraseCost>,
    kit_id: KitId,
    secret: &[u8; 32],
) -> Zeroizing<[u8; piece::TAG_LEN]> {
    let mut h = blake3::Hasher::new_derive_key(TAG_CONTEXT);
    h.update(vault_id);
    h.update(&[piece::header(kind, passphrase_x, 0), piece::cost_byte(cost)]);
    h.update(&kit_id.0);
    h.update(secret);
    let mut digest = h.finalize();
    let mut tag = Zeroizing::new([0; piece::TAG_LEN]);
    tag.copy_from_slice(&digest.as_bytes()[..piece::TAG_LEN]);
    // The hasher's block buffer still holds the secret's bytes. Scratch inside the
    // provider's own frames (its finalize block) is not reached: best effort.
    h.zeroize();
    digest.zeroize();
    tag
}

// GF(2^8), irreducible polynomial x^8+x^4+x^3+x+1. Fixed work per secret byte.
fn multiply(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0;
    for _ in 0..8 {
        result ^= a & 0u8.wrapping_sub(b & 1);
        a = (a << 1) ^ (0x1b & 0u8.wrapping_sub(a >> 7));
        b >>= 1;
    }
    result
}
fn inverse(a: u8) -> u8 {
    let mut result = 1;
    let mut power = a;
    for bit in 0..8 {
        if 254 & (1 << bit) != 0 {
            result = multiply(result, power);
        }
        power = multiply(power, power);
    }
    result
}
