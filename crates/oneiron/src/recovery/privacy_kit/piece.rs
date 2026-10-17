//! Piece format v2: a 47-byte body and a 3-byte check, typed as a recovery code or kept
//! as an export with its home. A direct switch before GA: there is no v1 decoder.
//!
//! ```text
//! body   [0]      version 2 (bits 7..5) | kind (bit 4) | passphrase x (bits 3..2) | x (bits 1..0)
//!        [1]      cost: log2(MiB) (high nibble) | passes (low nibble); 0 without a passphrase piece
//!        [2..6]   kit id, non-zero
//!        [6..38]  y
//!        [38..47] tag
//! code   = Crockford base32 of body ‖ check: 80 symbols in groups of 4
//! export = magic ‖ home (18 B) ‖ body ‖ check
//! ```
use zeroize::Zeroizing;

use super::{CodeKeeping, KitError, KitMachine, KitSecretKind, PassphraseCost, PieceHome};
use crate::EntityId;

const MAGIC: &[u8] = b"oneiron/kit-piece/v2\0";
const CHECK_CONTEXT: &str = "oneiron/kit/v2/check";
const VERSION: u8 = 2;
/// The kit's self-check. 9 bytes: one genuine piece and a search of 2^72 hashes would be
/// needed to forge a second piece that restores to a secret the forger knows.
pub(super) const TAG_LEN: usize = 9;
const BODY_LEN: usize = 38 + TAG_LEN;
const CODE_LEN: usize = BODY_LEN + 3;
const HOME_LEN: usize = 18;
const EXPORT_LEN: usize = MAGIC.len() + HOME_LEN + CODE_LEN;
const CODE_SYMBOLS: usize = CODE_LEN * 8 / 5;
const CODE_GROUP: usize = 4;
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Public kit identifier, inside every stored piece; it also salts the passphrase point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct KitId(pub [u8; 4]);

/// One point of a kit's line and the kit facts every piece repeats.
pub(super) struct Point {
    pub(super) x: u8,
    pub(super) kind: KitSecretKind,
    pub(super) passphrase_x: u8,
    pub(super) cost: Option<PassphraseCost>,
    pub(super) kit_id: KitId,
    pub(super) y: Zeroizing<[u8; 32]>,
    pub(super) tag: Zeroizing<[u8; TAG_LEN]>,
}

/// One stored piece. Debug never prints its material; drop scrubs it.
pub struct KitPiece {
    home: Option<PieceHome>,
    point: Point,
}

impl std::fmt::Debug for KitPiece {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KitPiece")
            .field("x", &self.point.x)
            .field("kind", &self.point.kind)
            .field("kit_id", &self.point.kit_id)
            .field("home", &self.home)
            .finish_non_exhaustive()
    }
}

/// A piece's binary form. Debug never prints it; drop scrubs it.
pub struct PieceExport(Zeroizing<Vec<u8>>);

impl std::fmt::Debug for PieceExport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PieceExport(<redacted>)")
    }
}

impl PieceExport {
    /// Explicit access for the keystore slot, file or security key that keeps it.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A piece's text form, the recovery code. Debug never prints it; drop scrubs it.
pub struct RecoveryCode(Zeroizing<String>);

impl std::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryCode(<redacted>)")
    }
}

impl RecoveryCode {
    /// Explicit access for showing, printing or sending it from the owner's device.
    pub fn reveal(&self) -> &str {
        &self.0
    }
}

impl KitPiece {
    pub(super) fn issued(home: PieceHome, point: Point) -> Self {
        Self {
            home: Some(home),
            point,
        }
    }
    pub(super) fn point(&self) -> &Point {
        &self.point
    }
    /// The Shamir point, 1..=3.
    pub fn x(&self) -> u8 {
        self.point.x
    }
    /// The secret this piece's kit carries.
    pub fn kind(&self) -> KitSecretKind {
        self.point.kind
    }
    /// The kit this piece belongs to.
    pub fn kit_id(&self) -> KitId {
        self.point.kit_id
    }
    /// The home picked at issue; `None` for a piece read back from a recovery code.
    pub fn home(&self) -> Option<&PieceHome> {
        self.home.as_ref()
    }
    /// The kit has a passphrase piece, so this piece plus the passphrase opens it.
    pub fn has_passphrase_piece(&self) -> bool {
        self.point.passphrase_x != 0
    }
    /// Explicit sensitive export for a keystore slot, a file or a security key.
    pub fn export(&self) -> PieceExport {
        let mut bytes = Zeroizing::new(Vec::with_capacity(EXPORT_LEN));
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&encode_home(self.home.as_ref()));
        bytes.extend_from_slice(&*self.code_bytes());
        PieceExport(bytes)
    }
    /// Strict import of an export. A v1 share, or any other shape, is refused.
    pub fn import(bytes: &[u8]) -> Result<Self, KitError> {
        if bytes.len() != EXPORT_LEN || !bytes.starts_with(MAGIC) {
            return Err(KitError::InvalidPiece);
        }
        let (home, code) = bytes[MAGIC.len()..].split_at(HOME_LEN);
        let home = decode_home(home)?;
        let point = decode_code_bytes(code)?;
        Ok(Self { home, point })
    }
    /// Explicit sensitive export as text: 80 symbols in groups of 4.
    pub fn recovery_code(&self) -> RecoveryCode {
        let bytes = self.code_bytes();
        let mut text = Zeroizing::new(String::with_capacity(
            CODE_SYMBOLS + CODE_SYMBOLS / CODE_GROUP,
        ));
        let (mut acc, mut bits) = (0u16, 0u32);
        for byte in bytes.as_slice() {
            acc = (acc << 8) | u16::from(*byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                if !text.is_empty() && text.len() % (CODE_GROUP + 1) == CODE_GROUP {
                    text.push('-');
                }
                text.push(char::from(ALPHABET[usize::from((acc >> bits) & 31)]));
            }
            acc &= (1 << bits) - 1;
        }
        RecoveryCode(text)
    }
    /// Reads a typed recovery code back: case, `-` and whitespace are ignored, `O` reads
    /// as `0`, and `I` and `L` read as `1`. A failed check is a typo, `CodeChecksum`.
    pub fn from_recovery_code(text: &str) -> Result<Self, KitError> {
        let mut bytes = Zeroizing::new([0u8; CODE_LEN]);
        let (mut acc, mut bits, mut symbols, mut at) = (0u16, 0u32, 0usize, 0usize);
        for c in text.chars() {
            let value = match c.to_ascii_uppercase() {
                c if c == '-' || c.is_whitespace() => continue,
                'O' => 0,
                'I' | 'L' => 1,
                c => ALPHABET
                    .iter()
                    .position(|symbol| char::from(*symbol) == c)
                    .ok_or(KitError::InvalidPiece)? as u16,
            };
            symbols += 1;
            if symbols > CODE_SYMBOLS {
                return Err(KitError::InvalidPiece);
            }
            acc = (acc << 5) | value;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                bytes[at] = (acc >> bits) as u8;
                at += 1;
                acc &= (1 << bits) - 1;
            }
        }
        if symbols != CODE_SYMBOLS {
            return Err(KitError::InvalidPiece);
        }
        let point = decode_code_bytes(&bytes[..])?;
        Ok(Self { home: None, point })
    }
    fn code_bytes(&self) -> Zeroizing<[u8; CODE_LEN]> {
        let point = &self.point;
        let mut bytes = Zeroizing::new([0u8; CODE_LEN]);
        bytes[0] = header(point.kind, point.passphrase_x, point.x);
        bytes[1] = cost_byte(point.cost);
        bytes[2..6].copy_from_slice(&point.kit_id.0);
        bytes[6..38].copy_from_slice(&*point.y);
        bytes[38..BODY_LEN].copy_from_slice(&*point.tag);
        let check = check(&bytes[..BODY_LEN]);
        bytes[BODY_LEN..].copy_from_slice(&check);
        bytes
    }
}

pub(super) fn kind_bit(kind: KitSecretKind) -> u8 {
    match kind {
        KitSecretKind::VaultKey => 0,
        KitSecretKind::RecoveryRoot => 1,
    }
}

pub(super) fn header(kind: KitSecretKind, passphrase_x: u8, x: u8) -> u8 {
    (VERSION << 5) | (kind_bit(kind) << 4) | (passphrase_x << 2) | x
}

pub(super) fn cost_byte(cost: Option<PassphraseCost>) -> u8 {
    cost.map_or(0, |cost| {
        ((cost.memory_mib().trailing_zeros() as u8) << 4) | cost.passes()
    })
}

pub(super) fn check(body: &[u8]) -> [u8; 3] {
    let mut check = [0; 3];
    check.copy_from_slice(&blake3::derive_key(CHECK_CONTEXT, body)[..3]);
    check
}

/// The check, then every field: one encoding per piece.
fn decode_code_bytes(bytes: &[u8]) -> Result<Point, KitError> {
    let (body, sum) = bytes.split_at(BODY_LEN);
    if check(body) != sum {
        return Err(KitError::CodeChecksum);
    }
    let header = body[0];
    let kind = match (header >> 5, (header >> 4) & 1) {
        (VERSION, 0) => KitSecretKind::VaultKey,
        (VERSION, _) => KitSecretKind::RecoveryRoot,
        _ => return Err(KitError::InvalidPiece),
    };
    let (passphrase_x, x) = ((header >> 2) & 3, header & 3);
    if x == 0 || x == passphrase_x {
        return Err(KitError::InvalidPiece);
    }
    let cost = match (passphrase_x, body[1]) {
        (0, 0) => None,
        (0, _) | (_, 0) => return Err(KitError::InvalidPiece),
        (_, byte) => Some(
            PassphraseCost::new(1 << (byte >> 4), byte & 0x0f)
                .map_err(|_| KitError::InvalidPiece)?,
        ),
    };
    let mut kit_id = [0; 4];
    kit_id.copy_from_slice(&body[2..6]);
    if kit_id == [0; 4] {
        return Err(KitError::InvalidPiece);
    }
    let mut y = Zeroizing::new([0u8; 32]);
    y.copy_from_slice(&body[6..38]);
    let mut tag = Zeroizing::new([0; TAG_LEN]);
    tag.copy_from_slice(&body[38..]);
    Ok(Point {
        x,
        kind,
        passphrase_x,
        cost,
        kit_id: KitId(kit_id),
        y,
        tag,
    })
}

/// Kind byte, sub byte, then a machine id or zeros. Kind 0 is a piece read back from a
/// code, whose home was never recorded. A passphrase is never a stored piece's home.
fn encode_home(home: Option<&PieceHome>) -> [u8; HOME_LEN] {
    let mut bytes = [0; HOME_LEN];
    let machine =
        |bytes: &mut [u8; HOME_LEN], id: &EntityId| bytes[2..].copy_from_slice(id.as_bytes());
    match home {
        None | Some(PieceHome::Passphrase) => {}
        Some(PieceHome::ThisMachine) => bytes[0] = 1,
        Some(PieceHome::OtherMachine(id)) => {
            bytes[0] = 2;
            machine(&mut bytes, id);
        }
        Some(PieceHome::RecoveryCode(keeping)) => {
            bytes[0] = 3;
            bytes[1] = match keeping {
                CodeKeeping::FileOn(KitMachine::ThisMachine) => 1,
                CodeKeeping::FileOn(KitMachine::Other(id)) => {
                    machine(&mut bytes, id);
                    2
                }
                CodeKeeping::FileElsewhere => 3,
                CodeKeeping::Paper => 4,
                CodeKeeping::PasswordManager => 5,
                CodeKeeping::OwnEmail => 6,
            };
        }
        Some(PieceHome::TrustedPerson) => bytes[0] = 4,
        Some(PieceHome::SecurityKey) => bytes[0] = 5,
    }
    bytes
}

/// Strict: every byte a home does not use is zero, and a machine id is a valid entity id.
fn decode_home(bytes: &[u8]) -> Result<Option<PieceHome>, KitError> {
    let (kind, sub, id) = (bytes[0], bytes[1], &bytes[2..]);
    let no_id = id.iter().all(|byte| *byte == 0);
    let machine = || {
        let mut raw = [0; 16];
        raw.copy_from_slice(id);
        EntityId::from_bytes(raw).map_err(|_| KitError::InvalidPiece)
    };
    let home = match (kind, sub) {
        (0, 0) if no_id => None,
        (1, 0) if no_id => Some(PieceHome::ThisMachine),
        (2, 0) => Some(PieceHome::OtherMachine(machine()?)),
        (3, 2) => Some(PieceHome::RecoveryCode(CodeKeeping::FileOn(
            KitMachine::Other(machine()?),
        ))),
        (3, _) if no_id => Some(PieceHome::RecoveryCode(match sub {
            1 => CodeKeeping::FileOn(KitMachine::ThisMachine),
            3 => CodeKeeping::FileElsewhere,
            4 => CodeKeeping::Paper,
            5 => CodeKeeping::PasswordManager,
            6 => CodeKeeping::OwnEmail,
            _ => return Err(KitError::InvalidPiece),
        })),
        (4, 0) if no_id => Some(PieceHome::TrustedPerson),
        (5, 0) if no_id => Some(PieceHome::SecurityKey),
        _ => return Err(KitError::InvalidPiece),
    };
    Ok(home)
}
