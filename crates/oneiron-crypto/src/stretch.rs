//! A stretched passphrase as raw key material, for constructions that are not envelope
//! wraps: the recovery kit rebuilds a Shamir point from the owner's passphrase.

use zeroize::Zeroizing;

use crate::error::Result;
use crate::keys::{Argon2Cost, Passphrase};

/// Argon2id v0x13 over `passphrase` with `salt`, 32-byte output: the same stretch a
/// passphrase envelope runs, in work memory this crate allocates and wipes. `cost` must
/// pass the format bounds (19 MiB..=2 GiB, 1..=64 passes, 1..=16 lanes); a caller with a
/// stricter floor checks it first.
pub fn stretch_passphrase(
    passphrase: &Passphrase,
    cost: &Argon2Cost,
    salt: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    cost.check()?;
    crate::envelope::argon2id(passphrase, cost, salt)
}
