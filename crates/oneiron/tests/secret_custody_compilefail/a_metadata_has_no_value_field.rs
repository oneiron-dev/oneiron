//! (a) `SecretCustodyMetadata` — the value-less projection returned by
//! `Vault::get_secret_metadata` and `SecretCustodyRecord::metadata` — has no
//! value member at all, so out-of-crate code cannot read the secret through
//! the metadata read even by naming the field.

fn peek(meta: &oneiron::secret_custody::SecretCustodyMetadata) -> &[u8] {
    &meta.value_bytes
}

fn main() {
    let _ = peek;
}
