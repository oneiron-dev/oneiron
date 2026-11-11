//! [RESERVED-PREDICATE-FLAG-PUBLIC]: `decode_claim_body` and
//! `validate_predicate` take `allow_reserved` as a `pub` argument, but that
//! flag only loosens a check. The door that WRITES a reserved predicate stays
//! crate-private in core, so another crate cannot store one.

fn main() {
    let _ = oneiron::Vault::put_reserved_claim_in_txn;
}
