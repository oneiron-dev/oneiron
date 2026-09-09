//! (b) `SecretCustodyRecord` cannot be struct-literalled out of crate: both
//! `value_bytes` and `manifest_ref` are `pub(crate)`. Every other field value
//! below is well-typed and public on purpose, so the diagnostic is exactly the
//! privacy one — no out-of-crate mint of a custody record carrying chosen
//! value bytes, and no bypass of the bound door `get_secret_value_in_txn`.

fn forge(value: Vec<u8>) -> oneiron::secret_custody::SecretCustodyRecord {
    oneiron::secret_custody::SecretCustodyRecord {
        name: "api-key".to_owned(),
        class: oneiron::secret_custody::CustodyClass::CustodyPortable,
        device_only: false,
        value_bytes: value,
        status: oneiron::secret_custody::SecretCustodyStatus::Active,
        registered_at: 0,
        rotated_at: None,
        rotation_generation: 0,
        bindings: Vec::new(),
        manifest_ref: String::new(),
        declared_paths: Vec::new(),
        policy_floor_snapshot: oneiron::secret_custody::SecretCustodyFloor::default(),
    }
}

fn main() {
    let _ = forge;
}
