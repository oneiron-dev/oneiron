//! The vault id a vault read off its disk folds to (PAD-1, FIX 11293): the
//! AUTHORITY_LOG records a read-only door took in the transaction that read
//! its custody and its pad objects, folded as [`fold_authority_log`] folds a
//! log, with no `Store`, no cache and no write. A vault's id is its genesis
//! root, so no posture, pin or clock of the install it is open in changes
//! which vault the rows name. A vault that adopted a checkpoint image, and
//! may hold its genesis only through it, folds from that image as the live
//! fold does (FIX 11823): its stored pin row and the image bytes it names,
//! read in the same transaction, verified as a stored adoption is.

use super::*;

/// The vault id `records` fold to: each an AUTHORITY_LOG record as the type
/// index names it, its id key and its stored bytes (header and signed body).
/// A vault that adopted a checkpoint image (`adopted_pin`, its stored pin
/// row, and `adopted_image`, the stored bytes of the image that row names)
/// folds from it, as the live fold does: the pin verified against the image
/// ([`crate::authority::checkpoint_adopt::verified_adoption_of_rows`]), the
/// image's vault id seeded, then the records above it, the ones it does not
/// cover, folded for another root. `None` when they fold to no one vault: no
/// valid genesis among them and no adopted image, or more than one root.
///
/// # Errors
///
/// A record of another type, or a header or an entry that does not decode;
/// a sealed genesis (the overlay-unavailable error); a pin row that does not
/// decode, or an adoption whose image is missing or no longer verifies.
pub(crate) fn folded_vault_id_of_records(
    records: &[(Vec<u8>, Vec<u8>)],
    adopted_pin: Option<&[u8]>,
    adopted_image: Option<&[u8]>,
) -> Result<Option<AuthorityVaultId>> {
    let mut entries = Vec::with_capacity(records.len());
    for (_, raw) in records {
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_AUTHORITY_LOG {
            return Err(Error::CorruptedIndex("type index row kind mismatch"));
        }
        let body = raw
            .get(ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        // The source's overlay records open only under its own custody, so a
        // sealed row is read by its verified scaffold. Only a genesis roots a
        // vault id (every other entry inherits its parents'), so a sealed row
        // of another kind changes no root and is left out; a sealed genesis
        // cannot be judged without its overlay and answers unavailable.
        let read = read_authority_log_entry_body(body)
            .map_err(|_| Error::CorruptedIndex("stored authority log row"))?;
        match read {
            AuthorityEntryRead::Open(entry) => entries.push(entry),
            AuthorityEntryRead::Sealed(scaffold) if scaffold.op_kind == OP_KIND_GENESIS => {
                return Err(authority_overlay_unavailable());
            }
            AuthorityEntryRead::Sealed(_) => {}
        }
    }
    let Some(pin_row) = adopted_pin else {
        return Ok(fold_authority_log(&entries).vault_id);
    };
    let verified =
        crate::authority::checkpoint_adopt::verified_adoption_of_rows(pin_row, adopted_image);
    let adopted = match verified {
        Ok(adopted) => adopted,
        // A pin that does not verify, or names no image here, folds as the
        // paired read did before it took the pin: from the records alone.
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "a disk source's adopted checkpoint pin did not verify; its vault id folds \
                 from its records alone"
            );
            return Ok(fold_authority_log(&entries).vault_id);
        }
    };
    let image = adopted.image();
    let mut above = Vec::new();
    for entry in entries {
        if !image.rows.contains_key(&authority_entry_hash(&entry)?) {
            above.push(entry);
        }
    }
    // A genesis above the image roots another vault: more than one root.
    let fold = fold_authority_log(&above);
    let another_root = match fold.vault_id {
        Some(root) => root != image.vault_id,
        None => fold.vault_root_is_conflicted(),
    };
    Ok((!another_root).then_some(image.vault_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn a_paired_disk_identity_leaves_out_a_sealed_row_and_refuses_a_sealed_genesis() {
        let signing = SigningKey::from_bytes(&[41; 32]);
        let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
        let sign_entry = |vault_id: Option<AuthorityVaultId>,
                          seq: u64,
                          parent_hashes: Vec<AuthorityEntryHash>,
                          op: AuthorityOp| {
            let overlay_seed = authority_overlay_seed_for(&op).unwrap();
            let mut entry = AuthorityLogEntry {
                schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
                vault_id,
                seq,
                parent_hashes,
                op,
                signer: AuthoritySignature {
                    suite: key.suite(),
                    public_key: key.clone(),
                    signature: vec![0; 64],
                },
                cosigns: Vec::new(),
                ts: 100 + seq,
                overlay_seed,
            };
            let transcript = authority_transcript(&entry).unwrap();
            entry.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
            entry
        };
        let device = DeviceAuthority {
            key: key.clone(),
            transport_key_binding: [7; 32],
            attestation: AuthorityAttestation {
                kind: SOFTWARE_ARGON2ID_ATTESTATION_KIND.to_owned(),
                evidence: vec![1, 2, 3],
            },
            tier: AuthorityTier::Software,
            roles: ROLE_OWNER | ROLE_ADMIN,
        };
        let genesis = sign_entry(
            None,
            0,
            Vec::new(),
            AuthorityOp::Genesis {
                device: device.clone(),
                genesis_nonce: [51; 32],
                recovery: GenesisRecoveryStep::Saved([1; 32]),
            },
        );
        assert!(genesis.overlay_seed.is_none());
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let mut identifying_device = device;
        identifying_device.attestation.kind = "device-attestation".to_owned();
        assert!(
            !NON_IDENTIFYING_ATTESTATION_KINDS
                .contains(&identifying_device.attestation.kind.as_str())
        );
        assert!(!identifying_device.attestation.evidence.is_empty());
        let mut enrolled_device = identifying_device.clone();
        enrolled_device.key =
            AuthorityKey::Ed25519(SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes());
        let sealed = sign_entry(
            Some(vault_id),
            1,
            vec![authority_entry_hash(&genesis).unwrap()],
            AuthorityOp::EnrollDevice {
                device: enrolled_device,
            },
        );
        assert!(sealed.overlay_seed.is_some());
        let stored_record = |entry: &AuthorityLogEntry| {
            let body = encode_authority_log_entry_body(entry).unwrap();
            let mut raw = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
            raw.push(ENTITY_TYPE_AUTHORITY_LOG);
            raw.extend_from_slice(&entry.ts.to_be_bytes());
            raw.extend_from_slice(&entry.ts.to_be_bytes());
            raw.extend_from_slice(&entry.ts.to_be_bytes());
            raw.extend_from_slice(&0u64.to_be_bytes());
            assert_eq!(raw.len(), ENTITY_METADATA_HEADER_LEN);
            raw.extend_from_slice(&body);
            (
                authority_log_entity_id(entry).unwrap().as_bytes().to_vec(),
                raw,
            )
        };
        let genesis_record = stored_record(&genesis);
        let sealed_record = stored_record(&sealed);
        assert!(authority_body_is_sealed(&sealed_record.1[ENTITY_METADATA_HEADER_LEN..]).unwrap());
        assert_eq!(
            folded_vault_id_of_records(std::slice::from_ref(&genesis_record), None, None).unwrap(),
            Some(vault_id),
        );
        assert_eq!(
            folded_vault_id_of_records(&[genesis_record, sealed_record], None, None).unwrap(),
            Some(vault_id),
        );

        let sealed_genesis = sign_entry(
            None,
            0,
            Vec::new(),
            AuthorityOp::Genesis {
                device: identifying_device,
                genesis_nonce: [52; 32],
                recovery: GenesisRecoveryStep::Saved([1; 32]),
            },
        );
        assert!(sealed_genesis.overlay_seed.is_some());
        let sealed_genesis_record = stored_record(&sealed_genesis);
        assert!(
            authority_body_is_sealed(&sealed_genesis_record.1[ENTITY_METADATA_HEADER_LEN..])
                .unwrap()
        );
        let error = folded_vault_id_of_records(&[sealed_genesis_record], None, None).unwrap_err();
        assert!(is_authority_overlay_unavailable(&error));
    }
}
