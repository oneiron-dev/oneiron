//! The side tables `secret_custody` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One cloud registration slot's value-free binding (G7): the owner who linked it, the pinned
    /// issuer and audience, the verified cloud subject, its phase and fenced generation. Kept after
    /// a logout or a replacement until the owner's erase, which takes the slot. Key: id16 (slot).
    CLOUD_REGISTRATION: VaultMeta b"cloud_registration:v1:" Named
        // Payload family: A cloud registration slot's binding (G7): ids, the pinned issuer and
        // audience, the verified subject, a phase and a generation; its tokens stay in the slot's
        // sealed custody record.
        [restore: live] [family: structure] [tier: canonical]
        => crate::secret_custody::erase_cloud_registration_actor_in_txn;
    /// The sealed copy one export secret request's holder committed (FIX 4624(b)): the second it
    /// was sealed at, the request, then the custody value sealed to the recipient machine the owner
    /// chose, in its numbered envelopes, kept for the owner to fetch by its holder and by each
    /// install a window relays it to (FIX 11843). Holds no plaintext; its signed result names the
    /// copy's digest. Key: hash32 (the request's entry hash).
    SECRET_CUSTODY_EXPORT_OUTPUT: VaultMeta b"secret_custody:export_output:v1:" Raw Ciphertext
        // Restore class: An export secret supplement's sealed copy stands as a custody input does
        // (FIX 11843).
        // Payload family: An export secret supplement's sealed copy is kept and relayed as a
        // custody input row is (FIX 11843).
        [restore: live] [family: dispatch Credential] [tier: canonical];
    SECRET_CUSTODY_INPUT: VaultMeta b"secret_custody:input:v1:" Raw Ciphertext
        [restore: live] [family: dispatch Credential] [tier: canonical];
    /// What one custody request's executor committed (WILL L04 row 04): the digest of the custody
    /// transition it signed and the rotation receipt it wrote, immutable once written, beside the
    /// latest transition by id. A retry finds it and changes nothing. Key: hash32 (the request's
    /// entry hash).
    SECRET_CUSTODY_OUTPUT: VaultMeta b"secret_custody:output:v1:" Raw Engine
        [restore: live] [family: unclassified] [tier: canonical];
    /// The rewrap request whose bindings this vault took into one custody record it holds as a
    /// receiver (CALLS CUSTODY_REBIND_PENDING_FLOOR): a replay of its carrier never applies again,
    /// while a carrier kept as this vault's latest whose bindings the live floor refused stays
    /// pending. Canonical (FIX 5337): a checkpoint carries it with the record it was taken into,
    /// and a restore over a live vault keeps the live vault's. Key: hex32(entity id).
    SECRET_CUSTODY_REBIND: VaultMeta b"secret_custody:rebind:v1:" Raw Engine
        [restore: live] [family: unclassified] [tier: canonical];
    /// A restore batch whose owner's confirm stands on this vault while any of its credentials
    /// still waits (FIX-LIST 10671 (b)): the custody passes land those under it. Runtime tier, so
    /// no image carries one and an image's receipt is never an election here. Holds nothing but
    /// its key. Key: id16 (restore batch).
    SECRET_CUSTODY_RESTORE_ELECTION: VaultMeta b"secret_custody:restore_election:v1:" Named Engine
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// One credential a restore keeping this host's custody landed withheld, pending, because
    /// its source vault did not read (FIX-LIST 10671 (a)): its row as the image carried it, the
    /// value sealed under its generation's key, the digest of the withheld row that took its
    /// place, and the binding whose source it waits on. Never a plaintext or a key. Key: id16
    /// (restore batch) + id16 (custody record id).
    SECRET_CUSTODY_RESTORE_PENDING: VaultMeta b"secret_custody:restore_pending:v1:" Named Ciphertext
        // Restore class: A restore's pending credentials stand with the custody they wait on
        // (FIX-LIST 10671).
        [restore: live] [family: dispatch Credential] [tier: canonical];
    /// The owner's release of one restore batch's pending credentials (FIX-LIST 10671 (b)): who
    /// confirmed, when, the typed confirm and what each credential came to. Value-free; his
    /// election, never a check of the source. Key: id16 (restore batch).
    SECRET_CUSTODY_RESTORE_RELEASE: VaultMeta b"secret_custody:restore_release:v1:" Named Engine
        [restore: live] [family: structure] [tier: canonical]
        => crate::secret_custody::erase_pending_restore_actor_in_txn;
    /// The latest owner-signed custody transition this vault signed of one portable credential
    /// (OF-422): the record without its value, the value sealed to each machine mine here. Key:
    /// hex32(entity id).
    SECRET_CUSTODY_TRANSITION: VaultMeta b"secret_custody:transition:v1:" Raw Custody
        [restore: refuse "secret custody"] [family: dispatch Credential] [tier: canonical];
    /// One numbered part of a custody request's signed entry that a relayed input carries as its
    /// witness when the whole is past one row (FIX 8088): the part, its place and count, the
    /// request, input and whole-witness commitment it binds, signed by the request's signer. Holds
    /// no value. Key: hash32 (the part's own key).
    SECRET_CUSTODY_WITNESS: VaultMeta b"secret_custody:witness:v1:" Raw Engine
        [restore: live] [family: dispatch Credential] [tier: canonical];
    /// The keys a mask on write lifted out of one record or file, each with its handle, its kind,
    /// where it sat and what the owner did about it (OF-560's found-key notice). Holds no value.
    /// Key: id16 (the record, or the file's ASSET).
    SECRET_FOUND_KEY: VaultMeta b"secret_found_key:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::secret_custody::erase_found_key_actor_in_txn;
    /// The ruled screen of one record (L6-03-RULED-SCREEN-LOCAL): the keyed digest of each value
    /// the owner, or the person who wrote it, ruled no secret or kept as text there, under the
    /// vault's screen key. Written by the ruling on its install, and on every other install from
    /// the revoke the ruling carries. Holds no value and names no person. Key: id16 (the record,
    /// or the file's ASSET).
    SECRET_RULED_SCREEN: VaultMeta b"secret_ruled_screen:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The files ruled no secret on any install of the vault (Engine RULING
    /// PLAN-SEALED-FILE-RULING-CARRY): the keyed digest, under the vault's screen key, of each file
    /// the write door sealed whole that the owner answered not a secret, as the fold's sealed-file
    /// rulings name it, and whether this install's own seals of it were settled. Written by the
    /// owner work drain on every install. Holds no value and names no person. Key: hash32 (the
    /// keyed digest).
    SECRET_RULED_FILE: VaultMeta b"secret_ruled_file:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// A sealed-file ruling this install made and has not carried to the owner's other installs
    /// yet (Engine RULING PLAN-SEALED-FILE-RULING-CARRY, 14 Nov 16:48): while the vault data key is
    /// locked, or with no live machine profile or no install key loaded, the ruling stands here
    /// and its carry waits. The file's ASSET, the owner it is by and the surface he decided on.
    /// Holds no value, and is never carried itself. Key: hash32 (the file's BLAKE3).
    SECRET_RULED_FILE_OWED: VaultMeta b"secret_ruled_file:owed:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::secret_custody::erase_owed_file_ruling_actor_in_txn;
    /// One reveal of a secret's value by its handle: the agent's ask, the owner's answer and the
    /// lease that delivered it, or the owner's own read with its reason (OF-560). Holds no value.
    /// Key: id16 (reveal id).
    SECRET_REVEAL: VaultMeta b"secret_reveal:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::secret_custody::erase_reveal_actor_in_txn;
}
