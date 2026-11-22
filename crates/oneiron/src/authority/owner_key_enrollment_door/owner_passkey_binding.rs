//! An Owner's `human` binding to their own passkey, signed by that passkey
//! (the Oneiron lead 21 Nov 04:5x: "a passkey may sign its own human
//! binding, while the binding itself grants nothing the passkey limits bar";
//! row PASSKEY-SELF-BIND).
//!
//! A hosted Owner who signs in with a passkey alone holds no owner device
//! key to bind with ([`Vault::prepare_owner_key_binding_as`]), and the hosted
//! fold counts no `human` binding that only a key in the host's custody
//! signs. Without a binding their owner verbs answer OWNER_BINDING_REQUIRED
//! (`memory::verify_owner_actor_binding_in_txn`).
//!
//! This door binds them with the passkey the host vouched for as theirs.
//! Prepare builds `BindActor{P, owner, human, epoch 1}` with the passkey P as
//! its one signer at the heads now and answers the unsigned entry and the
//! challenge P's assertion names; land takes the entry back with P's
//! assertion envelope, and the binding lands only when the fold counts it
//! and the owner's binding stands. The fold counts it only as a passkey's
//! own first binding (`owner_key_enrollment::passkey_self_bind`): P is an
//! enrolled passkey, live, never bound and never revoked, and a counted
//! enrolment of P that a key in the host's custody signed names this owner.
//! The fold cannot read the census, so this door revalidates the owner as
//! the vault's live owner at both steps.
//!
//! The binding names the owner for their owner verbs and writes alone: P
//! stays passkey-limited, so it still re-roots nothing, revokes no other
//! owner key, binds no other key and proves nothing for the owner. The
//! owner key changes list names the binding (`OwnerKeyChangeKind::BoundByPasskey`),
//! so every owner device shows it.

use oneiron_authority::authority::{verify_entry_signatures, webauthn_assertion_context};

use super::*;

/// Integrity: no live passkey the host vouched for as this owner's carries
/// this credential id. Nothing was written.
const NOT_OWNERS_PASSKEY: &str = "no live passkey this vault's host enrolled for this owner \
                                  carries this credential id; enrol the passkey first";
/// Authority: a live `human` binding names the owner already, so their
/// owner verbs pass; a second binding binds nothing new. Nothing was
/// written.
const OWNER_ALREADY_BOUND: &str = "a live human binding already names this owner; there is \
                                   nothing to bind";
/// Authority: the passkey was bound before, or a revoke names it: a
/// passkey signs only its own first binding. Nothing was written.
const PASSKEY_BOUND_BEFORE: &str = "the passkey was bound before or a revoke names it, and a \
                                    passkey signs only its own first binding; nothing was written";
/// Integrity: the entry handed back is not a binding this door builds for
/// this owner: another op, owner, class, epoch, vault or signer, a cosign,
/// or bytes that are not its one encoding. Nothing was written.
const NOT_PREPARED_PASSKEY_BINDING: &str = "the binding is not one this vault builds for this \
                                            owner and passkey; prepare it again";
/// Integrity: since the binding was prepared, the passkey signed a later
/// entry, so its sequence no longer follows. Nothing was written.
const PREPARED_PASSKEY_BINDING_STALE: &str = "since this binding was prepared, the passkey signed \
                                              a later entry; prepare it again";
/// Integrity: the assertion handed back is not the passkey's own over the
/// binding's challenge, made with the user verified on the page its
/// enrolment pinned. Nothing was written.
const NOT_PASSKEYS_ASSERTION: &str = "the assertion is not the passkey's own over the binding's \
                                      challenge, with the user verified; assert the challenge \
                                      /bind/prepare answered with the passkey it names";
/// The fold did not count the passkey's binding of its owner. Nothing was
/// written.
const PASSKEY_BINDING_NOT_COUNTED: &str = "this install's fold does not count the passkey's \
                                           binding of its owner; nothing was written";

/// A binding of the owner to their own passkey, built for the passkey to
/// sign: the entry's canonical encoding with a zero signature, which the
/// client hands back unchanged, and the challenge the passkey's assertion
/// names, [`webauthn_challenge`] of the entry's authority transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedOwnerPasskeyBinding {
    /// The unsigned entry, canonical MessagePack.
    pub entry: Vec<u8>,
    /// The challenge the passkey's assertion names.
    pub challenge: [u8; 32],
}

/// What a counted binding answers, only once the fold counted it here and it
/// committed: its authority entry is its receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerPasskeyBindingReceipt {
    /// The binding's authority entry.
    pub entry: AuthorityEntryHash,
    /// The owner the binding names.
    pub owner: EntityId,
    /// The bound passkey's key, compressed SEC1.
    pub public_key: Vec<u8>,
    /// The binding's epoch: always 1, a passkey's first binding.
    pub epoch: u64,
}

impl Vault {
    /// The first step of the owner's binding to their passkey with
    /// `credential_id` (row PASSKEY-SELF-BIND): the `BindActor` of that
    /// passkey to the owner `authority` proves, as `human`, at epoch 1, with
    /// the passkey as its one signer at its next sequence, built at this
    /// vault's main-log heads with no signature. A frontier wider than one
    /// entry names is joined first, carried by this install; that join is
    /// written and kept, and nothing else is.
    ///
    /// # Errors
    /// [`RecordError::AuthorityRefused`] for an agent's act, an owner a live
    /// `human` binding names already, a passkey bound or revoked before, or
    /// a frontier join this install cannot carry;
    /// [`RecordError::InvalidAuthorityLogBody`] for a credential id that no
    /// live passkey the host enrolled for this owner carries; an owner
    /// refusal when the proof is no longer the vault's live owner.
    pub fn prepare_owner_passkey_binding_as(
        &self,
        authority: &ActAuthority,
        credential_id: &[u8],
    ) -> Result<PreparedOwnerPasskeyBinding> {
        let owner = match authority {
            ActAuthority::Owner(owner, _) => owner,
            ActAuthority::Agent(_) => return Err(authority_refused(OWNER_ONLY)),
        };
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let key = self.owner_passkey_by_credential_in_txn(&txn, &fold, actor, credential_id)?;
        self.refuse_owner_passkey_binding_in_txn(&txn, &fold, actor, &key)?;
        let fold = if fold.append_heads.len() > MAX_PARENTS {
            let (carrier, carrier_key) = self
                .carrier_in_txn(&txn, &fold)
                .map_err(authority_refusal_as(NO_CARRIER))?;
            let joiner = FrontierSigner::Install(carrier, &carrier_key);
            self.prepare_authority_frontier_in_txn(&mut txn, &fold, joiner, MAX_PARENTS)?
                .unwrap_or(fold)
        } else {
            fold
        };
        let parents = fold.append_heads.clone();
        if parents.is_empty() {
            return Err(invalid_authority());
        }
        if parents.len() > MAX_PARENTS {
            return Err(authority_refused(TOO_MANY_HEADS));
        }
        let entry = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some(vault_id),
            seq: next_sequence(&fold, &key)?,
            parent_hashes: parents.into_iter().collect(),
            op: AuthorityOp::BindActor {
                authority_key: key.clone(),
                actor_ref: actor,
                actor_class: ACTOR_CLASS_HUMAN.into(),
                epoch: 1,
            },
            signer: AuthoritySignature {
                suite: AuthoritySignatureSuite::P256,
                public_key: key,
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: self.instant_in_txn(&txn)?.secs(),
            overlay_seed: None,
        };
        let challenge = webauthn_challenge(&authority_transcript(&entry)?);
        let body = encode_value(&entry_value(&entry, true))?;
        // A frontier join the entry names must stand for it to land.
        txn.commit()?;
        Ok(PreparedOwnerPasskeyBinding {
            entry: body,
            challenge,
        })
    }

    /// The second step: the owner lands `entry`, as
    /// [`Self::prepare_owner_passkey_binding_as`] answered it, with
    /// `assertion`, the passkey's assertion envelope over its challenge, in
    /// place. The entry must be that door's binding for the owner
    /// `authority` proves now, in its one encoding, and the door's rules
    /// must still hold at the heads read here: the owner unbound, the
    /// passkey live, enrolled for them by the host, never bound and never
    /// revoked, at the passkey's next sequence. It lands only when the fold
    /// counts it and the owner's `human` binding then stands.
    ///
    /// # Errors
    /// [`RecordError::InvalidAuthorityLogBody`] for an entry this door does
    /// not build for this owner, a passkey that is no longer theirs, a
    /// sequence that no longer follows, or an assertion that is not the
    /// passkey's over the challenge with the user verified; an authority
    /// refusal as [`Self::prepare_owner_passkey_binding_as`] says, judged
    /// here again, and for a binding the fold does not count (a passkey
    /// only another passkey vouched for, an assertion made on a page its
    /// enrolment did not pin, an owner a removal ended); an owner refusal
    /// when the proof is no longer the vault's live owner.
    pub fn land_owner_passkey_binding_as(
        &self,
        authority: &ActAuthority,
        entry: &[u8],
        assertion: Vec<u8>,
    ) -> Result<OwnerPasskeyBindingReceipt> {
        let owner = match authority {
            ActAuthority::Owner(owner, _) => owner,
            ActAuthority::Agent(_) => return Err(authority_refused(OWNER_ONLY)),
        };
        let mut entry =
            decode_unsigned_entry(entry).ok_or_else(|| not_valid(NOT_PREPARED_PASSKEY_BINDING))?;
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let AuthorityOp::BindActor {
            authority_key,
            actor_ref,
            actor_class,
            epoch,
        } = &entry.op
        else {
            return Err(not_valid(NOT_PREPARED_PASSKEY_BINDING));
        };
        let (key, epoch) = (authority_key.clone(), *epoch);
        let AuthorityKey::P256(public_key) = &key else {
            return Err(not_valid(NOT_PREPARED_PASSKEY_BINDING));
        };
        let public_key = public_key.clone();
        if *actor_ref != actor
            || actor_class != ACTOR_CLASS_HUMAN
            || epoch != 1
            || entry.schema_version != AUTHORITY_LOG_SCHEMA_VERSION
            || entry.vault_id.is_none()
            || entry.vault_id != fold.vault_id
            || *entry.signer_key() != key
            || entry.signer.suite != AuthoritySignatureSuite::P256
            || !entry.cosigns.is_empty()
        {
            return Err(not_valid(NOT_PREPARED_PASSKEY_BINDING));
        }
        if !fold.host_vouched_passkey_for(&key, &actor) {
            return Err(not_valid(NOT_OWNERS_PASSKEY));
        }
        self.refuse_owner_passkey_binding_in_txn(&txn, &fold, actor, &key)?;
        let next = next_sequence(&fold, &key)?;
        if entry.seq < next {
            return Err(not_valid(PREPARED_PASSKEY_BINDING_STALE));
        }
        // Prepare names the passkey's next sequence, which only grows: an
        // entry above it is none prepare built. Landed, it would move the
        // passkey's next sequence to its own, at `u64::MAX` past every one it
        // could sign (blind review #10043 P1).
        if entry.seq > next {
            return Err(not_valid(NOT_PREPARED_PASSKEY_BINDING));
        }
        entry.signer.signature = assertion;
        // A raw P-256 signature is no assertion: the passkey's binding needs
        // the user verified, which only an assertion's flags say.
        if webauthn_assertion_context(&entry.signer.signature).is_none()
            || verify_entry_signatures(&entry).is_err()
        {
            return Err(not_valid(NOT_PASSKEYS_ASSERTION));
        }
        let hash = authority_entry_hash(&entry)?;
        let at = TimeRange {
            start: entry.ts,
            end: entry.ts,
        };
        let now = entry.ts;
        self.put_authority_log_entries_in_txn(&mut txn, &[(entry, at, now)])?;
        let after = self.authority_view_readonly_in_txn(&txn)?;
        let bound = after.actor_bindings.get(&key).is_some_and(|binding| {
            binding.status == ActorBindingStatus::Active
                && binding.actor_ref == actor
                && binding.actor_class == ACTOR_CLASS_HUMAN
        });
        if !after.valid_entries.contains(&hash) || after.install.held_back.contains(&hash) || !bound
        {
            return Err(authority_refused(PASSKEY_BINDING_NOT_COUNTED));
        }
        txn.commit()?;
        Ok(OwnerPasskeyBindingReceipt {
            entry: hash,
            owner: actor,
            public_key,
            epoch,
        })
    }

    /// The key of the live passkey with `credential_id` that a counted
    /// enrolment signed by a key in the host's custody names `owner` for on
    /// `fold` ([`AuthorityFold::host_vouched_passkey_for`]): every counted
    /// fresh enrolment of a key counts, not only the listed one, so a
    /// sibling branch's enrolment for this owner stands.
    fn owner_passkey_by_credential_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        owner: EntityId,
        credential_id: &[u8],
    ) -> Result<AuthorityKey> {
        self.enrolled_owner_passkeys_in_txn(txn)?
            .into_iter()
            .filter(|passkey| passkey.live && passkey.credential_id == credential_id)
            .map(|passkey| AuthorityKey::P256(passkey.public_key))
            .find(|key| fold.host_vouched_passkey_for(key, &owner))
            .ok_or_else(|| not_valid(NOT_OWNERS_PASSKEY))
    }

    /// Refuses the owner's binding to the passkey `key` on `fold` unless the
    /// door's rules hold: no live `human` binding names `owner`, `key` is a
    /// live owner key on the roster, and no binding (live or ended) and no
    /// revoke names `key`, so the binding takes epoch 1.
    fn refuse_owner_passkey_binding_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        owner: EntityId,
        key: &AuthorityKey,
    ) -> Result<()> {
        if actor_binding_is_active(fold, &owner, ACTOR_CLASS_HUMAN) {
            return Err(authority_refused(OWNER_ALREADY_BOUND));
        }
        if !fold
            .roster
            .get(key)
            .is_some_and(|device| !device.revoked && device.roles & ROLE_OWNER != 0)
        {
            return Err(not_valid(NOT_OWNERS_PASSKEY));
        }
        if fold.actor_bindings.contains_key(key)
            || self.next_binding_epoch_in_txn(txn, fold, key)? != 1
        {
            return Err(authority_refused(PASSKEY_BOUND_BEFORE));
        }
        Ok(())
    }
}
