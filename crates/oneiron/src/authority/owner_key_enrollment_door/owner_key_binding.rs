//! An Owner's `human` binding to an owner device key of their own, signed by
//! that key (lead ruling HOSTED-RELAY-OWNER-HUMAN-BIND-CEREMONY = B, Sat 21
//! Nov 04:3x).
//!
//! On a self-hosted vault an Owner whom no live `human` binding names binds
//! with their first owner key, in its enrolment's transaction, signed by the
//! enrolment's predecessor (OWNER-ENROL; OWNER-ENROL-BIND-SIGNER = A). A
//! hosted vault's predecessor is the custodial host root, and the hosted fold
//! counts no `human` binding that only a key in the host's custody signs, so
//! there the enrolment binds no one; a relay vault holds no root of its own.
//! Without a binding the Owner's owner verbs answer OWNER_BINDING_REQUIRED
//! (`memory::verify_owner_actor_binding_in_txn`).
//!
//! This door is the step that binds them: the owner's device signs the
//! binding with the key it enrolled. Prepare builds `BindActor{K, owner,
//! human, epoch}` with K as its one signer at the heads now and answers the
//! unsigned entry and the authority transcript K signs; land takes the entry
//! back with K's Ed25519 signature, and the binding lands only when the fold
//! counts it and the owner's binding stands. The fold already counts such a
//! row on every posture: an owner key enrolment starts the enrolled key's own
//! custody line, so a key the host root enrolled is outside the host's
//! custody, and it consents and proves for the owner as soon as it is on the
//! roster.
//!
//! K is an Ed25519 owner device key that a counted enrolment names this
//! owner for, live on the roster. A passkey signs only its own first
//! binding, through its own door ([`Vault::prepare_owner_passkey_binding_as`],
//! row PASSKEY-SELF-BIND), and the recovery root's authority key
//! stays off this door: it is the way back, not a key the owner acts with
//! each day. A device key only a passkey vouched for binds once a key that
//! is no passkey confirmed it: until then the hosted fold takes no owner
//! proof from it, and the binding does not count.

use ed25519_dalek::{Signature, VerifyingKey};

use super::owner_authority_closure::{EnrolmentRow, confirmations};
use super::*;

/// Integrity: the key this binding would name is not a live Ed25519 owner
/// device key that a counted enrolment names this owner for. Nothing was
/// written.
const NOT_OWNERS_DEVICE_KEY: &str = "the key is not a live owner device key enrolled for this \
                                     owner; enrol the device's key first";
/// Authority: a live `human` binding names the owner already, so their
/// owner verbs pass; a second binding binds nothing new. Nothing was
/// written.
const OWNER_ALREADY_BOUND: &str = "a live human binding already names this owner; there is \
                                   nothing to bind";
/// Authority: the key carries a live binding already, to this owner or
/// another actor. Nothing was written.
const KEY_ALREADY_BOUND: &str = "the key carries a live binding already; nothing was written";
/// Integrity: the entry handed back is not a binding this door builds for
/// this owner: another op, owner, class, vault or signer, a cosign, or bytes
/// that are not its one encoding. Nothing was written.
const NOT_PREPARED_BINDING: &str = "the binding is not one this vault builds for this owner and \
                                    key; prepare it again";
/// Integrity: since the binding was prepared, its key signed a later entry
/// or a binding of that key ended, so its sequence or epoch no longer
/// follows. Nothing was written.
const PREPARED_BINDING_STALE: &str = "since this binding was prepared, its key signed a later \
                                      entry or its binding changed; prepare it again";
/// Integrity: the signature handed back is not the bound key's own strict
/// Ed25519 signature over the binding's transcript. Nothing was written.
const NOT_KEYS_SIGNATURE: &str = "the signature is not the key's own over the binding's \
                                  transcript; sign the transcript /bind/prepare answered with the \
                                  key it names";

/// A binding of the owner to one of their owner device keys, built for that
/// key to sign: the entry's canonical encoding with a zero signature, which
/// the client hands back unchanged, and the bytes the key signs (the entry's
/// authority transcript).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedOwnerKeyBinding {
    /// The unsigned entry, canonical MessagePack.
    pub entry: Vec<u8>,
    /// The entry's authority transcript, which the key signs with Ed25519.
    pub transcript: Vec<u8>,
}

/// What a counted binding answers, only once the fold counted it here and it
/// committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerKeyBindingReceipt {
    /// The binding's authority entry.
    pub entry: AuthorityEntryHash,
    /// The owner the binding names.
    pub owner: EntityId,
    /// The bound key.
    pub public_key: [u8; 32],
    /// The binding's epoch.
    pub epoch: u64,
}

impl Vault {
    /// The first step of the owner's binding to `public_key`, an owner device
    /// key of theirs (HOSTED-RELAY-OWNER-HUMAN-BIND-CEREMONY = B): the
    /// `BindActor` of that key to the owner `authority` proves, as `human`,
    /// at the key's next epoch, with the key as its one signer at its next
    /// sequence, built at this vault's main-log heads with no signature. A
    /// frontier wider than one entry names is joined first, carried by this
    /// install; that join is written and kept, and nothing else is.
    ///
    /// # Errors
    /// [`RecordError::AuthorityRefused`] for an agent's act, an owner a live
    /// `human` binding names already, a key that carries a live binding, or
    /// a frontier join this install cannot carry;
    /// [`RecordError::InvalidAuthorityLogBody`] for a key that is not a live
    /// owner device key enrolled for this owner; an owner refusal when the
    /// proof is no longer the vault's live owner.
    pub fn prepare_owner_key_binding_as(
        &self,
        authority: &ActAuthority,
        public_key: [u8; 32],
    ) -> Result<PreparedOwnerKeyBinding> {
        let owner = match authority {
            ActAuthority::Owner(owner, _) => owner,
            ActAuthority::Agent(_) => return Err(authority_refused(OWNER_ONLY)),
        };
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let key = AuthorityKey::Ed25519(public_key);
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        self.refuse_owner_key_binding_in_txn(&txn, &fold, actor, &key)?;
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
                epoch: self.next_binding_epoch_in_txn(&txn, &fold, &key)?,
            },
            signer: AuthoritySignature {
                suite: AuthoritySignatureSuite::Ed25519,
                public_key: key,
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: self.instant_in_txn(&txn)?.secs(),
            overlay_seed: None,
        };
        let transcript = authority_transcript(&entry)?;
        let body = encode_value(&entry_value(&entry, true))?;
        // A frontier join the entry names must stand for it to land.
        txn.commit()?;
        Ok(PreparedOwnerKeyBinding {
            entry: body,
            transcript,
        })
    }

    /// The second step: the owner lands `entry`, as
    /// [`Self::prepare_owner_key_binding_as`] answered it, with `signature`,
    /// the bound key's Ed25519 signature over its transcript, in place. The
    /// entry must be that door's binding for the owner `authority` proves
    /// now, in its one encoding, and the door's rules must still hold at the
    /// heads read here: the owner unbound, the key a live owner device key
    /// enrolled for them that carries no live binding, at the key's next
    /// sequence and epoch. It lands only when the fold counts it and the
    /// owner's `human` binding then stands.
    ///
    /// # Errors
    /// [`RecordError::InvalidAuthorityLogBody`] for an entry this door does
    /// not build for this owner, a key that is no longer theirs, a sequence
    /// or epoch that no longer follows, or a signature that is not the key's
    /// over the transcript; an authority refusal as
    /// [`Self::prepare_owner_key_binding_as`] says, judged here again, and
    /// for a binding the fold does not count (a key only a passkey vouched
    /// for, on a hosted vault); an owner refusal when the proof is no longer
    /// the vault's live owner.
    pub fn land_owner_key_binding_as(
        &self,
        authority: &ActAuthority,
        entry: &[u8],
        signature: Vec<u8>,
    ) -> Result<OwnerKeyBindingReceipt> {
        let owner = match authority {
            ActAuthority::Owner(owner, _) => owner,
            ActAuthority::Agent(_) => return Err(authority_refused(OWNER_ONLY)),
        };
        let mut entry =
            decode_unsigned_entry(entry).ok_or_else(|| not_valid(NOT_PREPARED_BINDING))?;
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
            return Err(not_valid(NOT_PREPARED_BINDING));
        };
        let (key, epoch) = (authority_key.clone(), *epoch);
        let public_key = match &key {
            AuthorityKey::Ed25519(bytes) => *bytes,
            AuthorityKey::P256(_) => return Err(not_valid(NOT_PREPARED_BINDING)),
        };
        if *actor_ref != actor
            || actor_class != ACTOR_CLASS_HUMAN
            || entry.schema_version != AUTHORITY_LOG_SCHEMA_VERSION
            || entry.vault_id.is_none()
            || entry.vault_id != fold.vault_id
            || *entry.signer_key() != key
            || entry.signer.suite != AuthoritySignatureSuite::Ed25519
            || !entry.cosigns.is_empty()
        {
            return Err(not_valid(NOT_PREPARED_BINDING));
        }
        self.refuse_owner_key_binding_in_txn(&txn, &fold, actor, &key)?;
        let next = next_sequence(&fold, &key)?;
        if entry.seq < next || epoch != self.next_binding_epoch_in_txn(&txn, &fold, &key)? {
            return Err(not_valid(PREPARED_BINDING_STALE));
        }
        // Prepare names the key's next sequence, which only grows: an entry
        // above it is none prepare built. Landed, it would move the key's
        // next sequence to its own, at `u64::MAX` past every one it could
        // sign (blind review #10043 P1).
        if entry.seq > next {
            return Err(not_valid(NOT_PREPARED_BINDING));
        }
        if !signs_strictly(&public_key, &authority_transcript(&entry)?, &signature) {
            return Err(not_valid(NOT_KEYS_SIGNATURE));
        }
        entry.signer.signature = signature;
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
            return Err(authority_refused(BINDING_NOT_COUNTED));
        }
        txn.commit()?;
        Ok(OwnerKeyBindingReceipt {
            entry: hash,
            owner: actor,
            public_key,
            epoch,
        })
    }

    /// Refuses the owner's binding to `key` on `fold` unless the door's rules
    /// hold: no live `human` binding names `owner`, `key` is a live owner
    /// device key that a counted enrolment of a device key names `owner` for
    /// (no passkey, no recovery root's authority key, no confirmation), and
    /// no live binding rests on `key`.
    fn refuse_owner_key_binding_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        owner: EntityId,
        key: &AuthorityKey,
    ) -> Result<()> {
        if actor_binding_is_active(fold, &owner, ACTOR_CLASS_HUMAN) {
            return Err(authority_refused(OWNER_ALREADY_BOUND));
        }
        let live_owner_key = fold
            .roster
            .get(key)
            .is_some_and(|device| !device.revoked && device.roles & ROLE_OWNER != 0);
        if !live_owner_key || !self.device_key_enrolled_for_in_txn(txn, owner, key)? {
            return Err(not_valid(NOT_OWNERS_DEVICE_KEY));
        }
        if fold
            .actor_bindings
            .get(key)
            .is_some_and(|binding| binding.status == ActorBindingStatus::Active)
        {
            return Err(authority_refused(KEY_ALREADY_BOUND));
        }
        Ok(())
    }

    /// Whether a counted enrolment of a device's owner key names `owner` for
    /// `key`: an Ed25519 key under the device possession kind, among the
    /// entries this vault keeps. A confirmation is no enrolment: an owner
    /// key that vouches again for a key only a passkey vouched for names its
    /// own owner, whom the key was not enrolled for, and the removal of
    /// that owner does not end the key either
    /// ([`Vault::owner_authority_closure_in_txn`], one reading of which rows
    /// confirm). Sibling enrolments of one key on parallel branches each
    /// stand.
    fn device_key_enrolled_for_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: EntityId,
        key: &AuthorityKey,
    ) -> Result<bool> {
        let mut parents: BTreeMap<AuthorityEntryHash, Vec<AuthorityEntryHash>> = BTreeMap::new();
        let mut enrolments: Vec<EnrolmentRow> = Vec::new();
        let mut theirs: Vec<AuthorityEntryHash> = Vec::new();
        self.visit_authority_entries_in_txn(txn, |fold, hash, entry| {
            if !fold.valid_entries.contains(&hash) {
                return;
            }
            parents.insert(hash, entry.parent_hashes.clone());
            let AuthorityOp::OwnerKeyEnroll(enroll) = &entry.op else {
                return;
            };
            if enroll.device.key != *key {
                return;
            }
            enrolments.push(EnrolmentRow {
                hash,
                key: key.clone(),
                owner: enroll.act.owner,
            });
            if enroll.act.owner == owner
                && enroll.public_key().is_some()
                && EnrolledOwnerKeyKind::of(enroll) == EnrolledOwnerKeyKind::Device
            {
                theirs.push(hash);
            }
        })?;
        let confirmed = confirmations(&enrolments, &parents);
        Ok(theirs.iter().any(|hash| !confirmed.contains(hash)))
    }

    /// The epoch the next `BindActor` of `key` takes on `fold`: one above
    /// both the key's last binding, ended or not, and every counted
    /// `RevokeActor` of the key among the entries this vault keeps, which
    /// the fold's floor for a new binding takes in (`apply_actor_binding`):
    /// an owner-proved revoke of a key no binding rests on names any epoch.
    /// The first is 1, as the host root's binding of its embedded owner
    /// takes it again ([`Vault::restore_embedded_owner_binding_in_txn`]). A
    /// floor only a revoke the fold no longer counts holds
    /// (ONE-REVOKE-DURABILITY) still refuses the binding, and land answers
    /// that it did not count.
    ///
    /// # Errors
    /// [`invalid_authority`] for a floor at the last epoch; the store's.
    pub(super) fn next_binding_epoch_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        key: &AuthorityKey,
    ) -> Result<u64> {
        let mut floor = fold
            .actor_bindings
            .get(key)
            .map_or(0, |binding| binding.epoch);
        self.visit_authority_entries_in_txn(txn, |view, hash, entry| {
            let AuthorityOp::RevokeActor {
                authority_key,
                epoch,
            } = &entry.op
            else {
                return;
            };
            if authority_key == key && view.valid_entries.contains(&hash) {
                floor = floor.max(*epoch);
            }
        })?;
        floor.checked_add(1).ok_or_else(invalid_authority)
    }
}

/// Whether `signature` is `public_key`'s strict Ed25519 signature over
/// `message`.
fn signs_strictly(public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
    let (Ok(key), Ok(signature)) = (
        VerifyingKey::from_bytes(public_key),
        Signature::from_slice(signature),
    ) else {
        return false;
    };
    key.verify_strict(message, &signature).is_ok()
}
