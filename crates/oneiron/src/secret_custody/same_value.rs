//! The owner's machines' same-value statements (FIX [SECRETS-SAME-VALUE-FACT]; Engine RULINGS
//! SECRETS-LIST-DUP-GROUPING = A, SECRET-SAMEFACT-HOST-SEES = B and
//! SECRET-SAMEFACT-SEAL-RECIPIENTS = A, 16 Nov).
//!
//! A machine that holds two custody records whose current-generation known-value entries match
//! there (length and keyed fingerprint of the whole value) proves the two hold one value. On each
//! steady pass it derives every such pair from one custody snapshot and keeps one statement of
//! them: its machine id, the time it signed it, the pairs sealed to each machine mine here through
//! custody's own envelope path, and its signature over all of it. A host's node is never mine, so
//! it is never a recipient and relays bytes it cannot open. The statement travels through the
//! residence home (`residence.secret_same_value.exchange`). Every machine keeps the newest
//! statement of each writer whose signature its own fold admits, and opens the envelope sealed to
//! it, if one is.
//!
//! A pair says only that two records held one value when its writer last derived its pairs, at the
//! two generations it names. It is never a merge or a revoke basis by itself: the owner's list
//! reads it to show the two records as one item, and nothing else does. A pair the writer no longer
//! proves (a rotation, a value re-entered at the same generation, a revoke) leaves its next
//! statement. A pair whose generations are not the ones the reader lists groups nothing. The writer
//! signs again when its pairs or its recipients change, so a machine removed from the vault opens
//! nothing from the next statement on.

use heed::RoTxn;
#[cfg(feature = "sync")]
use heed::RwTxn;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::authority::AuthorityFold;
use crate::entity_id::EntityId;
#[cfg(feature = "sync")]
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

/// The most pairs one statement names. A machine that proves more names the first ones in record
/// order; the rest stay ungrouped elsewhere (one extra row each).
pub(crate) const SAME_VALUE_PAIRS_MAX: usize = 1024;
/// The most envelopes one statement carries: one per machine mine here.
#[cfg(feature = "sync")]
const SAME_VALUE_RECIPIENTS_MAX: usize = 256;
/// The longest hex text of one envelope a statement may carry: its pairs at the most, with room
/// for the envelope's header, capsule and tag.
const SEALED_HEX_MAX: usize =
    2 * (PAIRS_LABEL.len() + 4 + SAME_VALUE_PAIRS_MAX * PAIR_BYTES + 8192);
/// What the writer's machine key signs ahead of the statement's fields.
const STATEMENT_DOMAIN: &[u8] = b"oneiron/secret-custody/same-value/statement/v1";
/// The label every sealed list of pairs starts with, and the head of each envelope's key id.
const PAIRS_LABEL: &[u8] = b"oneiron/secret-custody/same-value/v1";
/// One pair as it is sealed: record a, its generation, record b, its generation.
const PAIR_BYTES: usize = 16 + 4 + 16 + 4;
#[cfg(feature = "sync")]
const ENVELOPE_EPOCH: u64 = 1;
#[cfg(feature = "sync")]
const AEAD: oneiron_crypto::SuiteId = oneiron_crypto::SuiteId::XCHACHA20POLY1305_V1;
#[cfg(feature = "sync")]
const KEM: oneiron_crypto::SuiteId = oneiron_crypto::SuiteId::KEM_X25519_MLKEM1024_V1;

/// Each writer's newest statement this install holds, with the pairs it opened from it. Key: the
/// writer's MACHINE row.
pub(super) const STATEMENTS: SideTable<EntityId, HeldSameValueStatement, Named> =
    SideTable::new(&side_table::SECRET_CUSTODY_SAME_VALUE);

/// Two custody records one machine proves hold one value, each at the generation it held then.
/// `a` sorts before `b`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct SameValuePair {
    pub(crate) a: EntityId,
    pub(crate) a_generation: u32,
    pub(crate) b: EntityId,
    pub(crate) b_generation: u32,
}

/// One machine's same-value statement as it travels and rests: its writer, the time it signed it,
/// one sealed list of its pairs per recipient machine, and the writer's signature over all of it.
/// Holds no value and no record id in the clear.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SameValueStatement {
    /// The machine that derived the pairs and signed the statement.
    pub(crate) writer: EntityId,
    /// When the writer signed it, on its recording clock: each statement of one writer is later
    /// than the one it replaces.
    pub(crate) issued_at: u64,
    /// The pairs sealed to each recipient, ordered by recipient, one each.
    pub(crate) envelopes: Vec<SameValueEnvelope>,
    /// The writer's machine signature over the statement's transcript, hex.
    pub(crate) signature: String,
}

/// The pairs of one statement sealed to one machine, as an E0 envelope in hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SameValueEnvelope {
    pub(crate) recipient: EntityId,
    pub(crate) sealed: String,
}

/// One writer's statement as this install keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HeldSameValueStatement {
    pub(crate) statement: SameValueStatement,
    /// The pairs this install read from it: its own, or the ones the envelope sealed to it opened
    /// to. `None` when no envelope was sealed to it or one did not open.
    pub(crate) opened: Option<Vec<SameValuePair>>,
}

/// Every pair this install opened from a statement whose writer's signature its fold still admits,
/// read in `txn`: what the owner's list groups records by beside its own proof. A table that does
/// not read groups nothing (a missed group costs one row).
pub(super) fn same_value_pairs_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    fold: &AuthorityFold,
) -> Vec<SameValuePair> {
    let Some(vault_id) = fold.vault_id else {
        return Vec::new();
    };
    let held = match STATEMENTS.scan(&vault.store, txn) {
        Ok(held) => held,
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "the same-value statements did not read; the list groups by its own proof alone"
            );
            return Vec::new();
        }
    };
    let mut pairs: Vec<SameValuePair> = held
        .into_iter()
        .filter(|(writer, held)| {
            *writer == held.statement.writer
                && signed_envelopes(fold, &vault_id, &held.statement).is_some()
        })
        .filter_map(|(_, held)| held.opened)
        .flatten()
        .collect();
    pairs.sort_unstable();
    pairs.dedup();
    pairs
}

/// The statement's envelopes as bytes, when its shape is bounded, its envelopes are ordered by
/// recipient with one each, and its writer's machine signs it as the fold admits that machine's
/// key: a live chain's install key, no chain removed, never a roster key
/// ([`super::leaf_delivery::machine_signed`]).
fn signed_envelopes(
    fold: &AuthorityFold,
    vault_id: &[u8; 32],
    statement: &SameValueStatement,
) -> Option<Vec<(EntityId, Vec<u8>)>> {
    let mut envelopes = Vec::with_capacity(statement.envelopes.len());
    for envelope in &statement.envelopes {
        if envelope.sealed.len() > SEALED_HEX_MAX {
            return None;
        }
        envelopes.push((
            envelope.recipient,
            oneiron_hex::decode_vec(&envelope.sealed)?,
        ));
    }
    if !envelopes.windows(2).all(|pair| pair[0].0 < pair[1].0) {
        return None;
    }
    let signature = oneiron_hex::decode_vec(&statement.signature)?;
    let transcript = transcript(vault_id, statement.writer, statement.issued_at, &envelopes);
    super::leaf_delivery::machine_signed(fold, statement.writer, &transcript, &signature)
        .then_some(envelopes)
}

/// What the writer's machine key signs: the domain, the vault, the writer, the time, then each
/// envelope with its recipient and length.
fn transcript(
    vault_id: &[u8; 32],
    writer: EntityId,
    issued_at: u64,
    envelopes: &[(EntityId, Vec<u8>)],
) -> Vec<u8> {
    let mut out = STATEMENT_DOMAIN.to_vec();
    out.extend_from_slice(vault_id);
    out.extend_from_slice(writer.as_bytes());
    out.extend_from_slice(&issued_at.to_be_bytes());
    out.extend_from_slice(
        &u32::try_from(envelopes.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for (recipient, sealed) in envelopes {
        out.extend_from_slice(recipient.as_bytes());
        out.extend_from_slice(
            &u64::try_from(sealed.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        out.extend_from_slice(sealed);
    }
    out
}

/// The key id each envelope of one statement binds: the label, the writer and the time.
#[cfg(feature = "sync")]
fn envelope_key_id(writer: EntityId, issued_at: u64) -> Vec<u8> {
    let mut out = PAIRS_LABEL.to_vec();
    out.extend_from_slice(writer.as_bytes());
    out.extend_from_slice(&issued_at.to_be_bytes());
    out
}

/// The pairs as they are sealed: the label, their count, then each pair.
#[cfg(feature = "sync")]
fn encode_pairs(pairs: &[SameValuePair]) -> Vec<u8> {
    let mut out = PAIRS_LABEL.to_vec();
    out.extend_from_slice(&u32::try_from(pairs.len()).unwrap_or(u32::MAX).to_be_bytes());
    for pair in pairs {
        out.extend_from_slice(pair.a.as_bytes());
        out.extend_from_slice(&pair.a_generation.to_be_bytes());
        out.extend_from_slice(pair.b.as_bytes());
        out.extend_from_slice(&pair.b_generation.to_be_bytes());
    }
    out
}

/// The pairs an opened envelope holds: `None` unless it starts with the label, its count matches
/// its length within the bound, and its pairs are ordered, each with `a` before `b`.
#[cfg(feature = "sync")]
fn decode_pairs(bytes: &[u8]) -> Option<Vec<SameValuePair>> {
    let rest = bytes.strip_prefix(PAIRS_LABEL)?;
    let (count, mut rest) = rest.split_first_chunk::<4>()?;
    let count = usize::try_from(u32::from_be_bytes(*count)).ok()?;
    if count > SAME_VALUE_PAIRS_MAX || rest.len() != count.checked_mul(PAIR_BYTES)? {
        return None;
    }
    let mut pairs = Vec::with_capacity(count);
    for _ in 0..count {
        let (a, after) = rest.split_first_chunk::<16>()?;
        let (a_generation, after) = after.split_first_chunk::<4>()?;
        let (b, after) = after.split_first_chunk::<16>()?;
        let (b_generation, after) = after.split_first_chunk::<4>()?;
        rest = after;
        let pair = SameValuePair {
            a: EntityId::from_bytes(*a).ok()?,
            a_generation: u32::from_be_bytes(*a_generation),
            b: EntityId::from_bytes(*b).ok()?,
            b_generation: u32::from_be_bytes(*b_generation),
        };
        if pair.a >= pair.b || pairs.last().is_some_and(|last| *last >= pair) {
            return None;
        }
        pairs.push(pair);
    }
    Some(pairs)
}

/// Every pair this install proves in `txn`, a custody snapshot: for each value two or more of its
/// live records hold at their current generations, the lowest record with each other one. A record
/// counts only when the fold proves it held at the generation it holds here, so a pair never names
/// a device-only record or one the other machines do not know of yet.
#[cfg(feature = "sync")]
fn proven_pairs_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    fold: &AuthorityFold,
) -> Result<Vec<SameValuePair>> {
    use crate::ports::EntityStoreRead;
    use crate::registry::ENTITY_TYPE_SECRET_CUSTODY;

    let held = fold.custody_held_generations();
    let mut printed = Vec::new();
    for entry in vault
        .store
        .port_entity_ids_by_type(txn, ENTITY_TYPE_SECRET_CUSTODY, None)?
    {
        let id = entry?;
        let Some(record) = super::read_secret_custody_meta_in_txn(&vault.store, txn, &id)? else {
            continue;
        };
        let generation = record.rotation_generation;
        if record.status != super::types::SecretCustodyStatus::Active
            || held.get(&id) != Some(&generation)
            || super::known_values::never_keyed(&record.name)
        {
            continue;
        }
        let print = match vault.store.known_entries_for_in_snapshot(txn, &id) {
            Ok(entries) => entries.and_then(|entries| {
                entries
                    .into_iter()
                    .find(|(at, _)| *at == generation)
                    .map(|(_, entry)| entry)
            }),
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a secret's known-value entry did not read; no same-value pair names it"
                );
                None
            }
        };
        if let Some(print) = print {
            printed.push((id, generation, print));
        }
    }
    printed.sort_by_key(|(id, _, _)| *id);
    let mut joined = vec![false; printed.len()];
    let mut pairs = Vec::new();
    for first in 0..printed.len() {
        if joined[first] {
            continue;
        }
        for other in first + 1..printed.len() {
            if !joined[other] && super::owner_list::same_value(&printed[first].2, &printed[other].2)
            {
                joined[other] = true;
                pairs.push(SameValuePair {
                    a: printed[first].0,
                    a_generation: printed[first].1,
                    b: printed[other].0,
                    b_generation: printed[other].1,
                });
            }
        }
    }
    pairs.truncate(SAME_VALUE_PAIRS_MAX);
    Ok(pairs)
}

/// Every machine mine here other than `this`, with the encryption key of its trusted identity,
/// ordered by machine: who a statement's pairs are sealed to. A profile whose key does not import
/// gets no envelope: it could open none.
#[cfg(feature = "sync")]
fn recipients(
    fold: &AuthorityFold,
    this: EntityId,
) -> Vec<(EntityId, oneiron_crypto::HybridPublicKey)> {
    let mut out = Vec::new();
    for id in fold.machines.keys() {
        if *id == this {
            continue;
        }
        let Some(trusted) = fold.trusted_machine(*id) else {
            continue;
        };
        let Ok(public) =
            oneiron_crypto::HybridPublicKey::from_bytes(&trusted.profile.encryption_key.key)
        else {
            continue;
        };
        out.push((*id, public));
    }
    out.truncate(SAME_VALUE_RECIPIENTS_MAX);
    out
}

/// `pairs` sealed to each of `recipients`, signed by `signing` as `writer`'s statement at
/// `issued_at`.
#[cfg(feature = "sync")]
fn sealed_statement(
    vault_id: &[u8; 32],
    writer: EntityId,
    issued_at: u64,
    pairs: &[SameValuePair],
    recipients: &[(EntityId, oneiron_crypto::HybridPublicKey)],
    signing: &ed25519_dalek::SigningKey,
) -> Result<SameValueStatement> {
    use ed25519_dalek::Signer;
    use oneiron_crypto::{Purpose, SealKey, SealParams, seal};

    let payload = zeroize::Zeroizing::new(encode_pairs(pairs));
    let key_id = envelope_key_id(writer, issued_at);
    let mut envelopes = Vec::with_capacity(recipients.len());
    for (machine, public) in recipients {
        let recipient = crate::authority::WrapRecipient::Machine(*machine).envelope_recipient();
        let params = SealParams {
            suite: AEAD,
            purpose: Purpose::SecretFile,
            epoch: ENVELOPE_EPOCH,
            key_id: &key_id,
            recipient: &recipient,
            vault_id,
        };
        let sealed = seal(
            &params,
            SealKey::Hybrid {
                recipient: public,
                kem_suite: KEM,
            },
            &payload,
            &mut getrandom::SysRng,
        )
        .map_err(|_| refused("sealing a same-value statement failed"))?
        .to_bytes();
        envelopes.push((*machine, sealed));
    }
    let signature = signing
        .sign(&transcript(vault_id, writer, issued_at, &envelopes))
        .to_bytes();
    Ok(SameValueStatement {
        writer,
        issued_at,
        envelopes: envelopes
            .into_iter()
            .map(|(recipient, sealed)| SameValueEnvelope {
                recipient,
                sealed: oneiron_hex::encode(&sealed),
            })
            .collect(),
        signature: oneiron_hex::encode(&signature),
    })
}

/// The pairs the envelope `envelopes` seal to `secret`'s machine open to, if one does.
#[cfg(feature = "sync")]
fn open_pairs(
    vault_id: &[u8; 32],
    statement: &SameValueStatement,
    envelopes: &[(EntityId, Vec<u8>)],
    secret: &crate::world_keys::MachineSecret,
) -> Option<Vec<SameValuePair>> {
    use oneiron_crypto::{Argon2Cost, Envelope, OpenKey, OpenPolicy, Purpose, WrapType};

    let (_, sealed) = envelopes
        .iter()
        .find(|(recipient, _)| *recipient == secret.machine)?;
    let envelope = Envelope::parse(sealed).ok()?;
    let recipient = crate::authority::WrapRecipient::Machine(secret.machine).envelope_recipient();
    let key_id = envelope_key_id(statement.writer, statement.issued_at);
    let policy = OpenPolicy {
        purpose: Purpose::SecretFile,
        vault_id,
        recipient: &recipient,
        key_id: &key_id,
        wraps: &[WrapType::HybridCapsule],
        aead_suites: &[AEAD],
        kem_suites: &[KEM],
        min_epoch: ENVELOPE_EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    let payload = envelope
        .open(OpenKey::Hybrid(&secret.secret), &policy)
        .ok()?;
    decode_pairs(&payload)
}

/// Whose statements a node takes in one merge.
#[cfg(feature = "sync")]
#[derive(Debug, Clone, Copy)]
enum StatementSource {
    /// The home's answer, on a machine: every writer's statement except this install's own.
    Home { this: EntityId },
    /// One proved machine's, at the home: the statement that machine signed as its writer.
    Machine { peer: EntityId },
}

#[cfg(feature = "sync")]
impl Vault {
    /// This install's statement, for its home: first brought up to the pairs it proves now and the
    /// machines mine here now, signed again only when either changed. `None` while this install
    /// serves no machine of the fold; an empty list while it proves no pair and never stated one.
    ///
    /// # Errors
    /// The store's, the fold's, the custody snapshot's and the machine key's.
    pub(crate) fn same_value_statements_written_here(
        &self,
    ) -> Result<Option<Vec<SameValueStatement>>> {
        let Some(this) = self.serving_machine_in_txn(&self.store.env.read_txn()?)? else {
            return Ok(None);
        };
        Ok(Some(
            self.refresh_own_same_value_statement(this)?
                .into_iter()
                .collect(),
        ))
    }

    /// Takes the statements of the home's answer: each one whose writer's signature this fold
    /// admits and that is later than the one held here from its writer replaces it, with the pairs
    /// the envelope sealed to this machine opens to. This install's own statement is never taken
    /// from the home. Returns how many statements changed here.
    ///
    /// # Errors
    /// The store's and the fold's.
    pub(crate) fn take_same_value_statements(
        &self,
        statements: Vec<SameValueStatement>,
    ) -> Result<usize> {
        let Some(this) = self.serving_machine_in_txn(&self.store.env.read_txn()?)? else {
            return Ok(0);
        };
        // The keystore is read before any transaction opens.
        let secret = self.machine_secret_outside_txn().ok();
        self.with_write_txn_grouped(|txn| {
            merge_statements_in_txn(
                self,
                txn,
                StatementSource::Home { this },
                secret.as_ref(),
                statements,
            )
        })
    }

    /// The home's half of `residence.secret_same_value.exchange`, for `peer`, a machine of the
    /// owner's its socket proved: keeps each statement `peer` signed as its writer that is later
    /// than the one held here from `peer`, then answers every statement held here whose writer's
    /// signature this fold admits, this home's own first brought up to the pairs it proves now.
    ///
    /// # Errors
    /// The store's and the fold's.
    pub(crate) fn exchange_same_value_statements_at_home(
        &self,
        peer: EntityId,
        statements: Vec<SameValueStatement>,
    ) -> Result<Vec<SameValueStatement>> {
        if let Some(this) = self.serving_machine_in_txn(&self.store.env.read_txn()?)?
            && let Err(error) = self.refresh_own_same_value_statement(this)
        {
            tracing::debug!(%error, "this home's own same-value statement was not refreshed");
        }
        let secret = self.machine_secret_outside_txn().ok();
        self.with_write_txn_grouped(|txn| {
            merge_statements_in_txn(
                self,
                txn,
                StatementSource::Machine { peer },
                secret.as_ref(),
                statements,
            )
        })?;
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let Some(vault_id) = fold.vault_id else {
            return Ok(Vec::new());
        };
        Ok(STATEMENTS
            .scan(&self.store, &txn)?
            .into_iter()
            .filter(|(writer, held)| {
                *writer == held.statement.writer
                    && signed_envelopes(&fold, &vault_id, &held.statement).is_some()
            })
            .map(|(_, held)| held.statement)
            .collect())
    }

    /// Brings this install's own statement up to the pairs it proves now, sealed to the machines
    /// mine here now: the held one when both are unchanged and it still verifies, else a new one
    /// signed past it. `None` while it proves no pair and never stated one, or the vault has no
    /// authority genesis.
    fn refresh_own_same_value_statement(
        &self,
        this: EntityId,
    ) -> Result<Option<SameValueStatement>> {
        let (vault_id, pairs, recipients) = {
            let snapshot = self.store.custody_snapshot()?;
            let txn: &RoTxn<'_> = &snapshot;
            let fold = self.authority_view_readonly_in_txn(txn)?;
            let Some(vault_id) = fold.vault_id else {
                return Ok(None);
            };
            let pairs = proven_pairs_in_txn(self, txn, &fold)?;
            (vault_id, pairs, recipients(&fold, this))
        };
        self.with_write_txn_grouped(|txn| {
            let held = STATEMENTS.get(&self.store, txn, &this)?;
            let fold = self.authority_view_readonly_in_txn(txn)?;
            if let Some(held) = &held {
                let same_recipients = held
                    .statement
                    .envelopes
                    .iter()
                    .map(|envelope| envelope.recipient)
                    .eq(recipients.iter().map(|(machine, _)| *machine));
                if same_recipients
                    && held.opened.as_deref() == Some(&pairs[..])
                    && signed_envelopes(&fold, &vault_id, &held.statement).is_some()
                {
                    return Ok(Some(held.statement.clone()));
                }
            } else if pairs.is_empty() {
                return Ok(None);
            }
            let (machine, signing) = crate::identity::machine_signer_in_txn(self, txn)?;
            if machine != this {
                return Err(refused(
                    "this install's machine key is not its serving machine's",
                ));
            }
            let issued_at =
                issued_at_past_in_txn(self, txn, held.map(|held| held.statement.issued_at))?;
            let statement =
                sealed_statement(&vault_id, this, issued_at, &pairs, &recipients, &signing)?;
            STATEMENTS.put(
                &self.store,
                txn,
                &this,
                &HeldSameValueStatement {
                    statement: statement.clone(),
                    opened: Some(pairs),
                },
            )?;
            Ok(Some(statement))
        })
    }
}

/// The time a writer signs a statement at: its recording clock, observed in `txn`, or one past
/// `held`, the time of the statement it replaces, when the clock is not past it.
#[cfg(feature = "sync")]
fn issued_at_past_in_txn(vault: &Vault, txn: &mut RwTxn<'_>, held: Option<u64>) -> Result<u64> {
    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    Ok(held.map_or(now, |held| now.max(held.saturating_add(1))))
}

/// Merges `statements` from `source` in `txn`; returns how many statements changed.
#[cfg(feature = "sync")]
fn merge_statements_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    source: StatementSource,
    secret: Option<&crate::world_keys::MachineSecret>,
    statements: Vec<SameValueStatement>,
) -> Result<usize> {
    let fold = vault.authority_view_readonly_in_txn(txn)?;
    let Some(vault_id) = fold.vault_id else {
        return Ok(0);
    };
    let mut changed = 0;
    for statement in statements {
        let admitted = match source {
            StatementSource::Home { this } => statement.writer != this,
            StatementSource::Machine { peer } => statement.writer == peer,
        };
        if !admitted || statement.envelopes.len() > SAME_VALUE_RECIPIENTS_MAX {
            continue;
        }
        let Some(envelopes) = signed_envelopes(&fold, &vault_id, &statement) else {
            continue;
        };
        let held = STATEMENTS.get(&vault.store, txn, &statement.writer)?;
        if held.is_some_and(|held| held.statement.issued_at >= statement.issued_at) {
            continue;
        }
        let opened =
            secret.and_then(|secret| open_pairs(&vault_id, &statement, &envelopes, secret));
        STATEMENTS.put(
            &vault.store,
            txn,
            &statement.writer,
            &HeldSameValueStatement {
                statement: statement.clone(),
                opened,
            },
        )?;
        changed += 1;
    }
    Ok(changed)
}

#[cfg(feature = "sync")]
fn refused(reason: &'static str) -> crate::Error {
    crate::Error::InvalidConfig(format!("same-value statement not signed: {reason}"))
}

/// The statement this install holds from `writer`, read in `txn`.
///
/// # Errors
/// The store's.
#[cfg(oneiron_test_support)]
pub(crate) fn same_value_statement_held_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    writer: EntityId,
) -> crate::error::Result<Option<HeldSameValueStatement>> {
    STATEMENTS.get(&vault.store, txn, &writer)
}

/// `statement` signed by `signing` in place of its writer's key, its writer kept and its time one
/// past: a statement no fold should admit.
#[cfg(oneiron_test_support)]
pub(crate) fn same_value_statement_signed_by(
    fold: &AuthorityFold,
    statement: &SameValueStatement,
    signing: &ed25519_dalek::SigningKey,
) -> SameValueStatement {
    use ed25519_dalek::Signer;

    let mut signed = statement.clone();
    signed.issued_at = statement.issued_at.saturating_add(1);
    let envelopes: Vec<(EntityId, Vec<u8>)> = signed
        .envelopes
        .iter()
        .map(|envelope| {
            (
                envelope.recipient,
                oneiron_hex::decode_vec(&envelope.sealed).unwrap_or_default(),
            )
        })
        .collect();
    let vault_id = fold.vault_id.unwrap_or_default();
    let signature = signing.sign(&transcript(
        &vault_id,
        signed.writer,
        signed.issued_at,
        &envelopes,
    ));
    signed.signature = oneiron_hex::encode(&signature.to_bytes());
    signed
}
