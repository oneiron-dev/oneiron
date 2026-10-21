//! Run-bound custody (FIX 8028, OF-560; ARCH-0069 secret custody): a secret
//! a run's browser or desktop finds becomes a custody record bound to that
//! run where it is found, and its handle is the record's `scN` short id.
//!
//! A run-bound record is an ordinary active custody record, its value sealed
//! under its own custody key, device-bound and never portable. It carries one
//! binding: the effector of the run's seat that found it
//! (`browser-run:<run>`, `desktop-run:<run>`), with `read`, up to T1, so the
//! reveal check reads it as it reads any found secret. Its name places it
//! under its run (`<seat>-run/<run>/<record>`). The known-value index never
//! keys it: with [`super::KNOWN_VALUE_MIN_BYTES`] at one byte, a found
//! three-digit code would otherwise mask every copy of those digits in the
//! vault. When the run's seat ends, every record it found is hard-erased
//! ([`Vault::erase_run_secrets`]): the record and its sealed value, its short
//! id and its name. Revoking would keep them.
//!
//! The run's own seat is the one trusted consumer
//! ([`Vault::with_run_secret`]): the record must be live and bound to that
//! run; its bytes go to the seat's closure alone, with no transaction held,
//! and every use the handle resolves for writes one value-free Gate use
//! record. Each mint writes one value-free Gate record of where the secret
//! was found.
//!
//! The model reads a run-bound value only through `reveal`, its one check
//! and its receipt, as any found secret's: the record is active, device-bound
//! (the floor's default band reaches T1) and its one binding reaches T1. A
//! reveal is tied to the run that found the record
//! ([`reveal_run_admission`]): an asker another run binds is refused before
//! the check; one no run binds takes the check alone.

use zeroize::Zeroizing;

use super::doors::{
    CustodyWrite, NAME_INDEX, read_secret_custody_admission_in_txn, register_custody_in_txn,
};
use super::types::{
    CustodyClass, CustodyTier, SECRET_CUSTODY_SCHEMA_VERSION, SECRET_SCOPE_READ, SecretBinding,
    SecretCustodyFloor, SecretCustodyRecord, SecretCustodyStatus,
};
use super::use_handle::{SECRET_USE_REASON, handle_record_in_txn};
use crate::AttemptId;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SecretError};
use crate::ports::ShortIdStoreRead;
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord, Store};
use crate::vault::Vault;

/// The Gate reason code of the record each run-bound mint writes.
pub const RUN_SECRET_FOUND_REASON: &str = "gate.secret.found";

/// The Gate content kind of a run-bound mint's record.
const FOUND_CONTENT_KIND: &str = "secret_found";

/// The Gate content kind of a run-bound use's record, as every use's.
const USE_CONTENT_KIND: &str = "secret_use";

/// Domain of a run-bound record's diff handle: a digest of what was found
/// or used, and by what, never of the value.
const RUN_DIFF_DOMAIN: &[u8] = b"oneiron.secret_run.v1";

/// Every seat a run-bound record's name can start with.
const RUN_SEATS: [RunSecretSeat; 2] = [RunSecretSeat::Browser, RunSecretSeat::Desktop];

/// The seat of a run that found a secret: its browser or its desktop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunSecretSeat {
    Browser,
    Desktop,
}

impl RunSecretSeat {
    /// The seat's word in its records' names and effector.
    const fn word(self) -> &'static str {
        match self {
            Self::Browser => "browser-run",
            Self::Desktop => "desktop-run",
        }
    }

    /// What every run-bound record name of `run` on this seat starts with.
    fn names(self, run: &EntityId) -> String {
        format!("{}/{}/", self.word(), run.to_hex())
    }

    /// The effector the one binding of a run-bound record of `run` on this
    /// seat names: only that seat of that run reads it.
    fn effector(self, run: &EntityId) -> String {
        format!("{}:{}", self.word(), run.to_hex())
    }
}

/// Who holds a run-bound secret: the run whose seat found it, that seat,
/// and the verified actor the run's call acts for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunSecretHolder {
    pub run: EntityId,
    pub seat: RunSecretSeat,
    pub actor: EntityId,
    pub actor_class: EdgeActorClass,
}

/// Whether `name` is a run-bound record's: the known-value index never
/// keys one.
pub(crate) fn is_run_bound_name(name: &str) -> bool {
    RUN_SEATS.iter().any(|seat| {
        name.strip_prefix(seat.word())
            .is_some_and(|rest| rest.starts_with('/'))
    })
}

/// Whether a reveal of the custody record named `name` (handle `handle`) by
/// an asker whose run holds the leased try `attempt` goes on to the one
/// reveal check (`reveal_run_tie`, CALLS row; FIX 8028). A record that is
/// not run-bound does, as before; a run-bound one does for the run that
/// found it (its executor run is that try), and for an asker no run binds,
/// whose reveal the check alone decides. The seat's end erases the record,
/// so a reveal asked after it finds nothing.
///
/// # Errors
/// [`SecretError::SecretBindingDenied`], naming the effector the asking run
/// would need, for an asker bound to another run.
pub(crate) fn reveal_run_admission(
    name: &str,
    handle: &str,
    attempt: Option<&AttemptId>,
) -> Result<()> {
    let Some(attempt) = attempt else {
        return Ok(());
    };
    let Some(seat) = RUN_SEATS.into_iter().find(|seat| {
        name.strip_prefix(seat.word())
            .is_some_and(|rest| rest.starts_with('/'))
    }) else {
        return Ok(());
    };
    let asking = EntityId::from_bytes(*attempt.as_bytes()).ok();
    if asking.is_some_and(|asking| name.starts_with(&seat.names(&asking))) {
        return Ok(());
    }
    let effector = asking.map_or_else(|| seat.word().to_owned(), |run| seat.effector(&run));
    Err(Error::Secret(SecretError::SecretBindingDenied {
        effector,
        secret_ref: handle.to_owned(),
    }))
}

impl Vault {
    /// Takes `value`, a secret of `kind` (`card`, `cvv`, `otp`, `password`)
    /// that `holder`'s seat found at `provenance` (its page's origin, or
    /// its window), into custody bound to `holder`'s run: the record and
    /// its handle (`scN`). The value is sealed under the record's own
    /// custody key and kept out of the known-value index; the run's seat's
    /// end erases it.
    ///
    /// # Errors
    /// An empty value; custody and storage faults.
    pub fn mint_run_secret(
        &self,
        holder: &RunSecretHolder,
        kind: &str,
        value: &[u8],
        provenance: &str,
    ) -> Result<(EntityId, String)> {
        if value.is_empty() {
            return Err(Error::Secret(SecretError::InvalidSecretCustodyBody(
                "a run-bound secret holds a value",
            )));
        }
        let write = CustodyWrite::of(self);
        let mut value = Zeroizing::new(value.to_vec());
        self.with_write_txn(|wtxn| {
            let floor = SecretCustodyFloor::resolve(&self.store, &*wtxn)?;
            let id = self.store.clock.entity_id()?;
            let mut rec = SecretCustodyRecord {
                schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
                name: format!("{}{}", holder.seat.names(&holder.run), id.to_hex()),
                class: CustodyClass::CustodyDeviceBound,
                device_only: true,
                value_bytes: std::mem::take(&mut *value),
                status: SecretCustodyStatus::Active,
                registered_at: self.store.clock.now_recorded_at(),
                rotated_at: None,
                rotation_generation: 0,
                bindings: vec![SecretBinding {
                    effector: holder.seat.effector(&holder.run),
                    tier_ceiling: CustodyTier::T1Leased,
                    scopes: vec![SECRET_SCOPE_READ.to_owned()],
                }],
                manifest_ref: String::new(),
                declared_paths: Vec::new(),
                policy_floor_snapshot: floor,
            };
            let registered = register_custody_in_txn(&write, wtxn, &id, &mut rec);
            // The value goes back to a wiping owner whatever the door did.
            *value = std::mem::take(&mut rec.value_bytes);
            registered?;
            let handle = self
                .store
                .port_short_id_reference(&*wtxn, &id)?
                .map(|(short_id, _)| short_id)
                .ok_or(Error::InvariantViolation(
                    "a run-bound secret's record has no handle",
                ))?;
            let details = vec![
                format!("found:{kind}"),
                format!("handle:{handle}"),
                format!("run:{}", holder.run.to_hex()),
                format!("seat:{}", holder.seat.word()),
                format!("origin:{provenance}"),
            ];
            let gate = RunRecord {
                holder,
                secret: &id,
                what: kind,
            };
            gate.append_in_txn(&self.store, wtxn, Found::Minted, details)?;
            Ok((id, handle))
        })
    }

    /// Lends the bytes run-bound `handle` holds to `use_`, the run's own
    /// seat's `operation` (its type or check, `browser.secret`): only a live
    /// record `holder`'s run's seat found, through the bound value door,
    /// with no transaction held while `use_` runs. Every use the handle
    /// resolves for writes one value-free Gate use record, refused or not.
    ///
    /// # Errors
    /// A handle that names no record; a record not this run's seat's, not
    /// active, or past the live floor; `use_`'s own error; storage faults.
    pub fn with_run_secret(
        &self,
        holder: &RunSecretHolder,
        handle: &str,
        operation: &str,
        use_: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        let (short, id, name) = {
            let txn = self.store.env.read_txn()?;
            let (short, id) = handle_record_in_txn(&self.store, &txn, handle)?;
            let held = read_secret_custody_admission_in_txn(&self.store, &txn, &id)?;
            (short, id, held.map(|held| held.name))
        };
        let effector = holder.seat.effector(&holder.run);
        let gate = RunRecord {
            holder,
            secret: &id,
            what: operation,
        };
        let details = |decision: &str| {
            vec![
                format!("use:{operation}"),
                format!("handle:{short}"),
                format!("effector:{effector}"),
                format!("decision:{decision}"),
            ]
        };
        let owned = name
            .as_deref()
            .is_some_and(|name| name.starts_with(&holder.seat.names(&holder.run)));
        if !owned {
            gate.append(self, Found::Refused, details("refused"))?;
            return Err(Error::Secret(SecretError::SecretBindingDenied {
                effector,
                secret_ref: short,
            }));
        }
        let used = self.inject_secret_record_at_door(&id, &effector, use_);
        let decision = if used.is_ok() {
            Found::Used
        } else {
            Found::Refused
        };
        gate.append(self, decision, details(decision.word()))?;
        used.map(drop)
    }

    /// Hard-erases every run-bound record `run`'s `seat` found, as the seat
    /// ends: each record and its sealed value, its short id and its name,
    /// in one transaction. The count erased.
    ///
    /// # Errors
    /// A legal hold on a record; storage faults. Nothing is erased then.
    pub fn erase_run_secrets(&self, seat: RunSecretSeat, run: EntityId) -> Result<usize> {
        let prefix = seat.names(&run);
        self.with_write_txn(|wtxn| {
            let held = NAME_INDEX.scan_from(&self.store, &*wtxn, prefix.as_bytes())?;
            for (name, entry) in &held {
                crate::batch::deindex_entity(&self.store, wtxn, &entry.id)?;
                // A run-bound name names its one record and is never
                // reclaimed: its high-water goes with it.
                NAME_INDEX.delete(&self.store, wtxn, name)?;
            }
            Ok(held.len())
        })
    }
}

/// What a run-bound Gate record says happened.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Found {
    Minted,
    Used,
    Refused,
}

impl Found {
    const fn word(self) -> &'static str {
        match self {
            Self::Minted => "minted",
            Self::Used => "used",
            Self::Refused => "refused",
        }
    }
}

/// One run-bound Gate record: whose secret, which record, and what was
/// found (its kind) or done (the operation).
struct RunRecord<'a> {
    holder: &'a RunSecretHolder,
    secret: &'a EntityId,
    what: &'a str,
}

impl RunRecord<'_> {
    /// Appends the record in a write of its own: the host's door, as the
    /// guest that asked holds its seat while it waits.
    fn append(&self, vault: &Vault, found: Found, details: Vec<String>) -> Result<()> {
        vault.with_write_txn(|wtxn| self.append_in_txn(&vault.store, wtxn, found, details))
    }

    /// Appends the record in the caller's writer: its outcome, reason and
    /// kind, the actor, and a digest of the record, run, seat and what was
    /// found or done, never of the value.
    fn append_in_txn(
        &self,
        store: &Store,
        wtxn: &mut heed::RwTxn<'_>,
        found: Found,
        details: Vec<String>,
    ) -> Result<()> {
        let (reason, kind) = match found {
            Found::Minted => (RUN_SECRET_FOUND_REASON, FOUND_CONTENT_KIND),
            Found::Used | Found::Refused => (SECRET_USE_REASON, USE_CONTENT_KIND),
        };
        let parts: [&[u8]; 5] = [
            RUN_DIFF_DOMAIN,
            self.secret.as_bytes(),
            self.holder.run.as_bytes(),
            self.holder.seat.word().as_bytes(),
            self.what.as_bytes(),
        ];
        let mut digest = blake3::Hasher::new();
        for part in parts {
            digest.update(&(part.len() as u64).to_be_bytes());
            digest.update(part);
        }
        let record = GateDecisionRecord {
            version: GATE_DECISION_LEDGER_VERSION,
            decision_id: GateDecisionId::from_bytes(store.clock.ulid()?),
            created_at: crate::ports::recorded_at_in_txn(store, wtxn)?,
            outcome: match found {
                Found::Minted | Found::Used => "approved",
                Found::Refused => "denied",
            }
            .into(),
            reason_codes: vec![reason.into()],
            receipt_reasons: Vec::new(),
            system_notices: crate::store::GateSystemNoticeRecord::receipt_details(kind, details),
            actor_class: self.holder.actor_class.gate_actor_class().into(),
            actor_ref: Some(self.holder.actor.to_hex()),
            content_kind: kind.into(),
            policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.into(),
            claim_id: None,
            grant_ref: None,
            diff_handle: digest.finalize().as_bytes().to_vec(),
            read_frontier_hash: [0; 32],
            redacted_at: None,
        };
        store.append_gate_decision_in_txn(wtxn, &record)
    }
}
