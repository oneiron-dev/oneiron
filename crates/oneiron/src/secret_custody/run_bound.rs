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
//! A `self.use` of the run's own leased try reaches the run's records too
//! (FIX 8334): every operation, a connector call's send included, presents
//! one through the seat's existing binding ([`Vault::with_run_secret_for`])
//! under the operation effector's own door policy. No other binding is
//! added, and a record another run found stays refused.
//!
//! The model reads a run-bound value only through `reveal`, its one check
//! and its receipt, as any found secret's: the record is active, device-bound
//! (the floor's default band reaches T1) and its one binding reaches T1. A
//! reveal is tied to the run that found the record
//! ([`reveal_run_admission`]): an asker another run binds is refused before
//! the check; one no run binds takes the check alone.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::doors::{
    CustodyWrite, NAME_INDEX, read_secret_custody_admission_in_txn, register_custody_in_txn,
};
use super::reveal::{SecretRevealCause, close_secret_reveals_in_txn};
use super::types::{
    CustodyClass, CustodyTier, SECRET_CUSTODY_SCHEMA_VERSION, SECRET_SCOPE_READ, SecretBinding,
    SecretCustodyFloor, SecretCustodyRecord, SecretCustodyStatus,
};
use super::use_handle::{SECRET_USE_REASON, handle_record_in_txn};
use crate::AttemptId;
use crate::credential_door::admit_materialization_in_txn;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SecretError};
use crate::ports::ShortIdStoreRead;
use crate::secret_lease::DoorInjectionReceipt;
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
/// and the verified actor the run's call acts for. Ids only, so a held
/// connector call's row keeps it (FIX 2822).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunSecretHolder {
    pub run: EntityId,
    pub seat: RunSecretSeat,
    pub actor: EntityId,
    #[serde(with = "actor_class_byte")]
    pub actor_class: EdgeActorClass,
}

/// An actor class kept in a row as its byte, as the edge codecs keep it.
pub(crate) mod actor_class_byte {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::edge::EdgeActorClass;

    pub(crate) fn serialize<S: Serializer>(
        class: &EdgeActorClass,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(*class as u8)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<EdgeActorClass, D::Error> {
        let byte = u8::deserialize(deserializer)?;
        EdgeActorClass::try_from_u8(byte)
            .ok_or_else(|| serde::de::Error::custom("an unknown actor class byte"))
    }
}

impl RunSecretHolder {
    /// The holder of run-bound `name` for `actor` in `run`: the seat of
    /// `run` that found it (FIX 8334). `None` for a name no seat of `run`
    /// found, another run's included.
    pub(crate) fn of_found(
        name: &str,
        run: EntityId,
        actor: EntityId,
        actor_class: EdgeActorClass,
    ) -> Option<Self> {
        run_secret_seat(name, &run).map(|seat| Self {
            run,
            seat,
            actor,
            actor_class,
        })
    }
}

/// The seat of `run` that found run-bound `name`, if one did.
fn run_secret_seat(name: &str, run: &EntityId) -> Option<RunSecretSeat> {
    RUN_SEATS
        .into_iter()
        .find(|seat| name.starts_with(&seat.names(run)))
}

/// The seat effector run-bound `name` of `run` is bound to: its one
/// binding, `browser-run:<run>` or `desktop-run:<run>` (FIX 8334). `None`
/// for a name no seat of `run` found.
pub(crate) fn run_secret_effector(name: &str, run: &EntityId) -> Option<String> {
    run_secret_seat(name, run).map(|seat| seat.effector(run))
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

    /// Lends the bytes run-bound `handle` holds to `use_`, a `self.use`
    /// operation's send for `effector` (FIX 8334): only a live record
    /// `holder`'s run's seat found, through that seat's existing binding,
    /// and only while `effector`'s own door policy admits it, with no
    /// transaction held while `use_` runs. No binding is added. The use that
    /// calls it writes the use's records.
    ///
    /// # Errors
    /// [`SecretError::SecretBindingDenied`] for a record not this run's
    /// seat's; a handle that names no record; the door policy's, the
    /// floor's and the bound door's refusals; `use_`'s own error; storage
    /// faults.
    pub fn with_run_secret_for(
        &self,
        holder: &RunSecretHolder,
        handle: &str,
        effector: &str,
        use_: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<DoorInjectionReceipt> {
        let id = {
            let txn = self.store.env.read_txn()?;
            let (short, id) = handle_record_in_txn(&self.store, &txn, handle)?;
            let held = read_secret_custody_admission_in_txn(&self.store, &txn, &id)?;
            let owned = held
                .as_ref()
                .is_some_and(|held| held.name.starts_with(&holder.seat.names(&holder.run)));
            if !owned {
                return Err(Error::Secret(SecretError::SecretBindingDenied {
                    effector: effector.to_owned(),
                    secret_ref: short,
                }));
            }
            admit_materialization_in_txn(&self.store, &txn, effector, None)?;
            id
        };
        self.inject_secret_record_at_door(&id, &holder.seat.effector(&holder.run), use_)
    }

    /// Whether a `self.use` for `effector` of run-bound `name`, which
    /// `holder`'s run found, is admitted (FIX 8334): the seat's own binding
    /// at the door, and `effector`'s door policy. Value-free.
    ///
    /// # Errors
    /// The door's refusals, as [`Vault::check_secret_at_door`]'s.
    pub(crate) fn check_run_secret_at_door(
        &self,
        holder: &RunSecretHolder,
        name: &str,
        effector: &str,
    ) -> Result<()> {
        let txn = self.store.env.read_txn()?;
        self.check_secret_at_door_in_txn(&txn, name, &holder.seat.effector(&holder.run))?;
        admit_materialization_in_txn(&self.store, &txn, effector, None)
    }

    /// Hard-erases every run-bound record `run`'s `seat` found, as the seat
    /// ends: each record and its sealed value, its short id and its name,
    /// in one transaction, each fenced and every key its id names staged to
    /// retire before its row goes, then retired after the commit (KS-6 part
    /// 2, FIX 8332). The count erased.
    ///
    /// # Errors
    /// A legal hold on a record; storage faults. Nothing is erased then.
    pub fn erase_run_secrets(&self, seat: RunSecretSeat, run: EntityId) -> Result<usize> {
        let prefix = seat.names(&run);
        let erased = self.with_write_txn(|wtxn| {
            let held = NAME_INDEX.scan_from(&self.store, &*wtxn, prefix.as_bytes())?;
            for (name, entry) in &held {
                self.fence_credential_in_txn(wtxn, &entry.id);
                // Its asks close with a named cause, in this same writer
                // (FIX 8350).
                close_secret_reveals_in_txn(
                    self,
                    wtxn,
                    &entry.id,
                    SecretRevealCause::RunSeatEnded,
                )?;
                crate::batch::deindex_entity(&self.store, wtxn, &entry.id)?;
                // A run-bound name names its one record and is never
                // reclaimed: its high-water goes with it.
                NAME_INDEX.delete(&self.store, wtxn, name)?;
            }
            Ok(held.len())
        })?;
        if erased > 0 {
            self.finish_credential_retirements_after_commit();
        }
        Ok(erased)
    }

    /// Hard-erases every run-bound record every run's seat left behind, as
    /// the host starts: no run guest outlives a restart, so a host that
    /// stopped mid-run leaves its `browser-run/` and `desktop-run/` names
    /// behind (FIX 8335). Each record and its sealed value, its short id
    /// and its name, in one transaction, each fenced and every key its id
    /// names staged to retire before its row goes, then retired after the
    /// commit. The count erased.
    ///
    /// # Errors
    /// A legal hold on a record; storage faults. Nothing is erased then.
    pub fn erase_all_run_secrets(&self) -> Result<usize> {
        let erased = self.with_write_txn(|wtxn| {
            let mut erased = 0;
            for seat in RUN_SEATS {
                let prefix = format!("{}/", seat.word());
                let held = NAME_INDEX.scan_from(&self.store, &*wtxn, prefix.as_bytes())?;
                for (name, entry) in &held {
                    self.fence_credential_in_txn(wtxn, &entry.id);
                    // Its asks close with a named cause, in this same writer
                    // (FIX 8350).
                    close_secret_reveals_in_txn(
                        self,
                        wtxn,
                        &entry.id,
                        SecretRevealCause::RunSeatEnded,
                    )?;
                    crate::batch::deindex_entity(&self.store, wtxn, &entry.id)?;
                    // A run-bound name names its one record and is never
                    // reclaimed: its high-water goes with it.
                    NAME_INDEX.delete(&self.store, wtxn, name)?;
                }
                erased += held.len();
            }
            Ok(erased)
        })?;
        if erased > 0 {
            self.finish_credential_retirements_after_commit();
        }
        Ok(erased)
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
            context: Default::default(),
            redacted_at: None,
        };
        store.append_gate_decision_in_txn(wtxn, &record)
    }
}
