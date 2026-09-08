//! CredentialDoorService: admission, lease tickets, one-shot redemption, witnesses.

use std::net::IpAddr;
use std::sync::Arc;

use super::door_credential::DoorCredential;
use super::door_policy::{DoorEffector, DoorPolicy, PolicyFloors};
use super::door_types::{
    CredentialDoorError, DOOR_MAX_OID_BYTES, DOOR_MAX_PATH_BYTES, DOOR_ONE_SHOT_MAX_LIFETIME_SECS,
    DOOR_RECEIVE_PACK_EFFECTOR, DOOR_VERB_INJECT, DOOR_VERB_LEASE, DOOR_VERB_RECEIVE_PACK,
    DOOR_VERB_REDEEM, DoorDenyReason, DoorResult, DoorScanVerdict, PushedBlob, SecretLiftProposal,
    TtlCeiling, UNUSABLE_PATH, custody, log_unreachable, repo_record,
};
use crate::batch::secret_scan::scan_file_content;
use crate::codebase::RepoRef;
use crate::secret_lease::{DoorInjectionReceipt, SecretLeaseMaterialization, VaultInstant};
use crate::store::Store;
use crate::vault::Vault;

#[cfg(test)]
use super::authority_log_fault_hook;
#[cfg(test)]
use super::scan_fault_hook;

/// Why the re-admission taken INSIDE the stamping transaction refused a scope
/// the door had already admitted at its own read.
///
/// A named constant because the two refusals are otherwise spelled the same:
/// the regression that proves this check runs in the write transaction, and not
/// merely at the door, has to be able to tell which one answered.
pub(crate) const STAMP_SCOPE_REFUSAL: &str =
    "the stamping transaction's dial no longer admits this scope";

/// PROOF that one door effector was admitted, and the authority it was admitted
/// under.
///
/// The door's scope check PRODUCES this; everything after it CONSUMES it. The
/// evaluator takes its channel argument from here rather than from the caller's
/// string, the TTL ceiling is computed from the floors recorded here, the
/// absolute bound is derived from the instant recorded here, and the stamping
/// transaction re-derives the dial to compare against the one recorded here.
///
/// Fields are private and [`AdmittedScope::admit`] is the only constructor, so
/// an admission cannot be assembled after the fact out of a dial, an effector
/// and an instant that never met — which is precisely what the three loose
/// arguments this replaces allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdmittedScope {
    effector: DoorEffector,
    policy: DoorPolicy,
    at: VaultInstant,
}

impl AdmittedScope {
    /// The door's scope check, and the ONLY way to obtain the proof: the
    /// effector must be one this door knows AND one the resolved dial still
    /// admits. An empty effector fails the first half, so there is no unscoped
    /// door operation to construct.
    fn admit(policy: DoorPolicy, effector: &str, at: VaultInstant) -> DoorResult<Self> {
        let admitted = DoorEffector::parse(effector)
            .filter(|proved| policy.dial.admits(*proved))
            .ok_or_else(|| CredentialDoorError::LeaseScopeRefused {
                effector: effector.to_owned(),
                reason: "not a door effector the resolved dial admits",
            })?;
        Ok(Self {
            effector: admitted,
            policy,
            at,
        })
    }

    /// The PROVED effector. Door operations bind their scope to this, never to
    /// the string the caller handed in.
    pub(crate) fn effector(&self) -> DoorEffector {
        self.effector
    }

    /// The single vault reading this operation authorizes and stamps under.
    pub(crate) fn instant(&self) -> VaultInstant {
        self.at
    }

    /// The floors the scope was admitted under.
    pub(crate) fn floors(&self) -> PolicyFloors {
        self.policy.floors
    }

    /// The effective lease ceiling under THIS admission — the floors, the
    /// slip's attenuation and its remaining validity, all against the one
    /// instant the proof carries. There is no way to compute a ceiling from a
    /// dial and an instant that were not admitted together.
    fn effective_ttl_ceiling(&self, credential: &DoorCredential) -> TtlCeiling {
        self.policy.effective_ttl_ceiling(credential, self.at)
    }
}

impl AdmittedScope {
    /// Sizes a lease against this scope, yielding the ONE admission shape that
    /// reaches the stamping operation. Consumes the scope by value: a proof
    /// spends into exactly one ticket.
    pub(super) fn into_lease(
        self,
        secret_ref: &str,
        ttl_secs: u64,
        not_after: VaultInstant,
    ) -> AdmittedLease {
        AdmittedLease {
            scope: self,
            secret_ref: secret_ref.to_owned(),
            ttl_secs,
            not_after,
        }
    }
}

/// The ONE admission shape that reaches the stamping operation.
///
/// [`Vault::materialize_admitted_lease`] takes this and nothing else — no raw
/// `max_lease_ttl_secs`, no caller-supplied effector string, no loose `now`,
/// and no separately-computed bound. Everything the stamp needs travelled
/// together, was admitted together, and can be checked together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdmittedLease {
    scope: AdmittedScope,
    secret_ref: String,
    ttl_secs: u64,
    not_after: VaultInstant,
}

impl AdmittedLease {
    /// The named secret the credential was evaluated against.
    pub(crate) fn secret_ref(&self) -> &str {
        &self.secret_ref
    }

    /// The admitted scope's effector CONSTANT.
    pub(crate) fn effector(&self) -> &'static str {
        self.scope.effector.as_str()
    }

    /// The requested TTL the ceiling admitted.
    pub(crate) fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    /// The witnessed instant this lease authorizes and stamps under.
    pub(crate) fn instant(&self) -> VaultInstant {
        self.scope.at
    }

    /// The absolute instant the authority that bought this lease dies at.
    pub(crate) fn not_after(&self) -> VaultInstant {
        self.not_after
    }

    /// The admission, taken AGAIN inside the transaction that is about to
    /// stamp — the whole point of this step.
    ///
    /// The door resolves the dial in a read transaction, and the lease commits
    /// in a write transaction opened afterwards. Between the two, a manifest
    /// row can land: the dial that admitted the request is then not the dial
    /// the row commits under, and the single row an operator reaches for in a
    /// catastrophe — an emptied effector set — loses to whatever was already
    /// in flight. Re-resolving HERE, under the transaction that writes, closes
    /// that window: the check and the commit are the same atomic act.
    ///
    /// Three arms, all denials, in order of how specifically they can name what
    /// went wrong:
    ///
    /// 1. the live dial no longer admits the scope — the emptied-dial case, and
    ///    the reason it carries is [`STAMP_SCOPE_REFUSAL`] rather than the
    ///    door's own, so a test can tell which side answered;
    /// 2. the live floors no longer admit the requested TTL — a dial that
    ///    narrowed the ceiling under a ticket already sized at the wider one;
    /// 3. any OTHER disagreement, including a dial that WIDENED. A widening is
    ///    harmless to mint under, but it is still evidence that the reading
    ///    this admission rests on is stale, and a stale reading is not
    ///    something a stamp gets to shrug at.
    ///
    /// Deliberately NO clock reading happens here. The instant is threaded in
    /// through the proof, because a second reading could disagree with the
    /// lifetime check that already passed and put the credential's window and
    /// the lease's dates on two different observations.
    pub(crate) fn reaffirm_in_txn(&self, store: &Store, txn: &heed::RoTxn<'_>) -> DoorResult<()> {
        let live = DoorPolicy::resolve(store, txn)?;
        if !live.dial.admits(self.scope.effector) {
            return Err(CredentialDoorError::LeaseScopeRefused {
                effector: self.scope.effector.as_str().to_owned(),
                reason: STAMP_SCOPE_REFUSAL,
            });
        }
        let ceiling = live.floors.lease_ttl;
        if !ceiling.admits(self.ttl_secs) {
            return Err(CredentialDoorError::LeaseTtlDenied {
                requested_secs: self.ttl_secs,
                ceiling_secs: ceiling.secs(),
            });
        }
        if live != self.scope.policy {
            return Err(CredentialDoorError::DialMovedUnderStamp {
                effector: self.scope.effector.as_str(),
            });
        }
        Ok(())
    }
}

/// The credential door over one landed vault.
///
/// It holds no secret state of its own: the vault owns custody, the authority
/// log owns grants, and the detector owns detection. What lives here is the
/// composition and its refusals.
pub(crate) struct CredentialDoorService {
    vault: Arc<Vault>,
}

/// Compatibility alias for the door's shorter name. One principal noun, two
/// spellings — never two organs.
pub(crate) type CredentialDoor = CredentialDoorService;

impl CredentialDoorService {
    /// Binds the door to a vault.
    pub(crate) fn new(vault: Arc<Vault>) -> Self {
        Self { vault }
    }

    /// The vault this door composes over.
    pub(crate) fn vault(&self) -> &Arc<Vault> {
        &self.vault
    }

    /// Resolves the door dial from the live vault, in a READ transaction.
    ///
    /// This is the door's admission-time reading, and it is deliberately no
    /// longer the last word. A read transaction cannot hold anything still for
    /// the write transaction that stamps a lease later, so what this resolves
    /// is re-resolved there and compared
    /// ([`AdmittedLease::reaffirm_in_txn`]). Treating this answer as final is
    /// exactly the gap that let a dial narrowed after the read still mint.
    pub(crate) fn door_policy(&self) -> DoorResult<DoorPolicy> {
        let rtxn = self.vault.store.env.read_txn().map_err(custody)?;
        DoorPolicy::resolve(&self.vault.store, &rtxn)
    }

    /// The ONE instant a door operation authorizes and stamps under.
    ///
    /// Read from the vault's own seam ([`Vault::instant_in_txn`]) inside a
    /// read transaction — the authority plane's persisted-floor monotone
    /// observation, the same clock the fold makes widen-maturity decisions on.
    /// It is not a parameter, it is not a trait a caller may implement, and it
    /// is not the raw wall clock.
    ///
    /// Every door operation calls this EXACTLY once and threads the reading
    /// through: the lifetime check, the remaining-validity ceiling, the
    /// absolute lease bound, and the stamped `granted_at` are then all one
    /// observation. Reading twice would reintroduce, inside this module, the
    /// very gap removing the caller's `now` closed.
    pub(super) fn door_instant(&self) -> DoorResult<VaultInstant> {
        let rtxn = self.vault.store.env.read_txn().map_err(custody)?;
        self.vault.instant_in_txn(&rtxn).map_err(custody)
    }

    /// Authenticates a receive-pack attempt.
    ///
    /// `peer_addr` is transport context the caller already has; it is
    /// deliberately NOT an authorization input, and the leading underscore is
    /// the proof that no branch reads it. A loopback push authenticates
    /// exactly like any other push, because "localhost" describes a route and
    /// never a principal.
    ///
    /// The catastrophe dial applies HERE too. Receive-pack is a door effector
    /// like any other, so the resolved dial is admitted before the push
    /// authenticates: a manifest that narrows `secret.door.allowed_effectors`
    /// away from [`DOOR_RECEIVE_PACK_EFFECTOR`] shuts the receive-pack door
    /// itself, not merely the leases and injections taken through it. Without
    /// that check the one row an operator would reach for in a catastrophe —
    /// an empty effector set — would leave the push path wide open while
    /// closing everything downstream of it. The credential is still evaluated
    /// unconditionally; the dial only ever narrows.
    pub(crate) fn authenticate_receive_pack(
        &self,
        presented: Option<&DoorCredential>,
        repo: &RepoRef,
        _peer_addr: IpAddr,
    ) -> DoorResult<()> {
        let Some(credential) = presented else {
            return Err(CredentialDoorError::UnauthorizedPrincipal {
                reason: DoorDenyReason::CredentialAbsent,
            });
        };
        let now = self.door_instant()?;
        let admitted = self.admit_scope(DOOR_RECEIVE_PACK_EFFECTOR, now)?;
        self.witness_single_use(credential)?;
        credential.evaluate(
            DOOR_VERB_RECEIVE_PACK,
            &repo_record(repo),
            admitted.effector().as_str(),
            admitted.instant(),
        )
    }

    /// The pre-receive verdict over a push's added lines.
    ///
    /// Unconditional ([`DOOR_SCAN_ALWAYS_ON`]): there is no credential, dial,
    /// or caveat argument that could turn it off, because none is accepted.
    /// Unscannable input never passes — binary content and scanner failure
    /// both leave through the error surface, not through a verdict.
    pub(crate) fn pre_receive_scan(
        &self,
        repo: &RepoRef,
        blobs: &[PushedBlob],
    ) -> DoorResult<DoorScanVerdict> {
        let mut proposals = Vec::new();
        for blob in blobs {
            if let Some(reason) = scan_one_blob(blob)? {
                proposals.push(SecretLiftProposal::new(repo, &blob.path, reason));
            }
        }
        if proposals.is_empty() {
            Ok(DoorScanVerdict::Clean)
        } else {
            Ok(DoorScanVerdict::Rejected { proposals })
        }
    }

    /// T0: use a secret at the door without anyone workspace-side holding it.
    ///
    /// `apply` runs INSIDE [`Vault::inject_secret_at_door`] and can only
    /// return `()`, so the value cannot come back out through it. The caller
    /// gets the receipt; the bytes stay at the door.
    pub(crate) fn inject_secret_at_door(
        &self,
        presented: &DoorCredential,
        secret_ref: &str,
        effector: &str,
        apply: &mut dyn FnMut(&[u8]) -> crate::error::Result<()>,
    ) -> DoorResult<DoorInjectionReceipt> {
        let now = self.door_instant()?;
        let admitted = self.admit_scope(effector, now)?;
        self.witness_single_use(presented)?;
        presented.evaluate(
            DOOR_VERB_INJECT,
            secret_ref,
            admitted.effector().as_str(),
            admitted.instant(),
        )?;
        let vault = &self.vault;
        // T0 stamps no lease, so there is no lease-stamping transaction for an
        // admission to move inside of. The landed injection keeps its
        // drop-then-apply shape exactly: the write txn is released BEFORE the
        // caller's closure runs, because no caller code may execute inside an
        // LMDB write transaction.
        vault
            .inject_secret_at_door(secret_ref, admitted.effector().as_str(), apply)
            .map_err(custody)
    }

    /// T1: issue a lease ticket over a named secret, in an exact door scope.
    ///
    /// The composition is thin on purpose: the landed materialization writes
    /// the lease row and its receipt BEFORE the value returns, so the door
    /// adds no second, unmarked materializing path and no receipt family of
    /// its own.
    ///
    /// The ticket is bounded by the credential's REMAINING validity as well as
    /// by floor, dial and attenuation: a slip may not sell more time than it
    /// still has.
    ///
    /// That bound is handed to the materialization as the credential's
    /// ABSOLUTE expiry, not only as a duration: a duration alone would let a
    /// slip at its exact remaining bound — which is precisely where redemption
    /// and a maximal request both land — buy a ticket that outlives it.
    ///
    /// Both halves of the bound, and the lifetime check they rest on, are
    /// computed from the SAME [`VaultInstant`] this call read at its start,
    /// and that instant is what
    /// [`Vault::materialize_admitted_lease`] stamps `granted_at` from. So the
    /// absolute expiry travels as `now.after(remaining)` — which IS
    /// `presented.expires_at`, exactly, because the evaluator has already
    /// proved `now < expires_at` — rather than as the credential's raw wire
    /// number. There is no second clock reading anywhere in the path for a
    /// delay to open a gap in, and no way for a caller to name the instant any
    /// of it happens at.
    ///
    /// What the ticket carries into the vault is the [`AdmittedLease`] — the
    /// admitted scope, the secret, the admitted TTL and the absolute bound, as
    /// one value — and the transaction that stamps it takes the door's
    /// admission AGAIN under itself before writing a row. A dial narrowed
    /// between the read above and that write denies rather than minting under
    /// this now-stale reading.
    pub(crate) fn issue_lease_ticket(
        &self,
        presented: &DoorCredential,
        secret_ref: &str,
        effector: &str,
        ttl_secs: u64,
    ) -> DoorResult<SecretLeaseMaterialization> {
        let now = self.door_instant()?;
        let admitted = self.admit_scope(effector, now)?;
        self.witness_single_use(presented)?;
        presented.evaluate(
            DOOR_VERB_LEASE,
            secret_ref,
            admitted.effector().as_str(),
            now,
        )?;

        let ceiling = admitted.effective_ttl_ceiling(presented);
        if !ceiling.admits(ttl_secs) {
            return Err(CredentialDoorError::LeaseTtlDenied {
                requested_secs: ttl_secs,
                ceiling_secs: ceiling.secs(),
            });
        }
        let not_after = now.after(presented.remaining_secs(now));
        let vault = &self.vault;
        vault.materialize_admitted_lease(&admitted.into_lease(secret_ref, ttl_secs, not_after))
    }

    /// Redeems a one-shot credential, consuming it BY MOVE.
    ///
    /// Single use is structural here: `one_shot` is moved in and dropped
    /// before this returns, and [`DoorCredential`] is not `Clone`, so a second
    /// redemption of the same credential cannot be written. That is the whole
    /// enforcement — there is no door-local burn ledger, no token registry,
    /// and no new authority-log entry, because no landed surface licenses one.
    /// What the door CAN do it does: it refuses a single-use caveat it cannot
    /// witness against the authority log, and it never hands back a ticket
    /// that outlives the one-shot it was redeemed from.
    pub(crate) fn redeem_one_shot(
        &self,
        one_shot: DoorCredential,
    ) -> DoorResult<SecretLeaseMaterialization> {
        if !one_shot.single_use {
            return Err(CredentialDoorError::UnauthorizedPrincipal {
                reason: DoorDenyReason::SingleUseCaveatAbsent,
            });
        }
        self.witness_single_use(&one_shot)?;

        let lifetime = one_shot.lifetime_secs();
        if lifetime == 0 || lifetime > DOOR_ONE_SHOT_MAX_LIFETIME_SECS {
            return Err(CredentialDoorError::OneShotLifetimeDenied {
                lifetime_secs: lifetime,
                ceiling_secs: DOOR_ONE_SHOT_MAX_LIFETIME_SECS,
            });
        }
        // A one-shot names EXACTLY one secret and EXACTLY one effector. Any
        // other shape is a wildcard wearing a caveat.
        let (Some(secret_ref), 1) = (one_shot.records.first(), one_shot.records.len()) else {
            return Err(CredentialDoorError::LeaseScopeRefused {
                effector: String::new(),
                reason: "a one-shot must name exactly one secret",
            });
        };
        let (Some(effector), 1) = (one_shot.channels.first(), one_shot.channels.len()) else {
            return Err(CredentialDoorError::LeaseScopeRefused {
                effector: String::new(),
                reason: "a one-shot must name exactly one effector",
            });
        };

        let now = self.door_instant()?;
        let admitted = self.admit_scope(effector, now)?;
        one_shot.evaluate(
            DOOR_VERB_REDEEM,
            secret_ref,
            admitted.effector().as_str(),
            now,
        )?;

        // The declared lifetime is the CAP the one-shot was written under; the
        // ceiling carries what is left of it at `now`, so a one-shot redeemed
        // late buys only the time it still has.
        let ceiling = admitted.effective_ttl_ceiling(&one_shot);
        let ttl = lifetime.min(ceiling.secs());
        if !ceiling.admits(ttl) {
            return Err(CredentialDoorError::LeaseTtlDenied {
                requested_secs: lifetime,
                ceiling_secs: ceiling.secs(),
            });
        }
        let vault = &self.vault;
        // The one-shot's own absolute expiry rides along, for the same reason
        // `issue_lease_ticket` sends the slip's, and derived the same way: the
        // redemption arm always asks for its whole remaining bound, so the
        // absolute instant is what keeps a redeemed ticket from outliving the
        // one-shot it was redeemed from.
        let not_after = now.after(one_shot.remaining_secs(now));
        vault.materialize_admitted_lease(&admitted.into_lease(secret_ref, ttl, not_after))
        // `one_shot` drops here: the credential is spent.
    }

    /// The one-shot MINT arm — a recorded stop, not a feature.
    ///
    /// Minting a slip is an authority-log act, and this tree exposes no landed
    /// append surface that admits slip-mint bodies. Inventing an operation
    /// variant, a door-local ledger, or a hash-at-rest token store to fake one
    /// is exactly the shortcut that must not be taken, so this fails closed
    /// and says why. Redemption above works today with a verified one-shot the
    /// verifier hands over.
    ///
    /// `_now` survives the typed-instant migration deliberately: this arm
    /// authorizes nothing and reads nothing, so it has no clock seam to move
    /// onto. When the mint surface lands it will read its instant the same way
    /// every other door operation does.
    pub(crate) fn mint_one_shot(
        &self,
        _secret_ref: &str,
        _effector: &str,
        _lifetime_secs: u64,
        _now: u64,
    ) -> DoorResult<DoorCredential> {
        Err(CredentialDoorError::MintUnavailable)
    }

    /// A single-use caveat is only meaningful against the log that records
    /// mints and revocations. A verifier that cannot READ that log refuses the
    /// caveat rather than assuming the credential is still live.
    ///
    /// Read-only: the fold is taken through the landed read-side face inside a
    /// read transaction, and nothing is appended here or anywhere else in this
    /// module.
    fn witness_single_use(&self, credential: &DoorCredential) -> DoorResult<()> {
        if !credential.single_use {
            return Ok(());
        }
        #[cfg(test)]
        {
            if authority_log_fault_hook::take_log_unreachable() {
                return Err(CredentialDoorError::AuthorityLogUnreachable);
            }
        }
        let vault = &self.vault;
        let rtxn = vault.store.env.read_txn().map_err(log_unreachable)?;
        vault
            .authority_fold_readonly_in_txn(&rtxn)
            .map_err(log_unreachable)?;
        Ok(())
    }
}

impl CredentialDoorService {
    /// A door operation is always scoped, and the scope check is where the
    /// operation's AUTHORITY becomes a value.
    ///
    /// One resolved dial, one proved effector, one witnessed instant, one
    /// [`AdmittedScope`]. Everything downstream reads that proof instead of
    /// re-deriving any part of it: the evaluator's channel argument, the TTL
    /// ceiling, the absolute bound, and the re-admission the stamping
    /// transaction takes. The `()` this used to return left the dial, the
    /// effector and the instant lying around as three separate values that
    /// nothing tied together — which is how they came apart.
    pub(super) fn admit_scope(
        &self,
        effector: &str,
        at: VaultInstant,
    ) -> DoorResult<AdmittedScope> {
        AdmittedScope::admit(self.door_policy()?, effector, at)
    }
}

/// Scans one blob's added lines, returning the detector reason on a hit.
///
/// Order is load-bearing: seam validation, then the binary check over EVERY
/// added line, and only then the detector. The landed scanner is
/// intentionally lossy (it classifies over `from_utf8_lossy`), so asking it
/// about binary bytes would be asking a question it cannot answer — the door
/// answers it first, and the answer is always rejection.
fn scan_one_blob(blob: &PushedBlob) -> DoorResult<Option<&'static str>> {
    validate_seam_fields(blob)?;
    #[cfg(test)]
    {
        if scan_fault_hook::take_scanner_failure() {
            return Err(CredentialDoorError::ScanFailure {
                path: blob.path.clone(),
                reason: "scanner unavailable",
            });
        }
    }
    for line in &blob.added_lines {
        reject_unscannable(&blob.path, line)?;
    }
    for line in &blob.added_lines {
        if let Some(reason) = scan_file_content(&blob.path, line) {
            return Ok(Some(reason));
        }
    }
    Ok(None)
}

/// Binary is rejected, never skipped: a NUL byte or invalid UTF-8 anywhere in
/// the added bytes ends the push. Entropy, magic bytes, and size do not enter
/// — there is no allowlist to be wrong about.
fn reject_unscannable(path: &str, line: &[u8]) -> DoorResult<()> {
    if line.contains(&0) || std::str::from_utf8(line).is_err() {
        return Err(CredentialDoorError::BinaryContentRejected {
            path: path.to_owned(),
        });
    }
    Ok(())
}

/// Seam input the door cannot use is a scanner failure, which is a rejection.
/// An unnamed or unaddressable blob must never become a quiet pass.
fn validate_seam_fields(blob: &PushedBlob) -> DoorResult<()> {
    if blob.path.is_empty()
        || blob.path.len() > DOOR_MAX_PATH_BYTES
        || blob.path.chars().any(char::is_control)
    {
        return Err(CredentialDoorError::ScanFailure {
            path: UNUSABLE_PATH.to_owned(),
            reason: "pushed blob path is empty, oversized, or carries control bytes",
        });
    }
    if blob.oid.is_empty()
        || blob.oid.len() > DOOR_MAX_OID_BYTES
        || !blob.oid.as_bytes().iter().all(u8::is_ascii_hexdigit)
    {
        return Err(CredentialDoorError::ScanFailure {
            path: blob.path.clone(),
            reason: "pushed blob oid is empty, oversized, or not hexadecimal",
        });
    }
    Ok(())
}
