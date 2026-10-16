//! The resumed fold against the whole fold, its oracle (exactness is the
//! named high-risk invariant): a chain of inert rows off the base's head
//! reaches the reference's fold field by field and transitions only the new
//! rows, and every disqualifier, in the new rows or in the log under them,
//! falls back to the reference.
use std::cell::Cell;

use rand::Rng;

use super::fold_scale::{agent_key, confirm_op, owner_row, scale_log};
use super::history_transfer::re_root_entry;
use super::machine_identity::request_for;
use super::owner_anchor::{YOURS, hosted_genesis, pin, profile, publish};
use super::support::*;
use super::world_chain_reads::edit;
use super::*;
use crate::HostingPrivacyPosture::Hosted;
use crate::authority::entry_transition::TRANSITIONED_FOR_TEST;
use crate::authority::fold_resume::{FoldBase, RESUMED_FOR_TEST, StoredLog, fold_stored_log};
use crate::authority::log_budget::fold_projected_bytes;
use crate::world_keys::{
    FIRST_GENERATION, PolicyRevision, RecoveryRootSeed, WorldKey, WorldKeyBinding, WrapRecipient,
    seal_world_key,
};

fn hash(entry: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(entry).unwrap()
}

/// What a log folds under besides its rows.
#[derive(Clone)]
struct Under {
    floors: BTreeMap<AuthorityEntryHash, u64>,
    vouched: BTreeSet<AuthorityEntryHash>,
    unvouched: bool,
    policy: AuthorityObservationPolicy,
    posture: crate::HostingPrivacyPosture,
    pin: Option<PinnedRoot>,
    peers: BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
    /// Rows with no first-seen receipt; every other row was first seen at 1.
    unseen: BTreeSet<AuthorityEntryHash>,
    now: u64,
}

impl Default for Under {
    fn default() -> Self {
        Self {
            floors: BTreeMap::new(),
            vouched: BTreeSet::new(),
            unvouched: false,
            policy: AuthorityObservationPolicy::default(),
            posture: crate::HostingPrivacyPosture::default(),
            pin: None,
            peers: BTreeMap::new(),
            unseen: BTreeSet::new(),
            now: 2,
        }
    }
}

/// A base, and how many of the log's rows it folded.
struct Base(FoldBase, usize);

/// Every way a test's folds missed, reported together.
#[derive(Default)]
struct Misses(Vec<String>);

impl Misses {
    /// The stored-log fold of `entries` from `base` under `under`, beside the
    /// reference's: a miss when they differ, when it resumed and `resumes`
    /// says otherwise (or the reverse), or when a resumed fold transitioned
    /// any row but the new ones. The next base.
    fn fold(
        &mut self,
        case: &str,
        entries: &[AuthorityLogEntry],
        under: &Under,
        base: Option<&Base>,
        resumes: bool,
    ) -> Option<Base> {
        let first_seen: BTreeMap<_, _> = entries
            .iter()
            .map(hash)
            .filter(|hash| !under.unseen.contains(hash))
            .map(|hash| (hash, 1))
            .collect();
        let observations = AuthorityLocalObservations {
            sequence_floors: under.floors.clone(),
            vouched: under.vouched.clone(),
            unvouched: under.unvouched,
            policy: under.policy,
        };
        let peers = &under.peers;
        let before = RESUMED_FOR_TEST.with(Cell::get);
        TRANSITIONED_FOR_TEST.with(|rows| *rows.borrow_mut() = Some(Vec::new()));
        let (fold, next) = fold_stored_log(
            StoredLog {
                entries,
                first_seen_at_secs: &first_seen,
                now_secs: under.now,
                peer_consent_roots: peers,
                observations: &observations,
                posture: under.posture,
                pin: under.pin.as_ref(),
            },
            base.map(|base| &base.0),
        );
        let transitioned = TRANSITIONED_FOR_TEST.with(|rows| rows.borrow_mut().take());
        let resumed = RESUMED_FOR_TEST.with(Cell::get) > before;
        let reference = fold_authority_log_with_local_observations_and_posture(
            entries,
            &first_seen,
            under.now,
            peers,
            &observations,
            under.posture,
            under.pin.as_ref(),
        );
        if fold != reference {
            let (fold, reference) = (format!("{fold:#?}"), format!("{reference:#?}"));
            let at = fold
                .lines()
                .zip(reference.lines())
                .position(|(ours, theirs)| ours != theirs);
            let line = |text: &str| text.lines().nth(at.unwrap_or(0)).unwrap_or("").to_owned();
            self.0.push(format!(
                "{case}: differs from the reference at line {at:?}: {:?} vs {:?}",
                line(&fold),
                line(&reference),
            ));
        }
        if resumed != resumes {
            self.0
                .push(format!("{case}: resumed {resumed}, expected {resumes}"));
        }
        let new: Vec<_> = entries[base.map_or(0, |base| base.1)..]
            .iter()
            .map(hash)
            .collect();
        if resumed && transitioned.as_ref() != Some(&new) {
            self.0.push(format!(
                "{case}: transitioned {:?} rows, not the {} new ones",
                transitioned.as_ref().map(Vec::len),
                new.len(),
            ));
        }
        next.map(|next| Base(next, entries.len()))
    }

    fn expect(&mut self, case: &str, holds: bool) {
        if !holds {
            self.0.push(format!("{case}: does not hold"));
        }
    }

    fn assert_none(self) {
        assert!(self.0.is_empty(), "{}", self.0.join("\n"));
    }
}

/// The owner's rows off a log's head: inert ones the resumed fold carries,
/// and disqualifiers it must not.
struct Chain {
    vault_id: AuthorityVaultId,
    owner: SigningKey,
    seq: u64,
    fresh: u64,
    /// Agents this chain enrolled and has not bound.
    unbound: Vec<SigningKey>,
    /// Slips this chain minted, and which of them are still live.
    minted: Vec<SlipClaims>,
    live: Vec<[u8; 32]>,
    nonces: Vec<[u8; 16]>,
}

impl Chain {
    fn after(log: &[AuthorityLogEntry]) -> Self {
        Self {
            vault_id: genesis_vault_id(&log[0]).unwrap(),
            owner: ed_key(91),
            seq: log.len() as u64 - 1,
            fresh: 1 << 32,
            unbound: Vec::new(),
            minted: Vec::new(),
            live: Vec::new(),
            nonces: Vec::new(),
        }
    }

    fn fresh(&mut self) -> [u8; 32] {
        self.fresh += 1;
        let mut bytes = [0xB7; 32];
        bytes[..8].copy_from_slice(&self.fresh.to_be_bytes());
        bytes
    }

    fn fresh16(&mut self) -> [u8; 16] {
        self.fresh()[..16].try_into().unwrap()
    }

    fn entity(&mut self) -> EntityId {
        self.fresh += 1;
        let mut bytes = [0x71; 16];
        bytes[8..].copy_from_slice(&self.fresh.to_be_bytes());
        EntityId::from_bytes(bytes).unwrap()
    }

    fn confirm(&mut self) -> AuthorityOp {
        self.fresh += 1;
        confirm_op(self.fresh as usize)
    }

    /// The owner's row `op` on `parent`, cosigned by `cosigner`.
    fn row(
        &mut self,
        parent: AuthorityEntryHash,
        op: AuthorityOp,
        cosigner: Option<&SigningKey>,
    ) -> AuthorityLogEntry {
        self.seq += 1;
        owner_row(
            self.vault_id,
            &self.owner,
            self.seq,
            vec![parent],
            op,
            cosigner,
        )
    }

    /// An inert row on `parent`. An agent enrolled and not yet bound is
    /// bound first, as a system actor: until then it counts toward the
    /// quorum an owner-only row needs. Otherwise 0 and 1 enrol an agent, 2
    /// is a federation confirm, 3 a critical-write confirm, 4 consumes a
    /// slip (or mints one), 5 mints one.
    fn inert(&mut self, kind: usize, parent: AuthorityEntryHash) -> AuthorityLogEntry {
        if let Some(agent) = self.unbound.pop() {
            let actor = self.entity();
            let op = bind_op(&authority_key_from_ed(&agent), actor, "system", 1);
            return self.row(parent, op, Some(&agent));
        }
        match kind {
            2 => {
                let op = self.confirm();
                self.row(parent, op, None)
            }
            3 => {
                let nonce = self.fresh16();
                self.nonces.push(nonce);
                let op = self.critical(nonce);
                self.row(parent, op, None)
            }
            4 if !self.live.is_empty() => {
                let slip_id = self.live.remove(0);
                self.row(parent, AuthorityOp::SlipConsume { slip_id }, None)
            }
            4 | 5 => {
                let claims = self.claims();
                self.minted.push(claims.clone());
                self.live.push(claims.slip_id);
                self.row(
                    parent,
                    AuthorityOp::SlipMint(SlipMintAction { claims }),
                    None,
                )
            }
            _ => {
                let agent = SigningKey::from_bytes(&self.fresh());
                let op = AuthorityOp::EnrollDevice {
                    device: device(
                        authority_key_from_ed(&agent),
                        ROLE_AGENT,
                        AuthorityTier::Software,
                    ),
                };
                self.unbound.push(agent);
                self.row(parent, op, None)
            }
        }
    }

    fn critical(&mut self, nonce: [u8; 16]) -> AuthorityOp {
        AuthorityOp::CriticalWriteConfirm(CriticalWriteConfirmAction {
            schema_version: CRITICAL_WRITE_CONFIRM_SCHEMA_VERSION,
            confirm_id: self.fresh(),
            gate_decision_id: self.fresh16(),
            claim_id: self.entity(),
            effect_digest: self.fresh(),
            read_frontier_hash: self.fresh(),
            nonce,
            expires_at: 600,
            disposition: CriticalWriteConfirmDisposition::Clear,
            method: CriticalWriteConfirmMethod::TokenReauth,
        })
    }

    fn claims(&mut self) -> SlipClaims {
        SlipClaims {
            slip_id: self.fresh(),
            vault_id: self.vault_id,
            parent_id: None,
            holder_ref: "fixture-owner".into(),
            binding_key: SigningKey::from_bytes(&self.fresh())
                .verifying_key()
                .to_bytes(),
            scope: crate::federation::Scope::top(),
            issued_at: 1,
            expires_at: 101,
            ttl_secs: 100,
            single_use: true,
            records: BTreeSet::new(),
            channels: BTreeSet::new(),
            actor_class: None,
            org_ref: None,
        }
    }

    /// Rows off the tip of `log` the resumed fold must not carry, each with
    /// what it folds under.
    fn disqualifiers(
        &mut self,
        log: &[AuthorityLogEntry],
        under: &Under,
        rng: &mut StdRng,
    ) -> Vec<(&'static str, Vec<AuthorityLogEntry>, Under)> {
        let tip = hash(log.last().unwrap());
        let ops = || log.iter().map(|entry| &entry.op);
        let mut rows: Vec<(&'static str, Vec<AuthorityLogEntry>)> = Vec::new();
        let late = hash(&log[rng.gen_range(0..log.len() - 1)]);
        let op = self.confirm();
        rows.push(("a late row below the head", vec![self.row(late, op, None)]));
        let (one, two) = (self.confirm(), self.confirm());
        let fork = vec![self.row(tip, one, None), self.row(tip, two, None)];
        rows.push(("a fork off the head", fork));
        let admin = SigningKey::from_bytes(&self.fresh());
        let op = AuthorityOp::EnrollDevice {
            device: device(
                authority_key_from_ed(&admin),
                ROLE_ADMIN,
                AuthorityTier::Software,
            ),
        };
        rows.push(("an admin enrollment", vec![self.row(tip, op, None)]));
        let enrolled = ops().find_map(|op| match op {
            AuthorityOp::EnrollDevice { device } => Some(device.key.clone()),
            _ => None,
        });
        let bound = ops().find_map(|op| match op {
            AuthorityOp::BindActor {
                authority_key,
                actor_ref,
                ..
            } => Some((authority_key.clone(), *actor_ref)),
            _ => None,
        });
        if let Some(confirm) = ops().find(|op| matches!(op, AuthorityOp::FederationConfirm(_))) {
            let row = self.row(tip, confirm.clone(), None);
            rows.push(("a confirm the log holds", vec![row]));
        }
        if let Some(key) = enrolled {
            let op = AuthorityOp::EnrollDevice {
                device: device(key.clone(), ROLE_AGENT, AuthorityTier::Software),
            };
            rows.push(("an agent the roster holds", vec![self.row(tip, op, None)]));
            let revoke = AuthorityOp::RevokeDevice { revoked_key: key };
            rows.push(("a revocation", vec![self.row(tip, revoke, None)]));
        }
        if let Some((key, actor)) = bound {
            let fresh = self.entity();
            let op = bind_op(&key, fresh, "system", 1);
            rows.push(("a key bound again", vec![self.row(tip, op, None)]));
            let op = bind_op(&authority_key_from_ed(&self.owner), actor, "human", 1);
            rows.push(("an actor bound again", vec![self.row(tip, op, None)]));
        }
        let never = AuthorityOp::SlipConsume {
            slip_id: self.fresh(),
        };
        rows.push(("a slip no one minted", vec![self.row(tip, never, None)]));
        if let Some(claims) = self.minted.first().cloned() {
            let again = AuthorityOp::SlipMint(SlipMintAction {
                claims: claims.clone(),
            });
            rows.push(("a slip minted twice", vec![self.row(tip, again, None)]));
            if !self.live.contains(&claims.slip_id) {
                let twice = AuthorityOp::SlipConsume {
                    slip_id: claims.slip_id,
                };
                rows.push(("a slip consumed twice", vec![self.row(tip, twice, None)]));
            }
        }
        if let Some(nonce) = self.nonces.first().copied() {
            let op = self.critical(nonce);
            rows.push(("a spent critical nonce", vec![self.row(tip, op, None)]));
        }
        let (_, _, owner_root) = publish(self.vault_id, log.last().unwrap());
        rows.push(("an owner root", vec![owner_root]));
        let mut cases: Vec<_> = rows
            .into_iter()
            .map(|(case, rows)| (case, rows, under.clone()))
            .collect();
        // One inert row, under inputs the base did not fold under.
        let genesis = hash(&log[0]);
        let (other_root, _, _) = publish(self.vault_id, log.last().unwrap());
        for case in [
            "a row below its floor",
            "a base row's first-seen receipt dropped",
            "a floor on a base row",
            "another policy",
            "another posture",
            "another pin",
            "a peer root",
            "another peer root",
            "a vouched row",
            "a vouched base row",
            "no vouch",
        ] {
            let op = self.confirm();
            let row = self.row(tip, op, None);
            let mut under = under.clone();
            match case {
                "a row below its floor" => {
                    under.floors.insert(hash(&row), row.seq + 1);
                }
                "a base row's first-seen receipt dropped" => {
                    under.unseen.insert(genesis);
                }
                "a floor on a base row" => {
                    under.floors.insert(genesis, 0);
                }
                "another policy" => under.policy.stale_roster_window_secs = 99,
                "another posture" => under.posture = Hosted,
                "another pin" => under.pin = Some(pin(&other_root)),
                "a peer root" => {
                    under.peers.insert([78; 32], BTreeSet::new());
                }
                "another peer root" => {
                    let key = authority_key_from_ed(&ed_key(78));
                    under.peers.insert([79; 32], BTreeSet::from([key]));
                }
                "a vouched row" => {
                    under.vouched.insert(hash(&row));
                }
                "a vouched base row" => {
                    under.vouched.insert(genesis);
                }
                _ => under.unvouched = true,
            }
            cases.push((case, vec![row], under));
        }
        cases
    }
}

#[test]
fn a_resumed_fold_is_the_whole_fold_on_every_row_of_a_chain() {
    let mut misses = Misses::default();
    let under = Under::default();
    for shape in ["agents", "chain"] {
        let log = scale_log(shape, 24);
        let mut base = None;
        for len in 1..=log.len() {
            let case = format!("{shape} at {len} rows");
            base = misses.fold(&case, &log[..len], &under, base.as_ref(), len > 1);
        }
        let base = misses.fold(
            &format!("{shape}: ten rows"),
            &log[..10],
            &under,
            None,
            false,
        );
        let case = format!("{shape}: fourteen rows at once");
        misses.fold(&case, &log, &under, base.as_ref(), true);
    }
    misses.assert_none();
}

#[test]
fn a_generated_chain_of_inert_rows_resumes_and_each_disqualifier_falls_back() {
    let mut misses = Misses::default();
    for seed in 0..16_u64 {
        let mut rng = StdRng::seed_from_u64(seed);
        let shape = if rng.gen_bool(0.5) { "agents" } else { "chain" };
        let mut log = scale_log(shape, 2 * rng.gen_range(1..5));
        let mut chain = Chain::after(&log);
        let mut under = Under::default();
        if rng.gen_bool(0.5) {
            let key = authority_key_from_ed(&ed_key(79));
            under.peers.insert([79; 32], BTreeSet::from([key]));
        }
        let mut base = misses.fold(&format!("seed {seed}: the log"), &log, &under, None, false);
        // At least `rows` rows, the last of them with every agent bound.
        let rows = rng.gen_range(1..10);
        let mut n = 0;
        while n < rows || !chain.unbound.is_empty() {
            n += 1;
            let row = chain.inert(rng.gen_range(0..6), hash(log.last().unwrap()));
            // A row with no first-seen receipt still resumes.
            if rng.gen_bool(0.3) {
                under.unseen.insert(hash(&row));
            }
            log.push(row);
            if (n >= rows && chain.unbound.is_empty()) || rng.gen_bool(0.5) {
                // Past the stale-roster window, the install view still
                // matches.
                under.now = if rng.gen_bool(0.3) { 86_402 } else { 2 };
                let case = format!("seed {seed}: to {} rows", log.len());
                base = misses.fold(&case, &log, &under, base.as_ref(), true);
            }
        }
        for (case, rows, under) in chain.disqualifiers(&log, &under, &mut rng) {
            let entries = [log.clone(), rows].concat();
            let case = format!("seed {seed}: {case}");
            misses.fold(&case, &entries, &under, base.as_ref(), false);
        }
    }
    misses.assert_none();
}

/// Folds `log` for a base, then `log` and `rows` from it: all at once, and
/// one row at a time from each fold's own base.
fn check(
    misses: &mut Misses,
    case: &str,
    log: &[AuthorityLogEntry],
    rows: Vec<AuthorityLogEntry>,
    under: &Under,
    resumes: bool,
) {
    let first = misses.fold(&format!("{case}: the log"), log, under, None, false);
    misses.expect(&format!("{case}: the log leaves a base"), first.is_some());
    let entries = [log.to_vec(), rows].concat();
    misses.fold(case, &entries, under, first.as_ref(), resumes);
    let mut base = first;
    for len in log.len() + 1..entries.len() {
        let case = format!("{case}: to {len} rows");
        base = misses.fold(&case, &entries[..len], under, base.as_ref(), resumes);
    }
    if entries.len() > log.len() + 1 {
        let case = format!("{case}: row by row");
        misses.fold(&case, &entries, under, base.as_ref(), resumes);
    }
}

#[test]
fn a_log_the_resumed_fold_cannot_carry_on_from_falls_back_to_the_whole_fold() {
    let mut misses = Misses::default();
    let plain = Under::default();
    let owner = ed_key(91);
    let chain_log = scale_log("chain", 8);
    let id = genesis_vault_id(&chain_log[0]).unwrap();
    let tip = |log: &[AuthorityLogEntry]| hash(log.last().unwrap());
    let confirm =
        |log: &[AuthorityLogEntry], signer: &SigningKey, seq, n, cosigner: Option<&SigningKey>| {
            owner_row(id, signer, seq, vec![tip(log)], confirm_op(n), cosigner)
        };
    let agent = |seed| AuthorityOp::EnrollDevice {
        device: device(
            authority_key_from_ed(&ed_key(seed)),
            ROLE_AGENT,
            AuthorityTier::Software,
        ),
    };

    // A tier floor in the chain's past (H411): a Hardware owner's genesis
    // floor refuses a Software signer.
    let mut genesis = genesis_entry(91, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    if let AuthorityOp::Genesis {
        device, tier_floor, ..
    } = &mut genesis.op
    {
        device.tier = AuthorityTier::Hardware;
        *tier_floor = AuthorityTier::Hardware;
    }
    let genesis = sign_ed(genesis, &owner);
    let floored_id = genesis_vault_id(&genesis).unwrap();
    let mut floored = vec![genesis];
    for n in 0..8 {
        let parent = tip(&floored);
        floored.push(owner_row(
            floored_id,
            &owner,
            n + 1,
            vec![parent],
            confirm_op(n as usize),
            None,
        ));
    }
    // The owner over the floor, before an unbound agent counts toward the
    // quorum an owner-only row needs.
    let strong = owner_row(
        floored_id,
        &owner,
        9,
        vec![tip(&floored)],
        confirm_op(100),
        None,
    );
    check(
        &mut misses,
        "the owner over the genesis floor",
        &floored,
        vec![strong],
        &plain,
        true,
    );
    floored.push(owner_row(
        floored_id,
        &owner,
        9,
        vec![tip(&floored)],
        agent(7),
        None,
    ));
    let weak = owner_row(
        floored_id,
        &ed_key(7),
        1,
        vec![tip(&floored)],
        confirm_op(100),
        Some(&owner),
    );
    check(
        &mut misses,
        "a signer under the genesis floor",
        &floored,
        vec![weak],
        &plain,
        false,
    );

    // A pre-handoff floor, then a handoff: the successor's agent row.
    let mut genesis = genesis_entry(91, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    if let AuthorityOp::Genesis { device, .. } = &mut genesis.op {
        device.tier = AuthorityTier::Hardware;
    }
    let genesis = sign_ed(genesis, &owner);
    let handoff_id = genesis_vault_id(&genesis).unwrap();
    let floor = set_tier_floor_entry(handoff_id, &genesis, &owner, 1, AuthorityTier::Hardware);
    let successor = ed_key(92);
    let mut handoff = re_root_entry(handoff_id, &floor, &owner, 2, &successor);
    if let AuthorityOp::ReRoot { new_device } = &mut handoff.op {
        new_device.tier = AuthorityTier::Hardware;
    }
    let handoff = sign_ed(handoff, &owner);
    let handed = vec![genesis, floor, handoff];
    let row = owner_row(
        handoff_id,
        &successor,
        1,
        vec![tip(&handed)],
        agent(7),
        None,
    );
    check(
        &mut misses,
        "an agent under a pre-handoff floor",
        &handed,
        vec![row],
        &plain,
        true,
    );

    // A fenced signer and a fenced cosigner after a handoff.
    let next = ed_key(92);
    let mut fenced = chain_log.clone();
    fenced.push(re_root_entry(id, fenced.last().unwrap(), &owner, 9, &next));
    let rows = [
        (
            "a fenced signer",
            confirm(&fenced, &owner, 10, 100, None),
            false,
        ),
        (
            "a fenced cosigner",
            confirm(&fenced, &next, 1, 101, Some(&owner)),
            false,
        ),
        (
            "the successor after a handoff",
            confirm(&fenced, &next, 1, 102, None),
            true,
        ),
    ];
    for (case, row, resumes) in rows {
        check(&mut misses, case, &fenced, vec![row], &plain, resumes);
    }

    // A revoked agent as signer or cosigner.
    let mut revoked = scale_log("agents", 8);
    let old = agent_key(0);
    revoked.push(revoke_entry(
        id,
        revoked.last().unwrap(),
        &owner,
        authority_key_from_ed(&old),
        9,
    ));
    let rows = [
        (
            "a revoked signer",
            confirm(&revoked, &old, 1, 100, Some(&owner)),
        ),
        (
            "a revoked cosigner",
            confirm(&revoked, &owner, 10, 101, Some(&old)),
        ),
    ];
    for (case, row) in rows {
        check(&mut misses, case, &revoked, vec![row], &plain, false);
    }
    let late = Under {
        now: 86_402,
        ..Under::default()
    };
    let row = confirm(&revoked, &owner, 10, 102, None);
    let case = "the owner past the stale window after a revocation";
    check(&mut misses, case, &revoked, vec![row], &late, true);

    // A machine row and its install key.
    let install = ed_key(70);
    let machine = scope_entity(70);
    let mut machined = chain_log.clone();
    let request = request_for(id, machine, &install);
    machined.push(owner_row(
        id,
        &owner,
        9,
        vec![tip(&machined)],
        profile(&request, YOURS, 1),
        None,
    ));
    let enroll = AuthorityOp::EnrollDevice {
        device: device(
            authority_key_from_ed(&install),
            ROLE_AGENT,
            AuthorityTier::Software,
        ),
    };
    let bind = bind_op(&authority_key_from_ed(&owner), machine, "human", 1);
    let rows = [
        ("an install key enrolled", enroll, false),
        ("a machine row bound", bind, false),
        ("a confirm after a machine profile", confirm_op(100), true),
    ];
    for (case, op, resumes) in rows {
        let row = owner_row(id, &owner, 10, vec![tip(&machined)], op, None);
        check(&mut misses, case, &machined, vec![row], &plain, resumes);
    }

    // #1422's rows: an owner root off the head, and a world's key record
    // under its settings edit, both side or non-inert rows.
    let (_, _, owner_root) = publish(id, chain_log.last().unwrap());
    check(
        &mut misses,
        "an owner root",
        &chain_log,
        vec![owner_root],
        &plain,
        false,
    );
    let world = scope_entity(80);
    let settings = edit(
        id,
        &[machined.last().unwrap()],
        (machine, &install),
        1,
        world,
        ReadLocation::MyMachines,
    );
    let seed = RecoveryRootSeed::generate().unwrap();
    let root = seed.public(&id).unwrap();
    let key = WorldKey::mint(world, FIRST_GENERATION).unwrap();
    let policy = PolicyRevision::of([hash(&settings)]);
    let binding = WorldKeyBinding {
        vault_id: id,
        key: *key.id(),
        owner: scope_entity(81),
        policy,
        commitment: key.commitment(),
    };
    let to = WrapRecipient::RecoveryRoot(root.id);
    let envelope = seal_world_key(&binding, to, &root.recovery_key, &key)
        .unwrap()
        .to_bytes();
    let record = AuthorityOp::WorldKeyWraps(WorldKeyWrapsRecord {
        key: *key.id(),
        commitment: key.commitment(),
        owner: binding.owner,
        policy,
        machine,
        wraps: vec![(to, envelope)],
    });
    let wraps = owner_row(id, &install, 2, vec![hash(&settings)], record, None);
    check(
        &mut misses,
        "a world's settings and key",
        &machined,
        vec![settings.clone(), wraps.clone()],
        &plain,
        false,
    );
    let with_settings = [machined.clone(), vec![settings]].concat();
    check(
        &mut misses,
        "a world's key record",
        &with_settings,
        vec![wraps.clone()],
        &plain,
        false,
    );
    // A base that holds a world and its key carries on, row by row, off
    // its main head (the machine's profile).
    let keyed = [with_settings, vec![wraps]].concat();
    let one = confirm(&machined, &owner, 10, 100, None);
    let two = owner_row(id, &owner, 11, vec![hash(&one)], confirm_op(101), None);
    let case = "confirms over a world's key record";
    check(&mut misses, case, &keyed, vec![one, two], &plain, true);

    // A side row in the log that names the new row as its parent.
    let row = confirm(&machined, &owner, 10, 100, None);
    let side = edit(
        id,
        &[&row],
        (machine, &install),
        1,
        scope_entity(83),
        ReadLocation::MyMachines,
    );
    let waiting = [machined, vec![side]].concat();
    check(
        &mut misses,
        "a row a side row waits on",
        &waiting,
        vec![row],
        &plain,
        false,
    );

    // A log the fold refuses or cannot settle leaves no base: a second
    // root, a main row whose parent never arrived.
    let rival = genesis_entry(92, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let orphan = owner_row(id, &owner, 9, vec![[0xEE; 32]], confirm_op(100), None);
    for (case, extra) in [
        ("a second root", rival),
        ("a main row without its parent", orphan),
    ] {
        let log = [chain_log.clone(), vec![extra]].concat();
        let base = misses.fold(&format!("{case}: the log"), &log, &plain, None, false);
        misses.expect(&format!("{case}: no base"), base.is_none());
        let row = confirm(&chain_log, &owner, 10, 101, None);
        let entries = [log, vec![row]].concat();
        misses.fold(case, &entries, &plain, base.as_ref(), false);
    }

    // The memory floor over the whole log, the issuer's uncounted slip rows
    // included: a row at the floor resumes, a row past it falls back to the
    // refusal.
    let mut slipped = chain_log.clone();
    let mut chain = Chain::after(&slipped);
    for kind in [5, 4] {
        let row = chain.inert(kind, tip(&slipped));
        slipped.push(row);
    }
    let row = chain.inert(2, tip(&slipped));
    let rows = slipped.len() + 1;
    let bytes = fold_projected_bytes(rows, (rows * (rows - 1) / 2) as u64);
    for (case, floor, resumes) in [
        ("a row at the memory floor", bytes, true),
        ("a row past the memory floor", bytes - 1, false),
    ] {
        let under = Under {
            policy: AuthorityObservationPolicy {
                log_fold_memory_floor_bytes: Some(floor),
                ..AuthorityObservationPolicy::default()
            },
            ..Under::default()
        };
        check(
            &mut misses,
            case,
            &slipped,
            vec![row.clone()],
            &under,
            resumes,
        );
    }

    // A missing receipt reads at its signer's high-water mark (F4, F16):
    // the head's floor is its own sequence while it is the newest row, and
    // the new row's once that lands, which puts the head below it.
    let head = chain_log.last().unwrap();
    let at_head = Under {
        floors: BTreeMap::from([(hash(head), head.seq)]),
        ..Under::default()
    };
    let case = "a missing receipt";
    let base = misses.fold(
        &format!("{case}: the log"),
        &chain_log,
        &at_head,
        None,
        false,
    );
    misses.expect(&format!("{case}: the log leaves a base"), base.is_some());
    let row = confirm(&chain_log, &owner, 9, 100, None);
    let raised = Under {
        floors: BTreeMap::from([(hash(head), row.seq)]),
        ..Under::default()
    };
    let entries = [chain_log, vec![row]].concat();
    let case = "a missing receipt read at the new high-water mark";
    misses.fold(case, &entries, &raised, base.as_ref(), false);

    misses.assert_none();
}

#[test]
fn a_pact_hosted_or_pinned_log_resumes_only_under_its_own_inputs() {
    let mut misses = Misses::default();
    let plain = Under::default();
    let owner = ed_key(91);
    let chain_log = scale_log("chain", 8);
    let id = genesis_vault_id(&chain_log[0]).unwrap();
    let tip = |log: &[AuthorityLogEntry]| hash(log.last().unwrap());
    let confirm = |log: &[AuthorityLogEntry], signer: &SigningKey, seq, n| {
        owner_row(id, signer, seq, vec![tip(log)], confirm_op(n), None)
    };
    let agent = AuthorityOp::EnrollDevice {
        device: device(
            authority_key_from_ed(&ed_key(7)),
            ROLE_AGENT,
            AuthorityTier::Software,
        ),
    };

    // A pact the head's state holds narrower than the merge does not
    // capture; the other order does.
    let fixture = pact_fixture_with_scope(91, symmetric_scope(ScopeAxis::All, ScopeAxis::All));
    let connect = lifecycle_entry(&fixture, vec![tip(&chain_log)], 9, connect_action(&fixture));
    let narrow = FederationDirectionScope {
        worlds: ScopeAxis::All,
        facets: ScopeAxis::from_iter([scope_entity(7)].map(ScopeId)),
        bands: ScopeAxis::All,
    };
    let broad = FederationDirectionScope {
        worlds: ScopeAxis::All,
        facets: ScopeAxis::All,
        bands: ScopeAxis::All,
    };
    for (case, first, then, captures) in [
        (
            "a pact broadened at its epoch",
            narrow.clone(),
            broad.clone(),
            false,
        ),
        ("a pact narrowed at its epoch", broad, narrow, true),
    ] {
        let rescope = |parent, seq, scope| {
            let action = narrow_action_with(&fixture, fixture.pact_id, fixture.grant_ref, 1, scope);
            lifecycle_entry(&fixture, vec![parent], seq, action)
        };
        let one = rescope(hash(&connect), 10, first);
        let two = rescope(hash(&one), 11, then);
        let pacts = [chain_log.clone(), vec![connect.clone(), one, two]].concat();
        let base = misses.fold(&format!("{case}: the log"), &pacts, &plain, None, false);
        misses.expect(
            &format!("{case}: a base is {captures}"),
            base.is_some() == captures,
        );
        let row = confirm(&pacts, &owner, 12, 100);
        let entries = [pacts, vec![row]].concat();
        misses.fold(case, &entries, &plain, base.as_ref(), captures);
    }

    // A hosted vault resumes under its posture, and not under another.
    let hosted = Under {
        posture: Hosted,
        ..Under::default()
    };
    let genesis = hosted_genesis(&owner);
    let hosted_id = genesis_vault_id(&genesis).unwrap();
    let mut hosted_log = vec![genesis];
    for n in 0..8 {
        let parent = tip(&hosted_log);
        hosted_log.push(owner_row(
            hosted_id,
            &owner,
            n + 1,
            vec![parent],
            confirm_op(n as usize),
            None,
        ));
    }
    let row = owner_row(hosted_id, &owner, 9, vec![tip(&hosted_log)], agent, None);
    check(
        &mut misses,
        "a hosted vault's agent",
        &hosted_log,
        vec![row.clone()],
        &hosted,
        true,
    );
    let base = misses.fold("a hosted base", &hosted_log, &hosted, None, false);
    let entries = [hosted_log, vec![row]].concat();
    misses.fold(
        "a hosted base, another posture",
        &entries,
        &plain,
        base.as_ref(),
        false,
    );

    // A pinned install resumes under its pin, and not without it.
    let (root, _, published) = publish(id, chain_log.last().unwrap());
    let pinned_log = [chain_log, vec![published]].concat();
    let pinned = Under {
        pin: Some(pin(&root)),
        ..Under::default()
    };
    let row = confirm(&pinned_log, &owner, 9, 100);
    check(
        &mut misses,
        "a pinned install",
        &pinned_log,
        vec![row.clone()],
        &pinned,
        true,
    );
    let base = misses.fold("a pinned base", &pinned_log, &pinned, None, false);
    let entries = [pinned_log, vec![row]].concat();
    misses.fold(
        "a pinned base, unpinned",
        &entries,
        &plain,
        base.as_ref(),
        false,
    );
    misses.assert_none();
}
