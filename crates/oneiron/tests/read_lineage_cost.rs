//! Fable pass 30 MEASURE.md (bench only; never merged): what a
//! source-audience lineage walk and a stored floor each cost per read, what
//! raising a floor costs a write, and what a floor stores. It prices
//! DESIGN.md section 2 of
//! lanes/post-untangle/fable/30-read-lineage.
//!
//! Prints one `## COST` line per cell and one `## BYTES` line per floor set;
//! `#P` lines are progress. Every timing is single-threaded, five passes
//! with the first dropped.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked --profile bench-fast -p oneiron --all-features --test read_lineage_cost -- --ignored --nocapture --test-threads=1`
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::claim::{PointRead, ScopedReadActorKey, base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{
    AllRelationships, ClaimRelationships, ClaimScope, Memory, ScopedClaimInput, WitnessAssertions,
    WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::policy_model::SecretScanMode;
use oneiron::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON, ENTITY_TYPE_SUMMARY,
    ENTITY_TYPE_TURN,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::read_lineage_cost::{self as door, RowTime};
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CONVERSATIONS: usize = 1_000;
const TURNS_PER_CONVERSATION: usize = 20;
const MESSAGES_PER_TURN: usize = 2;
const SOURCES: usize = 10;
const THREADS_PER_SOURCE: usize = 100;
const SET_ROWS: usize = 5_000;
const SMALL_SET_ROWS: usize = 1_000;
const W_ROWS: usize = 1_000;
const PASSES: usize = 5;
const FRAME: usize = 1_000;
const SEARCH_CALLS_PER_PASS: usize = 50;
const FLOOR_SAMPLE: usize = 100;
const OCCURRED_AT: u64 = 1_769_947_200;

/// Seconds since the bench started, for the progress lines.
fn since(start: Instant) -> f64 {
    start.elapsed().as_secs_f64()
}

fn ns(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// p50 and p99 (nearest rank) of `samples`.
fn percentiles(samples: &[u64]) -> (u64, u64) {
    if samples.is_empty() {
        return (0, 0);
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let rank = |p: f64| {
        let index = ((p * sorted.len() as f64).ceil() as usize).max(1) - 1;
        sorted[index.min(sorted.len() - 1)]
    };
    (rank(0.50), rank(0.99))
}

fn mean(samples: &[u64]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    samples.iter().map(|value| *value as f64).sum::<f64>() / samples.len() as f64
}

struct Cell<'a> {
    arm: &'a str,
    set: &'a str,
    vault: &'a str,
    reader: &'a str,
    switch: &'a str,
    rows: usize,
}

fn print_cost(cell: &Cell<'_>, samples: &[u64], readable: usize, sample: &str) {
    let (p50, p99) = percentiles(samples);
    println!(
        "## COST arm={} set={} vault={} reader={} switch={} n={} p50_ns={p50} p99_ns={p99} readable={readable} samples={} sample={sample}",
        cell.arm,
        cell.set,
        cell.vault,
        cell.reader,
        cell.switch,
        cell.rows,
        samples.len(),
    );
}

/// The filesystem type the path sits on, read from /proc/mounts.
fn filesystem_of(path: &Path) -> String {
    let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
        return "unknown".to_owned();
    };
    let path = path.to_string_lossy();
    let mut best = ("", "unknown");
    for line in mounts.lines() {
        let mut parts = line.split_whitespace();
        let (_, Some(point), Some(kind)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        if path.starts_with(point) && point.len() >= best.0.len() {
            best = (point, kind);
        }
    }
    format!("{} on {}", best.1, best.0)
}

/// Bytes of every `data.mdb` under `dir`.
fn mdb_bytes(dir: &Path) -> u64 {
    let mut total = 0;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            total += mdb_bytes(&path);
        } else if path.file_name().is_some_and(|name| name == "data.mdb") {
            total += entry.metadata().map_or(0, |meta| meta.len());
        }
    }
    total
}

/// One bench vault: the owner, the IN pen (an AGENT_DEF anchored to the
/// PERSON every policy names) and the OUT agent (no policy names it), both
/// with an owner read Grant over CLAIM, TURN and MESSAGE.
struct Bench {
    vault: Vault,
    dir: tempfile::TempDir,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    person: EntityId,
    pen: EntityId,
    outsider: EntityId,
    facet: EntityId,
    claims_written: usize,
}

/// One mail thread: its CONVERSATION, thread policy and TURNs.
struct Thread {
    policy: EntityId,
    turns: Vec<EntityId>,
}

/// One claim set: its rows and, per row, the policies its floor holds.
struct ClaimSet {
    name: &'static str,
    rows: Vec<EntityId>,
    floors: Vec<BTreeSet<EntityId>>,
}

impl Bench {
    fn open(base: &Path, label: &str) -> TestResult<Self> {
        let dir = tempfile::Builder::new()
            .prefix(&format!("read-lineage-{label}-"))
            .tempdir_in(base)?;
        println!(
            "#P vault {label} at {} ({})",
            dir.path().display(),
            filesystem_of(dir.path())
        );
        let vault = Vault::open(dir.path(), VaultConfig::default())?;
        let owner = vault.ensure_embedded_owner_actor()?;
        let issuer = HostSlipIssuer::from_secret(b"read-lineage-cost-host")?;
        vault.ensure_host_root_slip(&issuer)?;
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let owner_proof =
            vault.authenticate_owner(owner, "principal:owen", true, GateDecisionId::now())?;
        vault.set_secret_scan_mode(&owner_proof, SecretScanMode::Off, 10)?;
        let person = EntityId::now();
        let now = vault.now_recorded_at();
        vault.put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            b"pat",
        )?;
        let pen = Self::agent(&vault, &owner_proof, "lineage_bench_pen")?;
        oneiron::subject_model::anchor_actor_subject(
            &vault,
            pen,
            person,
            WriteActor::new(owner, EdgeActorClass::Human),
            vault.now_recorded_at(),
        )?;
        let outsider = Self::agent(&vault, &owner_proof, "lineage_bench_outsider")?;
        let facet = vault.default_facet()?;
        Ok(Self {
            vault,
            dir,
            owner,
            owner_proof,
            person,
            pen,
            outsider,
            facet,
            claims_written: 0,
        })
    }

    /// An enabled agent with an owner read Grant over CLAIM, TURN and MESSAGE.
    fn agent(vault: &Vault, proof: &AuthenticatedOwner, agent_id: &str) -> TestResult<EntityId> {
        let agent = EntityId::now();
        create_agent_definition_as(
            vault,
            proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: agent,
                definition: serde_json::from_value(json!({
                    "agent_id": agent_id,
                    "desc": "Read lineage cost bench reader",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))?,
            },
        )?;
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
        scope.bands = ScopeAxis::Some(BTreeSet::from([
            ENTITY_TYPE_CLAIM,
            ENTITY_TYPE_TURN,
            ENTITY_TYPE_MESSAGE,
        ]));
        Self::grant(vault, proof, agent, scope)?;
        Ok(agent)
    }

    fn grant(
        vault: &Vault,
        proof: &AuthenticatedOwner,
        agent: EntityId,
        scope: Scope,
    ) -> TestResult {
        let minted = mint_agent_grant_as(
            vault,
            proof,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent,
                authority_scope: scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
            },
        )?;
        assert!(minted.grant.confers, "the bench reader's Grant is live");
        Ok(())
    }

    fn owner_memory(&self) -> Memory<'_> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .with_owner_authorship(&self.owner_proof)
    }

    fn key(&self, actor: EntityId) -> TestResult<ScopedReadActorKey> {
        Ok(self.vault.memory(actor, EdgeActorClass::Agent).read_key()?)
    }

    /// The owner's 1,000 conversations of 20 TURNs of 2 MESSAGEs, unbound.
    fn owner_conversations(&self, start: Instant) -> TestResult {
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
        for conversation in 0..CONVERSATIONS {
            let conversation_ref = EntityId::now().to_hex();
            for turn in 0..TURNS_PER_CONVERSATION {
                memory.witness(&WitnessTurn {
                    conversation_ref: conversation_ref.clone(),
                    turn_ref: None,
                    thread_audience: None,
                    messages: (0..MESSAGES_PER_TURN)
                        .map(|order| WitnessMessage {
                            id: None,
                            author: WitnessAuthor::User,
                            message_type: "dialogue".to_owned(),
                            content: format!("note {conversation}.{turn}.{order} about the day"),
                            parts: None,
                            metadata: None,
                            is_visible: true,
                            order: u32::try_from(order).unwrap_or(u32::MAX),
                            quote: None,
                        })
                        .collect(),
                    occurred_at: OCCURRED_AT - 86_400 + (conversation * 40 + turn) as u64,
                    assertions: WitnessAssertions::default(),
                })?;
            }
            if (conversation + 1) % 100 == 0 {
                println!(
                    "#P {:.1}s owner conversations {}/{CONVERSATIONS}",
                    since(start),
                    conversation + 1
                );
            }
        }
        Ok(())
    }

    /// The 10 source policies, each read by the owner and the IN pen's
    /// PERSON, with 100 mail threads each.
    fn mail(&self, start: Instant) -> TestResult<Vec<Thread>> {
        // The landing's writer, as `mail_pack::landing` builds it.
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
        let readers = BTreeSet::from([self.owner, self.person]);
        let mut threads = Vec::with_capacity(SOURCES * THREADS_PER_SOURCE);
        for source_index in 0..SOURCES {
            let source = door::create_source_policy(&self.vault, readers.clone(), self.owner)?;
            for thread_index in 0..THREADS_PER_SOURCE {
                let conversation = EntityId::now();
                let mut turns = Vec::with_capacity(TURNS_PER_CONVERSATION);
                let mut policy = None;
                for turn in 0..TURNS_PER_CONVERSATION {
                    let texts: Vec<String> = (0..MESSAGES_PER_TURN)
                        .map(|order| format!("mail {source_index}.{thread_index}.{turn}.{order}"))
                        .collect();
                    let landed = door::land_mail_turn(
                        &self.vault,
                        &memory,
                        self.owner,
                        source,
                        conversation,
                        &texts,
                        OCCURRED_AT - 43_200 + (thread_index * 40 + turn) as u64,
                    )?;
                    turns.push(landed.turn);
                    policy = Some(landed.thread);
                }
                threads.push(Thread {
                    policy: policy.ok_or("a thread landed no TURN")?,
                    turns,
                });
            }
            println!(
                "#P {:.1}s mail sources {}/{SOURCES}",
                since(start),
                source_index + 1
            );
        }
        Ok(threads)
    }

    fn claim_input(&mut self, set: &str, index: usize, evidence: &[EntityId]) -> ScopedClaimInput {
        self.claims_written += 1;
        ScopedClaimInput {
            id: Some(EntityId::now().to_hex()),
            predicate: format!("fact.{set}_n{index}"),
            subject_ref: self.owner.to_hex(),
            value: json!(format!("the lease ends in March, fact {set} {index}")),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            scope: ClaimScope {
                world_id: base_world_id().to_hex(),
                scope_facet_id: self.facet.to_hex(),
                scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                scope_project_id: default_project_id().to_hex(),
            },
            sensitivity: None,
            evidence_turn_refs: evidence.iter().map(EntityId::to_hex).collect(),
            valid_from: None,
            valid_to: None,
            occurred_at: Some(OCCURRED_AT),
            learned_at: Some(OCCURRED_AT),
            salience: None,
        }
    }

    /// Writes one claim through the scoped upsert; its id.
    fn upsert(&mut self, set: &str, index: usize, evidence: &[EntityId]) -> TestResult<EntityId> {
        let input = self.claim_input(set, index, evidence);
        let id = EntityId::from_hex(input.id.as_deref().ok_or("claim id")?)?;
        self.owner_memory().claim_upsert_scoped(&input)?;
        Ok(id)
    }

    /// `C0`: 5,000 claims with no lineage.
    fn c0(&mut self, start: Instant) -> TestResult<ClaimSet> {
        let mut rows = Vec::with_capacity(SET_ROWS);
        for index in 0..SET_ROWS {
            rows.push(self.upsert("c0", index, &[])?);
        }
        println!("#P {:.1}s set C0 written", since(start));
        Ok(ClaimSet {
            name: "C0",
            floors: vec![BTreeSet::new(); rows.len()],
            rows,
        })
    }
}

/// The evidence TURNs of claim `index` at K = `k`, with the thread policy of
/// each: K = 1 or 3 in one thread; K = 8 in 8 threads of 2 source policies;
/// K = 64 in 64 threads of all 10.
fn evidence(threads: &[Thread], k: usize, index: usize) -> Vec<(EntityId, EntityId)> {
    let turn_of = |thread: usize, turn: usize| {
        let thread = &threads[thread];
        (thread.turns[turn % thread.turns.len()], thread.policy)
    };
    match k {
        1 => vec![turn_of(index % threads.len(), index / threads.len())],
        3 => {
            let first = (index / threads.len() * 3) % (TURNS_PER_CONVERSATION - 2);
            (0..3)
                .map(|offset| turn_of(index % threads.len(), first + offset))
                .collect()
        }
        8 => {
            let first = index % SOURCES;
            let second = (index + 1) % SOURCES;
            (0..8)
                .map(|offset| {
                    let (source, shift) = if offset < 4 {
                        (first, offset)
                    } else {
                        (second, 50 + offset)
                    };
                    let thread = source * THREADS_PER_SOURCE
                        + (index / SOURCES + shift) % THREADS_PER_SOURCE;
                    turn_of(thread, index)
                })
                .collect()
        }
        _ => (0..64)
            .map(|offset| {
                let source = offset % SOURCES;
                let round = offset / SOURCES;
                let thread =
                    source * THREADS_PER_SOURCE + (index * 3 + round * 17) % THREADS_PER_SOURCE;
                turn_of(thread, index + offset)
            })
            .collect(),
    }
}

fn floor_of(pairs: &[(EntityId, EntityId)]) -> BTreeSet<EntityId> {
    pairs.iter().map(|(_, policy)| *policy).collect()
}

/// `C1`, `C3`, `C8`, `C64`: claims whose birth names K evidence TURNs.
fn evidence_set(
    bench: &mut Bench,
    threads: &[Thread],
    name: &'static str,
    k: usize,
    count: usize,
    start: Instant,
) -> TestResult<ClaimSet> {
    let label = name.to_lowercase();
    let mut rows = Vec::with_capacity(count);
    let mut floors = Vec::with_capacity(count);
    for index in 0..count {
        let pairs = evidence(threads, k, index);
        let turns: Vec<EntityId> = pairs.iter().map(|(turn, _)| *turn).collect();
        rows.push(bench.upsert(&label, index, &turns)?);
        floors.push(floor_of(&pairs));
    }
    println!("#P {:.1}s set {name} written", since(start));
    Ok(ClaimSet { name, rows, floors })
}

/// `E3`: as `C3`, but the lineage is 3 `DerivedFrom` edges from the CLAIM to
/// the TURNs, and the birth names none.
fn e3(bench: &mut Bench, threads: &[Thread], start: Instant) -> TestResult<ClaimSet> {
    let mut rows = Vec::with_capacity(SET_ROWS);
    let mut floors = Vec::with_capacity(SET_ROWS);
    for index in 0..SET_ROWS {
        let pairs = evidence(threads, 3, index);
        let claim = bench.upsert("e3", index, &[])?;
        let mut batch = bench.vault.batch();
        for (turn, _) in &pairs {
            batch = batch.edge(&claim, EdgeKind::DerivedFrom, turn, 1.0);
        }
        batch.commit()?;
        rows.push(claim);
        floors.push(floor_of(&pairs));
    }
    println!("#P {:.1}s set E3 written", since(start));
    Ok(ClaimSet {
        name: "E3",
        rows,
        floors,
    })
}

fn summary_body(text: &str) -> TestResult<Vec<u8>> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(rmpv::Value::from("text"), rmpv::Value::from(text))]),
    )?;
    Ok(body)
}

/// `D3`, depth 3: per claim, 4 SUMMARYs each `DerivedFrom` 8 TURNs of one
/// thread, a second SUMMARY `DerivedFrom` the 4, and a CLAIM whose birth
/// names the second.
fn d3(bench: &mut Bench, threads: &[Thread], start: Instant) -> TestResult<ClaimSet> {
    let mut rows = Vec::with_capacity(SMALL_SET_ROWS);
    let mut floors = Vec::with_capacity(SMALL_SET_ROWS);
    for index in 0..SMALL_SET_ROWS {
        let occurred = TimeRange {
            start: OCCURRED_AT,
            end: OCCURRED_AT,
        };
        let mut floor = BTreeSet::new();
        let mut firsts = Vec::with_capacity(4);
        let mut batch = bench.vault.batch();
        for part in 0..4 {
            let thread = &threads[(index * 4 + part) % threads.len()];
            floor.insert(thread.policy);
            let summary = EntityId::now();
            batch = batch.put(
                &summary,
                ENTITY_TYPE_SUMMARY,
                occurred,
                bench.vault.now_recorded_at(),
                &summary_body(&format!("summary {index}.{part}"))?,
            );
            for offset in 0..8 {
                let turn = thread.turns[(index % 12 + offset) % thread.turns.len()];
                batch = batch.edge(&summary, EdgeKind::DerivedFrom, &turn, 1.0);
            }
            firsts.push(summary);
        }
        let second = EntityId::now();
        batch = batch.put(
            &second,
            ENTITY_TYPE_SUMMARY,
            occurred,
            bench.vault.now_recorded_at(),
            &summary_body(&format!("summary of summaries {index}"))?,
        );
        for first in &firsts {
            batch = batch.edge(&second, EdgeKind::DerivedFrom, first, 1.0);
        }
        batch.commit()?;
        let input = bench.claim_input("d3", index, &[]);
        let claim = EntityId::from_hex(input.id.as_deref().ok_or("claim id")?)?;
        bench
            .owner_memory()
            .claim_upsert_scoped_born_from(&input, &[second])?;
        rows.push(claim);
        floors.push(floor);
    }
    println!("#P {:.1}s set D3 written", since(start));
    Ok(ClaimSet {
        name: "D3",
        rows,
        floors,
    })
}

/// Arm A and the read half of arm E: `ScopedRead::read` of `ids` in frames
/// of 1,000, five passes, the first dropped. Answers the per-row time of
/// each frame and the rows the last pass admitted.
fn time_scoped_read(
    bench: &Bench,
    actor: EntityId,
    ids: &[EntityId],
) -> TestResult<(Vec<u64>, usize)> {
    let mut samples = Vec::new();
    let mut admitted = 0;
    for pass in 0..PASSES {
        admitted = 0;
        for frame in ids.chunks(FRAME) {
            let reads: Vec<PointRead<'_>> = frame.iter().map(|id| PointRead::id(*id)).collect();
            let lane = bench.vault.scoped_read(bench.key(actor)?);
            let start = Instant::now();
            let result = lane.read(&reads, None)?;
            let elapsed = ns(start);
            admitted += result.value.iter().filter(|row| row.is_some()).count();
            if pass > 0 {
                samples.push(elapsed / frame.len() as u64);
            }
        }
    }
    Ok((samples, admitted))
}

/// The search half of arm E: `ScopedRead::search(query, vector, 50, None)`,
/// 50 calls a pass, five passes, the first dropped: the time of each call
/// and the results of the last. MEASURE.md's `&[]` vector is refused
/// (`pipeline/scoped_channels.rs`: `DimensionMismatch`), so the query
/// carries a unit vector of the vault's dimension; the vault has no
/// embedding model, so the vector channel holds no row and the lexical
/// channel answers.
fn time_search(bench: &Bench, actor: EntityId) -> TestResult<(Vec<u64>, usize)> {
    let mut vector = vec![0.0_f32; VaultConfig::default().dimensions];
    if let Some(first) = vector.first_mut() {
        *first = 1.0;
    }
    let mut samples = Vec::new();
    let mut results = 0;
    for pass in 0..PASSES {
        for _ in 0..SEARCH_CALLS_PER_PASS {
            let lane = bench.vault.scoped_read(bench.key(actor)?);
            let start = Instant::now();
            let found = lane.search("lease", &vector, 50, None)?;
            let elapsed = ns(start);
            results = found.value.len();
            if pass > 0 {
                samples.push(elapsed);
            }
        }
    }
    Ok((samples, results))
}

/// A door arm (B, C, D): five passes of `run` over `ids`, the first dropped.
fn time_door(
    ids: &[EntityId],
    run: impl Fn(&[EntityId]) -> oneiron::Result<Vec<RowTime>>,
) -> TestResult<(Vec<u64>, usize)> {
    let mut samples = Vec::new();
    let mut readable = 0;
    for pass in 0..PASSES {
        let times = run(ids)?;
        readable = times.iter().filter(|time| time.verdict).count();
        if pass > 0 {
            samples.extend(times.iter().map(|time| time.ns));
        }
    }
    Ok((samples, readable))
}

/// Arm A over `C0` for both readers in one vault.
fn arm_a(bench: &Bench, c0: &ClaimSet, vault_label: &str) -> TestResult {
    for (reader, actor) in [("IN", bench.pen), ("OUT", bench.outsider)] {
        let (samples, admitted) = time_scoped_read(bench, actor, &c0.rows)?;
        print_cost(
            &Cell {
                arm: "A",
                set: "C0",
                vault: vault_label,
                reader,
                switch: "off",
                rows: c0.rows.len(),
            },
            &samples,
            admitted,
            "frame1000",
        );
    }
    Ok(())
}

/// A reader whose banded Grant admits no CLAIM gets a whole-scope read
/// Grant too, so arm A measures a read and not a refusal; said in a NOTE line.
fn ensure_reads_claims(bench: &Bench, c0: &ClaimSet, vault_label: &str) -> TestResult {
    let sample = &c0.rows[..10.min(c0.rows.len())];
    for (reader, actor) in [("IN", bench.pen), ("OUT", bench.outsider)] {
        let reads: Vec<PointRead<'_>> = sample.iter().map(|id| PointRead::id(*id)).collect();
        let admitted = bench
            .vault
            .scoped_read(bench.key(actor)?)
            .read(&reads, None)?
            .value
            .iter()
            .filter(|row| row.is_some())
            .count();
        println!(
            "#P vault {vault_label} reader {reader} reads {admitted} of {} C0 claims under its banded Grant",
            sample.len()
        );
        if admitted == 0 {
            let mut scope = Scope::top();
            scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
            Bench::grant(&bench.vault, &bench.owner_proof, actor, scope)?;
            println!(
                "## NOTE vault={vault_label} reader={reader} the CLAIM/TURN/MESSAGE banded Grant admitted no CLAIM; a whole-scope read Grant was added"
            );
        }
    }
    Ok(())
}

fn door_cell(bench: &Bench, arm: &str, switch: &str, set: &ClaimSet, probe: bool) -> TestResult {
    for (reader, viewer) in [("IN", bench.pen), ("OUT", bench.outsider)] {
        let (samples, readable) = if probe {
            time_door(&set.rows, |ids| {
                door::time_floor_probe(&bench.vault, ids, viewer)
            })?
        } else {
            time_door(&set.rows, |ids| {
                door::time_mail_walk(&bench.vault, ids, viewer)
            })?
        };
        print_cost(
            &Cell {
                arm,
                set: set.name,
                vault: "V1",
                reader,
                switch,
                rows: set.rows.len(),
            },
            &samples,
            readable,
            "row",
        );
    }
    Ok(())
}

/// Checks 100 sampled rows of `set` against the policies the switched-on
/// walk reaches. Answers the mismatches.
fn floor_check(bench: &Bench, set: &ClaimSet) -> TestResult<usize> {
    let step = (set.rows.len() / FLOOR_SAMPLE).max(1);
    let mut mismatches = 0;
    let mut checked = 0;
    for index in (0..set.rows.len()).step_by(step).take(FLOOR_SAMPLE) {
        let reached = door::walk_policies(&bench.vault, set.rows[index], &[bench.pen])?;
        checked += 1;
        if reached != set.floors[index] {
            mismatches += 1;
            if mismatches <= 3 {
                println!(
                    "#P floor mismatch set {} row {}: walk {} policies, fixture {}",
                    set.name,
                    set.rows[index].to_hex(),
                    reached.len(),
                    set.floors[index].len()
                );
            }
        }
    }
    println!(
        "## FLOORCHECK set={} sampled={checked} mismatches={mismatches}",
        set.name
    );
    Ok(mismatches)
}

#[test]
#[ignore = "bench: Fable pass 30 MEASURE.md; run with --ignored on the fleet"]
fn read_lineage_cost() -> TestResult {
    let start = Instant::now();
    let base = std::env::var_os("LINEAGE_BENCH_DIR")
        .map_or_else(std::env::temp_dir, std::path::PathBuf::from);
    println!(
        "#P host {} base {}",
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap_or_default()
            .trim(),
        base.display()
    );
    door::set_follow_birth_inputs(false);

    // V0: no source.
    {
        let mut v0 = Bench::open(&base, "v0")?;
        v0.owner_conversations(start)?;
        let c0 = v0.c0(start)?;
        ensure_reads_claims(&v0, &c0, "V0")?;
        arm_a(&v0, &c0, "V0")?;
        println!(
            "#P {:.1}s V0 done; data.mdb {} bytes",
            since(start),
            mdb_bytes(v0.dir.path())
        );
    }

    // V1: V0's rows and 10 mailboxes.
    let mut v1 = Bench::open(&base, "v1")?;
    v1.owner_conversations(start)?;
    let c0 = v1.c0(start)?;
    let threads = v1.mail(start)?;
    let c1 = evidence_set(&mut v1, &threads, "C1", 1, SET_ROWS, start)?;
    let c3 = evidence_set(&mut v1, &threads, "C3", 3, SET_ROWS, start)?;
    let c8 = evidence_set(&mut v1, &threads, "C8", 8, SET_ROWS, start)?;
    let c64 = evidence_set(&mut v1, &threads, "C64", 64, SMALL_SET_ROWS, start)?;
    let d3_set = match d3(&mut v1, &threads, start) {
        Ok(set) => Some(set),
        Err(error) => {
            println!("## SKIP set=D3 reason={error}");
            None
        }
    };
    let e3_set = e3(&mut v1, &threads, start)?;
    println!(
        "#P {:.1}s V1 built: {} claims; data.mdb {} bytes",
        since(start),
        v1.claims_written,
        mdb_bytes(v1.dir.path())
    );
    ensure_reads_claims(&v1, &c0, "V1")?;

    // Arm A: today's tax.
    arm_a(&v1, &c0, "V1")?;

    // Arm B: the walk as built.
    door::set_follow_birth_inputs(false);
    for set in [&c0, &e3_set, &c3] {
        door_cell(&v1, "B", "off", set, false)?;
    }

    // The floors the fixture will write, against the walk made correct.
    door::set_follow_birth_inputs(true);
    let mut walk_sets: Vec<&ClaimSet> = vec![&c0, &c1, &c3, &c8, &c64];
    if let Some(set) = &d3_set {
        walk_sets.push(set);
    }
    let mut mismatches = 0;
    for set in walk_sets.iter().copied().chain([&e3_set]) {
        mismatches += floor_check(&v1, set)?;
    }

    // Arm C: the walk made correct.
    for set in &walk_sets {
        door_cell(&v1, "C", "on", set, false)?;
    }

    // Arm E: end to end, today and with the walk made correct.
    for (switch, on) in [("off", false), ("on", true)] {
        door::set_follow_birth_inputs(on);
        match time_scoped_read(&v1, v1.pen, &c3.rows) {
            Ok((samples, admitted)) => print_cost(
                &Cell {
                    arm: "E",
                    set: "C3",
                    vault: "V1",
                    reader: "IN",
                    switch,
                    rows: c3.rows.len(),
                },
                &samples,
                admitted,
                "frame1000",
            ),
            Err(error) => println!("## SKIP arm=E set=C3 switch={switch} reason={error}"),
        }
        match time_search(&v1, v1.pen) {
            Ok((samples, results)) => print_cost(
                &Cell {
                    arm: "E",
                    set: "search",
                    vault: "V1",
                    reader: "IN",
                    switch,
                    rows: 50,
                },
                &samples,
                results,
                "call",
            ),
            Err(error) => println!("## SKIP arm=E set=search switch={switch} reason={error}"),
        }
    }
    door::set_follow_birth_inputs(false);

    // The floors, set by set, and arm S's bytes.
    let mut floored: Vec<&ClaimSet> = vec![&c1, &c3, &c8, &c64];
    if let Some(set) = &d3_set {
        floored.push(set);
    }
    floored.push(&e3_set);
    for set in &floored {
        let before = door::floor_table_bytes(&v1.vault)?;
        let mdb_before = mdb_bytes(v1.dir.path());
        let floors: Vec<(EntityId, BTreeSet<EntityId>)> = set
            .rows
            .iter()
            .copied()
            .zip(set.floors.iter().cloned())
            .collect();
        door::write_floors(&v1.vault, &floors, 500)?;
        let after = door::floor_table_bytes(&v1.vault)?;
        let mdb_after = mdb_bytes(v1.dir.path());
        let entries = after.entries.saturating_sub(before.entries);
        let sources = if set.floors.is_empty() {
            0.0
        } else {
            set.floors
                .iter()
                .map(|floor| floor.len() as f64)
                .sum::<f64>()
                / set.floors.len() as f64
        };
        let growth = i128::from(mdb_after) - i128::from(mdb_before);
        println!(
            "## BYTES set={} sources={sources:.1} entries={entries} key_bytes={} value_bytes={} mdb_growth_per_entry={:.1} key_bytes_per_entry={:.1} value_bytes_per_entry={:.1} mdb_growth={growth}",
            set.name,
            after.key_bytes.saturating_sub(before.key_bytes),
            after.value_bytes.saturating_sub(before.value_bytes),
            if entries == 0 {
                0.0
            } else {
                growth as f64 / entries as f64
            },
            if entries == 0 {
                0.0
            } else {
                after.key_bytes.saturating_sub(before.key_bytes) as f64 / entries as f64
            },
            if entries == 0 {
                0.0
            } else {
                after.value_bytes.saturating_sub(before.value_bytes) as f64 / entries as f64
            },
        );
        let sample = set.rows[0];
        let stored = door::stored_floor(&v1.vault, sample)?.unwrap_or_default();
        assert_eq!(stored, set.floors[0], "the floor written is the fixture's");
    }

    // Arm D: the floor.
    let mut probe_sets: Vec<&ClaimSet> = vec![&c0, &c1, &c3, &c8, &c64];
    if let Some(set) = &d3_set {
        probe_sets.push(set);
    }
    for set in &probe_sets {
        door_cell(&v1, "D", "-", set, true)?;
    }

    // Arm W: the write.
    for k in [1_usize, 3, 8, 64] {
        let label = format!("wk{k}");
        let mut rows = Vec::with_capacity(W_ROWS);
        let mut upserts = Vec::with_capacity(W_ROWS);
        for index in 0..W_ROWS {
            // An index range of its own, past every C set's.
            let pairs = evidence(&threads, k, index + 7 * SET_ROWS);
            let turns: Vec<EntityId> = pairs.iter().map(|(turn, _)| *turn).collect();
            let input = v1.claim_input(&label, index, &turns);
            let id = EntityId::from_hex(input.id.as_deref().ok_or("claim id")?)?;
            let memory = v1.owner_memory();
            let begin = Instant::now();
            memory.claim_upsert_scoped(&input)?;
            upserts.push(ns(begin));
            rows.push(id);
        }
        let (raises, whole) = door::time_raise_floor(&v1.vault, &rows)?;
        let raised = raises.iter().filter(|time| time.verdict).count();
        let raise_ns: Vec<u64> = raises.iter().map(|time| time.ns).collect();
        let set = format!("K{k}");
        print_cost(
            &Cell {
                arm: "W",
                set: &set,
                vault: "V1",
                reader: "owner",
                switch: "upsert",
                rows: W_ROWS,
            },
            &upserts,
            W_ROWS,
            "row",
        );
        print_cost(
            &Cell {
                arm: "W",
                set: &set,
                vault: "V1",
                reader: "owner",
                switch: "raise",
                rows: W_ROWS,
            },
            &raise_ns,
            raised,
            "row",
        );
        let upsert_mean = mean(&upserts);
        let raise_mean = mean(&raise_ns);
        let raise_with_commit = whole as f64 / W_ROWS as f64;
        println!(
            "## WRITE k={k} upsert_mean_ns={upsert_mean:.0} raise_mean_ns={raise_mean:.0} raise_write_per_row_ns={raise_with_commit:.0} ratio_raise_over_upsert={:.5} ratio_with_commit={:.5}",
            raise_mean / upsert_mean,
            raise_with_commit / upsert_mean,
        );
    }
    println!(
        "#P {:.1}s done; data.mdb {} bytes",
        since(start),
        mdb_bytes(v1.dir.path())
    );
    assert_eq!(
        mismatches, 0,
        "a sampled floor differs from the switched-on walk"
    );
    Ok(())
}
