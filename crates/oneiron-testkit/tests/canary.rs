//! The canary leak detector, step 1: each audience class seeded through
//! public verbs reaches the readers in its audience, and no reader outside
//! it finds its word on any surface it reaches.

use std::collections::BTreeSet;

use oneiron_testkit::TestVault;
use oneiron_testkit::canary::{
    CanaryActor, CanaryClass, CanaryScan, CanaryVault, ClaimBand, NEUTRAL_PHRASE, PENDING,
};
use oneiron_testkit::dreamer::{
    DreamerPass, allow_scripted_extraction, attach_test_host, grant_dreamer_read, print_seen,
    read_everything_scope, scripted_backend,
};
use oneiron_testkit::provider::SeenCall;
use serde_json::{Value, json};

fn seeded() -> (TestVault, CanaryVault) {
    CanaryVault::seeded("canary-audiences").expect("the canary fixture seeds through public doors")
}

#[test]
fn every_feasible_audience_class_holds_one_unique_canary_and_no_pending_class_is_seeded() {
    let (_vault, canaries) = seeded();
    let classes: Vec<CanaryClass> = canaries
        .canaries()
        .iter()
        .map(|canary| canary.class)
        .collect();
    assert_eq!(classes, CanaryClass::SEEDED.to_vec());
    let mut words: Vec<&str> = canaries
        .canaries()
        .iter()
        .map(|canary| canary.word.as_str())
        .collect();
    words.sort_unstable();
    words.dedup();
    assert_eq!(
        words.len(),
        canaries.canaries().len(),
        "every canary word is unique"
    );
    for canary in canaries.canaries() {
        assert!(
            canary.word.starts_with("canary")
                && canary
                    .word
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "{} is one token of lower-case letters and digits",
            canary.word
        );
        assert!(
            canary.text.contains(NEUTRAL_PHRASE),
            "{} carries the shared phrase",
            canary.class
        );
        assert!(
            !canary.audience.is_empty(),
            "{} has an audience",
            canary.class
        );
    }
    for pending in PENDING {
        assert!(
            !pending.reason.is_empty(),
            "{} says why it is pending",
            pending.name
        );
        assert!(
            CanaryClass::SEEDED
                .iter()
                .all(|class| class.name() != pending.name),
            "{} is both seeded and pending",
            pending.name
        );
    }
}

#[test]
fn an_agent_granted_only_public_rows_reads_no_canary_outside_its_audience() {
    let (test_vault, canaries) = seeded();
    let vault = test_vault.open_owned().expect("open the seeded vault");
    let scan = canaries.assert_no_canary_leak(&vault, CanaryActor::Outside);
    // A clean scan of a reader that reads nothing proves nothing: its Grant
    // must confer, so it reads the public-band claim.
    let public = canaries.surfaces_seeing(&scan, CanaryClass::Claim(ClaimBand::Public));
    assert!(
        !public.is_empty(),
        "the outside agent's public-band Grant confers on no surface; refused: {:#?}",
        scan.refused
    );
    assert!(scan.incomplete.is_empty(), "{:?}", scan.incomplete);
}

#[test]
fn an_agent_granted_every_band_reads_no_other_actors_diary() {
    let (test_vault, canaries) = seeded();
    let vault = test_vault.open_owned().expect("open the seeded vault");
    let scan = canaries.assert_no_canary_leak(&vault, CanaryActor::Inside);
    let restricted = canaries.surfaces_seeing(&scan, CanaryClass::Claim(ClaimBand::Restricted));
    assert!(
        !restricted.is_empty(),
        "the inside agent's every-band Grant confers on no surface; refused: {:#?}",
        scan.refused
    );
    assert!(scan.incomplete.is_empty(), "{:?}", scan.incomplete);
}

#[test]
fn the_vault_owner_reads_no_agents_diary() {
    let (test_vault, canaries) = seeded();
    let vault = test_vault.open_owned().expect("open the seeded vault");
    let scan = canaries.assert_no_canary_leak(&vault, CanaryActor::Owner);
    assert!(scan.incomplete.is_empty(), "{:?}", scan.incomplete);
}

#[test]
fn every_seeded_class_reaches_a_reader_in_its_audience() {
    let (test_vault, canaries) = seeded();
    let vault = test_vault.open_owned().expect("open the seeded vault");
    let scans: Vec<CanaryScan> = CanaryActor::ALL
        .iter()
        .map(|actor| canaries.scan(&vault, *actor))
        .collect();
    for sighting in canaries.assert_not_blind(&scans) {
        println!("{} seen by {:?}", sighting.class, sighting.seen_by);
    }
}

#[test]
fn the_detector_names_each_canary_that_reaches_a_reader_outside_its_audience() {
    let (test_vault, canaries) = seeded();
    let vault = test_vault.open_owned().expect("open the seeded vault");

    // The owner reads its own canaries. Declared outside every audience, it
    // must be reported for them, one line each, surface named.
    let owner = canaries.scan(&vault, CanaryActor::Owner);
    let lines = canaries.excluding(CanaryActor::Owner).leaks(&owner);
    for class in [
        CanaryClass::Diary(CanaryActor::Owner),
        CanaryClass::OwnerKeyValue,
        CanaryClass::Claim(ClaimBand::Restricted),
    ] {
        let head = format!("LEAK: {class} canary {} reached owner via ", class.word());
        assert!(
            lines.iter().any(|line| line.starts_with(&head)),
            "no line starting `{head}` in:\n{}",
            lines.join("\n")
        );
    }
    // The assertion every leak test relies on fails on that same scan: it
    // panics, never returns the scan. (The panic it prints here is expected.)
    let narrowed = canaries.excluding(CanaryActor::Owner);
    let asserted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        narrowed.assert_no_canary_leak(&vault, CanaryActor::Owner)
    }));
    assert!(
        asserted.is_err(),
        "assert_no_canary_leak returned the scan of a reader that read canaries outside its audience"
    );

    // A prompt is a surface too: the outside agent's diary sent to a model
    // that speaks for the owner leaks it; sent for the outside agent, not.
    let diary = CanaryClass::Diary(CanaryActor::Outside);
    let call = SeenCall {
        step: Some("canary-prompt".to_owned()),
        method: "generate".to_owned(),
        path: String::new(),
        digest: None,
        streamed: false,
        model: None,
        body: json!({"messages": [{"role": "user", "content": [{"type": "text", "text": diary.text()}]}]}),
    };
    let prompt_leaks = canaries.scan_prompts(std::slice::from_ref(&call), &[CanaryActor::Owner]);
    assert_eq!(prompt_leaks.len(), 1, "{prompt_leaks:#?}");
    let head = format!(
        "LEAK: {diary} canary {} reached owner via prompt 0 (step canary-prompt): ",
        diary.word()
    );
    assert!(prompt_leaks[0].starts_with(&head), "{}", prompt_leaks[0]);
    assert!(
        canaries
            .scan_prompts(&[call], &[CanaryActor::Outside])
            .is_empty()
    );
}

/// Whether `surface` is `door` reading an entity by its 32-hex id: a ref an
/// answer named, since the seed holds short refs only.
fn reads_a_named_entity(surface: &str, door: &str) -> bool {
    surface
        .strip_prefix(door)
        .and_then(|rest| rest.strip_prefix(' '))
        .is_some_and(|id| id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

#[test]
fn the_scan_reads_the_point_doors_and_follows_the_refs_its_answers_name() {
    let (test_vault, canaries) = seeded();
    let vault = test_vault.open_owned().expect("open the seeded vault");
    let scan = canaries.scan(&vault, CanaryActor::Owner);
    let restricted = CanaryClass::Claim(ClaimBand::Restricted);
    // Each point door reads the owner's own canary, so a leak through it
    // would show as one.
    for (class, door) in [
        (CanaryClass::OwnerKeyValue, "vault.kv.get"),
        (restricted, "vault.claims.history "),
        (restricted, "vault.refs.resolve "),
        (CanaryClass::RelationshipMessage, "vault.refs.links "),
    ] {
        let surfaces = canaries.surfaces_seeing(&scan, class);
        assert!(
            surfaces.iter().any(|surface| surface.starts_with(door)),
            "the owner's scan read its {class} canary on no `{door}` surface, only on {surfaces:#?}; refused: {:#?}",
            scan.refused
        );
    }
    // The filtered claim doors serve only the claims retrieval may surface
    // (approved or auto, and active), which the restricted-band canary is
    // not: each reads the owner's claim canary in a band it serves.
    for door in ["vault.claims.list_filtered", "vault.claims.read_filtered "] {
        let served = ClaimBand::ALL.into_iter().any(|band| {
            canaries
                .surfaces_seeing(&scan, CanaryClass::Claim(band))
                .iter()
                .any(|surface| surface.starts_with(door))
        });
        assert!(
            served,
            "the owner's scan read no claim canary on a `{door}` surface; refused: {:#?}",
            scan.refused
        );
    }
    // A ref an answer names is followed: the claim lists name the claim by
    // its 32-hex id, which the seed never held.
    let followed = canaries.surfaces_seeing(&scan, restricted);
    assert!(
        followed
            .iter()
            .any(|surface| reads_a_named_entity(surface, "vault.get")),
        "the owner's scan followed no named ref to its {restricted} canary: {followed:#?}"
    );
    assert!(scan.incomplete.is_empty(), "{:?}", scan.incomplete);
}

#[test]
fn the_owners_export_is_scanned_as_its_decoded_archive() {
    let (test_vault, canaries) = seeded();
    let vault = test_vault.open_owned().expect("open the seeded vault");
    let owner = canaries.scan(&vault, CanaryActor::Owner);
    let decoded = "vault.export (archive decoded)".to_owned();
    for class in [
        CanaryClass::Claim(ClaimBand::Restricted),
        CanaryClass::RelationshipMessage,
    ] {
        let surfaces = canaries.surfaces_seeing(&owner, class);
        assert!(
            surfaces.contains(&decoded),
            "the owner's decoded export holds no {class} canary; it was read on {surfaces:#?}; incomplete: {:?}",
            owner.incomplete
        );
    }
    assert!(owner.incomplete.is_empty(), "{:?}", owner.incomplete);
    // An agent's whole-vault export is refused before it reads: owner only.
    let inside = canaries.scan(&vault, CanaryActor::Inside);
    assert!(
        inside
            .refused
            .iter()
            .any(|read| read.surface == "vault.export"),
        "the inside agent's vault.export was not refused; refused: {:#?}",
        inside.refused
    );
}

/// The surface the owner's export is read as, decoded.
const EXPORT_DECODED: &str = "vault.export (archive decoded)";
/// The surface the export's custody records are read as.
const EXPORT_CUSTODY: &str = "vault.export (custody records decoded)";

/// Every surface `scan` read, answered or refused.
fn surfaces(scan: &CanaryScan) -> BTreeSet<&str> {
    scan.seen
        .iter()
        .chain(&scan.refused)
        .map(|read| read.surface.as_str())
        .collect()
}

/// The JSON of each answer `scan` read on `surface`.
fn answers_on(scan: &CanaryScan, surface: &str) -> Vec<Value> {
    scan.seen
        .iter()
        .filter(|read| read.surface == surface)
        .map(|read| serde_json::from_str(&read.text).expect("a decoded surface reads as JSON"))
        .collect()
}

#[test]
fn every_entity_the_owners_export_names_is_followed_through_get_and_resolve() {
    let (test_vault, canaries) = seeded();
    let vault = test_vault.open_owned().expect("open the seeded vault");
    let scan = canaries.scan(&vault, CanaryActor::Owner);
    let ids: Vec<String> = answers_on(&scan, EXPORT_DECODED)
        .iter()
        .filter_map(|document| document.pointer("/evidence_ledger/entities"))
        .filter_map(Value::as_array)
        .flatten()
        .filter_map(|entity| entity.get("id").and_then(Value::as_str))
        .map(str::to_owned)
        .collect();
    assert!(
        !ids.is_empty(),
        "the owner's decoded export names no ledger entity; incomplete: {:?}",
        scan.incomplete
    );
    let read = surfaces(&scan);
    let missed: Vec<String> = ids
        .iter()
        .flat_map(|id| ["vault.get", "vault.refs.resolve"].map(|door| format!("{door} {id}")))
        .filter(|surface| !read.contains(surface.as_str()))
        .collect();
    assert!(
        missed.is_empty(),
        "the owner's scan never read these entities its export names ({} of {} ids): {missed:#?}",
        missed.len(),
        ids.len()
    );
    assert!(scan.incomplete.is_empty(), "{:?}", scan.incomplete);
}

#[test]
fn every_entity_a_scan_gets_by_id_it_also_resolves_whatever_the_get_answered() {
    let (test_vault, canaries) = seeded();
    let vault = test_vault.open_owned().expect("open the seeded vault");
    for actor in CanaryActor::ALL {
        let scan = canaries.scan(&vault, actor);
        let read = surfaces(&scan);
        let unresolved: Vec<&str> = read
            .iter()
            .filter_map(|surface| surface.strip_prefix("vault.get "))
            .filter(|id| id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .filter(|id| !read.contains(format!("vault.refs.resolve {id}").as_str()))
            .collect();
        assert!(
            unresolved.is_empty(),
            "{actor}'s scan read these ids through vault.get and never through vault.refs.resolve: {unresolved:#?}"
        );
    }
}

/// A custody record's name: the owner's decoded export reads it.
const CUSTODY_NAME: &str = "canary-custody-record-name";
/// Its value: no surface may hold it.
const CUSTODY_VALUE: &str = "canary-custody-record-value";
/// The effector its one binding names.
const CUSTODY_EFFECTOR: &str = "canary:custody-scan";
/// Its registration instant, unix seconds.
const CUSTODY_REGISTERED_AT: u64 = 1_767_225_600;

/// Registers an active portable custody record named [`CUSTODY_NAME`]. Its
/// value field is crate-private, so the record is built as
/// tests/it/snapshot_custody_binding.rs builds one: the custody codec's
/// key map, encoded and decoded.
fn register_custody_record(vault: &oneiron::Vault) {
    use oneiron::secret_custody::{
        CustodyClass, CustodyTier, SECRET_CUSTODY_BODY_KEYS, SECRET_CUSTODY_SCHEMA_VERSION,
        SecretCustodyStatus, decode_secret_custody_body,
    };
    use rmpv::Value as Pack;

    let band = |min: u64, max: u64| {
        Pack::Map(vec![
            (Pack::from("min"), Pack::from(min)),
            (Pack::from("max"), Pack::from(max)),
        ])
    };
    let floor = Pack::Map(vec![
        (Pack::from("portable"), band(0, 2)),
        (Pack::from("device_bound"), band(0, 2)),
        (Pack::from("cross_vault"), band(0, 0)),
        (Pack::from("rotation_max_age_secs"), Pack::Nil),
        (Pack::from("env_bindings"), Pack::Map(vec![])),
    ]);
    let binding = Pack::Map(vec![
        (Pack::from("effector"), Pack::from(CUSTODY_EFFECTOR)),
        (
            Pack::from("tier_ceiling"),
            Pack::from(u64::from(CustodyTier::T1Leased.as_u8())),
        ),
        (Pack::from("scopes"), Pack::Array(vec![Pack::from("get")])),
    ]);
    let key = |index: usize| Pack::from(SECRET_CUSTODY_BODY_KEYS[index]);
    let body = Pack::Map(vec![
        (key(0), Pack::from(u64::from(SECRET_CUSTODY_SCHEMA_VERSION))),
        (key(1), Pack::from(CUSTODY_NAME)),
        (key(2), Pack::from(CustodyClass::CustodyPortable.as_str())),
        (key(3), Pack::from(false)),
        (key(4), Pack::Binary(CUSTODY_VALUE.as_bytes().to_vec())),
        (key(5), Pack::from(SecretCustodyStatus::Active.as_str())),
        (key(6), Pack::from(CUSTODY_REGISTERED_AT)),
        (key(7), Pack::Nil),
        (key(8), Pack::from(0_u64)),
        (key(9), Pack::Array(vec![binding])),
        (key(10), Pack::from("")),
        (key(11), Pack::Array(vec![])),
        (key(12), floor),
        (key(13), Pack::from(true)),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body).expect("encode the custody body");
    let record = decode_secret_custody_body(&bytes).expect("decode the custody body");
    vault
        .register_secret(record)
        .expect("register the custody record");
}

#[test]
fn the_owners_decoded_export_reads_each_custody_record_less_its_value() {
    let (test_vault, canaries) = seeded();
    let vault = test_vault.open_owned().expect("open the seeded vault");
    register_custody_record(&vault);
    let scan = canaries.scan(&vault, CanaryActor::Owner);
    let custody = answers_on(&scan, EXPORT_CUSTODY);
    let named: Vec<&Value> = custody
        .iter()
        .filter_map(Value::as_array)
        .flatten()
        .filter(|record| record.get("name").and_then(Value::as_str) == Some(CUSTODY_NAME))
        .collect();
    assert_eq!(
        named.len(),
        1,
        "the owner's scan read the custody record named {CUSTODY_NAME} on no `{EXPORT_CUSTODY}` surface: {custody:?}; incomplete: {:?}",
        scan.incomplete
    );
    assert!(
        named.iter().all(|record| record.get("body").is_none()),
        "the custody surface keeps the record's value field: {named:?}"
    );
    let holding: Vec<&str> = scan
        .seen
        .iter()
        .chain(&scan.refused)
        .filter(|read| read.text.contains(CUSTODY_VALUE))
        .map(|read| read.surface.as_str())
        .collect();
    assert!(
        holding.is_empty(),
        "these surfaces hold the custody value: {holding:?}"
    );
    assert!(scan.incomplete.is_empty(), "{:?}", scan.incomplete);
}

/// The custody records the raw `vault.export` answer in `scan` carries, as
/// the archive's custody member writes them.
fn raw_export_custody_records(scan: &CanaryScan) -> Vec<Value> {
    use std::io::Read as _;

    use oneiron::memory::ExportAnswer;

    let mut records = Vec::new();
    for read in scan
        .seen
        .iter()
        .filter(|read| read.surface == "vault.export")
    {
        let Ok(ExportAnswer::Inline(export)) = serde_json::from_str::<ExportAnswer>(&read.text)
        else {
            panic!("the raw vault.export surface holds no inline export");
        };
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(export.archive))
            .expect("the raw export is a ZIP");
        let mut text = String::new();
        archive
            .by_name("records/secret_custody.jsonl")
            .expect("the raw export has a custody member")
            .read_to_string(&mut text)
            .expect("the custody member reads");
        records.extend(
            text.lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| serde_json::from_str::<Value>(line).expect("a custody line is JSON")),
        );
    }
    records
}

#[test]
fn the_raw_export_the_owners_scan_keeps_carries_no_custody_value() {
    let (test_vault, canaries) = seeded();
    let vault = test_vault.open_owned().expect("open the seeded vault");
    register_custody_record(&vault);
    let scan = canaries.scan(&vault, CanaryActor::Owner);
    let records = raw_export_custody_records(&scan);
    let named = |record: &&Value| record.get("name").and_then(Value::as_str) == Some(CUSTODY_NAME);
    assert_eq!(
        records.iter().filter(named).count(),
        1,
        "the raw export the owner's scan kept names no custody record {CUSTODY_NAME}; incomplete: {:?}",
        scan.incomplete
    );
    let valued: Vec<&str> = records
        .iter()
        .filter(|record| record.get("body").is_some_and(|body| !body.is_null()))
        .map(|record| record.get("name").and_then(Value::as_str).unwrap_or("?"))
        .collect();
    assert!(
        valued.is_empty(),
        "the raw export the owner's scan kept carries the values of these custody records: {valued:?}"
    );
}

/// The 32 hex of each entity reference node in `value`: a decoded export
/// writes a MessagePack body as its nodes, an id slot as
/// `{"type": "entity_reference", "value": [<16 bytes>]}`.
fn entity_reference_nodes(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(fields) => {
            if fields.get("type").and_then(Value::as_str) == Some("entity_reference")
                && let Some(bytes) = fields.get("value").and_then(Value::as_array)
            {
                out.insert(
                    bytes
                        .iter()
                        .filter_map(Value::as_u64)
                        .map(|byte| format!("{byte:02x}"))
                        .collect(),
                );
            }
            for item in fields.values() {
                entity_reference_nodes(item, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                entity_reference_nodes(item, out);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

#[test]
fn every_entity_reference_in_the_owners_decoded_export_is_followed_through_get_and_resolve() {
    let (test_vault, canaries) = seeded();
    let vault = test_vault.open_owned().expect("open the seeded vault");
    let scan = canaries.scan(&vault, CanaryActor::Owner);
    let mut ids = BTreeSet::new();
    for document in answers_on(&scan, EXPORT_DECODED) {
        entity_reference_nodes(&document, &mut ids);
    }
    assert!(
        !ids.is_empty(),
        "the owner's decoded export holds no entity reference node (each claim's worldId is one); incomplete: {:?}",
        scan.incomplete
    );
    let read = surfaces(&scan);
    let missed: Vec<String> = ids
        .iter()
        .flat_map(|id| ["vault.get", "vault.refs.resolve"].map(|door| format!("{door} {id}")))
        .filter(|surface| !read.contains(surface.as_str()))
        .collect();
    assert!(
        missed.is_empty(),
        "the owner's scan never read these entity references its decoded export holds ({} of {} ids): {missed:#?}",
        missed.len(),
        ids.len()
    );
    assert!(scan.incomplete.is_empty(), "{:?}", scan.incomplete);
}

/// The turn wake's model calls over the canary vault, as `(prompt digest,
/// reply)` (see tests/dreamer.rs for how a table is filled). The turn wake
/// reads the newest owner turn, the relationship message, with the owner's
/// three claims (public, private and private-flag) listed beside it, and its
/// reply proposes no claim. A claim extracted from that message inherits its
/// relationship set (dreamer_consolidation/executor/extraction.rs), and a
/// relationship-stamped claim lands only over a live RELATIONSHIP row, which
/// no public door mints (the pending class `claim/relationship`; the fixture
/// mints the space's row through `Vault::put_entity`, since a MESSAGE's rel
/// must name one). The rescan of a row the pass derived waits for that door.
const DREAMER_TURN_WAKE_CALLS: &[(&str, &str)] = &[(
    "e0f6de2c4438d6edd527c59320a5704a8c59f24d613b4478d7059f019aeca343",
    r#"{"candidates":[],"persons":[]}"#,
)];

/// The Timer wake's model calls over the canary vault, after the turn wake.
const DREAMER_TIMER_WAKE_CALLS: &[(&str, &str)] = &[];

#[test]
fn a_dreamer_pass_sends_the_model_no_agents_diary_and_leaks_no_canary() {
    let (test_vault, canaries) = seeded();
    let vault = test_vault.open_owned().expect("open the seeded vault");
    attach_test_host(&vault).expect("the test host attaches after the open");
    allow_scripted_extraction(&vault).expect("the owner lets extraction run on the scripted model");
    grant_dreamer_read(&vault, read_everything_scope())
        .expect("the owner grants the Dreamer its reads");

    let turn = scripted_backend("canary-turn-wake", DREAMER_TURN_WAKE_CALLS);
    let turn_pass = DreamerPass::new(&turn)
        .with_run_id("canary-turn-wake")
        .run_turn_wake(&vault, test_vault.clock());
    print_seen(&turn.seen());
    let timer = scripted_backend("canary-timer-wake", DREAMER_TIMER_WAKE_CALLS);
    let timer_pass = DreamerPass::new(&timer)
        .with_run_id("canary-timer-wake")
        .run_timer_wake(&vault, test_vault.clock());
    print_seen(&timer.seen());
    // Both wakes run before either script is checked, so one run names every
    // call a table misses.
    let mut prompts = turn.finish();
    prompts.extend(timer.finish());
    // Either pass's error names the other's outcome too.
    let (turn_report, timer_report) = match (turn_pass, timer_pass) {
        (Ok(turn), Ok(timer)) => (turn, timer),
        (turn, timer) => panic!(
            "turn wake: {}\ntimer wake: {}",
            turn.map_or_else(|error| error.to_string(), |_| "finished".to_owned()),
            timer.map_or_else(|error| error.to_string(), |_| "finished".to_owned()),
        ),
    };
    for report in [&turn_report, &timer_report] {
        println!(
            "## DREAMER {:?} wake: {} claim(s) landed in {} ms; queue after it: {:?}",
            report.wake,
            report.landed().len(),
            report.wall_ms,
            report.queue
        );
        for attempt in &report.attempts {
            println!(
                "## DREAMER {:?} wake ran {} {} in {} ms (unlent: {}): {:?}",
                report.wake,
                attempt.attempt_type,
                attempt.attempt_id,
                attempt.wall_ms,
                attempt.unlent,
                attempt.execution
            );
        }
    }

    // The Dreamer's model speaks for the owner, so a prompt may carry what
    // the owner may read and never an agent's diary.
    let prompt_leaks = canaries.scan_prompts(&prompts, &[CanaryActor::Owner]);
    assert!(prompt_leaks.is_empty(), "{}", prompt_leaks.join("\n"));
    // The positive control: the prompts did carry restricted canaries, and
    // the scan names each one once the owner is outside its audience.
    let carried = canaries
        .excluding(CanaryActor::Owner)
        .scan_prompts(&prompts, &[CanaryActor::Owner]);
    for class in [
        CanaryClass::RelationshipMessage,
        CanaryClass::PrivateFlagClaim,
    ] {
        let head = format!("LEAK: {class} canary ");
        assert!(
            carried.iter().any(|line| line.starts_with(&head)),
            "the Dreamer's prompts carried no {class} canary, so the prompt scan proves nothing for it:\n{}",
            carried.join("\n")
        );
    }

    // What the passes wrote reaches no reader outside a canary's audience.
    for actor in CanaryActor::ALL {
        let scan = canaries.assert_no_canary_leak(&vault, actor);
        assert!(scan.incomplete.is_empty(), "{actor}: {:?}", scan.incomplete);
    }
}
