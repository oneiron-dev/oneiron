#![cfg(oneiron_test_support)]
//! The owner's restore installs the held egress, protection and scheduled-effect side tables live (SIDE-4a).
//!
//! Public doors only; neutral fixtures (`yuki`); vaults in tempdirs. Each destination
//! opens at least one wall-clock second after its source (sleep 1100 ms), as
//! in `archive_import_retained_side_rows.rs`.
//!
//! * `the_owner_restore_installs_the_egress_rows_and_the_scan_mode_and_the_actorless_import_does_not`:
//!   the owner import installs one WEB_CONNECTOR_SETTING row (Exa on a named
//!   secret, non-default), one MODEL_OWNER_FALLBACK row and one
//!   OWNER_POLICY_SECRET_SCAN_MODE row (Off) live and reports one installed
//!   row for each; a repeat owner import reports one unchanged live row for
//!   each; the actorless import of the same archive leaves every read at its
//!   default and installs nothing, while the archive retains one tuple per table.
//! * `a_past_due_person_schedule_installs_with_its_next_run_after_the_import`:
//!   a Person Daily schedule with `next_due_at: 1` installs with its next run
//!   at or after the import time, phase-kept from 1, with no hold and no saved
//!   period for the missed window; a repeat owner import reports one kept-live
//!   row (the destination holds live-adapted bytes, not the source bytes).
//!   No `render_due` first-run assertion: it cannot be proven fixture-safe
//!   without execution (the live projection's grant and manifest path needs a run).
//! * `unknown_provider_choices_install_verbatim`: a fallback row naming a model
//!   the destination serves no rung for, and a web setting naming a hub
//!   connector the destination never installed, still install live byte for
//!   byte: the rows are choices, and every use-time door fails closed.
//! * `the_owner_restore_installs_the_responses_store_switch_live`,
//!   `the_owner_restore_installs_the_dreamer_sieve_policy_live` and
//!   `the_owner_restore_installs_the_dreamer_wake_policy_live`: one non-default
//!   MODEL_OWNER_RESPONSES_STORE, DREAMER_SIEVE_POLICY and DREAMER_WAKE_POLICY row
//!   each installs on a bare destination, and the destination's own read returns
//!   the source's value where it returned the shipped default before the import.
//! * `the_owner_restore_installs_the_digest_settings_and_the_coach_proposal_live`:
//!   the owner's digest settings row and one Pending Coach proposal
//!   (WEAVE_DIGEST_SETTINGS, WEAVE_DIGEST_SETTING_CHANGE) install together, and the
//!   owner's accept on the destination applies the restored proposal on the
//!   restored generation.
//!
//! DREAMER_WAKE_RECIPE_POLICY has no landing and no test: the export withholds
//! every row of it (FIX-LIST ARCHIVE-WAKE-RECIPE-POLICY-WITHHELD-AS-CREDENTIAL).
//!
//! New report counts are read through `serde_json::to_value` of the SIDE-1
//! summary, so this file compiles on the base; an absent field fails its
//! assertion as a missing outcome, never as a setup panic.
//! `cargo test --locked -p oneiron --all-features --test archive_import_owner_installs_side_effects`.

#[path = "archive_import_retained_side_rows.rs"]
mod retained_side_rows;

use std::io::Cursor;

use oneiron::claim::{
    ScopedReadActorKey, WeaveDigestCadence, WeaveDigestFeedback, WeaveDigestReader,
    WeaveDigestSchedule, WeaveDigestSettingChangeStatus, WeaveReader, WeaveSectionKind,
    WeaveSectionSpec,
};
use oneiron::policy_model::SecretScanMode;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::web_connector::{WebConnectorSetting, WebProvider, WebProviderKey};
use oneiron::{DreamerHomeNodeCandidate, DreamerRunnerStore, EntityId, TimeRange};
use retained_side_rows::{
    export_whole, open_later_vault, open_source_vault, owner_proof, retained_rows, rows_for,
};

/// A fixed entity id from one repeated byte. The banned bytes (00, 11, 42,
/// 47, A1..A6, D7, E1, FF) belong to other fixtures.
fn fixed_id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("a non-reserved repeated byte is a valid entity id")
}

/// The `field` count for `table` in a `retained_side_rows` JSON summary, when
/// the table entry and the field are both present.
fn table_count(summary: &serde_json::Value, table: &str, field: &str) -> Option<u64> {
    summary
        .get("tables")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("source_table").and_then(|name| name.as_str()) == Some(table))?
        .get(field)?
        .as_u64()
}

/// The three egress and protection tables the first test carries through the archive.
const EFFECT_TABLES: [&str; 3] = [
    "WEB_CONNECTOR_SETTING",
    "MODEL_OWNER_FALLBACK",
    "OWNER_POLICY_SECRET_SCAN_MODE",
];

/// The owner restore installs the egress rows and the scan mode live; the
/// actorless import leaves every read at its default.
#[test]
fn the_owner_restore_installs_the_egress_rows_and_the_scan_mode_and_the_actorless_import_does_not()
{
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let offer = "ab".repeat(32);
    assert_eq!(offer.len(), 64, "the offer key is 64 hex: {offer:?}");
    let model = "test-provider/test-model@1";
    let web = WebConnectorSetting {
        provider: WebProvider::Exa,
        key: WebProviderKey::Secret {
            name: "test-web-key".to_owned(),
        },
    };
    assert_ne!(
        web,
        WebConnectorSetting::default(),
        "the web fixture is non-default so live-vs-absent is observable"
    );
    source
        .replace_web_connector_setting_as_owner(&source_owner, web.clone())
        .expect("the owner stores the source web setting");
    assert_eq!(
        source
            .web_connector_setting()
            .expect("read the source web setting"),
        web,
        "the source holds the web row"
    );
    source
        .set_model_fallback(&offer, model)
        .expect("the owner stores the source fallback row");
    assert_eq!(
        source
            .model_fallback(&offer)
            .expect("read the source fallback row"),
        Some(model.to_owned()),
        "the source holds the fallback row"
    );
    let at = source.now_recorded_at();
    source
        .set_secret_scan_mode(&source_owner, SecretScanMode::Off, at)
        .expect("the owner switches the source scan off");
    assert_eq!(
        source
            .secret_scan_mode()
            .expect("read the source scan mode"),
        SecretScanMode::Off,
        "the source holds the scan row"
    );
    let archive = export_whole(&source);

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    assert_eq!(
        dest.web_connector_setting()
            .expect("read the restored web setting"),
        web,
        "the owner import installs the web row live"
    );
    assert_eq!(
        dest.model_fallback(&offer)
            .expect("read the restored fallback row"),
        Some(model.to_owned()),
        "the owner import installs the fallback row live"
    );
    assert_eq!(
        dest.secret_scan_mode()
            .expect("read the restored scan mode"),
        SecretScanMode::Off,
        "the owner import installs the scan row live"
    );
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    for table in EFFECT_TABLES {
        assert_eq!(
            table_count(&summary, table, "installed_rows"),
            Some(1),
            "the owner import reports one installed {table} row; an absent field means it installed nothing: {summary}"
        );
    }

    let repeat = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the repeat owner import succeeds");
    let repeat_summary =
        serde_json::to_value(&repeat.retained_side_rows).expect("the repeat summary serializes");
    for table in EFFECT_TABLES {
        assert_eq!(
            table_count(&repeat_summary, table, "unchanged_live_rows"),
            Some(1),
            "the repeat owner import reports one unchanged live {table} row; an absent field means it counted no live outcome: {repeat_summary}"
        );
        assert_eq!(
            table_count(&repeat_summary, table, "installed_rows"),
            Some(0),
            "the repeat owner import installs no {table} row; an absent field means it counted no live outcome: {repeat_summary}"
        );
    }

    let (_bare_dir, bare) = open_later_vault();
    let bare_receipt = bare
        .import_whole_vault_archive_from(Cursor::new(&archive))
        .expect("the actorless import succeeds");
    assert_eq!(
        bare.web_connector_setting()
            .expect("read the actorless web setting"),
        WebConnectorSetting::default(),
        "the actorless import leaves the web setting at its default"
    );
    assert_eq!(
        bare.model_fallback(&offer)
            .expect("read the actorless fallback row"),
        None,
        "the actorless import leaves the fallback row unset"
    );
    assert_eq!(
        bare.secret_scan_mode()
            .expect("read the actorless scan mode"),
        SecretScanMode::On,
        "the actorless import leaves the scan mode on"
    );
    let bare_summary =
        serde_json::to_value(&bare_receipt.retained_side_rows).expect("the summary serializes");
    for table in EFFECT_TABLES {
        assert!(
            matches!(
                table_count(&bare_summary, table, "installed_rows"),
                None | Some(0)
            ),
            "the actorless import installs no {table} row: {bare_summary}"
        );
    }
    for table in EFFECT_TABLES {
        assert_eq!(
            rows_for(&retained_rows(&archive), table).len(),
            1,
            "the source archive holds one retained {table} tuple"
        );
    }
}

/// A past-due Person schedule installs with its next run at or after the
/// import time; no missed-window run fires.
#[test]
fn a_past_due_person_schedule_installs_with_its_next_run_after_the_import() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let yuki = fixed_id(0x35);
    source
        .put_entity(
            &yuki,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"reader",
        )
        .expect("the source holds the person reader");
    let recipe = vec![WeaveSectionSpec {
        kind: WeaveSectionKind::Links,
        predicates: vec!["report.digest".to_owned()],
        edge_kinds: Vec::new(),
    }];
    let schedule = WeaveDigestSchedule {
        reader: WeaveDigestReader::Person(yuki),
        cadence: WeaveDigestCadence::Daily,
        next_due_at: 1,
        recipe,
    };
    source
        .set_weave_digest_schedule(&source_owner, &schedule)
        .expect("the owner stores the source person schedule");
    let stored = source
        .weave_digest_schedule(&source_owner, WeaveDigestReader::Person(yuki))
        .expect("read the source person schedule");
    assert!(stored.is_some(), "the source holds the person schedule");
    assert_eq!(
        stored.expect("the source schedule reads").next_due_at,
        1,
        "the source schedule is past due"
    );
    let archive = export_whole(&source);

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let t0 = dest.now_recorded_at();
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let live = dest
        .weave_digest_schedule(&dest_owner, WeaveDigestReader::Person(yuki))
        .expect("read the restored person schedule");
    assert!(
        live.is_some(),
        "the owner import installs the person schedule live; None means it installed nothing"
    );
    let live = live.unwrap();
    assert!(
        live.next_due_at >= t0,
        "the restored run is at or after the import time {}: {}",
        t0,
        live.next_due_at
    );
    assert_eq!(
        (live.next_due_at - 1) % 86_400,
        0,
        "the restored run keeps the Daily phase from 1: {}",
        live.next_due_at
    );
    let holds = dest
        .weave_digest_schedules(&dest_owner)
        .expect("read the restored schedule holds");
    assert_eq!(
        holds.len(),
        1,
        "the destination holds one schedule after the import: {holds:?}"
    );
    assert!(
        holds[0].1.is_none(),
        "the restored schedule carries no hold: {:?}",
        holds[0].1
    );
    let lane = dest
        .scoped_read(ScopedReadActorKey::new(yuki.to_hex()).expect("the person actor key builds"));
    assert!(
        matches!(
            lane.read_weave_digest(WeaveReader::Person(yuki), 1),
            Ok(None)
        ),
        "no digest is saved for the missed window"
    );
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "WEAVE_DIGEST_SCHEDULE", "installed_rows"),
        Some(1),
        "the owner import reports one installed WEAVE_DIGEST_SCHEDULE row; an absent field means it installed nothing: {summary}"
    );

    let repeat = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the repeat owner import succeeds");
    let repeat_summary =
        serde_json::to_value(&repeat.retained_side_rows).expect("the repeat summary serializes");
    assert_eq!(
        table_count(&repeat_summary, "WEAVE_DIGEST_SCHEDULE", "kept_live_rows"),
        Some(1),
        "the repeat owner import reports one kept-live WEAVE_DIGEST_SCHEDULE row; an absent field means it counted no live outcome: {repeat_summary}"
    );
}

/// Unknown models and hub choices install verbatim: the rows are choices,
/// and every use-time door fails closed.
#[test]
fn unknown_provider_choices_install_verbatim() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let offer = "ab".repeat(32);
    assert_eq!(offer.len(), 64, "the offer key is 64 hex: {offer:?}");
    let unknown_model = "no-such-provider/no-such-model@0";
    let unknown_hub = WebConnectorSetting {
        provider: WebProvider::Exa,
        key: WebProviderKey::Hub {
            connector: "no-such-hub-connector".to_owned(),
        },
    };
    source
        .set_model_fallback(&offer, unknown_model)
        .expect("the owner stores the unknown fallback row");
    assert_eq!(
        source
            .model_fallback(&offer)
            .expect("read the source fallback row"),
        Some(unknown_model.to_owned()),
        "the source holds the unknown fallback row"
    );
    source
        .replace_web_connector_setting_as_owner(&source_owner, unknown_hub.clone())
        .expect("the owner stores the unknown hub setting");
    assert_eq!(
        source
            .web_connector_setting()
            .expect("read the source web setting"),
        unknown_hub,
        "the source holds the unknown hub row"
    );
    let archive = export_whole(&source);

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    assert_eq!(
        dest.model_fallback(&offer)
            .expect("read the restored fallback row"),
        Some(unknown_model.to_owned()),
        "the owner import installs the unknown fallback row verbatim"
    );
    assert_eq!(
        dest.web_connector_setting()
            .expect("read the restored web setting"),
        unknown_hub,
        "the owner import installs the unknown hub row verbatim"
    );
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "MODEL_OWNER_FALLBACK", "installed_rows"),
        Some(1),
        "the owner import reports one installed MODEL_OWNER_FALLBACK row; an absent field means it installed nothing: {summary}"
    );
    assert_eq!(
        table_count(&summary, "WEB_CONNECTOR_SETTING", "installed_rows"),
        Some(1),
        "the owner import reports one installed WEB_CONNECTOR_SETTING row; an absent field means it installed nothing: {summary}"
    );
}

/// The owner restore installs the Responses store switch live.
#[test]
fn the_owner_restore_installs_the_responses_store_switch_live() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    assert!(
        !source
            .responses_store()
            .expect("read the source store switch"),
        "the source switch starts off"
    );
    source
        .set_responses_store(&source_owner, true)
        .expect("the owner turns the source switch on");
    assert!(
        source
            .responses_store()
            .expect("read the source store switch"),
        "the source holds the store row"
    );
    let archive = export_whole(&source);
    assert_eq!(
        rows_for(&retained_rows(&archive), "MODEL_OWNER_RESPONSES_STORE").len(),
        1,
        "the source archive holds one retained MODEL_OWNER_RESPONSES_STORE tuple"
    );
    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    assert!(
        !dest
            .responses_store()
            .expect("read the destination switch before"),
        "the destination switch starts off"
    );
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "MODEL_OWNER_RESPONSES_STORE", "installed_rows"),
        Some(1),
        "the owner import reports one installed MODEL_OWNER_RESPONSES_STORE row; an absent field means it installed nothing: {summary}"
    );
    assert!(
        dest.responses_store()
            .expect("read the restored store switch"),
        "the owner import installs the store row live"
    );
}

/// The owner restore installs the Dreamer sieve policy live.
#[test]
fn the_owner_restore_installs_the_dreamer_sieve_policy_live() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let defaults = source
        .dreamer_sieve_policy()
        .expect("read the shipped sieve defaults");
    let mut policy = defaults;
    policy.date_interest += 1;
    assert_ne!(
        policy, defaults,
        "the sieve fixture differs from the defaults"
    );
    source
        .set_dreamer_sieve_policy(&source_owner, policy)
        .expect("the owner stores the source sieve row");
    assert_eq!(
        source
            .dreamer_sieve_policy()
            .expect("read the source sieve row"),
        policy,
        "the source holds the sieve row"
    );
    let archive = export_whole(&source);
    assert_eq!(
        rows_for(&retained_rows(&archive), "DREAMER_SIEVE_POLICY").len(),
        1,
        "the source archive holds one retained DREAMER_SIEVE_POLICY tuple"
    );
    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    assert_eq!(
        dest.dreamer_sieve_policy()
            .expect("read the destination sieve before"),
        defaults,
        "the destination reads the shipped sieve defaults before the import"
    );
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "DREAMER_SIEVE_POLICY", "installed_rows"),
        Some(1),
        "the owner import reports one installed DREAMER_SIEVE_POLICY row; an absent field means it installed nothing: {summary}"
    );
    assert_eq!(
        dest.dreamer_sieve_policy()
            .expect("read the restored sieve row"),
        policy,
        "the owner import installs the sieve row live"
    );
}

/// The owner restore installs the Dreamer wake policy live.
#[test]
fn the_owner_restore_installs_the_dreamer_wake_policy_live() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let defaults = source
        .dreamer_wake_policy()
        .expect("read the shipped wake defaults");
    let mut policy = defaults;
    policy.longest_wait_secs += 1;
    assert_ne!(
        policy, defaults,
        "the wake fixture differs from the defaults"
    );
    source
        .set_dreamer_wake_policy(&source_owner, policy)
        .expect("the owner stores the source wake row");
    assert_eq!(
        source
            .dreamer_wake_policy()
            .expect("read the source wake row"),
        policy,
        "the source holds the wake row"
    );
    let archive = export_whole(&source);
    assert_eq!(
        rows_for(&retained_rows(&archive), "DREAMER_WAKE_POLICY").len(),
        1,
        "the source archive holds one retained DREAMER_WAKE_POLICY tuple"
    );
    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    assert_eq!(
        dest.dreamer_wake_policy()
            .expect("read the destination wake before"),
        defaults,
        "the destination reads the shipped wake defaults before the import"
    );
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "DREAMER_WAKE_POLICY", "installed_rows"),
        Some(1),
        "the owner import reports one installed DREAMER_WAKE_POLICY row; an absent field means it installed nothing: {summary}"
    );
    assert_eq!(
        dest.dreamer_wake_policy()
            .expect("read the restored wake row"),
        policy,
        "the owner import installs the wake row live"
    );
}

/// The owner restore installs the digest settings row and the Coach proposal live: the
/// source files one Pending proposal from the owner's feedback, the archive carries one
/// tuple per table, the owner import installs both, and the owner's accept applies the
/// restored change on the restored generation.
#[test]
fn the_owner_restore_installs_the_digest_settings_and_the_coach_proposal_live() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let owner = source
        .ensure_embedded_owner_actor()
        .expect("embedded owner");
    let recipe = vec![WeaveSectionSpec {
        kind: WeaveSectionKind::Links,
        predicates: vec!["report.digest".to_owned()],
        edge_kinds: Vec::new(),
    }];
    let schedule = WeaveDigestSchedule {
        reader: WeaveDigestReader::Owner(owner),
        cadence: WeaveDigestCadence::Daily,
        next_due_at: 1,
        recipe,
    };
    source
        .set_weave_digest_schedule(&source_owner, &schedule)
        .expect("the owner stores the source schedule");
    let stored = source
        .weave_digest_schedule(&source_owner, WeaveDigestReader::Owner(owner))
        .expect("read the source schedule")
        .expect("the source holds the schedule");
    assert_eq!(
        stored.cadence,
        WeaveDigestCadence::Daily,
        "the source schedule is daily"
    );
    let feedback = WeaveDigestFeedback {
        preferred_cadence: Some(WeaveDigestCadence::Weekly),
        lead_section: None,
        keep_current: false,
    };
    assert_eq!(
        source
            .set_weave_digest_feedback(&source_owner, &feedback)
            .expect("the owner tells the Coach weekly"),
        feedback,
        "the feedback lands"
    );
    let runner = DreamerRunnerStore::new(&source);
    let me = runner
        .local_home_node_candidate(false, false, false)
        .expect("the local node id");
    let now = source.now_recorded_at();
    let home = runner
        .elect_home_node(
            &[DreamerHomeNodeCandidate::always_on_local(me.node_id)],
            now,
        )
        .expect("the home election runs");
    assert_eq!(
        home.map(|designation| designation.node_id),
        Some(me.node_id),
        "this node is the elected home"
    );
    source
        .serve_due_weave_digests(now, me.node_id)
        .expect("the timer serves");
    let changes = source
        .weave_digest_setting_changes(&source_owner)
        .expect("read the source changes");
    assert_eq!(
        changes.len(),
        1,
        "the Coach files one proposal: {changes:?}"
    );
    assert_eq!(
        changes[0].status,
        WeaveDigestSettingChangeStatus::Pending,
        "the proposal waits for an answer"
    );
    assert_eq!(
        changes[0].after.cadence,
        WeaveDigestCadence::Weekly,
        "the proposal sets the asked rhythm"
    );
    assert_eq!(
        changes[0].base_generation, 1,
        "the proposal stands on the first generation"
    );
    let archive = export_whole(&source);
    assert_eq!(
        rows_for(&retained_rows(&archive), "WEAVE_DIGEST_SETTINGS").len(),
        1,
        "the archive holds one settings tuple"
    );
    assert_eq!(
        rows_for(&retained_rows(&archive), "WEAVE_DIGEST_SETTING_CHANGE").len(),
        1,
        "the archive holds one change tuple"
    );

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    assert!(
        dest.weave_digest_setting_changes(&dest_owner)
            .expect("read the destination changes before")
            .is_empty(),
        "the bare destination holds no change"
    );
    assert!(
        dest.weave_digest_schedule(&dest_owner, WeaveDigestReader::Owner(owner))
            .expect("read the destination schedule before")
            .is_none(),
        "the bare destination holds no schedule"
    );
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "WEAVE_DIGEST_SETTINGS", "installed_rows"),
        Some(1),
        "one installed WEAVE_DIGEST_SETTINGS row; an absent field means none: {summary}"
    );
    assert_eq!(
        table_count(&summary, "WEAVE_DIGEST_SETTING_CHANGE", "installed_rows"),
        Some(1),
        "one installed WEAVE_DIGEST_SETTING_CHANGE row; an absent field means none: {summary}"
    );
    let restored = dest
        .weave_digest_setting_changes(&dest_owner)
        .expect("read the restored changes");
    assert_eq!(
        restored.len(),
        1,
        "the destination holds one change: {restored:?}"
    );
    assert_eq!(
        restored[0].status,
        WeaveDigestSettingChangeStatus::Pending,
        "the restored change waits for an answer"
    );
    assert_eq!(
        restored[0].after.cadence,
        WeaveDigestCadence::Weekly,
        "the restored change sets the asked rhythm"
    );
    let change_id = EntityId::from_hex(&restored[0].change_ref).expect("the change ref parses");
    let answered = dest
        .answer_weave_digest_setting_change(&dest_owner, change_id, true)
        .expect("the accept applies on the live generation");
    assert_eq!(
        answered.status,
        WeaveDigestSettingChangeStatus::Accepted,
        "the accept settles the restored change"
    );
    let live = dest
        .weave_digest_schedule(&dest_owner, WeaveDigestReader::Owner(owner))
        .expect("read the applied schedule")
        .expect("the destination holds the schedule");
    assert_eq!(
        live.cadence,
        WeaveDigestCadence::Weekly,
        "the accept sets the restored schedule weekly"
    );
}
