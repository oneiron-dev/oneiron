//! ROLES-CHECKIN PR 1 (ONEIRON-ARCH-0082): the check-in modes, the act
//! table, the role defaults and the `check_in` resolution of power, mode,
//! rung 0 and the unsure test.
//!
//! Rulings: ROLES-CHECKIN = A with R1 = A, R3 = B split (owner, 10 Nov 08:42
//! and 08:43), R4 seven presets; the catastrophe floor's one home is
//! ARCH-0082 #catastrophe-floor.
//!
//! `cargo test --locked -p oneiron --all-features --test check_in_tables`.

use std::cell::Cell;
use std::collections::BTreeSet;

use oneiron::check_in::{
    ACT_CLASS, ActClass, CheckInAnswer, CheckInMode, CheckInRequest, GoReason, ModeSource,
    ModelCheck, ROLE_PRESET, ResolvedMode, RoleDefault, RolePreset, UnsureTest, WaitReason,
    check_in, check_in_with_mode, resolve_mode,
};
use oneiron::consent::CATASTROPHE_FLOOR_V2;
use oneiron::federation::FederationGrantRole;
use oneiron::{Error, Result};

use CheckInMode::{AlwaysAsk, AskWhenUnsure, NeverAsk};

/// The rung-1 stand-in: `None` fails, as a missing model does.
struct Stub {
    answer: Option<bool>,
    calls: Cell<usize>,
}

impl Stub {
    fn new(answer: Option<bool>) -> Self {
        Self {
            answer,
            calls: Cell::new(0),
        }
    }
}

impl UnsureTest for Stub {
    fn is_sure(&self) -> Result<bool> {
        self.calls.set(self.calls.get() + 1);
        self.answer
            .ok_or_else(|| Error::InvalidConfig("no decision model".to_owned()))
    }
}

fn request(role: RolePreset, act: ActClass) -> CheckInRequest<'static> {
    CheckInRequest {
        act,
        role,
        holds_power: true,
        explicit_mode: None,
        standing_row: None,
    }
}

fn mode_of(resolved: ResolvedMode) -> Option<CheckInMode> {
    match resolved {
        ResolvedMode::Mode { mode, .. } => Some(mode),
        _ => None,
    }
}

#[test]
fn strictest_mode_wins() {
    for a in CheckInMode::ALL {
        for b in CheckInMode::ALL {
            assert_eq!(a.stricter(b), b.stricter(a), "{a:?} {b:?}");
        }
        assert_eq!(a.stricter(AlwaysAsk), AlwaysAsk);
        assert_eq!(a.stricter(NeverAsk), a);
    }
    assert_eq!(AskWhenUnsure.stricter(NeverAsk), AskWhenUnsure);
}

/// The stored and digested wire tokens stay the fan-out's (CHECKIN-PR1-SHAPE Q1).
#[test]
fn wire_tokens_are_the_fanout_tokens() {
    for (mode, token) in [
        (AlwaysAsk, "manual"),
        (AskWhenUnsure, "auto"),
        (NeverAsk, "full-access"),
    ] {
        assert_eq!(mode.as_str(), token);
        assert_eq!(
            serde_json::to_value(mode).ok(),
            Some(serde_json::Value::String(token.to_owned()))
        );
        let back: CheckInMode = serde_json::from_value(serde_json::Value::String(token.to_owned()))
            .unwrap_or_else(|error| panic!("{token}: {error}"));
        assert_eq!(back, mode);
    }
    assert_eq!(CheckInMode::default(), AskWhenUnsure);
}

#[test]
fn tables_have_one_row_per_act_and_role() {
    assert_eq!(ACT_CLASS.len(), ActClass::ALL.len());
    for (row, act) in ACT_CLASS.iter().zip(ActClass::ALL) {
        assert_eq!(row.act, act);
        assert_eq!(act.row().act, act);
    }
    let names: BTreeSet<_> = ActClass::ALL.into_iter().map(ActClass::as_str).collect();
    assert_eq!(names.len(), ActClass::ALL.len());
    assert_eq!(ROLE_PRESET.len(), RolePreset::ALL.len());
    for (row, role) in ROLE_PRESET.iter().zip(RolePreset::ALL) {
        assert_eq!(row.role, role);
    }
}

/// ARCH-0082 #catastrophe-floor: the eight C rows and the F row, and a C row
/// is AlwaysAsk for every role but Owner, whatever row a caller passes.
#[test]
fn catastrophe_rows_ask_every_role_but_owner() {
    let catastrophe: BTreeSet<_> = ACT_CLASS
        .iter()
        .filter(|row| row.catastrophe)
        .map(|row| row.act)
        .collect();
    let expected: BTreeSet<_> = [
        ActClass::Sign,
        ActClass::VaultDelete,
        ActClass::Erase,
        ActClass::OwnershipTransfer,
        ActClass::KeyRecovery,
        ActClass::SecurityControlDisable,
        ActClass::MassSecretExport,
        ActClass::WorldWiden,
    ]
    .into_iter()
    .collect();
    assert_eq!(catastrophe, expected);
    let fixed: Vec<_> = ACT_CLASS
        .iter()
        .filter(|row| row.fixed)
        .map(|row| row.act)
        .collect();
    assert_eq!(fixed, [ActClass::WidenOwnGrant]);

    for act in catastrophe.iter().copied().chain(fixed) {
        assert!(
            matches!(
                resolve_mode(&request(RolePreset::Owner, act)),
                ResolvedMode::OwnProof
            ),
            "Owner acts on its own proof: {act:?}"
        );
        for role in RolePreset::ALL.into_iter().skip(1) {
            let loosened = CheckInRequest {
                explicit_mode: Some(NeverAsk),
                ..request(role, act)
            };
            match resolve_mode(&loosened) {
                ResolvedMode::Mode { mode, .. } => assert_eq!(mode, AlwaysAsk, "{role:?} {act:?}"),
                ResolvedMode::Propose | ResolvedMode::Absent => {}
                ResolvedMode::OwnProof => panic!("{role:?} {act:?} acted on its own proof"),
            }
        }
    }

    // No stop-asking row reaches a C row: the Deputy's erase still waits,
    // and the model is never called.
    let stub = Stub::new(Some(true));
    let erase = CheckInRequest {
        standing_row: Some("stop-asking:erase"),
        ..request(RolePreset::Deputy, ActClass::Erase)
    };
    assert_eq!(
        check_in(&erase, &stub),
        CheckInAnswer::Wait(WaitReason::AlwaysAsk)
    );
    assert_eq!(stub.calls.get(), 0);
}

/// The built floor (consent CATASTROPHE_FLOOR_V2) and the act table agree:
/// each floor class is one row, and that row is a C row or the F row.
#[test]
fn built_floor_classes_are_c_or_f_rows() {
    for class in CATASTROPHE_FLOOR_V2 {
        let rows: Vec<_> = ACT_CLASS
            .iter()
            .filter(|row| row.floor_class == Some(class))
            .collect();
        assert_eq!(rows.len(), 1, "{class:?}");
        assert!(rows[0].catastrophe || rows[0].fixed, "{class:?}");
    }
}

/// R3 split (owner 08:43): remove or demote asks; add or raise, and deletes
/// in scope, ask when unsure. The Deputy's catastrophe rows always ask.
#[test]
fn deputy_defaults_follow_r3() {
    let deputy = |act| mode_of(resolve_mode(&request(RolePreset::Deputy, act)));
    assert_eq!(deputy(ActClass::RemoveOrDemoteMember), Some(AlwaysAsk));
    assert_eq!(deputy(ActClass::AddOrRaiseMember), Some(AskWhenUnsure));
    assert_eq!(deputy(ActClass::DeleteItems), Some(AskWhenUnsure));
    assert_eq!(deputy(ActClass::ReversibleWork), Some(NeverAsk));
    for act in [
        ActClass::Erase,
        ActClass::VaultDelete,
        ActClass::OwnershipTransfer,
    ] {
        assert_eq!(deputy(act), Some(AlwaysAsk), "{act:?}");
    }
    // The remove row is not a catastrophe row: an explicit row may loosen it.
    let loosened = CheckInRequest {
        explicit_mode: Some(AskWhenUnsure),
        ..request(RolePreset::Deputy, ActClass::RemoveOrDemoteMember)
    };
    assert_eq!(mode_of(resolve_mode(&loosened)), Some(AskWhenUnsure));
}

/// The composition (ARCH-0082 #composing): no power is absent or a
/// proposal; with no row the role default decides; an explicit row replaces it.
#[test]
fn power_then_role_default_then_explicit_row() {
    let without_power = |role, act| CheckInRequest {
        holds_power: false,
        ..request(role, act)
    };
    assert_eq!(
        resolve_mode(&without_power(RolePreset::Member, ActClass::Billing)),
        ResolvedMode::Absent
    );
    assert_eq!(
        resolve_mode(&without_power(
            RolePreset::Steward,
            ActClass::AddOrRaiseMember
        )),
        ResolvedMode::Propose
    );
    // Any actor, in any role, may open an erase proposal.
    for role in RolePreset::ALL {
        assert_eq!(
            check_in(&without_power(role, ActClass::Erase), &Stub::new(None)),
            CheckInAnswer::Propose,
            "{role:?}"
        );
    }
    assert_eq!(
        resolve_mode(&request(RolePreset::Owner, ActClass::SpendAboveCap)),
        ResolvedMode::Mode {
            mode: NeverAsk,
            source: ModeSource::RoleDefault
        }
    );
    let tightened = CheckInRequest {
        explicit_mode: Some(AskWhenUnsure),
        ..request(RolePreset::Owner, ActClass::SpendAboveCap)
    };
    assert_eq!(
        resolve_mode(&tightened),
        ResolvedMode::Mode {
            mode: AskWhenUnsure,
            source: ModeSource::ExplicitRows
        }
    );
    // A power the role lacks, held through a named Grant with no row: ask.
    assert_eq!(
        resolve_mode(&request(RolePreset::Member, ActClass::Billing)),
        ResolvedMode::Mode {
            mode: AlwaysAsk,
            source: ModeSource::ExtraPowerDefault
        }
    );
}

/// The ladder (ARCH-0082 #ladder): rung 0, then the mode, then the unsure test.
#[test]
fn ladder_goes_waits_or_asks_the_model() {
    let act = ActClass::SpendAboveCap;
    let cases = [
        (
            NeverAsk,
            None,
            Some(false),
            CheckInAnswer::Go(GoReason::NeverAsk),
            0,
        ),
        (
            AlwaysAsk,
            None,
            Some(true),
            CheckInAnswer::Wait(WaitReason::AlwaysAsk),
            0,
        ),
        (
            AskWhenUnsure,
            None,
            Some(true),
            CheckInAnswer::Go(GoReason::Sure),
            1,
        ),
        (
            AskWhenUnsure,
            None,
            Some(false),
            CheckInAnswer::Wait(WaitReason::Unsure),
            1,
        ),
        (
            AskWhenUnsure,
            None,
            None,
            CheckInAnswer::Wait(WaitReason::UnsureTestFailed),
            1,
        ),
        (
            AlwaysAsk,
            Some("standing:spend"),
            Some(false),
            CheckInAnswer::Go(GoReason::StandingRow("standing:spend".to_owned())),
            0,
        ),
        (
            AskWhenUnsure,
            Some("standing:spend"),
            Some(false),
            CheckInAnswer::Go(GoReason::StandingRow("standing:spend".to_owned())),
            0,
        ),
    ];
    for (mode, standing, answer, expected, calls) in cases {
        let stub = Stub::new(answer);
        assert_eq!(
            check_in_with_mode(act, mode, standing, &stub),
            expected,
            "{mode:?} {standing:?} {answer:?}"
        );
        assert_eq!(stub.calls.get(), calls, "{mode:?} {standing:?} {answer:?}");
    }
    // The model never decides a grant widen: unsure there means ask.
    assert_eq!(
        ActClass::WidenAnothersGrant.row().model_check,
        ModelCheck::Never
    );
    let stub = Stub::new(Some(true));
    assert_eq!(
        check_in(
            &request(RolePreset::Deputy, ActClass::WidenAnothersGrant),
            &stub
        ),
        CheckInAnswer::Wait(WaitReason::ModelNotAllowed)
    );
    assert_eq!(stub.calls.get(), 0);
}

/// R4: Viewer is a label for a read-only Member; every grant role has a preset.
#[test]
fn grant_roles_map_to_seven_presets() {
    for (role, preset) in [
        (FederationGrantRole::Owner, RolePreset::Owner),
        (FederationGrantRole::Admin, RolePreset::Admin),
        (FederationGrantRole::Steward, RolePreset::Steward),
        (FederationGrantRole::Member, RolePreset::Member),
        (FederationGrantRole::Viewer, RolePreset::Member),
        (FederationGrantRole::Deputy, RolePreset::Deputy),
        (FederationGrantRole::Delegate, RolePreset::Delegate),
        (FederationGrantRole::Guest, RolePreset::Guest),
    ] {
        assert_eq!(RolePreset::of_grant_role(role), preset, "{role:?}");
    }
}

/// CHECKIN-PR1-SHAPE Q3: fan-out checks in as act class `spawn`, a power in
/// every role but Guest, with the shipped fan-out default (ask when unsure).
#[test]
fn spawn_row_carries_the_fanout_default() {
    let row = ActClass::Spawn.row();
    assert!(!row.catastrophe && !row.fixed);
    assert_eq!(row.model_check, ModelCheck::UnsureTest);
    for role in RolePreset::ALL {
        let expected = if role == RolePreset::Guest {
            RoleDefault::NoVerb
        } else {
            RoleDefault::Mode(AskWhenUnsure)
        };
        assert_eq!(role.default_for(ActClass::Spawn), expected, "{role:?}");
    }
}
