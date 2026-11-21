//! A generated card's result-set action reaches only the rows its clicker
//! ticked (GENUI-SELECTION-EVENT; Engine RULING GENUI-SELECTION-ROUTE = B,
//! 14 Nov).
//!
//! The UI posts result-set picks to `vault.lenses.result_set.action` as a
//! `GeneratedUiResultSetActionEvent { action, selection }`. The server turns
//! the posted selection refs back into the read handles `vault.lenses.select`
//! issued and hands them to the verb's engine entry,
//! `Memory::lens_frame_result_set_action`. That entry proves the event
//! against the rendered result set under the clicker's own read, requires
//! the handles to be exactly the ticked rows in rendered order (or, for
//! select-all, the rendered filter's one predicate), re-resolves each
//! handle, and answers the card's declared deterministic action. These
//! tests drive that entry as the server does, on public paths: picked rows
//! resolve, a foreign row is refused, and select-all stays within the
//! filter.
//!
//! The fixture is the run repo fixture's owned vault (`tests/repo_run`).
//! The card's frame takes the owner's lens principal from the owner's own
//! default lens, and mints one backing ref per row from the row's engine
//! short id. `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test lens_result_set_selection`.
#![cfg(oneiron_test_support)]

#[path = "repo_run/fixture.rs"]
mod fixture;

use fixture::{RepoFixture, TestResult};
use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::lens::{
    ButtonControl, CollectionAtom, GeneratedLens, GeneratedUiActionDeclaration,
    GeneratedUiActionEvent, GeneratedUiActionTier, GeneratedUiCard, GeneratedUiRender,
    GeneratedUiResultSetActionEvent, GeneratedUiResultSetAtom, GeneratedUiResultSetRow,
    GeneratedUiResultSetSelectAll, GeneratedUiResultSetSelection, GeneratedUiStateSnapshot,
    GeneratedUiSurfaceCapabilities, GeneratedUiValidatedAction, LensAtom, LensAtomId,
    LensBackingTarget, LensBackingTargetKind, LensDefaultRequest, LensHandleName, LensHandleRef,
    LensHandleRole, LensNode, LensReadHandle, LensRenderFrame, LensRenderId, LensResultSetRowId,
    LensSelectRequest, LensText, SelfUiAction, SelfUiActionId, SelfUiControl, SelfUiControlId,
};
use oneiron::retrieval_depth::short_ref_or_hex;
use oneiron::{EntityId, TimeRange, Vault};

/// A predicate the shipped policy manifest names normal (its `profile.`
/// rule), so the owner's Approved claims land without pending.
const NOTE_PREDICATE: &str = "profile.note";
/// The card's action-bar action, declared on its archive button.
const ARCHIVE: &str = "archive";
/// The engine command the archive declaration names.
const ARCHIVE_COMMAND: &str = "archive.selected";
/// The result-set node: every row handle and the filter are its bindings.
const RESULTS: &str = "results";
/// Every result-set refusal of a selection that is not exactly the ticked
/// rows or the rendered predicate.
const SELECTION_MISMATCH: &str =
    "result-set selections must match exactly the ticked rows or rendered predicate";

/// One Approved, Active claim the owner stated about the owner.
fn put_note(repo: &RepoFixture, value: &str) -> TestResult<EntityId> {
    let at = repo.vault.now_recorded_at();
    let mut body = ClaimBody::new(
        NOTE_PREDICATE,
        ClaimSubject::Entity(repo.owner),
        rmpv::Value::from(value),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    let id = EntityId::now();
    repo.vault
        .put_claim(&id, &body, TimeRange { start: at, end: at }, at)?;
    Ok(id)
}

/// A PERSON row holding `data`.
fn put_person(vault: &Vault, id: &EntityId, data: &[u8]) -> TestResult {
    let at = vault.now_recorded_at();
    vault.put_entity(
        id,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: at, end: at },
        at,
        data,
    )?;
    Ok(())
}

/// The backing target of `id` as the engine names it: its short id and
/// content hash, read from the engine's `name:hh` short reference.
fn target_of(
    vault: &Vault,
    id: EntityId,
    kind: LensBackingTargetKind,
) -> TestResult<LensBackingTarget> {
    let short_ref = short_ref_or_hex(vault, &id)?;
    let (short_id, hash) = short_ref
        .rsplit_once(':')
        .ok_or_else(|| format!("row {} has no engine short id: {short_ref}", id.to_hex()))?;
    let hash = u8::from_str_radix(hash, 16)?;
    Ok(match kind {
        LensBackingTargetKind::Claim => LensBackingTarget::claim(id, short_id, hash)?,
        LensBackingTargetKind::Entity => LensBackingTarget::entity(id, short_id, hash)?,
    })
}

fn atom_id(value: &str) -> TestResult<LensAtomId> {
    Ok(LensAtomId::new(value)?)
}

fn handle(value: &str) -> TestResult<LensHandleName> {
    Ok(LensHandleName::new(value)?)
}

fn text(value: &str) -> TestResult<LensText> {
    Ok(LensText::new(value)?)
}

fn archive_action() -> TestResult<SelfUiAction> {
    Ok(SelfUiAction {
        command: SelfUiActionId::new(ARCHIVE_COMMAND)?,
        args: Vec::new(),
    })
}

fn row(id: &str, target: &str) -> TestResult<GeneratedUiResultSetRow> {
    Ok(GeneratedUiResultSetRow {
        id: LensResultSetRowId::new(id)?,
        label: text(id)?,
        target_handle: handle(target)?,
    })
}

fn binding(name: &str, role: LensHandleRole) -> TestResult<LensHandleRef> {
    Ok(LensHandleRef {
        name: handle(name)?,
        role,
    })
}

/// The card `card_id`: one result set of three rows (two claims and a
/// person) whose action bar allowlists the archive button's deterministic
/// action, beside that button. `select_all` is the result set's select-all.
fn results_render(
    card_id: &LensRenderId,
    select_all: GeneratedUiResultSetSelectAll,
) -> TestResult<GeneratedUiRender> {
    let mut results = LensNode::with_fallback_text(
        atom_id(RESULTS)?,
        LensAtom::ResultSet(GeneratedUiResultSetAtom {
            rows: vec![
                row("row-1", "claim-a")?,
                row("row-2", "claim-b")?,
                row("row-3", "person")?,
            ],
            select_all,
            action_bar: vec![SelfUiActionId::new(ARCHIVE)?],
        }),
        text("Results")?,
    );
    results.bindings = vec![
        binding("claim-a", LensHandleRole::ClaimSet)?,
        binding("claim-b", LensHandleRole::ClaimSet)?,
        binding("person", LensHandleRole::EntitySet)?,
        binding("filter", LensHandleRole::QueryResult)?,
    ];
    let archive = LensNode::with_fallback_text(
        atom_id(ARCHIVE)?,
        LensAtom::SelfUi(SelfUiControl::Button(ButtonControl {
            id: SelfUiControlId::new(ARCHIVE)?,
            label: text("Archive")?,
            action: archive_action()?,
        })),
        text("Archive")?,
    );
    let mut root = LensNode::with_fallback_text(
        atom_id("root")?,
        LensAtom::Sheet(CollectionAtom {
            title: text("Notes")?,
            rows: Vec::new(),
        }),
        text("Notes")?,
    );
    root.children = vec![results, archive];
    let card = GeneratedUiCard::interactive(
        card_id.clone(),
        GeneratedLens::new(root)?,
        vec![GeneratedUiActionDeclaration {
            element_id: atom_id(ARCHIVE)?,
            action_id: SelfUiActionId::new(ARCHIVE)?,
            tier: GeneratedUiActionTier::DeterministicTool,
            action: archive_action()?,
        }],
        GeneratedUiStateSnapshot::default(),
    )?;
    Ok(card.render()?)
}

/// The owner's results card: its frame, bound to the owner's lens
/// principal, holds one backing ref per row and the filter's predicate.
struct ResultsCard {
    repo: RepoFixture,
    frame: LensRenderFrame,
    render: GeneratedUiRender,
    claim_b: EntityId,
    person: EntityId,
}

impl ResultsCard {
    fn new() -> TestResult<Self> {
        let repo = RepoFixture::new()?;
        let claim_a = put_note(&repo, "owen")?;
        let claim_b = put_note(&repo, "yuki")?;
        let person = EntityId::now();
        put_person(&repo.vault, &person, b"person")?;

        // The owner's lens principal, as the owner's own default lens binds
        // it; the host mints that lens's ledger row from the same short ref
        // this test reads.
        let hosted = repo
            .owner_memory()
            .lenses_default_framed(LensDefaultRequest {
                title: "Ledger".to_owned(),
                ledger: vec![claim_a.to_hex()],
                dossiers: Vec::new(),
                threads: Vec::new(),
                as_of: None,
                surface: None,
            })?
            .value;
        let (default_frame, _) = hosted.lower(&GeneratedUiSurfaceCapabilities::all_atom_kit())?;
        let ledger = default_frame
            .backing_refs()
            .iter()
            .find(|backing| backing.handle().as_str() == "ledger-0")
            .ok_or("the default lens mints its ledger row")?;
        assert_eq!(
            *ledger.target(),
            target_of(&repo.vault, claim_a, LensBackingTargetKind::Claim)?,
            "the host names the claim by the short ref this test reads"
        );

        let principal = default_frame.principal().clone();
        let card_id = LensRenderId::new("result-set-card")?;
        let mut frame = LensRenderFrame::new(card_id.clone(), principal.clone());
        let read = repo
            .vault
            .scoped_read(principal.selected_read_key().clone());
        for (name, role, row, kind) in [
            (
                "claim-a",
                LensHandleRole::ClaimSet,
                claim_a,
                LensBackingTargetKind::Claim,
            ),
            (
                "claim-b",
                LensHandleRole::ClaimSet,
                claim_b,
                LensBackingTargetKind::Claim,
            ),
            (
                "person",
                LensHandleRole::EntitySet,
                person,
                LensBackingTargetKind::Entity,
            ),
            (
                "filter",
                LensHandleRole::QueryResult,
                claim_a,
                LensBackingTargetKind::Claim,
            ),
        ] {
            frame.mint_backing_ref(
                &read,
                handle(name)?,
                role,
                target_of(&repo.vault, row, kind)?,
            )?;
        }
        let render = results_render(
            &card_id,
            GeneratedUiResultSetSelectAll::WithinFilter {
                predicate_handle: handle("filter")?,
            },
        )?;
        Ok(Self {
            repo,
            frame,
            render,
            claim_b,
            person,
        })
    }

    /// The read handle `vault.lenses.select` issues the owner for `name` on
    /// `render`, through `frame`.
    fn pick_on(
        &self,
        frame: &LensRenderFrame,
        render: &GeneratedUiRender,
        name: &str,
    ) -> TestResult<LensReadHandle> {
        Ok(self.repo.owner_memory().lens_frame_select(
            frame,
            render,
            &LensSelectRequest {
                card_id: render.card_id.clone(),
                atom_id: atom_id(RESULTS)?,
                handle: handle(name)?,
                span: None,
            },
        )?)
    }

    fn pick(&self, name: &str) -> TestResult<LensReadHandle> {
        self.pick_on(&self.frame, &self.render, name)
    }

    /// The owner clicks archive on `render` with `selection`, the server
    /// handing over `selected`: the verb's engine entry, as the server
    /// calls it. A refusal is its message.
    fn act_on(
        &self,
        render: &GeneratedUiRender,
        selection: GeneratedUiResultSetSelection,
        selected: &[LensReadHandle],
    ) -> TestResult<Result<GeneratedUiValidatedAction, String>> {
        let event = GeneratedUiResultSetActionEvent {
            action: GeneratedUiActionEvent {
                card_id: render.card_id.clone(),
                element_id: atom_id(ARCHIVE)?,
                action_id: SelfUiActionId::new(ARCHIVE)?,
                patch: Vec::new(),
                occurred_at: 23,
            },
            selection,
        };
        Ok(self
            .repo
            .owner_memory()
            .lens_frame_result_set_action(&self.frame, render, &render.state, &event, selected)
            .map_err(|error| error.message))
    }

    fn act(
        &self,
        selection: GeneratedUiResultSetSelection,
        selected: &[LensReadHandle],
    ) -> TestResult<Result<GeneratedUiValidatedAction, String>> {
        self.act_on(&self.render, selection, selected)
    }
}

fn ticked(rows: &[&str]) -> TestResult<GeneratedUiResultSetSelection> {
    Ok(GeneratedUiResultSetSelection::Explicit {
        row_ids: rows
            .iter()
            .map(|row| LensResultSetRowId::new(*row))
            .collect::<Result<_, _>>()?,
    })
}

/// The answer is the card's declared archive command, emitted by the
/// clicker's own lens principal.
fn assert_archive(card: &ResultsCard, answer: Result<GeneratedUiValidatedAction, String>) {
    match answer {
        Ok(GeneratedUiValidatedAction::DeterministicTool { emitter, action }) => {
            assert_eq!(action.command().as_str(), ARCHIVE_COMMAND);
            assert_eq!(
                emitter.selected_read_key(),
                card.frame.principal().selected_read_key(),
                "the clicker emits the action"
            );
        }
        other => panic!("the archive action resolves: {other:?}"),
    }
}

fn assert_refused(answer: Result<GeneratedUiValidatedAction, String>, reason: &str, case: &str) {
    match answer {
        Err(message) => assert!(
            message.contains(reason),
            "{case}: refused for another reason: {message}"
        ),
        Ok(action) => panic!("{case}: answered {action:?}"),
    }
}

#[test]
fn ticked_rows_resolve_to_the_cards_declared_action() -> TestResult {
    let card = ResultsCard::new()?;
    let claim_a = card.pick("claim-a")?;
    let claim_b = card.pick("claim-b")?;
    let person = card.pick("person")?;

    assert_archive(
        &card,
        card.act(
            ticked(&["row-1", "row-2"])?,
            &[claim_a.clone(), claim_b.clone()],
        )?,
    );
    assert_archive(&card, card.act(ticked(&["row-2"])?, &[claim_b])?);
    assert_archive(&card, card.act(ticked(&["row-3"])?, &[person.clone()])?);
    // The engine walks the ticks in rendered order, whatever order the UI
    // posted them in.
    assert_archive(
        &card,
        card.act(ticked(&["row-3", "row-1"])?, &[claim_a, person])?,
    );
    Ok(())
}

#[test]
fn handles_that_differ_from_the_ticked_rows_are_refused() -> TestResult {
    let card = ResultsCard::new()?;
    let claim_a = card.pick("claim-a")?;
    let claim_b = card.pick("claim-b")?;

    assert_refused(
        card.act(ticked(&["row-1"])?, &[claim_a.clone(), claim_b.clone()])?,
        SELECTION_MISMATCH,
        "a handle for a row the clicker did not tick",
    );
    assert_refused(
        card.act(ticked(&["row-1", "row-2"])?, &[claim_a.clone()])?,
        SELECTION_MISMATCH,
        "a ticked row without its handle",
    );
    assert_refused(
        card.act(ticked(&["row-1", "row-2"])?, &[claim_b.clone(), claim_a])?,
        SELECTION_MISMATCH,
        "the handles out of rendered order",
    );
    assert_refused(
        card.act(ticked(&["row-2"])?, &[claim_b.clone(), claim_b])?,
        SELECTION_MISMATCH,
        "one handle twice",
    );
    Ok(())
}

#[test]
fn a_row_from_outside_the_rendered_result_set_is_refused() -> TestResult {
    let card = ResultsCard::new()?;
    let claim_b = card.pick("claim-b")?;

    assert_refused(
        card.act(ticked(&["row-9"])?, &[claim_b.clone()])?,
        "result set selections must name rows of this rendered atom",
        "a row id the card did not render",
    );
    assert_refused(
        card.act(ticked(&[])?, &[])?,
        "result set explicit selections must name at least one row",
        "a selection of no rows",
    );
    assert_refused(
        card.act(ticked(&["row-2", "row-2"])?, &[claim_b.clone()])?,
        "result set selections must not repeat a row id",
        "a row ticked twice",
    );

    // The same claim, picked on another card the owner holds: its handle
    // carries that card's render and backing ref, not this card's.
    let twin_id = LensRenderId::new("result-set-twin")?;
    let mut twin = LensRenderFrame::new(twin_id.clone(), card.frame.principal().clone());
    let read = card
        .repo
        .vault
        .scoped_read(card.frame.principal().selected_read_key().clone());
    twin.mint_backing_ref(
        &read,
        handle("claim-b")?,
        LensHandleRole::ClaimSet,
        target_of(&card.repo.vault, card.claim_b, LensBackingTargetKind::Claim)?,
    )?;
    let twin_render = results_render(&twin_id, GeneratedUiResultSetSelectAll::Disabled {})?;
    let foreign = card.pick_on(&twin, &twin_render, "claim-b")?;
    assert_eq!(foreign.short_ref(), claim_b.short_ref(), "the same row");
    assert_refused(
        card.act(ticked(&["row-2"])?, &[foreign])?,
        SELECTION_MISMATCH,
        "another card's handle for the same row",
    );
    assert_archive(&card, card.act(ticked(&["row-2"])?, &[claim_b])?);
    Ok(())
}

#[test]
fn a_ticked_row_that_moved_since_its_selection_is_refused() -> TestResult {
    let card = ResultsCard::new()?;
    let person = card.pick("person")?;
    assert_archive(&card, card.act(ticked(&["row-3"])?, &[person.clone()])?);

    let before = short_ref_or_hex(&card.repo.vault, &card.person)?;
    put_person(&card.repo.vault, &card.person, b"person, revised")?;
    assert_ne!(
        short_ref_or_hex(&card.repo.vault, &card.person)?,
        before,
        "the revised row has a new content hash"
    );
    let answer = card.act(ticked(&["row-3"])?, &[person])?;
    assert!(
        answer.is_err(),
        "the stale row is re-proved under the clicker's read and refused: {answer:?}"
    );
    Ok(())
}

#[test]
fn select_all_resolves_to_the_rendered_filter_predicate_only() -> TestResult {
    let card = ResultsCard::new()?;
    let filter = card.pick("filter")?;
    let claim_a = card.pick("claim-a")?;
    let claim_b = card.pick("claim-b")?;
    let person = card.pick("person")?;

    assert_archive(
        &card,
        card.act(
            GeneratedUiResultSetSelection::AllWithinFilter {},
            std::slice::from_ref(&filter),
        )?,
    );
    assert_refused(
        card.act(
            GeneratedUiResultSetSelection::AllWithinFilter {},
            &[claim_a, claim_b, person],
        )?,
        SELECTION_MISMATCH,
        "select-all handing over the rows instead of the predicate",
    );
    assert_refused(
        card.act(ticked(&["row-1"])?, std::slice::from_ref(&filter))?,
        SELECTION_MISMATCH,
        "a ticked row handing over the predicate",
    );

    // A later render of the same card with select-all disabled has no
    // predicate to take.
    let disabled = results_render(
        card.frame.render_id(),
        GeneratedUiResultSetSelectAll::Disabled {},
    )?;
    assert_refused(
        card.act_on(
            &disabled,
            GeneratedUiResultSetSelection::AllWithinFilter {},
            &[filter],
        )?,
        "result set select-all is disabled on this rendered atom",
        "select-all on a card that disables it",
    );
    Ok(())
}
