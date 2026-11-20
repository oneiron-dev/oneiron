//! The `library_find` door's tests: the refusal before the store, the
//! forwarded filters, the seed candidates beside the cards, and the
//! loader's note beside them.
//!
//! The store is a fake: these tests prove what the door forwards and
//! returns, not the real vault store's filter, order or ownership rules.

use super::session_fixture::SessionFixture;
use super::workflow_store::{StoreCall, card};
use oneiron_browser::{
    BrowserDriver, BrowserError, LibraryFindInput, SeedBody, SeedCandidate, SiteOrigin,
    SiteSkillError, SiteSkillErrorCode, SiteSkillLoader, SiteSkillMatch, SiteSkillQuery,
};
use std::sync::{Arc, Mutex};

/// The page an explicit find names: the skill query keeps its exact
/// origin and its path, never the query or the fragment.
const PAGE_URL: &str = "https://shop.example/form?mode=test#top";

/// A page on another site: an explicit site beside it disagrees.
const OTHER_URL: &str = "https://other.example/form";

/// The host's site skills as a test reads them: the queries it saw and
/// the one answer it gives.
struct ScriptedLoader {
    /// Every query the session asked, in order.
    queries: Mutex<Vec<SiteSkillQuery>>,
    /// The answer `site_skills` gives to every query.
    answer: Result<Vec<SiteSkillMatch>, SiteSkillError>,
}

impl ScriptedLoader {
    /// A loader that answers `answer` and records its queries.
    fn new(answer: Result<Vec<SiteSkillMatch>, SiteSkillError>) -> Self {
        Self {
            queries: Mutex::new(Vec::new()),
            answer,
        }
    }
}

impl SiteSkillLoader for ScriptedLoader {
    fn site_skills(&self, query: &SiteSkillQuery) -> Result<Vec<SiteSkillMatch>, SiteSkillError> {
        self.queries
            .lock()
            .expect("loader queries lock")
            .push(query.clone());
        self.answer.clone()
    }

    fn seed(&self, _candidate: &str) -> Result<SeedBody, SiteSkillError> {
        Err(SiteSkillError::new(
            SiteSkillErrorCode::Unresolved,
            "fixture resolves no seed",
        ))
    }
}

/// The skill query the page at [`PAGE_URL`] parses to.
fn page_query() -> SiteSkillQuery {
    SiteSkillQuery {
        origin: SiteOrigin {
            scheme: "https".to_owned(),
            host: "shop.example".to_owned(),
            port: 443,
        },
        path: "/form".to_owned(),
    }
}

#[test]
fn a_site_that_disagrees_with_the_url_is_refused_before_the_store_reads() {
    let mut fixture = SessionFixture::attach("about:blank");
    let mark = fixture.peer.mark();
    let error = fixture
        .session
        .library_find(LibraryFindInput {
            site: Some(" SHOP.EXAMPLE ".to_owned()),
            url: Some(OTHER_URL.to_owned()),
            ..Default::default()
        })
        .expect_err("a site that disagrees with the url is refused");
    assert_eq!(
        error,
        BrowserError::Input(
            "find's site shop.example and its url's site other.example differ; name one".to_owned()
        )
    );
    let store = fixture.store.lock().expect("store locks");
    assert!(store.calls.is_empty(), "a refused find reads no store");
    drop(store);
    fixture.assert_methods(mark, &[]);
}

#[test]
fn an_explicit_site_passes_the_normalized_key_and_both_filters_to_the_store() {
    let mut fixture = SessionFixture::attach("about:blank");
    let card1 = card("wf1");
    fixture.store.lock().expect("store locks").find_cards = vec![card1.clone()];
    let mark = fixture.peer.mark();
    let result = fixture.session.library_find(LibraryFindInput {
        site: Some(" SHOP.EXAMPLE ".to_owned()),
        subgoal: Some("Ready FORM".to_owned()),
        type_ref: Some("forms.fill@2".to_owned()),
        ..Default::default()
    });
    let output = fixture.expect_ok(result, "an explicit site lists");
    assert_eq!(output.site, "shop.example");
    assert_eq!(
        serde_json::to_value(&output.workflows).expect("workflows encode"),
        serde_json::to_value(&[card1]).expect("card encodes")
    );
    assert!(output.candidates.is_empty());
    assert!(output.site_skill_notes.is_empty());
    let store = fixture.store.lock().expect("store locks");
    assert_eq!(
        store.calls,
        [StoreCall::Find(
            "shop.example".to_owned(),
            Some("Ready FORM".to_owned()),
            Some("forms.fill@2".to_owned())
        )]
    );
    drop(store);
    fixture.assert_methods(mark, &[]);
}

#[test]
fn seeds_match_the_explicit_page_and_do_not_join_the_workflow_cards() {
    let mut fixture = SessionFixture::attach("about:blank");
    let card1 = card("wf1");
    fixture.store.lock().expect("store locks").find_cards = vec![card1.clone()];
    let seed = SeedCandidate {
        candidate: "seed-1".to_owned(),
        path: "skills/shop/seed.json".to_owned(),
        digest: "digest-1".to_owned(),
        license: "MIT".to_owned(),
    };
    let skill = SiteSkillMatch {
        skill_id: "shop-skill".to_owned(),
        revision: "1".to_owned(),
        knowledge: "Shop knowledge.".to_owned(),
        seeds: vec![seed.clone()],
    };
    let loader = Arc::new(ScriptedLoader::new(Ok(vec![skill])));
    fixture.session.set_site_skill_loader(loader.clone());
    let mark = fixture.peer.mark();
    let result = fixture.session.library_find(LibraryFindInput {
        url: Some(PAGE_URL.to_owned()),
        ..Default::default()
    });
    let output = fixture.expect_ok(result, "an explicit page lists its seeds");
    assert_eq!(output.site, "shop.example");
    assert_eq!(
        serde_json::to_value(&output.workflows).expect("workflows encode"),
        serde_json::to_value(&[card1]).expect("card encodes")
    );
    assert_eq!(output.candidates, [seed]);
    assert!(output.site_skill_notes.is_empty());
    let queries = loader.queries.lock().expect("loader queries lock").clone();
    assert_eq!(queries, [page_query()]);
    let store = fixture.store.lock().expect("store locks");
    assert_eq!(
        store.calls,
        [StoreCall::Find("shop.example".to_owned(), None, None)]
    );
    drop(store);
    fixture.assert_methods(mark, &[]);
}

#[test]
fn a_seed_loader_error_is_a_note_beside_the_workflow_cards() {
    let mut fixture = SessionFixture::attach("about:blank");
    let card1 = card("wf1");
    fixture.store.lock().expect("store locks").find_cards = vec![card1.clone()];
    let note = SiteSkillError::new(SiteSkillErrorCode::Loader, "fixture cannot load");
    let loader = Arc::new(ScriptedLoader::new(Err(note.clone())));
    fixture.session.set_site_skill_loader(loader.clone());
    let mark = fixture.peer.mark();
    let result = fixture.session.library_find(LibraryFindInput {
        url: Some(PAGE_URL.to_owned()),
        ..Default::default()
    });
    let output = fixture.expect_ok(result, "a loader error keeps the cards");
    assert_eq!(output.site, "shop.example");
    assert_eq!(
        serde_json::to_value(&output.workflows).expect("workflows encode"),
        serde_json::to_value(&[card1]).expect("card encodes")
    );
    assert!(output.candidates.is_empty());
    assert_eq!(output.site_skill_notes, [note]);
    let queries = loader.queries.lock().expect("loader queries lock").clone();
    assert_eq!(queries, [page_query()]);
    let store = fixture.store.lock().expect("store locks");
    assert_eq!(
        store.calls,
        [StoreCall::Find("shop.example".to_owned(), None, None)]
    );
    drop(store);
    fixture.assert_methods(mark, &[]);
}
