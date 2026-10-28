//! The session's site skills (CUA E10, `crate::site`): the host's loader,
//! the last open's matches waiting for the answer of the call that made
//! it, and the seed candidates this browser listed, which a proposal names.

use super::*;
use crate::site::{
    SeedBody, SeedCandidate, SiteSkillError, SiteSkillErrorCode, SiteSkillLoader, SiteSkillMatch,
    SiteSkillQuery,
};
use std::collections::BTreeMap;

/// What the session keeps of the host's site skills.
#[derive(Default)]
pub(super) struct SiteSkills {
    /// None until the host gives one; an open then carries no skills and
    /// no note.
    loader: Option<Arc<dyn SiteSkillLoader>>,
    /// The last open's matches, for the answer of the call that made it.
    pending: Option<Opened>,
    /// Every seed candidate an open or a find of this session listed, by
    /// its handle, as it was listed.
    issued: BTreeMap<String, SeedCandidate>,
}

/// What an open loaded: the page it landed on, by exact origin and path
/// (none when its URL names no site), and that page's matches and notes.
struct Opened {
    key: Option<SiteSkillQuery>,
    matches: Vec<SiteSkillMatch>,
    notes: Vec<SiteSkillError>,
}

impl SiteSkills {
    /// The skills `query` matches, their seeds listed as issued, or the
    /// note that names why there are none; nothing with no loader.
    fn load(
        &mut self,
        query: &Result<SiteSkillQuery, SiteSkillError>,
    ) -> Option<(Vec<SiteSkillMatch>, Vec<SiteSkillError>)> {
        let loader = self.loader.as_ref()?;
        let loaded = match query {
            Ok(query) => loader.site_skills(query),
            Err(note) => Err(note.clone()),
        };
        Some(match loaded {
            Ok(matches) => {
                for seed in matches.iter().flat_map(|found| &found.seeds) {
                    self.issued.insert(seed.candidate.clone(), seed.clone());
                }
                (matches, Vec::new())
            }
            Err(note) => (Vec::new(), vec![note]),
        })
    }
}

/// The exact origin and path of the page at `url`.
fn page_key(url: Result<String, BrowserError>) -> Result<SiteSkillQuery, SiteSkillError> {
    let url = url.map_err(|error| {
        SiteSkillError::new(
            SiteSkillErrorCode::Origin,
            format!("the page's URL did not read ({})", error.code()),
        )
    })?;
    SiteSkillQuery::parse(&url).map_err(SiteSkillError::from)
}

impl BrowserSession {
    /// Gives the session the host's site skills (CUA E10): every open from
    /// now on carries the loadable skills of the exact site it lands on.
    pub fn set_site_skill_loader(&mut self, loader: Arc<dyn SiteSkillLoader>) {
        self.sites.loader = Some(loader);
    }

    /// The open hook (CALL 2): the skills of the page an open landed on,
    /// matched on its raw top-level URL after its redirects, never the URL
    /// asked for or the masked one an observation shows. They wait for the
    /// answer of the call that opened it; a load that fails is a note,
    /// never the open's failure.
    pub(super) fn site_skills_opened(&mut self) {
        if self.sites.loader.is_none() {
            return;
        }
        let key = page_key(self.driver.url());
        if let Some((matches, notes)) = self.sites.load(&key) {
            self.sites.pending = Some(Opened {
                key: key.ok(),
                matches,
                notes,
            });
        }
    }

    /// A batch or a library run starts: an open before it delivers on no
    /// answer of its.
    pub(super) fn site_skills_unsent(&mut self) {
        self.sites.pending = None;
    }

    /// The delivery rule (CALL 6): the last open's skills and notes go on
    /// the answer of the call that made it, once, only while the page it
    /// shows is still at the exact origin and path that open landed on.
    /// Its pages each carry them; no later call's answer repeats them, and
    /// paging loads nothing again.
    pub(super) fn deliver_site_skills(&mut self, observation: &mut Observation) {
        let Some(opened) = self.sites.pending.take() else {
            return;
        };
        if page_key(self.driver.url()).ok() == opened.key {
            observation.site_skills = opened.matches;
            observation.site_skill_notes = opened.notes;
        }
    }

    /// The same for a batch's or a library run's answer: its last
    /// observation, else its failed step's.
    pub(super) fn deliver_batch_site_skills(&mut self, batch: &mut BatchOutput) {
        let observation = match batch.observation.as_mut() {
            Some(observation) => Some(observation),
            None => batch
                .failed_receipt
                .as_mut()
                .and_then(|failed| failed.observation.as_mut()),
        };
        match observation {
            Some(observation) => self.deliver_site_skills(observation),
            None => self.site_skills_unsent(),
        }
    }

    /// The find query (CALL 4): the workflow site key, and the page whose
    /// seed candidates `find` lists. An explicit `url` names both, its key
    /// `site_of(url)`, which beside `site` must be the same; with no url,
    /// the open page's raw URL, only while its key is the site asked for.
    /// A bare host names no page: no scheme, port or route is guessed.
    pub(super) fn find_query(
        &mut self,
        site: Option<&str>,
        url: Option<&str>,
    ) -> Result<(String, Option<String>), BrowserError> {
        let asked = site.map(|site| site.trim().to_ascii_lowercase());
        if let Some(url) = url {
            let key = site_of(url).ok_or_else(|| {
                BrowserError::Input("find's url is no http or https page with a host".to_owned())
            })?;
            if let Some(site) = asked.filter(|site| *site != key) {
                return Err(BrowserError::Input(format!(
                    "find's site {site} and its url's site {key} differ; name one"
                )));
            }
            return Ok((key, Some(url.to_owned())));
        }
        if let Some(site) = asked {
            let page = self
                .sites
                .loader
                .as_ref()
                .and_then(|_| self.driver.url().ok())
                .filter(|page| site_of(page).as_deref() == Some(site.as_str()));
            return Ok((site, page));
        }
        let page = self.live()?.url()?;
        let site = site_of(&page)
            .ok_or_else(|| BrowserError::Input("the open page has no site; name one".to_owned()))?;
        Ok((site, Some(page)))
    }

    /// The seed candidates of the site skills that match `page`, kept as
    /// issued, apart from the library's programs, or the note that names
    /// why there are none.
    pub(super) fn find_candidates(
        &mut self,
        page: Option<&str>,
    ) -> (Vec<SeedCandidate>, Vec<SiteSkillError>) {
        let Some(page) = page else {
            return (Vec::new(), Vec::new());
        };
        let key = SiteSkillQuery::parse(page).map_err(SiteSkillError::from);
        let Some((matches, notes)) = self.sites.load(&key) else {
            return (Vec::new(), Vec::new());
        };
        let candidates = matches.into_iter().flat_map(|found| found.seeds).collect();
        (candidates, notes)
    }

    /// The proposal's two modes (CALL 5): a program given whole goes on as
    /// it is; a candidate's resolved program and provenance stand in for
    /// every program field the proposal gave, and its `args`,
    /// `replay_args` and `supersedes` stay the caller's. Either then takes
    /// the same two checks.
    pub(super) fn seeded_proposal(
        &self,
        mut input: ProposeInput,
    ) -> Result<ProposeInput, BrowserError> {
        let Some(candidate) = input.candidate.take() else {
            return Ok(input);
        };
        let body = self
            .resolved_seed(&candidate)
            .map_err(BrowserError::SiteSkill)?;
        Ok(ProposeInput {
            args: input.args,
            replay_args: input.replay_args,
            supersedes: input.supersedes,
            seed: Some(body.seed),
            candidate: Some(candidate),
            ..body.program
        })
    }

    /// The seed `candidate` names, as the host resolved it (CALL 3, CALL
    /// 7): the host's resolver checks the exact bytes against their
    /// import's digest; here the digest it gives must be the one this
    /// browser listed the candidate with.
    fn resolved_seed(&self, candidate: &str) -> Result<SeedBody, SiteSkillError> {
        let loader = self.sites.loader.as_ref().ok_or_else(|| {
            SiteSkillError::new(
                SiteSkillErrorCode::NoLoader,
                "this browser's host loads no site skills",
            )
        })?;
        let issued = self.sites.issued.get(candidate).ok_or_else(|| {
            SiteSkillError::new(
                SiteSkillErrorCode::NotIssued,
                format!("no open or find of this browser listed candidate {candidate}"),
            )
        })?;
        let body = loader.seed(candidate)?;
        if body.seed.digest != issued.digest {
            return Err(SiteSkillError::new(
                SiteSkillErrorCode::DigestMismatch,
                format!(
                    "candidate {candidate} was listed at digest {} and resolved at {}",
                    issued.digest, body.seed.digest
                ),
            ));
        }
        Ok(body)
    }
}
