//! The host's follow-up drafts: the draft page and draft request the vault
//! reads, their scheduling, and the standing-reach-out checks behind them.

use super::*;

impl Vault {
    /// One page of the standing reach-outs whose rule has a draft route and
    /// no draft yet, read after the reach-out `after`: each one applied and
    /// not reverted, or held for the owner and not declined. A page is a
    /// traversal unit, never a cap: the host follows
    /// [`StewardshipDraftPage::next`] until it is `None`, so every due draft
    /// is read. A reach-out the vault holds no record to cite for has
    /// nothing to ground a draft in and is left to the owner.
    pub fn stewardship_draft_page(&self, after: Option<EntityId>) -> Result<StewardshipDraftPage> {
        let Some(rules) = self.stewardship_rules()? else {
            return Ok(StewardshipDraftPage::default());
        };
        if rules.rules.iter().all(|rule| rule.draft.is_none()) {
            return Ok(StewardshipDraftPage::default());
        }
        let authority = self.dreamer_authority()?.entity_ref();
        let reader = dreamer_reader(self)?;
        let page = {
            let txn = self.store.env.read_txn()?;
            crate::claim::claim_ids_for_predicate_page_in_txn(
                &self.store,
                &txn,
                STEWARDSHIP_PREDICATE,
                after,
                READ_CHUNK,
            )?
        };
        // A short page is the index's end.
        let next = if page.len() < READ_CHUNK {
            None
        } else {
            page.last().copied()
        };
        let mut drafts = Vec::new();
        for id in page {
            if let Some(request) = draft_request(self, &reader, &rules, authority, id)? {
                drafts.push(request);
            }
        }
        Ok(StewardshipDraftPage { drafts, next })
    }

    /// The draft request the reach-out `proposal` makes now, when it is a
    /// standing reach-out of the Dreamer's whose rule routes drafts and that
    /// has no draft yet: what a host drafts again against once its draft
    /// went stale (FIX 6079).
    pub fn stewardship_draft_request(
        &self,
        proposal: EntityId,
    ) -> Result<Option<StewardshipDraftRequest>> {
        let Some(rules) = self.stewardship_rules()? else {
            return Ok(None);
        };
        let authority = self.dreamer_authority()?.entity_ref();
        draft_request(self, &dreamer_reader(self)?, &rules, authority, proposal)
    }

    /// Schedules the host's draft of `draft`, the request it was written
    /// for, through the representation seam, once. The plan is that
    /// request's, never one derived again: its reach-out must still stand
    /// undrafted at its revision and its rule still route it exactly,
    /// checked before the planner and again in the writer, or the draft is
    /// [`StewardshipDraftOutcome::Stale`] and schedules nothing (FIX 6079),
    /// so text written under an old rule never goes out under a new one. A
    /// reach-out the owner reverted or declined, or a rule they removed, is
    /// stale too. The queued draft carries the reach-out and lands only
    /// while it still stands. The planner, its checks and the stored draft
    /// run outside any writer; the plan's row, its queued landing and the
    /// reach-out's draft mark then commit in one write (FIX 1000), so a
    /// crash between them drafts nothing twice.
    pub fn schedule_stewardship_draft(
        &self,
        draft: &StewardshipDraftRequest,
        planner: &mut dyn RepresentationPlanner,
        now: u64,
    ) -> Result<StewardshipDraftOutcome> {
        let authority = self.dreamer_authority()?.entity_ref();
        {
            let txn = self.store.env.read_txn()?;
            if !still_drafts_in_txn(self, &txn, authority, draft)? {
                return Ok(StewardshipDraftOutcome::Stale);
            }
        }
        let plan =
            self.prepare_follow_up(&draft.request, draft.proposal, draft.revision, planner)?;
        self.with_write_txn_grouped(|txn| {
            // The writer's own snapshot: still undrafted, the reach-out still
            // stands at the drafted revision, and its rule still routes this
            // draft.
            if !still_drafts_in_txn(self, &*txn, authority, draft)? {
                return Ok(StewardshipDraftOutcome::Stale);
            }
            let outcome = plan.enqueue_in_txn(self, txn, now)?;
            DRAFTED.put(&self.store, txn, &draft.proposal, &now)?;
            Ok(StewardshipDraftOutcome::Scheduled(outcome))
        })
    }
}

/// The person and draft route the owner's rules name for the reach-out
/// `body`, when its rule still routes drafts.
fn draft_route<'a>(
    rules: &'a StewardshipRules,
    body: &ClaimBody,
) -> Result<Option<(EntityId, &'a StewardshipDraftRoute)>> {
    let ClaimSubject::Entity(person) = body.subject else {
        return Ok(None);
    };
    let value: serde_json::Value =
        serde_json::from_str(body.value.as_str().ok_or_else(invalid)?).map_err(|_| invalid())?;
    Ok(rules
        .rules
        .iter()
        .find(|rule| rule.person == person && value["rule"].as_str() == Some(rule.id.as_str()))
        .and_then(|rule| rule.draft.as_ref())
        .map(|route| (person, route)))
}

impl StewardshipDraftRequest {
    /// Whether this request, read after `stale` went stale, is the owner's
    /// rule or the reach-out really moved (FIX 6079): its revision or its
    /// exact route differs. The evidence it cites may differ either way.
    #[must_use]
    pub fn moved_from(&self, stale: &Self) -> bool {
        self.revision != stale.revision
            || self.request.owner != stale.request.owner
            || self.instruction != stale.instruction
            || self.request.verb != stale.request.verb
            || self.request.channel != stale.request.channel
            || self.request.target != stale.request.target
            || self.request.voice != stale.request.voice
    }

    /// Whether `route`, in rules set by `owner`, still drafts this request:
    /// its voice is some of the route's, at least one, as a draft written
    /// over the voice samples one model was sent records only those (FIX
    /// 9447).
    fn drafted_by(&self, owner: EntityId, route: &StewardshipDraftRoute) -> bool {
        self.request.owner == owner
            && self.instruction == route.instruction
            && self.request.verb == route.verb
            && self.request.channel == route.channel
            && self.request.target == route.target
            && !self.request.voice.is_empty()
            && self
                .request
                .voice
                .iter()
                .all(|voice| route.voice.contains(voice))
    }
}

/// Whether `draft` still drafts as it was requested, read in `txn` (FIX
/// 1000, 6079): its reach-out undrafted and still standing at its revision,
/// and the owner's rules still routing it exactly.
fn still_drafts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    authority: EntityId,
    draft: &StewardshipDraftRequest,
) -> Result<bool> {
    if DRAFTED.contains(&vault.store, txn, &draft.proposal)? {
        return Ok(false);
    }
    let Some((body, revision)) = standing_reach_out_in_txn(vault, txn, authority, draft.proposal)?
    else {
        return Ok(false);
    };
    let Some(rules) = RULES.get(&vault.store, txn, &())? else {
        return Ok(false);
    };
    Ok(revision == draft.revision
        && draft_route(&rules, &body)?
            .is_some_and(|(_, route)| draft.drafted_by(rules.owner, route)))
}

/// The draft request one claim makes, when it is a standing reach-out of
/// the Dreamer's whose rule routes drafts and that has no draft yet.
fn draft_request(
    vault: &Vault,
    reader: &ScopedRead<'_>,
    rules: &StewardshipRules,
    authority: EntityId,
    proposal: EntityId,
) -> Result<Option<StewardshipDraftRequest>> {
    let (body, revision) = {
        let txn = vault.store.env.read_txn()?;
        if DRAFTED.contains(&vault.store, &txn, &proposal)? {
            return Ok(None);
        }
        match standing_reach_out_in_txn(vault, &txn, authority, proposal)? {
            Some(standing) => standing,
            None => return Ok(None),
        }
    };
    let Some((person, route)) = draft_route(rules, &body)? else {
        return Ok(None);
    };
    // Every eligible text record about the person, newest first. One the
    // route names as voice is cited there: the loader reads a source once.
    let evidence: Vec<RepresentationSourceRef> = recent(vault, reader, person, true)?
        .into_iter()
        .filter(|(claim, _)| !route.voice.iter().any(|voice| voice.claim == *claim))
        .map(|(claim, _)| RepresentationSourceRef { claim })
        .collect();
    if evidence.is_empty() {
        return Ok(None);
    }
    Ok(Some(StewardshipDraftRequest {
        proposal,
        instruction: route.instruction.clone(),
        request: RepresentationRequest {
            owner: rules.owner,
            kind: RepresentationKind::FollowUp,
            verb: route.verb.clone(),
            channel: route.channel.clone(),
            target: route.target.clone(),
            evidence,
            voice: route.voice.clone(),
        },
        revision,
    }))
}
