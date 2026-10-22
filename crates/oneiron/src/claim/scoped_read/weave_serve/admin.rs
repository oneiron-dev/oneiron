//! The served weave Admin lens (OF-499 A3): an Admin's live report, its
//! live lens's two reads, its saved digest and its wrong labels, each under
//! the current Admin proof its caller presents. The proof is never chosen
//! for a caller: an ordinary read stays the person's or the agent's, and an
//! Owner proof stays the Owner's. Every read builds the Admin's lane in its
//! own transaction and revalidates the proof there; a proof no longer
//! current refuses that Admin request alone, typed
//! `AuthorityRefused(WEAVE_ADMIN_NOT_CURRENT)`. The served route is L13's to
//! bind (FIX 9431); nothing here is one.
//!
//! An Admin's lens card binds no backing ref and carries no wrong control
//! on its links or items yet: its frame holds a key that reads no row, so no
//! Admin key outlives the transaction that checked it, and the Admin label
//! verbs are L13's (FIX-LIST).
use super::super::weave_report::admin::WeaveAdminFrame;
use super::super::{
    ScopedRead, ScopedReadActorKey, WeaveItemTarget, WeaveLensRender, WeaveLiveLens, WeaveReader,
    WeaveReport,
};
use super::{
    WeaveDigestFramed, WeaveDigestRequest, WeaveDigestView, WeaveItemCorrectionView,
    WeaveLinkCorrectionView, WeaveReportRequest, WeaveReportView, WeaveWrongItemRequest,
    WeaveWrongLinkRequest,
};
use crate::Vault;
use crate::authority::AuthenticatedWeaveAdmin;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::lens::HostedLensRender;
use crate::memory::{Memory, MemoryError, MemoryResult};

/// The lane an Admin's lens composes under: its person's key that reads no
/// row, with no proof, grant or owner binding. Its frame mints no backing
/// ref and its later events read nothing.
fn weave_admin_compose_lane<'v>(
    vault: &'v Vault,
    admin: &AuthenticatedWeaveAdmin,
) -> Result<ScopedRead<'v>> {
    let key = ScopedReadActorKey::read_nothing(
        admin.actor().to_hex(),
        EdgeActorClass::Human.gate_actor_class(),
    )
    .ok_or_else(|| Error::InvalidConfig("a weave admin's person keys no lens frame".into()))?;
    Ok(vault.scoped_read(key))
}

impl Memory<'_> {
    /// This handle's read ceilings for an Admin read under `admin`: the
    /// handle must be the proof's own person's, and its destination and
    /// room turn are kept, resolved before any Admin read opens.
    fn weave_admin_frame(&self, admin: &AuthenticatedWeaveAdmin) -> MemoryResult<WeaveAdminFrame> {
        if self.actor() != admin.actor() || self.actor_class() != EdgeActorClass::Human {
            return Err(MemoryError::new(
                crate::memory::MEMORY_CODE_FORBIDDEN,
                "a weave admin reads on its own person's handle",
                &["Bind the handle to the person the Admin proof stands for."],
            ));
        }
        Ok(WeaveAdminFrame::new(
            self.destination().clone(),
            self.room_turn_now()?,
        ))
    }

    /// The Admin's live report for `request`, under its own lane.
    fn weave_admin_live_report(
        &self,
        admin: &AuthenticatedWeaveAdmin,
        request: &WeaveReportRequest,
    ) -> MemoryResult<crate::claim::ScopedReadResult<WeaveReport>> {
        let frame = self.weave_admin_frame(admin)?;
        Ok(self
            .vault()
            .weave_admin_report(admin, &frame, &Self::weave_recipe(request)?)?)
    }

    /// The live weave report of the Admin `admin` stands for, through its
    /// own lane and the vault's admin policy row held by its person: a
    /// vault-global shape inside the Admin's Scope.
    ///
    /// # Errors
    /// `AuthorityRefused(WEAVE_ADMIN_NOT_CURRENT)` when the proof is not
    /// current; `FORBIDDEN` on another actor's handle.
    pub fn weave_admin_report(
        &self,
        admin: &AuthenticatedWeaveAdmin,
        request: &WeaveReportRequest,
    ) -> MemoryResult<WeaveReportView> {
        let report = self.weave_admin_live_report(admin, request)?;
        self.produced_from(report.value.source_rows());
        Ok(WeaveReportView {
            sections: self.weave_sections(&report.value)?,
            narrowing: report.receipt,
        })
    }

    /// The Admin lens before its generate step: the Admin's live report,
    /// read as [`Self::weave_admin_report`] reads it and keyed for the
    /// weave-report skill. `None` when the skill does not load.
    ///
    /// # Errors
    /// As [`Self::weave_admin_report`].
    pub fn weave_admin_lens_prepare(
        &self,
        admin: &AuthenticatedWeaveAdmin,
        request: &WeaveReportRequest,
    ) -> MemoryResult<Option<WeaveLiveLens>> {
        let report = self.weave_admin_live_report(admin, request)?.value;
        self.produced_from(report.source_rows());
        let sections = self.weave_sections(&report)?;
        Ok(WeaveLiveLens::prepare(
            self.vault(),
            crate::gate::weave_policy::ADMIN_ROLE,
            report,
            &sections,
        )?)
    }

    /// The Admin lens after its generate step: re-reads the Admin's live
    /// report under a lane built again from its proof, and composes
    /// `answer` over the rows the first read admitted while the re-read
    /// still serves each of them; else `None`, and the host asks again from
    /// a fresh read. The render is kept under the Admin's grant; keeping it
    /// never gates the lens.
    ///
    /// # Errors
    /// As [`Self::weave_admin_report`]; `MODEL_UNAVAILABLE` for a plan that
    /// does not cite each item exactly once.
    pub fn weave_admin_lens_finish_framed(
        &self,
        admin: &AuthenticatedWeaveAdmin,
        request: &WeaveReportRequest,
        live: WeaveLiveLens,
        answer: &str,
        model: &str,
    ) -> MemoryResult<Option<HostedLensRender>> {
        let fresh = self.weave_admin_live_report(admin, request)?.value;
        if !super::super::weave_lens::snapshot_still_served(&live.report, &fresh) {
            return Ok(None);
        }
        let report = live.report;
        self.produced_from(report.source_rows());
        let plan = super::super::weave_lens::weave_lens_answer_plan(answer, &report).map_err(
            |reason| {
                MemoryError::new(
                    crate::memory::MEMORY_CODE_MODEL_UNAVAILABLE,
                    format!("the model's weave lens plan was refused: {reason}"),
                    &["Ask for the lens again."],
                )
            },
        )?;
        let render = WeaveLensRender {
            plan,
            skill_ref: live.skill_ref,
            skill_version: live.skill_version,
            model: model.to_owned(),
            rendered_at: self.vault().store.clock.now_recorded_at(),
        };
        let lane = weave_admin_compose_lane(self.vault(), admin)?;
        let lens = super::super::weave_lens::compose_weave_lens_framed(
            &lane,
            WeaveReader::Admin(admin),
            &report,
            &render,
        )?;
        if let Err(error) = self
            .vault()
            .keep_weave_admin_live_lens(admin, &report, &render)
        {
            tracing::warn!(
                error_kind = ?error.kind(),
                "an admin's live weave lens render was not kept"
            );
        }
        Ok(Some(lens))
    }

    /// The Admin's saved digest where no host keeps the frame: the period of
    /// [`Self::weave_admin_digest_framed`], its lens lowered for the whole
    /// atom kit.
    ///
    /// # Errors
    /// As [`Self::weave_admin_digest_framed`].
    pub fn weave_admin_digest(
        &self,
        admin: &AuthenticatedWeaveAdmin,
        request: &WeaveDigestRequest,
    ) -> MemoryResult<Option<WeaveDigestView>> {
        Ok(self
            .weave_admin_digest_framed(admin, request)?
            .map(|framed| framed.lower().0))
    }

    /// One of the Admin's saved digests, under the current read policy and
    /// its own lane, with its lens as a card beside its frame. Foreground
    /// only: the open renders no due period, and no Admin schedule writes
    /// one yet, so this answers `None` until one does.
    ///
    /// # Errors
    /// As [`Self::weave_admin_report`].
    pub fn weave_admin_digest_framed(
        &self,
        admin: &AuthenticatedWeaveAdmin,
        request: &WeaveDigestRequest,
    ) -> MemoryResult<Option<WeaveDigestFramed>> {
        let frame = self.weave_admin_frame(admin)?;
        let Some(stored) =
            self.vault()
                .read_weave_admin_digest(admin, &frame, request.scheduled_for)?
        else {
            return Ok(None);
        };
        let lane = weave_admin_compose_lane(self.vault(), admin)?;
        Ok(Some(self.weave_digest_view(
            &lane,
            WeaveReader::Admin(admin),
            stored,
        )?))
    }

    /// The Admin's wrong-link tap on a link its own Admin report shows,
    /// filed under its proof with its grant on the label. No verb calls it
    /// yet (L13).
    ///
    /// # Errors
    /// As [`Self::weave_admin_report`]; `NOT_FOUND` for a link its report
    /// does not show.
    pub fn weave_admin_wrong_link(
        &self,
        admin: &AuthenticatedWeaveAdmin,
        request: &WeaveWrongLinkRequest,
    ) -> MemoryResult<WeaveLinkCorrectionView> {
        let frame = self.weave_admin_frame(admin)?;
        let link = request.link()?;
        self.produced_from([link.source, link.target]);
        let filed = self
            .vault()
            .file_weave_admin_link_label(admin, &frame, link)?;
        Ok(WeaveLinkCorrectionView::from_correction(&filed))
    }

    /// The Admin's wrong-item tap on a claim, project, budget or sieve audit
    /// row its own Admin report shows, filed as a link's is.
    ///
    /// # Errors
    /// As [`Self::weave_admin_wrong_link`].
    pub fn weave_admin_wrong_item(
        &self,
        admin: &AuthenticatedWeaveAdmin,
        request: &WeaveWrongItemRequest,
    ) -> MemoryResult<WeaveItemCorrectionView> {
        let frame = self.weave_admin_frame(admin)?;
        let target = request.target()?;
        if !matches!(target, WeaveItemTarget::SieveAudit { .. }) {
            self.produced_from([target.id()]);
        }
        let filed = self
            .vault()
            .file_weave_admin_item_label(admin, &frame, target)?;
        Ok(WeaveItemCorrectionView::from_correction(&filed))
    }
}
