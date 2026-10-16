//! The server's half of a kind slot version move (OF-370; ARCH-0004
//! `#swap-check-ruling`, `#swap-check-not-worse`). The media backfill fills an
//! open move's candidate beside the spaces the slots bind; once a pass finds
//! nothing left to embed there, the vault's probes run paired on both spaces
//! ([`oneiron::Vault::check_space_move`]): each probe query goes through the
//! incumbent's tower twice, for its retest noise, and through the candidate's
//! once. The engine swaps the candidate in, keeps the incumbent, or leaves the
//! move open, and leaves the result note.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oneiron::embed::{
    InputKind, MediaEmbedReport, MediaEmbedder, SpaceMove, SpaceMoveOutcome, SpaceMoveState,
    SpaceProbeEncoder, SpaceRef,
};

use super::core::SyncServer;
use super::media_embedding::{MediaEmbedRefusal, RuntimeMediaEmbedder};

/// How long an undecided move waits before its probes run again.
const SPACE_MOVE_RECHECK: Duration = Duration::from_secs(6 * 60 * 60);
/// The media type a probe query is sent as.
const PROBE_MEDIA_TYPE: &str = "text/plain; charset=utf-8";

/// One media backfill pass's result per space.
pub(super) type SpacePasses = Vec<(String, Result<MediaEmbedReport, MediaEmbedRefusal>)>;

/// The query towers a move's probes go through: the server's own text
/// embedder for the vault's text index, a declared space's `ai.embed` rung
/// otherwise.
struct ServerProbeEncoder<'a> {
    server: &'a SyncServer,
    incumbent: Option<RuntimeMediaEmbedder>,
    candidate: RuntimeMediaEmbedder,
    runtime: &'a tokio::runtime::Handle,
}

impl SpaceProbeEncoder for ServerProbeEncoder<'_> {
    fn encode_probe(&self, space: &SpaceRef, query: &str) -> oneiron::Result<Vec<f32>> {
        let embedder = match space {
            SpaceRef::TextIndex => {
                return self.server.embed_query(query).map_err(|refusal| {
                    oneiron::Error::InvalidConfig(format!(
                        "the text index's embedder refused a probe query: {refusal:?}"
                    ))
                });
            }
            SpaceRef::Declared(id) if *id == self.candidate.space_id() => &self.candidate,
            SpaceRef::Declared(id) => self
                .incumbent
                .as_ref()
                .filter(|incumbent| incumbent.space_id() == id)
                .ok_or_else(|| {
                    oneiron::Error::InvalidConfig(format!(
                        "no probe tower is open for embedding space {id}"
                    ))
                })?,
        };
        Ok(self.runtime.block_on(embedder.embed_query(
            InputKind::Text,
            PROBE_MEDIA_TYPE,
            query.as_bytes().to_vec(),
        ))?)
    }
}

impl SyncServer {
    /// Runs the paired probes of every open move whose candidate's pass just
    /// stored nothing, once it has never run or [`SPACE_MOVE_RECHECK`] has
    /// passed since. A check that fails takes the candidate's place in
    /// `passes`, so the backfill logs it once and backs off. Blocking.
    pub(super) fn check_space_moves(
        &self,
        runtime: &tokio::runtime::Handle,
        moves: &[SpaceMove],
        passes: &mut SpacePasses,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        for moving in moves
            .iter()
            .filter(|moving| moving.state == SpaceMoveState::Open)
        {
            let Some(pass) = passes
                .iter_mut()
                .find(|(space, _)| *space == moving.candidate)
                .map(|(_, pass)| pass)
            else {
                continue;
            };
            if !matches!(pass, Ok(report) if report.embedded == 0) {
                continue;
            }
            if moving.last_check.as_ref().is_some_and(|check| {
                now.saturating_sub(check.checked_at) < SPACE_MOVE_RECHECK.as_secs()
            }) {
                continue;
            }
            match self.check_space_move(runtime, moving) {
                Ok(SpaceMoveOutcome::Filling) => {}
                Ok(SpaceMoveOutcome::SwappedIn(check)) => tracing::info!(
                    candidate = %moving.candidate,
                    incumbent = %moving.incumbent,
                    verdict = ?check.verdict,
                    "embedding space move swapped in: not worse on the vault's probes"
                ),
                Ok(SpaceMoveOutcome::Kept(check)) => tracing::info!(
                    candidate = %moving.candidate,
                    incumbent = %moving.incumbent,
                    verdict = ?check.verdict,
                    "embedding space move kept the incumbent: the candidate scored worse"
                ),
                Ok(SpaceMoveOutcome::Undecided(check)) => tracing::info!(
                    candidate = %moving.candidate,
                    incumbent = %moving.incumbent,
                    verdict = ?check.verdict,
                    "embedding space move undecided: the incumbent keeps serving"
                ),
                Err(refusal) => *pass = Err(refusal),
            }
        }
    }

    fn check_space_move(
        &self,
        runtime: &tokio::runtime::Handle,
        moving: &SpaceMove,
    ) -> Result<SpaceMoveOutcome, MediaEmbedRefusal> {
        let candidate = self
            .media_embedder(&moving.candidate)?
            .on_runtime(runtime.clone());
        let incumbent = match &moving.incumbent {
            SpaceRef::TextIndex => None,
            SpaceRef::Declared(id) => Some(self.media_embedder(id)?.on_runtime(runtime.clone())),
        };
        let encoder = ServerProbeEncoder {
            server: self,
            incumbent,
            candidate,
            runtime,
        };
        Ok(self.vault.check_space_move(&moving.candidate, &encoder)?)
    }
}
