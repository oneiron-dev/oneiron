//! The bytes one served vault's model host holds at once (FIX 9321, FIX
//! 9323): one set per vault's runtime, built with its server and handed to
//! every adapter and mesh site that runtime builds, never a process-wide
//! line the first server to start installs.
//!
//! - The media-reply line (`limits.media_reply_bytes`): the bytes provider
//!   media replies hold, booked as [`super::http`] reads them and held by
//!   the media call they were read for until its answer leaves the adapter.
//!   Its crossings ask on the vault's own `[limits]` row.
//! - The model mesh's staging budget: what this node's mesh service holds
//!   for other nodes' calls and what its mesh transports hold for its own,
//!   one budget shared by the service, device sync's transport and the
//!   discovered routes' transport.
//!
//! Each is pacing only: work waits its turn while its budget is full, and
//! nothing is refused for its size. The totals are the vault's settings, or
//! the rows' defaults, as before.

use std::sync::Arc;

use crate::byte_line::ByteLine;
use crate::config::LimitsConfig;
use crate::wire_telemetry::{LimitQuestions, LimitRow};

/// One vault's model byte budgets. Clones share them.
#[derive(Clone)]
pub(crate) struct ModelHostBudgets {
    media: Arc<MediaReplyLine>,
    #[cfg(feature = "mesh")]
    staging: oneiron_llm_own_server::StagingBudget,
}

/// The media-reply line and where its row asks.
pub(in crate::models) struct MediaReplyLine {
    pub(in crate::models) line: ByteLine,
    pub(in crate::models) questions: Arc<LimitQuestions>,
}

impl ModelHostBudgets {
    /// The budgets of the vault whose `[limits]` are `limits`, its row
    /// crossings asked on `questions`.
    #[must_use]
    pub(crate) fn new(limits: &LimitsConfig, questions: Arc<LimitQuestions>) -> Self {
        Self {
            media: Arc::new(MediaReplyLine {
                line: ByteLine::new(
                    LimitRow::MediaReplyBytes,
                    usize::try_from(limits.media_reply_bytes).unwrap_or(usize::MAX),
                ),
                questions,
            }),
            #[cfg(feature = "mesh")]
            staging: oneiron_llm_own_server::StagingBudget::default(),
        }
    }

    /// A runtime's own budgets when no server hands it its vault's: the
    /// rows' defaults, whose crossings are logged and not kept.
    #[must_use]
    pub(crate) fn unhosted() -> Self {
        Self::new(&LimitsConfig::default(), Arc::default())
    }

    /// The media-reply line.
    pub(in crate::models) fn media_line(&self) -> &MediaReplyLine {
        &self.media
    }

    /// The model mesh's staging budget, shared by every mesh site of this
    /// vault.
    #[cfg(feature = "mesh")]
    #[must_use]
    pub(crate) fn mesh_staging(&self) -> oneiron_llm_own_server::StagingBudget {
        self.staging.clone()
    }
}
