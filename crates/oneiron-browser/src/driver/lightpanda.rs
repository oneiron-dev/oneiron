//! Where a Lightpanda guest differs from a Chromium one (FIX 6680,
//! BROWSER-SPLIT), on Lightpanda 1.0.0's CDP (lightpanda-io/browser at
//! 588f6223b9cae8a2406aeef035ed9363a3e404fd). Every Chromium call stays as
//! it is; on Lightpanda:
//!
//! - one page per connection: `Target.createTarget` refuses a second page
//!   while the first stands, so the driver keeps the page it opened first
//!   and never asks for another. A second tab, and the blank tab Chromium
//!   opens once every tab closed, answer [`BrowserError::Unsupported`]
//!   naming the engine, before any attach or create;
//! - `Target.setAutoAttach` follows no popup, so the browser-wide follow is
//!   not asked for; the first page's network still goes through the host's
//!   proxy (its `Fetch` domain) before any page loads, as on Chromium;
//! - `DOM.getNodeForLocation` is not served, and a click at a point needs
//!   it to find the row whose press the click takes: `click_at` answers
//!   `Unsupported` before any input is sent;
//! - `DOM.pushNodesByBackendIdsToFrontend` is not served: the gone-node
//!   probe is never sent, which proves no node gone, as a failed probe does;
//! - `DOM.scrollIntoViewIfNeeded` answers without scrolling: the driver
//!   sends it all the same;
//! - a `rawKeyDown` is ignored: a key goes down as a `keyDown`, with its
//!   text when it types, else with none, and comes up as a `keyUp`.

use super::{CdpDriver, KeySpec};
use crate::{BrowserEngine, BrowserError, TabSwitchCause};

/// What Lightpanda does not serve, as its refusal names it.
fn unsupported(what: &str) -> BrowserError {
    BrowserError::Unsupported(format!(
        "{what} on the {} engine",
        BrowserEngine::Lightpanda.as_str()
    ))
}

impl CdpDriver {
    /// Refuses `what` on a Lightpanda guest, which does not serve it; a
    /// Chromium guest serves it as always.
    pub(super) fn chromium_only(&self, what: &str) -> Result<(), BrowserError> {
        match self.engine {
            BrowserEngine::Chromium => Ok(()),
            BrowserEngine::Lightpanda => Err(unsupported(what)),
        }
    }

    /// Whether the browser is asked to attach every page it opens: only
    /// Chromium follows its popups.
    pub(super) const fn follows_pages(&self) -> bool {
        matches!(self.engine, BrowserEngine::Chromium)
    }

    /// Whether the gone-node probe is sent: only Chromium serves it.
    pub(super) const fn probes_gone_nodes(&self) -> bool {
        matches!(self.engine, BrowserEngine::Chromium)
    }

    /// Follows the tabs at an agent verb's edge, as [`Self::follow`] does,
    /// with the refusal the verb answers apart. On Chromium a look that
    /// fails leaves the front where it was and refuses nothing, as always.
    /// On Lightpanda a tab the driver cannot follow (a second one, or a new
    /// one once its only page closed) is the verb's typed refusal.
    pub(crate) fn follow_or_refusal(&mut self) -> (Option<TabSwitchCause>, Option<BrowserError>) {
        match self.follow() {
            Ok(moved) => (moved, None),
            Err(refused @ BrowserError::Unsupported(_))
                if self.engine == BrowserEngine::Lightpanda =>
            {
                (None, Some(refused))
            }
            Err(_) => (None, None),
        }
    }

    /// One key going down that types nothing: a held modifier, or a key
    /// under ctrl, alt or meta. Chromium takes it as a `rawKeyDown`;
    /// Lightpanda ignores one, so there it is a `keyDown` with no text.
    pub(super) fn key_down_bare(&self, key: &KeySpec, modifiers: u32) -> Result<(), BrowserError> {
        match self.engine {
            BrowserEngine::Chromium => self.key_event("rawKeyDown", key, modifiers),
            BrowserEngine::Lightpanda => {
                let bare = KeySpec {
                    key: key.key.clone(),
                    code: key.code.clone(),
                    vk: key.vk,
                    text: None,
                };
                self.key_event("keyDown", &bare, modifiers)
            }
        }
    }
}
