"""The Generator a session layer runs on: the stock Generator over a
SessionPageTable, so the pages sessions retain join the page table's own
defragmentation and validation accounting. Everything else is stock; a
session-less Job runs on it exactly as on the stock Generator.
"""
from exllamav3 import Generator

from .pages import SessionPageTable


def unsupported(target, draft):
    """Why this layer cannot serve sessions on `target` with `draft`, or None
    when it can. Each is an explicit capability limit."""
    if not target.caps.get("recurrent_states"):
        # The stock prefill's partial-page match scans every page by token
        # on a model with no recurrent state, session pages included.
        return "the target keeps no recurrent state"
    if getattr(target, "loaded_tp", False):
        return "the target is loaded tensor-parallel"
    if draft is not None and draft.caps.get("mtp_draft"):
        return "the draft is an MTP head"
    return None


class SessionGenerator(Generator):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # No Job has run: the stock table is replaced before any page moves.
        self.pagetable = SessionPageTable(self, self.cache)
        if self.recurrent_cache is not None:
            self.recurrent_cache.pagetable = self.pagetable
        if self.cpu_page_cache is not None:
            self.cpu_page_cache.attach(self.pagetable)
            self.pagetable.cpu_tier = self.cpu_page_cache
        # The session layer, once the server has made it.
        self.sessions = None
