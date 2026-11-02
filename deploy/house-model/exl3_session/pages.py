"""The page table a session layer runs on: exllamav3's PageTable with owners.

An owner holds page references outside any Job: the pages a canonical
checkpoint retains, or the carry a thinking call's reasoning pass leaves its
answer pass. Each page an owner lists holds one reference from it, taken
with the stock `add_ref` and given back with `sub_ref`, so the stock
eviction order never takes a held page, and a Job attached to one shares it
read only.

Session pages keep the random hash they were taken with: none is ever a
content-hash candidate, for a session-less call or another session. A
session page nothing holds any more is cleared (`scrub`), so its KV is never
found again, even where its tokens repeat.

Defragmentation, which the stock table runs only with no page referenced
(active block tables index pages), also runs when every reference is an
owner's: owners hold CachePage objects and a block table is built only when
a Job attaches, so the stock page rotation moves their KV with them.
Validation counts the owners' references beside the Jobs'.
"""
from types import SimpleNamespace

from exllamav3.generator.pagetable import PageTable, is_content_hash


class Owner:
    """Page references held outside any Job, one per listed page."""

    __slots__ = ("pages",)

    def __init__(self):
        self.pages = []


class SessionPageTable(PageTable):

    def __init__(self, generator, cache):
        super().__init__(generator, cache)
        self.owners = set()

    def hold(self, owner, pages):
        """`owner` takes one reference on each of `pages`, which a Job or
        another owner references now."""
        for page in pages:
            self.access_serial += 1
            page.add_ref(self.access_serial)
            owner.pages.append(page)
        self.owners.add(owner)

    def adopt(self, owner, pages):
        """`owner` takes over the one reference each of `pages` holds from
        their allocation, which no Job holds: an import's fresh pages."""
        owner.pages.extend(pages)
        self.owners.add(owner)

    def release(self, owner):
        """Gives back every reference `owner` holds. A page nothing holds any
        more is free at once, and cleared."""
        pages, owner.pages = owner.pages, []
        self.owners.discard(owner)
        for page in pages:
            page.sub_ref()
        self.scrub(pages)

    def scrub(self, pages):
        """Clears each of `pages` nothing references that holds session KV:
        a page under a random hash with tokens in it."""
        for page in pages:
            if page.ref_count == 0 and page.kv_position and not is_content_hash(page.phash):
                page.clear()

    def held(self, owners=None):
        """The distinct pages `owners` hold (every owner by default)."""
        pages = {}
        for owner in self.owners if owners is None else owners:
            for page in owner.pages:
                pages[id(page)] = page
        return list(pages.values())

    def page_bytes(self):
        """The device bytes one page holds over the target's cache and the
        draft's; None when a cache layer cannot say."""
        caches = [self.cache]
        draft = getattr(self.generator, "draft_cache", None)
        if draft is not None:
            caches.append(draft)
        try:
            total = sum(int(layer.storage_size()) for cache in caches for layer in cache.layers.values())
        except Exception:
            return None
        return total // self.max_pages

    def defrag(self, debug=False):
        counts = {}
        for owner in self.owners:
            for page in owner.pages:
                counts[id(page)] = counts.get(id(page), 0) + 1
        if any(page.ref_count != counts.get(id(page), 0) for page in self.referenced_pages.values()):
            # A Job holds a page: as stock, never defragment under one.
            return
        referenced, self.referenced_pages = self.referenced_pages, {}
        try:
            super().defrag(debug)
        finally:
            self.referenced_pages = referenced

    def validate_pagetable(self, active_jobs):
        # Each owner as the stock check reads a Job: its pages, and no
        # tokens to compare.
        holders = [SimpleNamespace(sequences=[SimpleNamespace(allocated_pages=owner.pages, kv_position=0)])
                   for owner in self.owners]
        super().validate_pagetable(list(active_jobs) + holders)
