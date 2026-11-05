# Residence search completion

Online opened-item searches use the same home pager for every requested count.
The first request needs no cursor. A reply that fits one page still takes one
request.

The home ranks more actor-readable matches when the device's residence grant,
window selection or item admission removes earlier matches. It stops when it
has the requested number of selected hits or the ranking has no more matches.
A short initial candidate window is not treated as a complete search.

Each reply includes `hits`, `source`, `complete`, `revision` and `nextCursor`.
The device follows `nextCursor` until the selected list ends. A changed list
restarts the search, so pages do not combine different ranked lists. The first
page fixes the ranking time for later pages. Existing per-page hit and reply-byte
budgets determine each reply's size; they do not reduce the requested total.

Forwarded requests retain the caller proof, signed locality, recall scope and
device selector. Each page rechecks the app credential, grant and forwarded
caller before returning its rows. An initial request signs the same fields as
a search without a cursor; later requests also bind their cursor.

Offline searches remain local-only and incomplete. Forwarded or scoped searches
still do not fall back to a local scan when the home is unavailable.
