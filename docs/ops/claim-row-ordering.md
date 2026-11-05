# CLAIM row ordering in sealed mirrors

Stored entity rows have a 33-byte metadata header. The first 25 bytes still hold
its type, occurred interval and learned-at stamp. The next eight bytes hold a
big-endian `row_version`; the body starts at byte 33. Native non-CLAIM rows use
zero. This is the current format, not an upgrade reader for older rows.

## Where a version comes from

A local CLAIM put gets its version in the admitted write transaction. If its
actual stored type, occurred interval, learned-at stamp and physical body are
unchanged, it keeps the old version. A changed put takes one more than the
largest of the durable CLAIM floor, the previous row version and the version
observed by that put. Overflow is an error, not a saturated stamp.

Replicated and preserved rows carry their original version. Receiving an older
version does not restamp it or turn the write into last-writer-wins admission.
The write observes that version in the same transaction so a later local write
advances past it. A version is ordering data, not authority to read or write.

Session writes keep the version on the same journal entry as the put. Promotion
copies it with that entry's original times. The staging witness must name the
same open base store as the session; ordinary clones share that open store.

## What departure checks use

A sealed mirror still needs today's locally held CLAIM residence to prove that
a row left its window. When the same carried CLAIM has a strictly newer version,
its decoded residence must agree with that departure. The independent edge
check compares both endpoints by the same rule. A newer carried row can defeat
an old local proof; it cannot create a new departure that the old proof would
not allow.

An absent, unreadable, equal-version, older or non-CLAIM carrier leaves the old
proof in place. This does not choose a winning body, order unseen future peer
writes or replace the existing membership and consent checks.

## Copies and recovery

The raw metadata version follows admitted replicated entities, staged assets,
public replay and retained CLAIM shells. Byte-preserving actor-erasure and
value-redaction projections keep the original version. Local body or lifecycle
changes still use the local put path.

The CLAIM floor is a live scalar in `vault_meta`. Checkpoint capture saves it
before replacing authority-live rows and includes versions in the captured
entity headers. Restore retains the maximum of the image floor, captured CLAIM
headers and the destination's floor. It does not reset the destination clock.

Receipt-envelope header binding and corrupt-header capture compare all 33
metadata bytes. The body hash, signature domain and separate tombstone, request
and ONCF layouts do not change.

Engine and server builds must use the same entity format. There is no migration,
configuration switch or new timer, budget or residence cap.
