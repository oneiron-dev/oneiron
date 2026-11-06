# tendril 0.5.1 native backing reservation

Upstream: https://crates.io/crates/tendril/0.5.1, Servo/html5ever.
Archive SHA-256: `5fed54709c5b3a53d09bb1c113ea4f5ceafd1e772ddcb0030a82e1d56c087b08`.
MIT OR Apache-2.0; both upstream license files are retained.

This is a same-version production snapshot. The package version, production
features and dependencies stay unchanged. Examples, benches, dev dependencies
and final test-only modules are not vendored. No upstream test is modified.

## Local changes

- `ReserveError` and additive `try_from_slice_with_reservation` /
  `try_reserve_with_reservation` let a caller reserve native backing before
  allocation and settle the reported allocation size before copying bytes.
- The allocation extent is the actual `Vec<Header>` capacity times its element
  size, including the native header and rounding. The stored usable capacity
  reconstructs that same allocation on drop. No input-size multiplier is used.
- The native shared header owns the caller's `Send + Sync` reservation. Native
  clone, long subtendril and format moves retain the same allocation/header.
  Last-owner destruction extracts the reservation, drops the native header and
  backing, then releases the reservation. Plain header field drop would release
  it too early and is deliberately not used.
- A fallible replacement keeps old and new backing live and charged until the
  complete replacement has been settled and copied. Error leaves the original
  value unchanged; failed temporary buffers free before their reservation.
- Ordinary APIs remain available and unadmitted. Their copying/CoW paths can
  create unadmitted allocations. An ordinary growth of an admitted owned block
  uses a fresh ordinary block, then frees/releases the old one, rather than
  retaining an old-size reservation across realloc. In-place writes and native
  sharing keep the original allocation's reservation.
- Both refcount types retain their existing `usize` layout contract. The new
  non-generic header field has the same placement for both. Owned `into_send`
  moves that header; shared `into_send` keeps its ordinary copying behavior.
  Inline `into_send` skips `make_owned`, matching its existing no-allocation
  contract and preventing a hidden unadmitted block in atomic DOM wrapping.

Caller scope: the checked HTML comment producer reserves before each real UTF-8
append and moves the resulting native tendril into the existing DOM comment.
Other parser/DOM payloads, ordinary copies, the boxed guard's own metadata,
allocator-private overhead and opaque native intervals are not covered. This
is not a complete HTML heap or hard-time bound.
