# Window-pad receive buffers

A socket joins an UPDATE, RESIDENCE_UPDATE or REPLACEMENT from its existing
window-pad first frame and ordered parts. Each physical frame keeps its current
size limit. The envelope's length fields, digests, offsets, capsule checks and
receipt format are unchanged.

Before it allocates a receive buffer, the receiver takes a lease from the
process's shared physical-memory line. It does not wait on the socket's async
worker. A multipart delivery reserves room for both its joined wire bytes and
the decoded fields that coexist at completion. The join buffer reserves its
whole declared length once, so later parts do not grow it. Allocated capacities
replace the reservations as the buffers are made.

The decoded envelope keeps its lease through the home's existing admission,
persistence and fan-out path. On a device, the payload keeps the same lease
through the existing source projection and window import. A notice still
borrows its physical frame. The payload, references and capsule drop before
their lease, including when a delivery is replaced, malformed, disconnected or
rejected. Once the joined wire buffer is no longer needed, its allocation drops
before that part of the lease is returned.

If the current physical-memory line cannot admit a delivery, or its buffer
cannot be allocated, the existing transport storage-error path reports it.
Nothing from that incomplete delivery imports or earns a receipt. No new
memory cap, retry timer, protocol tag, cursor or durability state is introduced.

For a federated UPDATE, native owned payload bytes and their existing lease move
into retained work together. Retained-work clones share that same byte buffer
and lease. The ordinary borrowed federation import door still admits and copies
its input. Control frames and non-federated window imports keep their existing
borrowed path.

This accounting covers the received wire buffer and owned decoded fields, plus
the same original payload when it moves into retained federation work.
Source-projection and Loro internals, outbound frames, separate admitted-part
buffers, encoded queue rows and review copies have their own lifetimes. Moving
the original payload does not account for their internal allocations. The
separate federation logical-update size checks are unchanged.
