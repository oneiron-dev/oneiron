# Native stock-model download cards

A Coach STOCK offer for a captured managed llama.cpp or ExLlamaV3 worker now
publishes an owner inbox card when its exact files are not verified locally.
This uses the same immutable worker/artifact/store capture as the Coach's
verified local-weight facts. It never installs, launches, probes or calls a model.
A registry entry, local route or absent worker is not positive file evidence.
If the runtime has no native manifest supplier, the ordinary offer remains.

The `coach.stock_download_card` notification contains the actual model id,
native manifest SHA-256, repository and full source revision, licence id and
licence-file path, and every file's path, SHA-256 and size. The repository,
revision and licence-file path locate the pinned licence text. These are source
facts, not model instructions, licence permission or a claim that the model ran.
The original installer and its licence checks are unchanged.

The native producer validates the manifest without fetching it. The offer's
writer checks the pending STOCK candidate and its current nonstale registry
pin/source/licence before recording the card. All current Owners receive it.
No TRAIN offer, manual answer, undo or existing offer branch is changed.
Failures to obtain or record the card leave the original offer available.

The whole card determines the notification identity, independently of the
particular offer or its check date. Repeated offers reuse the same card and its
existing Seen/Acked state. Changed files or licence facts produce a different
identity. The notification itself follows the existing entity checkpoint,
restore, deletion, delivery and recipient rules; there is no new side table.
A deleted notification stays deleted under the existing replay rules.

Publishing or listing the notification does **not** mark it Seen. The existing
`Memory::inbox_mark` door records only its caller's Seen/Acked state, with its
original actor/read/write checks. `stock_download_card_seen` requires such a
mark by a current Owner on the exact card. An agent's own mark does not stand
for an Owner's mark. This is a delivery receipt, not an extra approval prompt.
The native automatic consumer must reconstruct the current worker's card
again, rather than accept a request boolean or an old receipt as current facts.

This source slice is not an automatic switch. The live saved-policy,
current-pair serving/rate, quality/sufficiency and original switch guards still
belong to that consumer. An already verified exact worker manifest may need no
download card, but says nothing about the actual served binding or permission.
Unknown comparisons retain the manual offer. TRAIN never auto-deploys.
