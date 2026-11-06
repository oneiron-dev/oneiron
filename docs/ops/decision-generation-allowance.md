# Decision generation allowances and receipts

A decision clock and a generation allowance are separate controls. `Deadline` means the
call ran out of work time, its answer arrived too late, or the caller took the answer
early. `GenerationAllowance` means the caller allowed no further logical generation to
start. It does not mean a timeout, a provider failure, or a measured token total.
`CaptureUnsupported` means no remaining provider can complete the requested captured
read. It does not turn the ordinary provider interface into a fallback.

The ladder keeps the same prior-answer rule for each cut. A reversible read may keep
its last eligible answer. A read with no answer, an abstained or in-band prior, or an
outbound effect cannot use that prior at the cut. Its receipt and any person ask name
the actual stop cause. A cut rung never becomes the source of an earlier answer.

The captured-provider interface keeps unsupported reads separate from unstarted reads.
An unsupported `None` returns before that provider reads or sends; it never permits a
retry through the ordinary interface. A supported read keeps its original provider
error and every native settlement in its paid prefix. `NotStarted` is not an abstention,
a negative answer, or a zero person probability. In a sequential pack, it retains its
question ordinal and leaves later questions unstarted.

Captured offline, standing host, attribution, and placement rule reads use their original
single and pack methods. They start no model generation and consume no generation allowance;
their settlement inventories are empty because those native methods admit and send nothing,
not because absence proves no work. Attribution still filters its prepared facts against the
question's options. Placement still uses its already-prepared tree reading; capture does not
read a new tree or turn that reading into authority.

The native captured-request adapter keeps the ordinary singleton, packed, and
person-appended request shapes. It transfers settlements before it checks the provider
result, arity, or answers. A fully answered request uses the original person join and
answer-clock handling. A mixed request keeps unstarted question ordinals unpinned; an
answered target whose person question did not start stays an incomplete logical read,
not an answer with a made-up person probability. A late answered target keeps only its
attempted provider pin.

The optional captured ladder uses that adapter at each native request boundary. A
whole unstarted chunk may skip an unsupported provider without splitting the native
pack into probes. Each question keeps the rung that served its chunk. A tournament
that already answered a chunk keeps its attempted pins and settlements if a later
chunk cannot start; its incomplete outer winner is not an answer. Unsupported
step-ups try the remaining configured takers, then use the same eligible-prior cut
rule. They never enter the unavailable-provider branch that discards that prior.

The allowance is a granted start slot, not proof of provider bytes or token use. A
native admission after that slot may still fail. Memo recovery starts no generation;
a schema correction uses a new logical generation, while a transport retry reuses the
same one. Receipt counts and successful-response counts do not establish that boundary.

The optional durable port checks a caller's logical-generation admission only after
memo recovery and the native request and schema preflights. Each schema correction
checks it again, while transport retries reuse that attempt's lease and logical
start. A denied first start returns a typed cut without usage. A denied correction
keeps the actual answered, settled prefix, including an actual zero report; it
never turns that prefix into a provider error, a fallback, or a memoized answer.
Lease-admitted observations and request captures remain separate from provider
bytes and logical-generation admission.

The optional scoped generated entry carries that same context through the first
generation and the native captured stronger-provider close. Generated-backend usage
stays in the caller's spend inventory; native stronger-provider settlements stay in
the caller's receipt inventory even on a later error. Neither inventory alone proves
complete usage. These ports do not connect the Arc's actual pace counter or enable
its stronger reads by themselves.

Settlement inventories also do not establish complete token measurement. Missing usage
stays unknown; billed reservations and currency charges are not actual token counts.
Reading a settlement never authorizes settling the model permit a second time.

The Arc stronger-read path remains excluded by `generated_only`. The typed captured
outcomes, native common path, and truthful stop vocabulary do not enable it by
themselves. Provider coverage, memo-aware correction pacing, and the accounting join
must be complete first.
