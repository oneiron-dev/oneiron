# Graph workflow input attribution

`skill::execute_graph_workflow_skill` declares the skill-pack and
`skill.graph_input` read-set producers before it loads the resident workflow.
The declaration only records attribution. It does not admit a call or change
its reader, principal, lease, budget, or scope.

For text-only graph inputs, the workflow records the entity IDs in the native
prepared `GraphUnitContext.sources`. These are the unit and evidence bodies
that passed the existing same-snapshot reads and checks. Earlier-stage answer
claims enter the set only when a later input actually reads them. The runner
does not turn caller-named IDs or typed-question side-table keys into source
entities.

The graph producer reports after the whole workflow returns successfully.
A failed graph input reports unknown before its error returns. A missing or
withheld input and any image or audio read also keep the graph set unknown;
the complete media read set is not captured by this path yet. The existing
abstentions, completed stages, proposal writes, and error results are unchanged.
An unknown read set is not a refusal.

Read-set writes are best-effort. A recording error warns and attempts to mark
the producer unknown instead of failing the workflow. The attempt's terminal
receipt is complete only if every producer its owner declared reported a
complete set under the existing read-set rules. The generic public
`run_graph_question` API has no queued attempt and does not record an attempt
read set.
