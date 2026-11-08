return { kind: "propose", claim: { subject: input.claim.subject,
  predicate: "local.hooks.sandboxcontrol.observed", confidence: 1,
  value: { marker: "violet-owner-progress", phase: input.claim.value.phase,
    trigger: input.fact.entity } } };
