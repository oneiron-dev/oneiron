if (input.claim.value.revision !== "original") return { kind: "nothing" };
const anchor = await oneiron.read({ claim: input.claim.value.anchor });
return {
  kind: "propose",
  claim: {
    subject: input.claim.subject,
    predicate: "local.hooks.observation",
    confidence: 1,
    value: {
      marker: "cobalt-hook-replay",
      revision: input.claim.value.revision,
      anchor: anchor.value,
      hook_version: input.hook.version,
      now: input.now,
      clock: Date.now()
    }
  }
};
