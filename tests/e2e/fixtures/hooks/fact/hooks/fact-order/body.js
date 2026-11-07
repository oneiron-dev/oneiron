return {
  kind: "propose",
  claim: {
    subject: input.claim.subject,
    predicate: "fact.hooks.observation",
    confidence: 1,
    value: {
      marker: "amber-fact-catchup",
      sequence: input.claim.value.sequence,
      fact: input.claim.value.fact
    }
  }
};
