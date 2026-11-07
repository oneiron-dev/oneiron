return {
  kind: "enqueue",
  task: {
    title: "Inspect the paused fixture budget",
    body: JSON.stringify({ seat: input.result.seat, accounting: input.result.accounting }),
  },
};
