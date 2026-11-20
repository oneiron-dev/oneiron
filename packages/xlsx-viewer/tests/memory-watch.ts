/**
 * Runs on its own thread in a child read ({@link ./read-in-child.ts}) and ends
 * the child's process once its resident memory passes the limit, so a read
 * that grows without end (SheetJS's `encode_col(Infinity)` builds one string
 * for ever) ends its own child, not the test run. Asked once the read is
 * done, it answers the most resident memory it saw.
 */
/** The most resident memory a child read may hold. */
const MEMORY_LIMIT_BYTES = 4 * 1024 ** 3;
/** How often the resident memory is read. */
const PERIOD_MS = 50;

/** The most resident memory seen so far, which the child asks for once it has read. */
let peakBytes = 0;

setInterval(() => {
  const resident = process.memoryUsage.rss();
  peakBytes = Math.max(peakBytes, resident);
  if (resident > MEMORY_LIMIT_BYTES) {
    console.error(`memory-watch: resident memory passed ${MEMORY_LIMIT_BYTES} bytes`);
    process.kill(process.pid, "SIGKILL");
  }
}, PERIOD_MS);
onmessage = () => {
  postMessage(Math.max(peakBytes, process.memoryUsage.rss()));
};
postMessage("watching");

export {};
