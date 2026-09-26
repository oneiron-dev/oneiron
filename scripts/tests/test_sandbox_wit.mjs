import assert from 'node:assert/strict';
import { createHostSdk } from '../../crates/oneiron/wit/generated/code-run.mjs';

const calls = [];
const sdk = createHostSdk({
  'ask': input => ({waitId: input.prompt}),
  'memory-put-claim': input => { calls.push(input); return { id: input.id }; },
  'memory-search': input => ({results: [JSON.stringify({value: input.query})]}),
  'clock-now-unix-ms': () => 1234,
  'random-bytes': length => new Uint8Array(length).fill(7),
});
assert.deepEqual(await sdk.self.memory.put_claim({id:'id', predicate:'profile.test', subject:{entity:'person'}, value:{text:'hello'}}), {id:'id'});
assert.equal(calls[0].subject, '{"entity":"person"}');
assert.equal(calls[0].value, '{"text":"hello"}');
assert.deepEqual(await sdk.self.memory.search({query:'hello'}), {results:[{value:'hello'}]});
assert.deepEqual(await sdk.ask({prompt:'hello'}), {waitId:'hello'});
assert.equal(sdk.self.ask_human, undefined);
assert.equal(sdk.self.askHuman, undefined);
assert.equal(sdk.oneiron.clock.now_unix_ms(), 1234);
assert.deepEqual(sdk.oneiron.random.bytes(3), new Uint8Array([7,7,7]));
assert.throws(() => sdk.oneiron.random.bytes(-1), RangeError);
const foreign = createHostSdk({'clock-now-unix-ms': () => 99});
assert.equal(foreign.self, undefined);
assert.equal(foreign.ask, undefined);
assert.equal(foreign.oneiron.clock.now_unix_ms(), 99);
console.log('WIT guest SDK adaptation: passed');
