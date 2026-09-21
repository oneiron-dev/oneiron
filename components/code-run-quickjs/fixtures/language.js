const twice = x => x * 2;
const values = new Map([["x", 21]]);
const result = await Promise.resolve(twice(values.get("x")));
finish({result, regexp: /quick(js)+/i.test("QuickJS"), bigint: String(2n ** 64n)});
